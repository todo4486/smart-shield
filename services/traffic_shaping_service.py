"""Optional, allow-listed traffic shaping with Linux `tc` (HTB). OFF by default.

Safety model
* Disabled unless SMART_SHIELD_TC_ENABLED=true, the OS is Linux, the tc binary
  exists, and the interface is in SMART_SHIELD_TC_INTERFACES.
* Only these fixed operations exist: apply an accepted recommendation, show the
  current qdisc, roll back to the previous state, and emergency-disable. Each
  builds argv lists from validated values and runs subprocess.run([...]) with
  shell=False. No user text ever becomes a command.
* Admin-only (APPLY_TRAFFIC_POLICY). Apply and rollback require the admin to
  type the interface name to confirm. Every attempt, failed ones included, is
  stored in policy_actions and the audit log.
* Reversible: the state before each apply is recorded, and rollback restores it
  (or removes the root qdisc if there was none).
* Never modifies firewall rules, routes or interface configuration.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from config import get_settings
from repositories import bandwidth_repository
from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import utc_now_iso

INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,15}$")  # Linux IFNAMSIZ - 1
MIN_RATE_BPS = 8_000  # tc cannot shape below ~1 kB/s meaningfully
MAX_RATE_BPS = 400_000_000_000
COMMAND_TIMEOUT_SECONDS = 10
DEFAULT_CLASS_MINOR = 99  # unclassified traffic

Runner = Callable[[List[str]], subprocess.CompletedProcess]


class ShapingError(Exception):
    pass


@dataclass
class Availability:
    available: bool
    reasons: List[str] = field(default_factory=list)
    interfaces: tuple = ()


def _default_runner(argv: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, shell=False, check=False, capture_output=True, text=True,
                          timeout=COMMAND_TIMEOUT_SECONDS)


_runner: Runner = _default_runner


def set_runner_for_tests(runner: Optional[Runner]) -> None:
    global _runner
    _runner = runner or _default_runner


def availability(system: Optional[str] = None) -> Availability:
    settings = get_settings()
    reasons = []
    if not settings.tc_enabled:
        reasons.append("Traffic shaping is disabled (SMART_SHIELD_TC_ENABLED is not true). This is the safe default.")
    if (system or platform.system()) != "Linux":
        reasons.append(f"Linux `tc` is required; this server runs {system or platform.system()}. "
                       "Recommendation mode still works fully.")
    if not os.path.isabs(settings.tc_binary) or not os.path.exists(settings.tc_binary):
        reasons.append(f"The tc binary was not found at {settings.tc_binary}.")
    bad = [i for i in settings.tc_interfaces if not INTERFACE_RE.match(i)]
    if bad:
        reasons.append("Invalid interface names in SMART_SHIELD_TC_INTERFACES: " + ", ".join(bad))
    if not settings.tc_interfaces:
        reasons.append("No interfaces are allow-listed in SMART_SHIELD_TC_INTERFACES.")
    return Availability(not reasons, reasons, tuple(i for i in settings.tc_interfaces if INTERFACE_RE.match(i)))


def _check_interface(interface: str) -> str:
    if not INTERFACE_RE.match(interface or ""):
        raise ShapingError("Invalid interface name.")
    if interface not in get_settings().tc_interfaces:
        raise ShapingError(f"Interface {interface} is not allow-listed for traffic shaping.")
    return interface


def _rate(value: float) -> str:
    rate = int(value)
    if not MIN_RATE_BPS <= rate <= MAX_RATE_BPS:
        raise ShapingError(f"Rate {rate} bit/s is outside the supported range.")
    return f"{rate}bit"


def build_apply_commands(interface: str, total_bps: int, classes: Sequence[dict]) -> List[List[str]]:
    """HTB tree: 1: root -> 1:1 (total) -> 1:1N per class (rate = allocation, ceil = maximum), plus a
    small default class for unmatched traffic. DSCP filters classify packets when a class has one."""
    tc = get_settings().tc_binary
    interface = _check_interface(interface)
    commands = [
        [tc, "qdisc", "replace", "dev", interface, "root", "handle", "1:", "htb", "default", str(DEFAULT_CLASS_MINOR)],
        [tc, "class", "replace", "dev", interface, "parent", "1:", "classid", "1:1", "htb",
         "rate", _rate(total_bps), "ceil", _rate(total_bps)],
    ]
    reserved = 0
    for index, c in enumerate(classes, start=10):
        if index >= DEFAULT_CLASS_MINOR:
            raise ShapingError("Too many traffic classes.")
        rate = max(int(c["allocated_bps"]), MIN_RATE_BPS)
        ceil = max(int(min(c["maximum_bps"], total_bps)), rate)
        reserved += rate
        commands.append([tc, "class", "replace", "dev", interface, "parent", "1:1", "classid", f"1:{index}", "htb",
                         "rate", _rate(rate), "ceil", _rate(ceil)])
        dscp = c.get("dscp")
        if dscp is not None:
            if not 0 <= int(dscp) <= 63:
                raise ShapingError("DSCP must be between 0 and 63.")
            commands.append([tc, "filter", "replace", "dev", interface, "parent", "1:", "protocol", "ip",
                             "prio", str(index), "u32", "match", "ip", "dsfield", hex(int(dscp) << 2), "0xfc",
                             "flowid", f"1:{index}"])
    default_rate = max(MIN_RATE_BPS, total_bps - reserved) if total_bps - reserved > MIN_RATE_BPS else MIN_RATE_BPS
    commands.append([tc, "class", "replace", "dev", interface, "parent", "1:1", "classid", f"1:{DEFAULT_CLASS_MINOR}",
                     "htb", "rate", _rate(default_rate), "ceil", _rate(total_bps)])
    return commands


def build_remove_commands(interface: str) -> List[List[str]]:
    return [[get_settings().tc_binary, "qdisc", "del", "dev", _check_interface(interface), "root"]]


def _run(commands: List[List[str]], tolerate_missing: bool = False) -> List[dict]:
    log = []
    for argv in commands:
        result = _runner(argv)
        entry = {"argv": argv, "returncode": result.returncode, "stderr": (result.stderr or "")[-500:]}
        log.append(entry)
        if result.returncode != 0:
            missing = "No such file" in entry["stderr"] or "Cannot delete qdisc with handle of zero" in entry["stderr"]
            if not (tolerate_missing and missing):
                raise ShapingError(f"`{' '.join(argv[1:4])}` failed: {entry['stderr'] or result.returncode}")
    return log


def current_state(principal: Principal, interface: str) -> str:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="shaping.view", details={"interface": interface})
    state = availability()
    if not state.available:
        raise ShapingError(" ".join(state.reasons))
    argv = [get_settings().tc_binary, "-s", "class", "show", "dev", _check_interface(interface)]
    result = _runner(argv)
    if result.returncode != 0:
        raise ShapingError(result.stderr or "tc failed")
    return result.stdout or "(no classes)"


def _record(principal: Principal, *, action_type: str, interface: str, recommendation_id: Optional[int],
            before: Optional[dict], after: Optional[dict], status: str, error: Optional[str]) -> int:
    with database_service.session(write=True) as conn:
        action_id = bandwidth_repository.insert_action(conn, {
            "recommendation_id": recommendation_id, "action_type": action_type, "target_interface": interface,
            "policy_before_json": json.dumps(before) if before is not None else None,
            "policy_after_json": json.dumps(after) if after is not None else None,
            "status": status, "executed_by": principal.user_id, "executed_at": utc_now_iso(),
            "error_message": error,
        })
        if status == "succeeded" and action_type == "apply" and recommendation_id:
            bandwidth_repository.set_recommendation_status(conn, recommendation_id, "applied")
        audit_service.record(conn, user_id=principal.user_id, action=f"shaping.{action_type}",
                             outcome="success" if status == "succeeded" else "failure",
                             details={"interface": interface, "recommendation_id": recommendation_id,
                                      "action_id": action_id, "error": error})
    return action_id


def preview_apply(principal: Principal, recommendation_id: int, interface: str) -> List[List[str]]:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="shaping.preview",
                       details={"recommendation_id": recommendation_id})
    _, commands = _plan(recommendation_id, interface)
    return commands


def _plan(recommendation_id: int, interface: str):
    with database_service.session() as conn:
        row = bandwidth_repository.get_recommendation(conn, recommendation_id)
    if row is None:
        raise ShapingError("Recommendation not found.")
    if row["status"] != "accepted":
        raise ShapingError("Only an accepted recommendation can be applied. Accept it first.")
    payload = json.loads(row["recommendation_json"])
    result = payload["result"]
    dscp = payload.get("dscp", {})
    classes = [{"name": a["name"], "allocated_bps": a["allocated_bps"], "maximum_bps": a["maximum_bps"],
                "dscp": dscp.get(a["name"])} for a in result["allocations"]]
    after = {"recommendation_id": recommendation_id, "total_bps": result["usable_bps"], "classes": classes}
    return after, build_apply_commands(interface, int(result["usable_bps"]), classes)


def apply_recommendation(principal: Principal, recommendation_id: int, interface: str, *, confirm_interface: str) -> int:
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="shaping.apply",
                       details={"recommendation_id": recommendation_id, "interface": interface})
    state = availability()
    if not state.available:
        raise ShapingError(" ".join(state.reasons))
    if confirm_interface != interface:
        raise ShapingError("Type the interface name exactly to confirm.")
    after, commands = _plan(recommendation_id, interface)
    with database_service.session() as conn:
        previous = bandwidth_repository.last_successful_apply(conn, interface)
    before = json.loads(previous["policy_after_json"]) if previous else {"state": "no shaping applied by Smart Shield"}
    try:
        _run(commands)
    except (ShapingError, subprocess.SubprocessError, OSError) as exc:
        _record(principal, action_type="apply", interface=interface, recommendation_id=recommendation_id,
                before=before, after=after, status="failed", error=str(exc)[:500])
        raise ShapingError(f"Applying failed: {exc}. Use rollback or emergency disable if the link misbehaves.") from exc
    return _record(principal, action_type="apply", interface=interface, recommendation_id=recommendation_id,
                   before=before, after=after, status="succeeded", error=None)


def rollback(principal: Principal, interface: str, *, confirm_interface: str) -> int:
    """Restore the state recorded before the most recent successful apply."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="shaping.rollback", details={"interface": interface})
    state = availability()
    if not state.available:
        raise ShapingError(" ".join(state.reasons))
    if confirm_interface != interface:
        raise ShapingError("Type the interface name exactly to confirm.")
    with database_service.session() as conn:
        last = bandwidth_repository.last_successful_apply(conn, interface)
    if last is None:
        raise ShapingError("There is no applied policy to roll back on this interface.")
    before = json.loads(last["policy_before_json"]) if last["policy_before_json"] else {}
    if before.get("classes"):
        commands = build_apply_commands(interface, int(before["total_bps"]), before["classes"])
        tolerate = False
    else:
        commands = build_remove_commands(interface)
        tolerate = True
    try:
        _run(commands, tolerate_missing=tolerate)
    except (ShapingError, subprocess.SubprocessError, OSError) as exc:
        _record(principal, action_type="rollback", interface=interface, recommendation_id=last["recommendation_id"],
                before=json.loads(last["policy_after_json"]), after=before, status="failed", error=str(exc)[:500])
        raise ShapingError(f"Rollback failed: {exc}. Use emergency disable.") from exc
    with database_service.session(write=True) as conn:
        bandwidth_repository.mark_rolled_back(conn, last["id"], utc_now_iso())
    return _record(principal, action_type="rollback", interface=interface, recommendation_id=last["recommendation_id"],
                   before=json.loads(last["policy_after_json"]), after=before, status="succeeded", error=None)


def emergency_disable(principal: Principal) -> List[int]:
    """Remove Smart Shield's root qdisc from every allow-listed interface."""
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="shaping.emergency_disable")
    state = availability()
    if not get_settings().tc_enabled or not state.interfaces:
        raise ShapingError(" ".join(state.reasons) or "Traffic shaping is not configured.")
    ids = []
    for interface in state.interfaces:
        try:
            _run(build_remove_commands(interface), tolerate_missing=True)
            ids.append(_record(principal, action_type="emergency_disable", interface=interface, recommendation_id=None,
                               before=None, after={"state": "root qdisc removed"}, status="succeeded", error=None))
        except (ShapingError, subprocess.SubprocessError, OSError) as exc:
            ids.append(_record(principal, action_type="emergency_disable", interface=interface, recommendation_id=None,
                               before=None, after=None, status="failed", error=str(exc)[:500]))
    return ids


def action_history(principal: Principal, limit: int = 100) -> List[dict]:
    require_permission(principal, Permission.VIEW_DASHBOARD, action="shaping.history")
    with database_service.session() as conn:
        return [dict(r) for r in bandwidth_repository.list_actions(conn, limit)]
