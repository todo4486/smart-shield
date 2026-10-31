"""Runs the mitigation engine's decisions on a real network, or shows what would run.

Which backend (SMART_SHIELD_ENFORCEMENT_BACKEND, read from the server's environment, never set from the dashboard)
* dry_run, the default: nothing is changed. The exact commands are stored and shown, and the action is labelled.
* pf or tc: used only if capability() finds the right OS, tools and privileges and an allow-listed interface.
  If not, the app stays in dry run and says why, so a badly configured server can never look as if it were enforcing.

Safety
* Commands come only from enforcement_adapters, as argv lists with no shell.
* Refused for every backend, dry run included: loopback, multicast and unspecified addresses, protected hosts, and
  blocking or isolating this machine's own address (that would cut it off). Isolation needs a lab interface.
* A failed apply undoes whatever part of it worked. A failed removal raises, so the action stays active and on show.

Limits to be honest about
* Limits live in the kernel, not this process. If the app is killed they stay until the next start (close_orphans),
  a rollback, or a reboot; expiry only runs while the app runs. `pfctl -E` needs a token to be released, and a restart
  loses it, so pf stays enabled with an empty anchor, which filters nothing.
* Capture sees incoming packets before pf or tc acts on them, so what happens to incoming traffic cannot be measured
  from capture. See measurable_after_enforcement.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from config import get_settings
from repositories import mitigation_repository as repo
from services import database_service, settings_service
from services.enforcement_adapters import (
    DNCTL, INTERFACE_RE, PF_CONF, PFCTL, EnforcementError, PfAdapter, Rule, Step, TcAdapter, rule_from, steps_public,
)

DRY_RUN = "dry-run"
COMMAND_TIMEOUT_SECONDS = 10
TOKEN_RE = re.compile(r"Token\s*:\s*(\d+)")
CHECK_TARGET = "203.0.113.77"  # TEST-NET-3 (RFC 5737): reserved for documentation, so no real traffic matches it
CHECK_LIMIT_BPS = 1_000_000
Runner = Callable[[Sequence[str], Optional[str]], subprocess.CompletedProcess]


def _default_runner(argv: Sequence[str], stdin: Optional[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), input=stdin, shell=False, check=False, capture_output=True, text=True,
                          timeout=COMMAND_TIMEOUT_SECONDS)


@dataclass
class Capability:
    requested: str  # what the server's configuration asks for
    backend: str  # what will really be used: "tc", "pf+dnctl" or "dry-run"
    reasons: List[str] = field(default_factory=list)  # why the requested backend cannot be used
    interfaces: Tuple[str, ...] = ()
    lab_interfaces: Tuple[str, ...] = ()
    privileged: bool = False

    @property
    def enforcing(self) -> bool:
        return self.backend != DRY_RUN


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _has_net_admin() -> bool:
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 12))
    except OSError:
        pass
    return False


def _pf_conf_has_anchors() -> bool:
    try:
        with open(PF_CONF) as handle:
            text = handle.read()
    except OSError:
        return False
    return 'dummynet-anchor "com.apple/*"' in text and 'anchor "com.apple/*"' in text


def capability() -> Capability:
    settings = get_settings()
    requested = settings.enforcement_backend
    system = platform.system()
    reasons: List[str] = []
    privileged = _is_root()
    if requested == "pf":
        if system != "Darwin":
            reasons.append(f"The pf backend needs macOS; this server runs {system}.")
        for tool in (PFCTL, DNCTL):
            if not os.path.exists(tool):
                reasons.append(f"{tool} was not found.")
        if not privileged:
            reasons.append("pf and dnctl need root. Start the app with sudo in a network you are allowed to change.")
        if not _pf_conf_has_anchors():
            reasons.append(f"{PF_CONF} does not evaluate the com.apple anchors, so rules there would have no effect.")
    elif requested == "tc":
        privileged = privileged or _has_net_admin()
        if system != "Linux":
            reasons.append(f"The tc backend needs Linux; this server runs {system}.")
        if not os.path.exists(settings.tc_binary):
            reasons.append(f"{settings.tc_binary} was not found (package iproute2).")
        if not privileged:
            reasons.append("tc needs root or the CAP_NET_ADMIN capability.")
    if requested != "dry_run":
        bad = [i for i in settings.enforcement_interfaces if not INTERFACE_RE.match(i)]
        if bad:
            reasons.append("Invalid names in SMART_SHIELD_ENFORCEMENT_INTERFACES: " + ", ".join(bad))
        if not settings.enforcement_interfaces:
            reasons.append("No interface is listed in SMART_SHIELD_ENFORCEMENT_INTERFACES.")
    backend = DRY_RUN
    if requested != "dry_run" and not reasons:
        backend = {"pf": PfAdapter.name, "tc": TcAdapter.name}[requested]
    return Capability(requested, backend, reasons, tuple(i for i in settings.enforcement_interfaces if INTERFACE_RE.match(i)),
                      settings.enforcement_lab_interfaces, privileged)


def isolation_allowed(interface: Optional[str]) -> bool:
    return bool(interface) and interface in get_settings().enforcement_lab_interfaces


def local_addresses() -> Set[str]:
    try:
        import psutil

        return {a.address.split("%")[0] for items in psutil.net_if_addrs().values() for a in items}
    except Exception:  # without it we cannot tell, and the caller treats traffic as unmeasurable
        return set()


def measurable_after_enforcement(target_kind: str, target: str) -> bool:
    """True when the limited traffic is leaving this machine, because capture sees outgoing packets after pf and tc."""
    is_local = target in local_addresses()
    return is_local if target_kind == "source" else not is_local


def refusal(mitigation: Mapping[str, Any]) -> Optional[str]:
    """Why this target may not be acted on, for any backend. None when it may."""
    if mitigation["target_kind"] == "link":  # no address to check: rule_from explains why it cannot be enforced
        return None
    target = mitigation["target"]
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return "The target must be a single IP address."
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        return f"{target} is a loopback, multicast or unspecified address, so it cannot be a target."
    if target in settings_service.get_mitigation_settings().protected_hosts:
        return f"{target} is on the protected hosts list, so nothing was changed."
    if mitigation["action_type"] in ("block", "isolate") and target in local_addresses():
        return f"{target} is this machine: blocking it would cut this machine off, so nothing was changed."
    if mitigation["action_type"] == "isolate" and not isolation_allowed(mitigation.get("interface_name")):
        return "Host isolation needs an interface marked as a lab network (SMART_SHIELD_ENFORCEMENT_LAB_INTERFACES)."
    return None


def _adapter_named(name: Optional[str]):
    if name == PfAdapter.name:
        return PfAdapter()
    if name == TcAdapter.name:
        return TcAdapter(get_settings().tc_binary)
    return None


def _plan_adapter():
    """The commands a dry run shows are those for this server's OS."""
    return PfAdapter() if platform.system() == "Darwin" else TcAdapter(get_settings().tc_binary)


class RealEnforcer:
    """Keeps no copy of what is enforced: the database's active actions, plus any being applied right now, are the state."""

    def __init__(self, runner: Runner = _default_runner):
        self._runner = runner
        self._lock = threading.Lock()  # a pf ruleset is rewritten whole, so changes must not overlap
        self._applying: Dict[int, Rule] = {}
        self._token: Optional[str] = None

    @property
    def name(self) -> str:
        return capability().backend

    def _run(self, steps: Iterable[Step]) -> None:
        for step in steps:
            try:
                result = self._runner(step.argv, step.stdin)
            except (subprocess.SubprocessError, OSError) as exc:
                raise EnforcementError(f"`{' '.join(step.argv[:3])}` could not run: {exc}") from exc
            output = f"{result.stdout or ''}\n{result.stderr or ''}"
            if result.returncode != 0 and not any(text in output for text in step.tolerate):
                raise EnforcementError(f"`{' '.join(step.argv[:3])}` failed: {(result.stderr or str(result.returncode))[-300:]}")
            if step.captures_token and result.returncode == 0:
                match = TOKEN_RE.search(output)
                self._token = match.group(1) if match else None

    def _rules_on(self, adapter_name: str, excluding: Optional[int] = None) -> List[Rule]:
        with database_service.session() as conn:
            rows = [dict(r) for r in repo.active_with_adapter(conn, adapter_name)]
            still_applying = [r for mid, r in self._applying.items()
                              if (row := repo.get(conn, mid)) is not None and row["status"] == "proposed"]
        rules = {rule_from(row).mitigation_id: rule_from(row) for row in rows}
        rules.update({r.mitigation_id: r for r in still_applying})
        rules.pop(excluding, None)
        return list(rules.values())

    def apply(self, mitigation: Mapping[str, Any]) -> List[Dict[str, Any]]:
        why_not = refusal(mitigation)
        if why_not:
            raise EnforcementError(why_not)
        rule = rule_from(mitigation)
        state = capability()
        if not state.enforcing:
            adapter = _plan_adapter()
            steps = adapter.plan_apply(rule, [])
            return steps_public(([adapter.enable_step] if adapter.enable_step else []) + steps)
        if rule.interface not in state.interfaces:
            raise EnforcementError(f"Interface {rule.interface} is not listed for enforcement, so nothing was changed.")
        adapter = _adapter_named(state.backend)
        with self._lock:
            others = self._rules_on(adapter.name, excluding=rule.mitigation_id)
            if any(adapter.slot(r) == adapter.slot(rule) for r in others):
                raise EnforcementError("Another active action uses the same slot. Roll it back first.")
            steps = list(adapter.plan_apply(rule, others))
            if adapter.enable_step and self._token is None:
                steps.append(adapter.enable_step)
            try:
                self._run(steps)
            except EnforcementError:
                self._undo_quietly(adapter, rule, others)
                raise
            self._applying[rule.mitigation_id] = rule
        return steps_public(steps)

    def _undo_quietly(self, adapter, rule: Rule, others: Sequence[Rule]) -> None:
        for step in adapter.plan_remove(rule, others):
            try:
                self._run([step])
            except EnforcementError:
                pass  # the original failure is the one to report

    def remove(self, mitigation: Mapping[str, Any]) -> None:
        adapter = _adapter_named(mitigation.get("adapter"))
        if adapter is None:  # a dry run changed nothing
            return
        rule = rule_from(mitigation)
        with self._lock:
            remaining = self._rules_on(adapter.name, excluding=rule.mitigation_id)
            steps = list(adapter.plan_remove(rule, remaining))
            release = adapter.release_step(self._token) if not remaining else None
            self._run(steps + ([release] if release else []))
            self._applying.pop(rule.mitigation_id, None)
            if release:
                self._token = None

    def clear(self) -> List[str]:
        """Emergency disable: everything this app installed, on every interface it could have used. Returns failures."""
        failures: List[str] = []
        state = capability()
        with database_service.session() as conn:
            rows = {name: [dict(r) for r in repo.active_with_adapter(conn, name)] for name in (PfAdapter.name, TcAdapter.name)}
        names = {n for n, items in rows.items() if items} | ({state.backend} if state.enforcing else set())
        with self._lock:
            for name in sorted(names):
                adapter = _adapter_named(name)
                rules = [rule_from(row) for row in rows[name]]
                interfaces = {*state.interfaces, *(r.interface for r in rules)}
                steps = adapter.plan_clear(interfaces, rules)
                release = adapter.release_step(self._token)
                try:
                    self._run(steps + ([release] if release else []))
                    self._applying.clear()
                    if release:
                        self._token = None
                except EnforcementError as exc:
                    failures.append(str(exc))
        return failures


def describe_commands(commands: Optional[Sequence[Mapping[str, Any]]]) -> str:
    """Commands as a person would read them. For display only: nothing ever runs this text."""
    lines = []
    for command in commands or []:
        line = " ".join(command["argv"])
        lines.append(f"{line}\n  <<rules\n" + "".join(f"  {r}\n" for r in command["stdin"].splitlines()) + "  rules"
                     if command.get("stdin") else line)
    return "\n".join(lines)


def self_check(backend: str, interface: str, *, install: bool, runner: Runner = _default_runner,
               output: Callable[[str], None] = print) -> bool:
    """Prove a backend on this machine with no database and no real traffic. The target is a reserved address.

    Without `install` it only prints the plan. With it: install a limit and a block, read them back, remove them, and
    read back again. A failure removes whatever was installed.
    """
    if not INTERFACE_RE.match(interface or ""):
        raise EnforcementError("Invalid interface name.")
    adapter = PfAdapter() if backend == "pf" else TcAdapter(get_settings().tc_binary)
    limit = rule_from({"id": 19_998, "action_type": "rate_limit", "target_kind": "source", "target": CHECK_TARGET,
                       "limit_bps": CHECK_LIMIT_BPS, "interface_name": interface})
    block = rule_from({"id": 19_999, "action_type": "block", "target_kind": "source", "target": "203.0.113.78",
                       "limit_bps": None, "interface_name": interface})
    enforcer = RealEnforcer(runner)
    plan = [*([adapter.enable_step] if adapter.enable_step else []), *adapter.plan_apply(limit, []),
            *adapter.plan_apply(block, [limit])]
    undo = [*adapter.plan_remove(block, [limit]), *adapter.plan_remove(limit, [])]
    output("Would install:\n" + describe_commands(steps_public(plan)))
    output("Would remove:\n" + describe_commands(steps_public(undo)))
    if not install:
        output("Nothing was changed. Add --install, as root, to try it for real.")
        return True

    def installed() -> bool:
        text = ""
        for step in adapter.read_back(interface):
            result = runner(step.argv, None)
            shown = f"{result.stdout or ''}{result.stderr or ''}"
            output(f"$ {' '.join(step.argv)}\n{shown}")
            text += shown
        return "203.0.113.78" in text

    passed = False
    try:
        enforcer._run(plan)
        passed = installed()
        output("Read back: the block rule is installed." if passed else "Read back: the block rule was NOT found.")
    except EnforcementError as exc:
        output(f"Installing failed: {exc}")
    finally:
        release = adapter.release_step(enforcer._token)
        try:
            enforcer._run([*undo, *([release] if release else [])])
        except EnforcementError as exc:
            output(f"REMOVING FAILED, check by hand: {exc}")
            passed = False
    if passed and installed():
        output("Read back: the block rule is STILL installed.")
        passed = False
    output("Self-check passed: installed, read back and removed." if passed else "Self-check FAILED.")
    return passed
