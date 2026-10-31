"""What to run to enforce a mitigation: fixed command plans for Linux `tc` and macOS `pf` + `dnctl` (pure functions).

Nothing runs here. Each adapter turns a validated Rule into Steps, which are argv lists for subprocess.run with no shell.
Rule validates its address, interface and rate before any command exists, so no free text can reach a command or a
pf ruleset.

Linux `tc`: a clsact qdisc with one flower filter per direction, using `police` to limit and `drop` to block. It sits
beside the root qdisc, so a class policy from traffic_shaping_service keeps working. Policing drops what exceeds the
limit instead of queueing it.

macOS `pf` + `dnctl`: a dummynet pipe per rate limit, and rules in the anchor `com.apple/smart_shield`. The default
/etc/pf.conf already evaluates `com.apple/*`, so the system's main ruleset is never touched. Loading a ruleset into an
anchor replaces it, so removing a rule means loading the remaining ones, and clearing means loading an empty one. No
plan ever uses `pfctl -F`.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

PFCTL = "/sbin/pfctl"
DNCTL = "/usr/sbin/dnctl"
PF_ANCHOR = "com.apple/smart_shield"
PF_CONF = "/etc/pf.conf"
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,15}$")
MIN_RATE_BPS = 8_000
MAX_RATE_BPS = 400_000_000_000
PIPE_BASE, PIPE_SPAN = 40_000, 20_000
PREF_BASE, PREF_SPAN = 1_000, 30_000
MISSING = ("not found", "Cannot find", "No such file", "handle of zero", "Invalid argument")
ANY_FAILURE = ("",)  # a substring of every message
ENFORCED_ACTIONS = ("rate_limit", "block", "isolate")


class EnforcementError(Exception):
    pass


@dataclass(frozen=True)
class Step:
    argv: Tuple[str, ...]
    stdin: Optional[str] = None
    tolerate: Tuple[str, ...] = ()  # a failure whose message holds one of these means there was nothing to undo
    captures_token: bool = False

    def public(self) -> Dict[str, Any]:
        return {"argv": list(self.argv), **({"stdin": self.stdin} if self.stdin is not None else {})}


@dataclass(frozen=True)
class Rule:
    mitigation_id: int
    action_type: str
    target_kind: str
    target: str
    limit_bps: Optional[int]
    interface: str

    @property
    def is_ipv6(self) -> bool:
        return ipaddress.ip_address(self.target).version == 6


def rule_from(mitigation: Mapping[str, Any]) -> Rule:
    """The only way to get a Rule. Everything a command will contain is checked here."""
    action = mitigation["action_type"]
    if action not in ENFORCED_ACTIONS:
        raise EnforcementError("Prioritizing by class is calculated per interval and is not available on a real link. "
                               "Use a class policy in Bandwidth Management → Enforcement.")
    interface = mitigation.get("interface_name")
    if not interface:
        raise EnforcementError("Only a live capture has an interface to enforce on, so nothing was changed.")
    if not INTERFACE_RE.match(str(interface)):
        raise EnforcementError("Invalid interface name, so nothing was changed.")
    if mitigation["target_kind"] not in ("source", "destination"):
        raise EnforcementError("The target must be a source or a destination.")
    try:
        target = str(ipaddress.ip_address(str(mitigation["target"])))
    except ValueError as exc:
        raise EnforcementError("The target must be a single IP address.") from exc
    limit = None
    if action == "rate_limit":
        limit = int(mitigation["limit_bps"] or 0)
        if not MIN_RATE_BPS <= limit <= MAX_RATE_BPS:
            raise EnforcementError(f"A rate of {limit} bit/s is outside the supported range.")
    return Rule(int(mitigation["id"]), action, mitigation["target_kind"], target, limit, str(interface))


# ------------------------------------------------------------------ Linux tc

class TcAdapter:
    name = "tc"
    enable_step: Optional[Step] = None

    def __init__(self, binary: str = "/sbin/tc"):
        self.binary = binary

    @staticmethod
    def slot(rule: Rule) -> int:
        return PREF_BASE + 2 * (rule.mitigation_id % PREF_SPAN)

    def _filter(self, rule: Rule, hook: str, pref: int, field: str) -> Step:
        action = (["police", "rate", f"{rule.limit_bps}bit", "burst", str(max(1600, int(rule.limit_bps / 80))),
                   "conform-exceed", "drop/ok"] if rule.action_type == "rate_limit" else ["drop"])
        return Step((self.binary, "filter", "add", "dev", rule.interface, hook, "protocol", "ipv6" if rule.is_ipv6 else "ip",
                     "pref", str(pref), "flower", field, rule.target, "action", *action))

    @staticmethod
    def _matches(rule: Rule) -> List[str]:
        if rule.action_type == "isolate":
            return ["src_ip", "dst_ip"]
        return ["src_ip" if rule.target_kind == "source" else "dst_ip"]

    def plan_apply(self, rule: Rule, others: Sequence[Rule]) -> List[Step]:
        steps = [Step((self.binary, "qdisc", "replace", "dev", rule.interface, "clsact"))]
        for offset, field in enumerate(self._matches(rule)):
            for hook in ("ingress", "egress"):
                steps.append(self._filter(rule, hook, self.slot(rule) + offset, field))
        return steps

    def plan_remove(self, rule: Rule, remaining: Sequence[Rule]) -> List[Step]:
        steps = []
        for offset, _ in enumerate(self._matches(rule)):
            for hook in ("ingress", "egress"):
                steps.append(Step((self.binary, "filter", "del", "dev", rule.interface, hook, "pref",
                                   str(self.slot(rule) + offset)), tolerate=MISSING))
        if not any(r.interface == rule.interface for r in remaining):
            steps.append(self._remove_qdisc(rule.interface))
        return steps

    def _remove_qdisc(self, interface: str) -> Step:
        return Step((self.binary, "qdisc", "del", "dev", interface, "clsact"), tolerate=MISSING)

    def plan_clear(self, interfaces: Iterable[str], rules: Sequence[Rule]) -> List[Step]:
        return [self._remove_qdisc(i) for i in sorted(set(interfaces)) if INTERFACE_RE.match(i)]

    def release_step(self, token: Optional[str]) -> Optional[Step]:
        return None

    def read_back(self, interface: str) -> List[Step]:
        return [Step((self.binary, "filter", "show", "dev", interface, hook), tolerate=MISSING) for hook in ("ingress", "egress")]


# ------------------------------------------------------------------ macOS pf + dnctl

class PfAdapter:
    name = "pf+dnctl"
    enable_step: Optional[Step] = Step((PFCTL, "-E"), captures_token=True)

    @staticmethod
    def slot(rule: Rule) -> int:
        return PIPE_BASE + rule.mitigation_id % PIPE_SPAN

    @staticmethod
    def rule_lines(rule: Rule) -> List[str]:
        family = "inet6" if rule.is_ipv6 else "inet"
        on = f"quick on {rule.interface} {family}"
        match = f"from {rule.target} to any" if rule.target_kind == "source" else f"from any to {rule.target}"
        if rule.action_type == "rate_limit":  # pf refuses a dummynet rule with no direction
            return [f"dummynet {direction} {on} {match} pipe {PfAdapter.slot(rule)}" for direction in ("in", "out")]
        lines = [f"block drop {on} {match}"]
        if rule.action_type == "isolate":
            lines = [f"block drop {on} from {rule.target} to any", f"block drop {on} from any to {rule.target}"]
        return lines

    @classmethod
    def ruleset(cls, rules: Sequence[Rule]) -> str:
        return "".join(line + "\n" for rule in sorted(rules, key=lambda r: r.mitigation_id) for line in cls.rule_lines(rule))

    @staticmethod
    def _load(ruleset: str) -> Step:
        return Step((PFCTL, "-a", PF_ANCHOR, "-f", "-"), stdin=ruleset)

    def plan_apply(self, rule: Rule, others: Sequence[Rule]) -> List[Step]:
        steps: List[Step] = []
        if rule.action_type == "rate_limit":
            steps.append(Step((DNCTL, "pipe", str(self.slot(rule)), "config", "bw", f"{rule.limit_bps}bit/s")))
        steps.append(self._load(self.ruleset([*others, rule])))
        if rule.action_type != "rate_limit":  # a rule does not touch connections pf is already tracking
            everyone = "::/0" if rule.is_ipv6 else "0.0.0.0/0"
            steps.append(Step((PFCTL, "-k", rule.target), tolerate=ANY_FAILURE))
            if rule.action_type == "isolate":
                steps.append(Step((PFCTL, "-k", everyone, "-k", rule.target), tolerate=ANY_FAILURE))
        return steps

    def plan_remove(self, rule: Rule, remaining: Sequence[Rule]) -> List[Step]:
        steps = [self._load(self.ruleset(remaining))]
        if rule.action_type == "rate_limit":
            steps.append(Step((DNCTL, "pipe", "delete", str(self.slot(rule))), tolerate=ANY_FAILURE))
        return steps

    def plan_clear(self, interfaces: Iterable[str], rules: Sequence[Rule]) -> List[Step]:
        steps = [self._load("")]
        for rule in rules:
            if rule.action_type == "rate_limit":
                steps.append(Step((DNCTL, "pipe", "delete", str(self.slot(rule))), tolerate=ANY_FAILURE))
        return steps

    def release_step(self, token: Optional[str]) -> Optional[Step]:
        return Step((PFCTL, "-X", token), tolerate=ANY_FAILURE) if token else None

    def read_back(self, interface: str) -> List[Step]:
        return [Step((PFCTL, "-a", PF_ANCHOR, "-s", "rules"), tolerate=ANY_FAILURE),
                Step((PFCTL, "-a", PF_ANCHOR, "-s", "dummynet"), tolerate=ANY_FAILURE),
                Step((DNCTL, "pipe", "show"), tolerate=ANY_FAILURE)]


def steps_public(steps: Sequence[Step]) -> List[Dict[str, Any]]:
    return [step.public() for step in steps]
