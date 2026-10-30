"""Host-aware bandwidth allocation: two levels of the water-filling allocator in bandwidth_allocation (pure functions).

Level 1 shares usable capacity between four classes. Level 2 shares each class's grant between its hosts, equally
weighted and capped at each host's demand and limit.

  critical    configured guaranteed minimum, highest weight
  normal      configured guaranteed minimum, middle weight
  suspicious  no guarantee, capped at a configured share of the link, so a flagged host cannot squeeze the rest
  restricted  no guarantee, each host capped at the rate limit of its active mitigation

One deliberate difference from a policy plan in bandwidth_allocation: the minimum given to `allocate` is
min(guaranteed minimum, demand). An unused guarantee is lent to other classes, as a queue with borrowing does, and is
returned as soon as the class asks for it. So a class always gets min(demand, guarantee) whatever the others do.

A host with a limit of 0 (blocked or isolated) gets nothing and is left out of the sharing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from services.bandwidth_allocation import AllocationError, TrafficClass, allocate

CRITICAL, NORMAL, SUSPICIOUS, RESTRICTED = "critical", "normal", "suspicious", "restricted"
CLASSES = (CRITICAL, NORMAL, SUSPICIOUS, RESTRICTED)
WEIGHTS = {CRITICAL: 6.0, NORMAL: 3.0, SUSPICIOUS: 1.0, RESTRICTED: 1.0}


@dataclass(frozen=True)
class AllocationPolicy:
    safety_margin: float = 0.05
    critical_min_share: float = 0.20
    normal_min_share: float = 0.30
    suspicious_max_share: float = 0.10

    def validate(self) -> "AllocationPolicy":
        for name, value in (("Safety margin", self.safety_margin), ("Critical minimum", self.critical_min_share),
                            ("Normal minimum", self.normal_min_share), ("Suspicious maximum", self.suspicious_max_share)):
            if not 0 <= float(value) <= 1:
                raise AllocationError(f"{name} must be between 0% and 100%.")
        if self.safety_margin >= 0.9:
            raise AllocationError("Safety margin must be below 90%.")
        if self.critical_min_share + self.normal_min_share > 1 - self.safety_margin + 1e-9:
            raise AllocationError("The guaranteed minimums exceed the usable capacity after the safety margin.")
        return self


@dataclass(frozen=True)
class HostDemand:
    host: str
    traffic_class: str  # one of CLASSES
    demand_bps: float
    limit_bps: Optional[float] = None  # the active mitigation's limit; only meaningful for restricted hosts


@dataclass(frozen=True)
class ClassGrant:
    name: str
    demand_bps: float
    allocated_bps: int
    unmet_bps: int
    guaranteed_bps: float


@dataclass(frozen=True)
class HostGrant:
    host: str
    traffic_class: str
    demand_bps: float
    allocated_bps: int
    limit_bps: Optional[float]


@dataclass(frozen=True)
class HostAllocation:
    capacity_bps: float
    usable_bps: int
    classes: Dict[str, ClassGrant]
    hosts: Dict[str, HostGrant]
    total_allocated_bps: int
    available_bps: float  # capacity no class asked for, including the safety margin


def _share_within_class(hosts: Sequence[HostDemand], grant: int) -> Dict[str, int]:
    if grant <= 0 or not hosts:
        return {h.host: 0 for h in hosts}
    result = allocate(float(grant), 0.0, [
        TrafficClass(h.host, 0.0, float(grant) if h.limit_bps is None else min(float(grant), float(h.limit_bps)), 1.0,
                     float(h.demand_bps))
        for h in hosts])
    return {a.name: a.allocated_bps for a in result.allocations}


def allocate_hosts(capacity_bps: float, policy: AllocationPolicy, demands: Sequence[HostDemand]) -> HostAllocation:
    """Deterministic: identical inputs give identical output, whatever their order."""
    policy.validate()
    if capacity_bps <= 0:
        raise AllocationError("Capacity must be a positive number of bits per second.")
    names = [d.host for d in demands]
    if len(set(names)) != len(names):
        raise AllocationError("Each host may appear only once.")
    groups: Dict[str, List[HostDemand]] = {name: [] for name in CLASSES}
    for demand in sorted(demands, key=lambda d: d.host):
        if demand.traffic_class not in groups:
            raise AllocationError(f"Unknown traffic class '{demand.traffic_class}'.")
        if demand.demand_bps < 0 or (demand.limit_bps is not None and demand.limit_bps < 0):
            raise AllocationError(f"Host {demand.host}: demand and limit cannot be negative.")
        groups[demand.traffic_class].append(demand)

    def wanted(name: str) -> float:
        return sum(d.demand_bps if d.limit_bps is None else min(d.demand_bps, d.limit_bps) for d in groups[name])

    guaranteed = {CRITICAL: capacity_bps * policy.critical_min_share, NORMAL: capacity_bps * policy.normal_min_share,
                  SUSPICIOUS: 0.0, RESTRICTED: 0.0}
    ceilings = {CRITICAL: capacity_bps, NORMAL: capacity_bps, SUSPICIOUS: capacity_bps * policy.suspicious_max_share,
                RESTRICTED: capacity_bps}
    level_one = allocate(capacity_bps, policy.safety_margin, [
        TrafficClass(name, min(guaranteed[name], wanted(name), ceilings[name]), ceilings[name], WEIGHTS[name], wanted(name))
        for name in CLASSES])
    granted = {a.name: a for a in level_one.allocations}
    classes: Dict[str, ClassGrant] = {}
    hosts: Dict[str, HostGrant] = {}
    for name in CLASSES:
        shares = _share_within_class(groups[name], granted[name].allocated_bps)
        total_demand = sum(d.demand_bps for d in groups[name])
        classes[name] = ClassGrant(name, total_demand, granted[name].allocated_bps,
                                   max(0, int(total_demand) - granted[name].allocated_bps), guaranteed[name])
        for demand in groups[name]:
            hosts[demand.host] = HostGrant(demand.host, name, demand.demand_bps, shares[demand.host], demand.limit_bps)
    return HostAllocation(float(capacity_bps), level_one.usable_bps, classes, hosts, level_one.total_allocated_bps,
                          max(0.0, capacity_bps - level_one.total_allocated_bps))
