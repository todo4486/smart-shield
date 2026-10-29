"""Bandwidth "what-if" sandbox: try capacities, classes, demands and weights without touching anything.

* simulate() calls bandwidth_allocation.allocate(), the same function behind real recommendations, so the
  sandbox can never disagree with them (and the allocator's 500 randomized property tests cover it).
* Nothing here stores data or runs tc. The only way out of the sandbox is propose(): an administrator saves the
  scenario as a bandwidth policy plus a PROPOSED recommendation. That still has to be accepted and applied in
  Bandwidth Management → Enforcement, with its own typed confirmation, audit and rollback.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from services import audit_service, bandwidth_allocation, bandwidth_service
from services.authorization import Permission, Principal, require_permission
from services.bandwidth_allocation import AllocationError, AllocationResult, TrafficClass

MAX_CLASSES = 12


class WhatIfError(Exception):
    pass


@dataclass(frozen=True)
class SimClass:
    name: str
    minimum_bps: float
    maximum_bps: float
    priority_weight: float
    demand_bps: float


def _classes(classes: Sequence[SimClass]) -> List[TrafficClass]:
    names = [c.name.strip() for c in classes]
    if not names:
        raise WhatIfError("Add at least one traffic class.")
    if len(names) > MAX_CLASSES:
        raise WhatIfError(f"Use at most {MAX_CLASSES} classes.")
    if any(not n for n in names) or len(set(names)) != len(names):
        raise WhatIfError("Every class needs a unique name.")
    return [TrafficClass(c.name.strip(), float(c.minimum_bps), float(c.maximum_bps), float(c.priority_weight),
                         float(c.demand_bps)) for c in classes]


def simulate(principal: Principal, capacity_bps: float, safety_margin: float,
             classes: Sequence[SimClass]) -> AllocationResult:
    """Run the real allocator on hypothetical inputs. Nothing is stored or enforced."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="what_if.simulate")
    try:
        return bandwidth_allocation.allocate(float(capacity_bps), float(safety_margin), _classes(classes))
    except AllocationError as exc:
        raise WhatIfError(str(exc)) from exc


def starting_point(principal: Principal, policy_name: Optional[str] = None,
                   capacity_bps: float = 100e6) -> Tuple[float, Optional[str], List[SimClass]]:
    """A saved policy (with zero demand) or the four-class template, as editable sandbox rows."""
    require_permission(principal, Permission.VIEW_DASHBOARD, action="what_if.simulate")
    if policy_name:
        policy = next((p for p in bandwidth_service.list_policies(principal) if p.name == policy_name), None)
        if policy is None:
            raise WhatIfError("Policy not found.")
    else:
        policy = bandwidth_service.template_policy(capacity_bps)
    return policy.capacity_bps, policy.interface_name, [
        SimClass(c.traffic_class, c.minimum_bps, c.maximum_bps, c.priority_weight, 0.0)
        for c in policy.classes if c.enabled]


def propose(principal: Principal, *, name: str, interface: Optional[str], capacity_bps: float, safety_margin: float,
            classes: Sequence[SimClass]) -> int:
    """Admin only: save the scenario as a policy and a PROPOSED recommendation. Nothing is enforced.

    Returns the recommendation id. Enforcing it still requires accepting it and applying it with the typed
    confirmation in Bandwidth Management.
    """
    require_permission(principal, Permission.APPLY_TRAFFIC_POLICY, action="what_if.propose", details={"policy": name})
    simulate(principal, capacity_bps, safety_margin, classes)  # same validation, fails before anything is saved
    policy = bandwidth_service.Policy(name.strip(), interface, float(capacity_bps), tuple(
        bandwidth_service.PolicyClass(c.name.strip(), float(c.minimum_bps), float(c.maximum_bps),
                                      float(c.priority_weight), None, True) for c in classes))
    try:
        saved = bandwidth_service.save_policy(principal, policy)
        recommendation = bandwidth_service.recommend(principal, saved.name,
                                                     {c.name.strip(): float(c.demand_bps) for c in classes},
                                                     safety_margin=float(safety_margin), demand_mode="manual")
    except bandwidth_service.BandwidthError as exc:
        raise WhatIfError(str(exc)) from exc
    audit_service.record_standalone(user_id=principal.user_id, action="what_if.propose", outcome="success",
                                    details={"policy": saved.name, "recommendation_id": recommendation.id})
    return int(recommendation.id)
