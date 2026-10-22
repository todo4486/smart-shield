"""Deterministic weighted water-filling bandwidth allocation (pure functions).

Rules
1. usable = capacity × (1 − safety_margin).
2. Every class is granted its minimum (a reservation, even if its demand is
   lower). If the minimums add up to more than the usable capacity, the policy
   is infeasible and an error explains by how much.
3. Each class's ceiling = min(maximum, max(demand, minimum)). A class never
   receives more than it can use or is allowed.
4. The remaining usable capacity is shared in proportion to priority weight
   among classes still below their ceiling. Shares that exceed a ceiling are
   capped, and the leftover is redistributed in the next round, until nothing
   changes.
5. Results are floored to whole bits per second, so the total never exceeds the
   usable capacity. Unmet demand = floor(demand) − allocation (never negative).

Invariants (unit-tested): every allocation ≥ 0, ≤ maximum, ≥ minimum; the total
≤ capacity; unmet demand is reported; identical inputs give identical output.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Sequence

MAX_ROUNDS = 1000
EPSILON = 1e-9


class AllocationError(ValueError):
    """Invalid or infeasible inputs. The message says what to change."""


@dataclass(frozen=True)
class TrafficClass:
    name: str
    minimum_bps: float
    maximum_bps: float
    priority_weight: float
    demand_bps: float


@dataclass
class ClassAllocation:
    name: str
    demand_bps: float
    minimum_bps: float
    maximum_bps: float
    priority_weight: float
    allocated_bps: int
    unmet_demand_bps: int
    limited_by: str  # "demand", "maximum", "capacity" or "minimum reservation"


@dataclass
class AllocationResult:
    capacity_bps: float
    safety_margin: float
    usable_bps: int
    allocations: List[ClassAllocation]
    total_allocated_bps: int
    total_demand_bps: float
    unmet_demand_bps: int
    unallocated_bps: int
    rounds: int
    rationale: List[str] = field(default_factory=list)
    invariants: Dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def validate(capacity_bps: float, safety_margin: float, classes: Sequence[TrafficClass]) -> None:
    if not classes:
        raise AllocationError("Define at least one traffic class.")
    if not (isinstance(capacity_bps, (int, float)) and math.isfinite(capacity_bps) and capacity_bps > 0):
        raise AllocationError("Capacity must be a positive number of bits per second.")
    if not 0 <= safety_margin < 0.9:
        raise AllocationError("Safety margin must be between 0% and 90%.")
    names = [c.name.strip() for c in classes]
    if any(not n for n in names) or len(set(names)) != len(names):
        raise AllocationError("Every traffic class needs a unique, non-empty name.")
    for c in classes:
        values = (c.minimum_bps, c.maximum_bps, c.priority_weight, c.demand_bps)
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in values):
            raise AllocationError(f"Class '{c.name}': every value must be a finite number.")
        if c.minimum_bps < 0 or c.demand_bps < 0:
            raise AllocationError(f"Class '{c.name}': minimum and demand cannot be negative.")
        if c.maximum_bps < c.minimum_bps:
            raise AllocationError(f"Class '{c.name}': maximum is below its minimum.")
        if c.maximum_bps > capacity_bps:
            raise AllocationError(f"Class '{c.name}': maximum exceeds the link capacity.")
        if c.priority_weight <= 0:
            raise AllocationError(f"Class '{c.name}': priority weight must be greater than 0.")
    usable = capacity_bps * (1 - safety_margin)
    reserved = sum(c.minimum_bps for c in classes)
    if reserved > usable + EPSILON:
        raise AllocationError(
            f"Infeasible: the minimum allocations add up to {reserved / 1e6:,.2f} Mbit/s, but only "
            f"{usable / 1e6:,.2f} Mbit/s is usable after the {safety_margin:.0%} safety margin. Lower some "
            f"minimums by {(reserved - usable) / 1e6:,.2f} Mbit/s in total, or reduce the safety margin."
        )


def allocate(capacity_bps: float, safety_margin: float, classes: Sequence[TrafficClass]) -> AllocationResult:
    validate(capacity_bps, safety_margin, classes)
    ordered = sorted(classes, key=lambda c: c.name)  # determinism does not depend on input order
    usable = capacity_bps * (1 - safety_margin)
    allocation = {c.name: float(c.minimum_bps) for c in ordered}
    ceiling = {c.name: min(c.maximum_bps, max(c.demand_bps, c.minimum_bps)) for c in ordered}
    remaining = usable - sum(allocation.values())
    rationale = [
        f"Usable capacity {usable / 1e6:,.2f} Mbit/s = {capacity_bps / 1e6:,.2f} Mbit/s configured capacity minus a "
        f"{safety_margin:.0%} safety margin.",
        f"Step 1: reserved each class's minimum ({sum(allocation.values()) / 1e6:,.2f} Mbit/s in total).",
    ]
    rounds = 0
    while remaining > EPSILON and rounds < MAX_ROUNDS:
        active = [c for c in ordered if ceiling[c.name] - allocation[c.name] > EPSILON]
        if not active:
            break
        rounds += 1
        total_weight = sum(c.priority_weight for c in active)
        given = 0.0
        for c in active:
            share = remaining * c.priority_weight / total_weight
            grant = min(share, ceiling[c.name] - allocation[c.name])
            allocation[c.name] += grant
            given += grant
        remaining -= given
        if given <= EPSILON:
            break
    rationale.append(
        f"Step 2: shared the remaining capacity by priority weight over {rounds} round(s), capping each class at "
        "min(maximum, demand) and redistributing what capped classes could not use."
    )

    results: List[ClassAllocation] = []
    for c in ordered:
        allocated = int(math.floor(allocation[c.name] + EPSILON))  # ≥ floor(minimum), since allocation ≥ minimum
        # Whole bits on both sides, so flooring a fully served fractional demand is not reported as unmet.
        unmet = max(0, int(math.floor(c.demand_bps + EPSILON)) - allocated)
        if c.demand_bps <= c.minimum_bps and allocated >= c.demand_bps:
            limited = "minimum reservation" if c.minimum_bps > c.demand_bps else "demand"
        elif allocated >= c.demand_bps - 1:
            limited = "demand"
        elif allocated >= c.maximum_bps - 1:
            limited = "maximum"
        else:
            limited = "capacity"
        results.append(ClassAllocation(c.name, float(c.demand_bps), float(c.minimum_bps), float(c.maximum_bps),
                                       float(c.priority_weight), allocated, unmet, limited))

    total = sum(r.allocated_bps for r in results)
    # Flooring can only lower the total; this guard only absorbs floating-point error at the boundary.
    usable_int = int(math.floor(usable + EPSILON))
    if total > usable_int:
        overshoot = total - usable_int
        for r in sorted(results, key=lambda r: (-(r.allocated_bps - r.minimum_bps), r.name)):
            take = min(overshoot, max(0, r.allocated_bps - int(math.floor(r.minimum_bps))))
            r.allocated_bps -= take
            overshoot -= take
            if not overshoot:
                break
        total = sum(r.allocated_bps for r in results)

    unmet_total = sum(r.unmet_demand_bps for r in results)
    for r in results:
        if r.limited_by == "maximum":
            rationale.append(f"'{r.name}' is held at its maximum of {r.maximum_bps / 1e6:,.2f} Mbit/s.")
        elif r.limited_by == "capacity" and r.unmet_demand_bps:
            rationale.append(f"'{r.name}' receives {r.allocated_bps / 1e6:,.2f} of {r.demand_bps / 1e6:,.2f} Mbit/s "
                             f"demanded (weight {r.priority_weight:g}); capacity ran out.")
        elif r.limited_by == "minimum reservation":
            rationale.append(f"'{r.name}' keeps its {r.minimum_bps / 1e6:,.2f} Mbit/s minimum although it currently "
                             "demands less.")
    if unmet_total:
        rationale.append(f"Unmet demand: {unmet_total / 1e6:,.2f} Mbit/s. No additional bandwidth is invented.")
    unallocated = max(0, usable_int - total)
    if unallocated:
        rationale.append(f"{unallocated / 1e6:,.2f} Mbit/s of usable capacity is left unallocated because every class "
                         "is at its demand or maximum.")

    result = AllocationResult(
        capacity_bps=float(capacity_bps), safety_margin=float(safety_margin), usable_bps=usable_int,
        allocations=results, total_allocated_bps=total, total_demand_bps=float(sum(c.demand_bps for c in ordered)),
        unmet_demand_bps=unmet_total, unallocated_bps=unallocated, rounds=rounds, rationale=rationale,
    )
    result.invariants = check_invariants(result)
    if not all(result.invariants.values()):  # pragma: no cover - would be a bug in this module
        raise AllocationError(f"Internal invariant violated: {result.invariants}")
    return result


def check_invariants(result: AllocationResult) -> Dict[str, bool]:
    a = result.allocations
    return {
        "every allocation is non-negative": all(r.allocated_bps >= 0 for r in a),
        "no allocation exceeds its maximum": all(r.allocated_bps <= r.maximum_bps + 1e-6 for r in a),
        "minimums are respected": all(r.allocated_bps >= math.floor(r.minimum_bps) for r in a),
        "total does not exceed capacity": result.total_allocated_bps <= result.capacity_bps,
        "total does not exceed usable capacity": result.total_allocated_bps <= result.usable_bps,
        "unmet demand is reported": all(r.unmet_demand_bps == max(0, int(math.floor(r.demand_bps + EPSILON)) - r.allocated_bps)
                                        for r in a),
    }
