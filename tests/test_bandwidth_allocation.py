from __future__ import annotations

import math
import random

import pytest

from services.bandwidth_allocation import AllocationError, TrafficClass, allocate, check_invariants

M = 1_000_000


def cls(name, minimum, maximum, weight, demand):
    return TrafficClass(name, minimum * M, maximum * M, weight, demand * M)


def by_name(result):
    return {a.name: a for a in result.allocations}


def test_enough_capacity_everyone_gets_demand():
    result = allocate(100 * M, 0.1, [cls("critical", 10, 50, 4, 20), cls("bulk", 0, 80, 1, 30)])
    a = by_name(result)
    assert a["critical"].allocated_bps == 20 * M and a["bulk"].allocated_bps == 30 * M
    assert result.unmet_demand_bps == 0 and result.unallocated_bps == 40 * M


def test_priority_weights_share_scarce_capacity():
    # usable 90; minimums 10 + 0; remaining 80 split 4:1 -> 64 / 16 (+ minimum for critical)
    result = allocate(100 * M, 0.1, [cls("critical", 10, 100, 4, 200), cls("bulk", 0, 100, 1, 200)])
    a = by_name(result)
    assert a["critical"].allocated_bps == 74 * M and a["bulk"].allocated_bps == 16 * M
    assert result.total_allocated_bps == 90 * M
    assert a["bulk"].unmet_demand_bps == 184 * M and a["bulk"].limited_by == "capacity"


def test_capped_class_leftover_is_redistributed():
    # critical wants only 5 above its minimum, so the rest goes to bulk
    result = allocate(100 * M, 0.0, [cls("critical", 5, 100, 10, 10), cls("bulk", 0, 100, 1, 500)])
    a = by_name(result)
    assert a["critical"].allocated_bps == 10 * M and a["critical"].limited_by == "demand"
    assert a["bulk"].allocated_bps == 90 * M and result.rounds >= 2


def test_maximum_is_never_exceeded():
    result = allocate(100 * M, 0.0, [cls("video", 0, 20, 10, 80), cls("web", 0, 100, 1, 10)])
    a = by_name(result)
    assert a["video"].allocated_bps == 20 * M and a["video"].limited_by == "maximum"
    assert a["video"].unmet_demand_bps == 60 * M


def test_minimum_reservation_held_even_without_demand():
    result = allocate(100 * M, 0.0, [cls("voice", 15, 30, 5, 2), cls("bulk", 0, 100, 1, 500)])
    a = by_name(result)
    assert a["voice"].allocated_bps == 15 * M and a["voice"].limited_by == "minimum reservation"
    assert a["bulk"].allocated_bps == 85 * M


def test_infeasible_minimums_give_clear_error():
    with pytest.raises(AllocationError, match="Infeasible.*Lower some minimums by 5.00 Mbit/s"):
        allocate(100 * M, 0.1, [cls("a", 50, 60, 1, 1), cls("b", 45, 60, 1, 1)])


@pytest.mark.parametrize("bad, message", [
    ([cls("a", 10, 5, 1, 1)], "maximum is below its minimum"),
    ([cls("a", 0, 200, 1, 1)], "exceeds the link capacity"),
    ([cls("a", 0, 10, 0, 1)], "priority weight"),
    ([cls("a", -1, 10, 1, 1)], "cannot be negative"),
    ([cls("a", 0, 10, 1, 1), cls("a", 0, 10, 1, 1)], "unique"),
    ([], "at least one"),
])
def test_invalid_inputs_rejected(bad, message):
    with pytest.raises(AllocationError, match=message):
        allocate(100 * M, 0.0, bad)


def test_identical_inputs_identical_output_regardless_of_order():
    classes = [cls("a", 1, 50, 3, 40), cls("b", 2, 60, 1, 70), cls("c", 0, 30, 2, 25)]
    first = allocate(97.3 * M, 0.07, classes)
    second = allocate(97.3 * M, 0.07, list(reversed(classes)))
    assert first.as_dict() == second.as_dict()


def test_randomized_invariants():
    rng = random.Random(1234)
    for _ in range(500):
        capacity = rng.uniform(1, 10_000) * M
        margin = rng.choice([0, 0.05, 0.1, 0.25])
        usable = capacity * (1 - margin)
        classes = []
        budget = usable
        for i in range(rng.randint(1, 6)):
            minimum = rng.uniform(0, budget / 6)
            budget -= minimum
            maximum = rng.uniform(minimum, capacity)
            classes.append(TrafficClass(f"c{i}", minimum, maximum, rng.uniform(0.1, 10), rng.uniform(0, capacity)))
        result = allocate(capacity, margin, classes)
        assert all(result.invariants.values()), result.invariants
        assert check_invariants(result) == result.invariants
        for a in result.allocations:
            assert 0 <= a.allocated_bps <= a.maximum_bps
            assert a.allocated_bps >= math.floor(a.minimum_bps)
            assert a.unmet_demand_bps >= 0
        assert result.total_allocated_bps <= capacity
        # Water-filling is work-conserving: capacity is only left over if every class is at its ceiling.
        if result.unallocated_bps > len(classes):
            assert all(a.allocated_bps >= min(a.maximum_bps, max(a.demand_bps, a.minimum_bps)) - 1
                       for a in result.allocations)


def test_fractional_demand_fully_served_has_no_phantom_unmet():
    result = allocate(1e9, 0.1, [TrafficClass("a", 0, 5e8, 1, 123_456_789.7), TrafficClass("b", 0, 5e8, 2, 1e8 / 3)])
    assert result.unmet_demand_bps == 0
    assert all(a.limited_by == "demand" for a in result.allocations)
