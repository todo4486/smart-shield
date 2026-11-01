"""Run the 12 acceptance tests against a throwaway copy of the database. Under a minute.

    python -m scripts.acceptance [--interface en0]

Your database is never written: it is copied first, and the copy is deleted at the end. Live monitoring here is passive and
simulated traffic is records in memory, so no packet is ever sent. The live test runs in real time; the simulated ones step a
clock one second at a time through the real engine. Each result says exactly what it was checked on, because
passing on a simulated link is not the same as passing on a real one:

    PASS     checked as the test asks.
    LIMITED  checked as far as this machine allows, and the line says what was not.
    FAIL     it did not work, or could not be run.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

RATE = 1e6
RESULTS: List[Tuple[int, str, str, str]] = []
NAMES = {
    1: "Monitoring shows actual incoming and outgoing traffic", 2: "Individual hosts and their bandwidth",
    3: "The Random Forest model runs", 4: "A controlled suspicious scenario in simulation", 5: "The suspicious traffic is identified",
    6: "The engine applies a rate limit or policy", 7: "Allocation changes dynamically", 8: "Before and after comparison",
    9: "The incident is recorded in the Incident Center", 10: "Reversing it restores the policy",
    11: "Legitimate traffic gets its configured priority", 12: "Live values are collected, simulated values labelled",
}


def working_copy(source: Path, directory: Path) -> Path:
    """A consistent copy even if the app is running and writing."""
    target = directory / "acceptance.db"
    if source.exists():
        from_db, to_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True), sqlite3.connect(target)
        with to_db:
            from_db.backup(to_db)
        from_db.close()
        to_db.close()
    return target


def report(number: int, status: str, evidence: str) -> None:
    RESULTS.append((number, status, NAMES[number], evidence))
    print(f"[{status:7}] {number:>2}. {NAMES[number]}\n            {evidence}", flush=True)


def wait_for(condition: Callable[[], object], seconds: float) -> object:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.5)
    return None


def mbit(value: Optional[float]) -> str:
    return "unavailable" if value is None else f"{value / RATE:,.1f} Mbit/s"


def percent(value: Optional[float]) -> str:
    return "unavailable" if value is None else f"{value:.1%}"


def run_live(principal, interface: str) -> None:
    from services import database_service, live_monitor_service as live, settings_service, telemetry_view_service

    settings_service.update_monitoring_settings(principal, settings_service.MonitoringSettings((interface,), "", 2))
    monitor = live.LiveMonitor()
    session_id = monitor.start(principal, interface, mode="counters", interval_seconds=2)
    arrived = wait_for(lambda: monitor.status.samples >= 3, 20)
    monitor.stop(principal)
    frame = telemetry_view_service.session_telemetry(principal, session_id, interface).metrics
    if not arrived or frame.empty:
        report(1, "FAIL", f"No samples arrived from {interface}. {monitor.status.last_error or ''}")
    else:
        latest = frame.iloc[-1]
        report(1, "PASS", f"{len(frame)} samples from {interface} in session #{session_id}: incoming "
                          f"{latest['incoming_bytes_per_second'] * 8 / RATE:,.3f} Mbit/s, outgoing "
                          f"{latest['outgoing_bytes_per_second'] * 8 / RATE:,.3f} Mbit/s, provenance {latest['provenance']}.")
    with database_service.session() as conn:
        kinds = {r[0] for r in conn.execute("SELECT DISTINCT provenance FROM network_metrics WHERE session_id = ?", (session_id,))}
    run_live.provenance = kinds  # for test 12


def run_hosts(principal, interface: str, simulated_hosts: int) -> None:
    from services import live_monitor_service as live, live_network_service

    capability = live.capture_capability()
    if not capability.packets:
        report(2, "LIMITED", f"Simulation only: {simulated_hosts} simulated hosts with rates. Real per-host capture was not run on "
                             f"this machine: {' '.join(capability.reasons)[:170]}")
        return
    monitor = live.LiveMonitor()
    monitor.start(principal, interface, mode="packets", interval_seconds=2)
    wait_for(lambda: monitor.status.samples >= 4, 25)
    status = monitor.status
    snapshot = live_network_service.snapshot(principal, live_running=status.running, live_session_id=status.session_id)
    monitor.stop(principal)
    if snapshot.hosts:
        report(2, "PASS", f"{len(snapshot.hosts)} real hosts measured from captured packets on {interface}.")
    else:
        report(2, "LIMITED", f"Capture ran on {interface} but saw no hosts in its window. Simulation showed {simulated_hosts}.")


class SteppedClock:
    """Drives the real engine one simulated second at a time, as its own thread would, so results do not depend on how fast
    the machine is or whether it sleeps. Everything else (flow extractor, models, allocator, engine, database) is the real code."""

    def __init__(self, engine):
        self.engine = engine
        self.now = time.time() - 1800

    def advance(self, seconds: int) -> None:
        for _ in range(seconds):
            if not self.engine.step(self.now):
                return
            self.now += 1

    def until(self, condition: Callable[[], object], seconds: int) -> object:
        for _ in range(seconds):
            value = condition()
            if value:
                return value
            self.advance(1)
        return condition()

    @property
    def moment(self) -> datetime:
        return datetime.fromtimestamp(self.now, tz=timezone.utc)


def run_simulation(principal, clock: SteppedClock) -> int:
    """Tests 3 to 10, on one bandwidth hog. Returns the number of hosts seen."""
    from services import (
        database_service, incident_correlation_service as correlation, live_network_service, mitigation_service as ms,
        simulation_service as sim,
    )

    engine = clock.engine
    session_id = engine.start(principal, "bandwidth_hog", capacity_bps=100e6, attack_delay_seconds=5, duration_seconds=150)
    report(4, "PASS", f"Scenario 'bandwidth_hog' in simulation session #{session_id}: records in memory, no packets.")
    proposal = clock.until(lambda: next((m for m in ms.list_for_session(principal, session_id) if m["status"] == "proposed"), None), 60)
    status = sim.status_copy()
    with database_service.session() as conn:
        scored = conn.execute("SELECT COUNT(*), COUNT(model_version) FROM network_flows WHERE session_id = ?", (session_id,)).fetchone()
    if scored[1]:
        report(3, "PASS", f"{status.flows_scored} flows scored by {status.model_version} through the registered, hash-verified model.")
    else:
        report(3, "FAIL", "No stored flow carries a model version.")
    snapshot = live_network_service.snapshot(principal, simulation_session_id=session_id)
    hosts = len(snapshot.hosts)
    if proposal is None:
        report(5, "FAIL", f"No proposal within 60 s. Flagged by category: {status.by_category}")
        engine.stop(principal)
        return hosts
    confidence = proposal["confidence"]
    report(5, "PASS", f"{proposal['target']} identified as '{proposal['category']}', severity {proposal['severity']}, confidence "
                      f"{'unavailable' if confidence is None else f'{confidence:.2f}'} ({proposal['confidence_basis']}, not a probability).")
    clock.advance(3)  # enough samples under attack for a clean "before"
    before_allocation = ms.latest_allocation(principal, session_id)
    applied = ms.approve(principal, proposal["id"], reason="Acceptance run", now=clock.moment)
    if applied["status"] == "active":
        report(6, "PASS", f"{ms.describe(applied)}, by {applied['adapter']}, expiring {applied['expires_at'][:19]}.")
    else:
        report(6, "FAIL", f"It was not applied: {applied['failure_reason']}")
    done = clock.until(lambda: (m := ms.get_action(principal, proposal["id"]))["recovery_status"] != "pending" and m, 30)
    after_allocation = ms.latest_allocation(principal, session_id)
    was, now = before_allocation["classes"], after_allocation["classes"]
    history = ms.allocation_history(principal, session_id)
    if now["restricted"]["allocated_bps"] > was["restricted"]["allocated_bps"] and after_allocation["available_bps"] != before_allocation["available_bps"]:
        report(7, "PASS", f"{len(history)} allocation intervals. Restricted {mbit(was['restricted']['allocated_bps'])} → "
                          f"{mbit(now['restricted']['allocated_bps'])}, suspicious {mbit(was['suspicious']['allocated_bps'])} → "
                          f"{mbit(now['suspicious']['allocated_bps'])}, available {mbit(before_allocation['available_bps'])} → "
                          f"{mbit(after_allocation['available_bps'])}.")
    else:
        report(7, "FAIL", f"Allocation did not change: {was} → {now}")
    b, a = (done or {}).get("before") or {}, (done or {}).get("after") or {}
    if b.get("samples") and a.get("samples"):
        report(8, "PASS", f"Target {mbit(b.get('target_bps'))} → {mbit(a.get('target_bps'))}, legitimate {mbit(b.get('other_bps'))} → "
                          f"{mbit(a.get('other_bps'))}, utilization {percent(b.get('utilization'))} → {percent(a.get('utilization'))}, loss "
                          f"{percent(b.get('loss_ratio'))} → {percent(a.get('loss_ratio'))}, latency unavailable, recovery "
                          f"'{done['recovery_status']}'. All simulated.")
    else:
        report(8, "FAIL", "No before and after was stored.")
    action = ms.get_action(principal, proposal["id"])
    incident = correlation.get_incident(principal, action["incident_id"]) if action["incident_id"] else None
    if incident is not None and incident.lifecycle == correlation.ACTIVE and incident.is_simulation:
        report(9, "PASS", f"Incident #{incident.id} '{incident.title}', status {incident.lifecycle}, {len(incident.alerts)} alerts, labelled simulation.")
    else:
        report(9, "FAIL", f"Incident state: {incident.lifecycle if incident else 'none'}")
    ms.rollback(principal, proposal["id"], reason="Acceptance run reversal", now=clock.moment)
    clock.advance(4)
    allocation = ms.latest_allocation(principal, session_id)
    loss = sim.status_copy().loss_ratio
    final = ms.get_action(principal, proposal["id"])
    lifecycle = correlation.get_incident(principal, action["incident_id"]).lifecycle
    if final["status"] == "rolled_back" and not allocation["enforced"] and loss and loss > 0.02:
        report(10, "PASS", f"Rolled back: nothing enforced, the hog's traffic is back and loss returned to {percent(loss)}. "
                           f"Incident now '{lifecycle}'. Original policy restored.")
    else:
        report(10, "FAIL", f"status {final['status']}, enforced {allocation['enforced']}, loss {percent(loss)}.")
    engine.stop(principal)
    return hosts


def run_priority(principal, clock: SteppedClock) -> None:
    from dataclasses import replace

    from services import database_service, mitigation_service as ms, settings_service, simulation_service as sim

    settings_service.update_mitigation_settings(principal, replace(settings_service.get_mitigation_settings(), policy="off"))
    engine = clock.engine
    session_id = engine.start(principal, "bandwidth_hog", capacity_bps=100e6, attack_delay_seconds=3, duration_seconds=60)
    critical = next(s for s in sim.baseline_sources(100e6) if s.traffic_class == "critical")
    clock.until(lambda: (s := sim.status_copy()).loss_ratio and s.loss_ratio > 0.02, 25)
    clock.advance(4)

    def rate() -> float:
        with database_service.session() as conn:
            rows = conn.execute("SELECT sent_bps FROM host_metrics WHERE session_id = ? AND host = ? ORDER BY timestamp DESC LIMIT 3",
                                (session_id, critical.sender)).fetchall()
        return sum(r[0] for r in rows) / len(rows) if rows else 0.0

    squeezed = rate()
    ms.request_action(principal, session_id, "prioritize", reason="Acceptance run", now=clock.moment)
    clock.advance(6)
    protected = rate()
    engine.stop(principal)
    if squeezed < critical.offered_bps * 0.98 and protected >= critical.offered_bps * 0.98:
        report(11, "LIMITED", f"On the simulated link only: the critical application got {mbit(squeezed)} of its {mbit(critical.offered_bps)} on a "
                              f"full link, and {mbit(protected)} once prioritized. On a real link, priority needs a class policy through Linux tc.")
    else:
        report(11, "FAIL", f"Critical traffic {mbit(squeezed)} → {mbit(protected)} of {mbit(critical.offered_bps)}.")


def run_labels(principal) -> None:
    from services import database_service

    live_kinds = getattr(run_live, "provenance", set())
    with database_service.session() as conn:
        simulated = {r[0] for r in conn.execute(
            "SELECT DISTINCT m.provenance FROM network_metrics m JOIN monitoring_sessions s ON s.id = m.session_id WHERE s.source_type = 'simulation'")}
        unlabelled = conn.execute(
            "SELECT COUNT(*) FROM incidents i WHERE i.is_simulation = 0 AND EXISTS (SELECT 1 FROM mitigation_actions m "
            "WHERE m.incident_id = i.id AND m.origin = 'simulation')").fetchone()[0]
        host_kinds = {r[0] for r in conn.execute(
            "SELECT DISTINCT h.provenance FROM host_metrics h JOIN monitoring_sessions s ON s.id = h.session_id WHERE s.source_type = 'simulation'")}
    measured_in_simulation = "measured" in simulated or "measured" in host_kinds
    if live_kinds == {"measured"} and not measured_in_simulation and not unlabelled:
        report(12, "PASS", f"Live samples are stored as {sorted(live_kinds)} from psutil. Simulated samples are stored as "
                           f"{sorted(simulated | host_kinds)}, never measured, and no simulated action sits on an unlabelled incident.")
    else:
        report(12, "FAIL", f"Live {live_kinds}, simulated {simulated | host_kinds}, unlabelled incidents {unlabelled}.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interface", default="en0", help="interface for the passive capture tests (default en0)")
    args = parser.parse_args(argv)
    from config import get_settings

    source = get_settings().db_path
    directory = Path(tempfile.mkdtemp(prefix="smart-shield-acceptance-"))
    try:
        os.environ["SMART_SHIELD_DB_PATH"] = str(working_copy(source, directory))
        os.environ["SMART_SHIELD_ENFORCEMENT_BACKEND"] = "dry_run"
        from services import database_service
        from services.authorization import Principal, Role

        database_service.run_migrations()
        with database_service.session() as conn:
            row = conn.execute("SELECT id, name, email FROM users WHERE role = 'admin' AND is_active = 1 ORDER BY id LIMIT 1").fetchone()
        if row is None:
            print("There is no administrator in this database. Create one first: python -m scripts.manage create-admin", file=sys.stderr)
            return 1
        principal = Principal(user_id=row["id"], name=row["name"], email=row["email"], role=Role.ADMIN)
        print(f"Working on a throwaway copy of {source}\n", flush=True)
        try:
            run_live(principal, args.interface)
        except Exception as exc:
            report(1, "FAIL", f"{type(exc).__name__}: {exc}")
        from services import simulation_service as sim

        engine = sim.SimulationEngine(tick_seconds=3600)  # its thread never ticks: the clock below drives it
        sim.reset_engine_for_tests(engine)
        clock = SteppedClock(engine)
        hosts = 0
        try:
            hosts = run_simulation(principal, clock)
        except Exception as exc:
            print(f"The simulation tests stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
            if engine.status.running:
                engine.stop(principal)
        try:
            run_hosts(principal, args.interface, hosts)
            run_priority(principal, clock)
            run_labels(principal)
        except Exception as exc:
            print(f"A test stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    print("\nSummary")
    for number in sorted(NAMES):
        found = next((r for r in RESULTS if r[0] == number), None)
        print(f"  {number:>2}. {found[1] if found else 'FAIL':7} {NAMES[number]}")
    done = {r[0]: r[1] for r in RESULTS}
    return 0 if all(done.get(n, "FAIL") != "FAIL" for n in NAMES) else 1


if __name__ == "__main__":
    sys.exit(main())
