"""M4: enforcement adapters, capability detection, the emergency stop, and the engine running on live capture.

Everything that would change the network is a fake runner here. The pf tests at the end hand the generated rules to the
real pfctl and dnctl parsers on a Mac (`-n` checks syntax and loads nothing), and are skipped elsewhere.
"""
from __future__ import annotations

import ast
import os
import subprocess
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from config import ConfigError, get_settings
from repositories import telemetry_repository
from services import (
    capture_worker, database_service, enforcement_service as es, mitigation_service as ms, session_service,
    settings_service,
)
from services.authorization import PermissionDenied
from services.enforcement_adapters import PF_ANCHOR, PFCTL, DNCTL, EnforcementError, PfAdapter, TcAdapter, rule_from
from services.mitigation_service import MitigationError, SenderDemand
from services.settings_service import SettingsError
from services.timeutil import to_iso, utc_now
from tests.conftest import audit_rows
from tests.test_live_monitoring import SAMPLE, ddos_flow, fake_worker, monitor, session_row, train_live_model, wait_for  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
M = 1_000_000
LOCAL = "192.168.1.20"
REMOTE = "203.0.113.5"


class FakeRunner:
    def __init__(self, fail_on=None, stderr="Operation not permitted"):
        self.calls = []
        self.fail_on = fail_on
        self.stderr = stderr

    def __call__(self, argv, stdin):
        self.calls.append((list(argv), stdin))
        if self.fail_on and self.fail_on in " ".join(argv):
            return subprocess.CompletedProcess(argv, 1, "", self.stderr)
        if argv[-1] == "-E":
            return subprocess.CompletedProcess(argv, 0, "", "pf enabled\nToken : 4242\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def loaded_rulesets(self):
        return [stdin for argv, stdin in self.calls if "-f" in argv]

    def commands(self):
        return [" ".join(argv) for argv, _ in self.calls]


def _row(**values):
    return {"id": 7, "action_type": "rate_limit", "target_kind": "source", "target": REMOTE, "limit_bps": 5 * M,
            "interface_name": "en0", **values}


@pytest.fixture(autouse=True)
def real_enforcer_restored():
    yield
    ms.set_enforcer_for_tests("real", None)


@pytest.fixture(autouse=True)
def this_machine(monkeypatch):
    monkeypatch.setattr(es, "local_addresses", lambda: {LOCAL, "127.0.0.1"})


@pytest.fixture
def session_id(admin):
    with database_service.session(write=True) as conn:
        return conn.execute(
            "INSERT INTO monitoring_sessions (user_id, source_type, status, interface_name, started_at, configuration_json) "
            "VALUES (?, 'live_capture', 'RUNNING', 'en0', ?, '{}')", (admin.user_id, to_iso(utc_now()))).lastrowid


def _use_backend(monkeypatch, backend="pf", system="Darwin", interfaces="en0", lab="", runner=None):
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_BACKEND", backend)
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_INTERFACES", interfaces)
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_LAB_INTERFACES", lab)
    monkeypatch.setenv("SMART_SHIELD_TC_BINARY", "/sbin/tc")
    monkeypatch.setattr(es.platform, "system", lambda: system)
    monkeypatch.setattr(es, "_is_root", lambda: True)
    monkeypatch.setattr(es, "_pf_conf_has_anchors", lambda: True)
    monkeypatch.setattr(es.os.path, "exists", lambda path: True)
    runner = runner or FakeRunner()
    ms.set_enforcer_for_tests("real", es.RealEnforcer(runner))
    return runner


def _limit(admin, session_id, target=REMOTE, **kwargs):
    return ms.request_action(admin, session_id, "rate_limit", target=target, limit_bps=5 * M, reason="Too much traffic", **kwargs)


def _stored(mitigation_id):
    with database_service.session() as conn:
        return dict(conn.execute("SELECT * FROM mitigation_actions WHERE id = ?", (mitigation_id,)).fetchone())


# ------------------------------------------------------------------ nothing unchecked reaches a command

@pytest.mark.parametrize("row, message", [
    (_row(interface_name="en0; rm -rf /"), "Invalid interface"),
    (_row(interface_name="en0\nblock all"), "Invalid interface"),
    (_row(interface_name=None), "live capture"),
    (_row(target="10.0.0.1 to any pipe 1\nblock all"), "single IP"),
    (_row(target="10.0.0.0/8"), "single IP"),
    (_row(limit_bps=10), "outside the supported"),
    (_row(limit_bps=None), "outside the supported"),
    (_row(action_type="prioritize", target_kind="link", target="link"), "not available on a real link"),
    (_row(target_kind="link"), "source or a destination"),
])
def test_a_rule_is_refused_before_any_command_exists(row, message):
    with pytest.raises(EnforcementError, match=message):
        rule_from(row)


def test_no_shell_anywhere_in_enforcement():
    for name in ("enforcement_adapters.py", "enforcement_service.py"):
        tree = ast.parse((ROOT / "services" / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert node.value.value is False
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("system", "popen") or name == "enforcement_service.py" and node.attr == "system"


# ------------------------------------------------------------------ tc

def test_tc_limit_uses_a_policing_filter_in_both_directions_beside_the_root_qdisc():
    steps = TcAdapter("/sbin/tc").plan_apply(rule_from(_row()), [])
    assert steps[0].argv == ("/sbin/tc", "qdisc", "replace", "dev", "en0", "clsact")
    assert [s.argv[5] for s in steps[1:]] == ["ingress", "egress"]
    assert steps[1].argv == ("/sbin/tc", "filter", "add", "dev", "en0", "ingress", "protocol", "ip", "pref", "1014", "flower",
                             "src_ip", REMOTE, "action", "police", "rate", "5000000bit", "burst", "62500",
                             "conform-exceed", "drop/ok")
    assert not any("root" in s.argv for s in steps)  # a class policy on the root qdisc is left alone


def test_tc_block_isolate_destination_and_ipv6():
    tc = TcAdapter("/sbin/tc")
    assert tc.plan_apply(rule_from(_row(action_type="block", limit_bps=None)), [])[1].argv[-2:] == ("action", "drop")
    isolate = tc.plan_apply(rule_from(_row(action_type="isolate", limit_bps=None)), [])[1:]
    assert {(s.argv[5], s.argv[11]) for s in isolate} == {(h, f) for h in ("ingress", "egress") for f in ("src_ip", "dst_ip")}
    assert tc.plan_apply(rule_from(_row(target_kind="destination")), [])[1].argv[11] == "dst_ip"
    assert tc.plan_apply(rule_from(_row(target="2001:db8::1")), [])[1].argv[7] == "ipv6"


def test_tc_keeps_the_qdisc_until_the_last_rule_on_that_interface_goes():
    tc = TcAdapter("/sbin/tc")
    rule, other = rule_from(_row()), rule_from(_row(id=8, target="203.0.113.6"))
    assert not any("qdisc" in s.argv for s in tc.plan_remove(rule, [other]))
    assert tc.plan_remove(rule, [])[-1].argv == ("/sbin/tc", "qdisc", "del", "dev", "en0", "clsact")


# ------------------------------------------------------------------ pf

def test_pf_only_ever_touches_its_own_anchor_and_never_flushes():
    pf = PfAdapter()
    rule, other = rule_from(_row()), rule_from(_row(id=8, action_type="isolate", limit_bps=None, target="203.0.113.6"))
    steps = [*pf.plan_apply(rule, [other]), *pf.plan_remove(rule, [other]), *pf.plan_clear(["en0"], [rule, other])]
    for step in steps:
        assert "-F" not in step.argv
        if "-f" in step.argv:
            assert step.argv[:3] == (PFCTL, "-a", PF_ANCHOR)


def test_pf_ruleset_lines():
    lines = PfAdapter.ruleset([rule_from(_row()), rule_from(_row(id=8, action_type="block", limit_bps=None, target="203.0.113.6"))])
    assert lines.splitlines() == [
        f"dummynet in quick on en0 inet from {REMOTE} to any pipe 40007",
        f"dummynet out quick on en0 inet from {REMOTE} to any pipe 40007",
        "block drop quick on en0 inet from 203.0.113.6 to any"]


# ------------------------------------------------------------------ which backend is really used

def test_dry_run_is_the_default_and_changes_nothing(monkeypatch):
    monkeypatch.delenv("SMART_SHIELD_ENFORCEMENT_BACKEND", raising=False)
    state = es.capability()
    assert state.backend == es.DRY_RUN and not state.enforcing


def test_an_unknown_backend_is_a_configuration_error(monkeypatch):
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_BACKEND", "iptables")
    with pytest.raises(ConfigError):
        get_settings()


@pytest.mark.parametrize("backend, system, interfaces, root, reason", [
    ("pf", "Darwin", "en0", False, "need root"),
    ("pf", "Linux", "en0", True, "needs macOS"),
    ("tc", "Darwin", "en0", True, "needs Linux"),
    ("pf", "Darwin", "", True, "No interface"),
    ("pf", "Darwin", "en0;x", True, "Invalid names"),
])
def test_a_backend_that_cannot_work_stays_in_dry_run_and_says_why(monkeypatch, backend, system, interfaces, root, reason):
    _use_backend(monkeypatch, backend, system, interfaces)
    monkeypatch.setattr(es, "_is_root", lambda: root)
    monkeypatch.setattr(es, "_has_net_admin", lambda: False)
    state = es.capability()
    assert state.backend == es.DRY_RUN and any(reason in r for r in state.reasons)


def test_pf_without_the_system_anchors_stays_in_dry_run(monkeypatch):
    _use_backend(monkeypatch)
    monkeypatch.setattr(es, "_pf_conf_has_anchors", lambda: False)
    assert es.capability().backend == es.DRY_RUN


def test_usable_backends_are_selected(monkeypatch):
    _use_backend(monkeypatch, "pf", "Darwin")
    assert es.capability().backend == "pf+dnctl"
    _use_backend(monkeypatch, "tc", "Linux")
    assert es.capability().backend == "tc"


# ------------------------------------------------------------------ a dry run is never mistaken for enforcement

def test_a_dry_run_records_the_commands_runs_nothing_and_says_so(admin, session_id, monkeypatch):
    runner = FakeRunner()
    ms.set_enforcer_for_tests("real", es.RealEnforcer(runner))
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_BACKEND", "dry_run")
    result = _limit(admin, session_id)
    assert runner.calls == []
    assert result["status"] == "active" and result["adapter"] == es.DRY_RUN
    assert result["recovery_status"] == "not_applied" and "Dry run" in result["recovery_note"]
    public = ms.list_for_session(admin, session_id)[0]
    assert any("-a" in c["argv"] or "filter" in c["argv"] for c in public["commands"])
    plan = ms.plan_interval(session_id, 100 * M, [SenderDemand(REMOTE, "", "normal", 50 * M)], utc_now())
    assert not plan.policy.enforcing  # the allocation must not show a limit that does not exist
    assert plan.allocation.hosts[REMOTE].traffic_class == "normal"
    ms.rollback(admin, result["id"], reason="Finished looking")
    assert runner.calls == []


def test_a_dry_run_is_never_checked_for_recovery(admin, session_id, monkeypatch):
    monkeypatch.setenv("SMART_SHIELD_ENFORCEMENT_BACKEND", "dry_run")
    result = _limit(admin, session_id)
    ms._verify_due(session_id, utc_now() + timedelta(seconds=60))
    assert _stored(result["id"])["recovery_status"] == "not_applied"


# ------------------------------------------------------------------ real backends through the engine (fake runner)

def test_pf_apply_rollback_and_token_release(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = _limit(admin, session_id)
    assert result["status"] == "active" and result["adapter"] == "pf+dnctl" and result["interface_name"] == "en0"
    pipe = str(40000 + result["id"])
    assert runner.calls[0][0] == [DNCTL, "pipe", pipe, "config", "bw", "5000000bit/s"]
    assert f"from {REMOTE} to any pipe {pipe}" in runner.calls[1][1]
    assert runner.calls[2][0] == [PFCTL, "-E"]
    assert ms.plan_interval(session_id, 100 * M, [SenderDemand(REMOTE, "", "normal", 50 * M)], utc_now()).policy.enforcing
    runner.calls.clear()
    ms.rollback(admin, result["id"], reason="Back to normal")
    assert runner.loaded_rulesets() == [""]
    assert f"{DNCTL} pipe delete {pipe}" in runner.commands() and f"{PFCTL} -X 4242" in runner.commands()
    assert _stored(result["id"])["status"] == "rolled_back"
    details = [r for r in audit_rows() if r["action"] == "mitigation.apply"]
    assert details and "dnctl" in details[0]["details_json"]


def test_pf_rules_of_other_actions_survive_a_change(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    first = _limit(admin, session_id, target="203.0.113.5")
    second = _limit(admin, session_id, target="203.0.113.6")
    assert "203.0.113.5" in runner.loaded_rulesets()[-1] and "203.0.113.6" in runner.loaded_rulesets()[-1]
    assert sum(1 for c in runner.commands() if c.endswith("-E")) == 1  # pf is enabled once, not per rule
    runner.calls.clear()
    ms.rollback(admin, first["id"], reason="Back to normal")
    assert "203.0.113.5" not in runner.loaded_rulesets()[-1] and "203.0.113.6" in runner.loaded_rulesets()[-1]
    assert not any("-X" in c for c in runner.commands())  # the other rule still needs pf
    ms.rollback(admin, second["id"], reason="Back to normal")
    assert any("-X" in c for c in runner.commands())


def test_tc_backend_through_the_engine(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch, "tc", "Linux")
    result = _limit(admin, session_id)
    assert result["adapter"] == "tc" and any("police" in c for c in runner.commands())
    runner.calls.clear()
    ms.rollback(admin, result["id"], reason="Back to normal")
    assert runner.commands()[-1] == "/sbin/tc qdisc del dev en0 clsact"


def test_a_failed_apply_is_recorded_undone_and_changes_nothing_else(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch, runner=FakeRunner(fail_on="-f -"))
    result = _limit(admin, session_id)
    assert result["status"] == "failed" and "Operation not permitted" in result["failure_reason"]
    assert any("pipe delete" in c for c in runner.commands())  # the pipe it had made is removed again
    assert [r for r in audit_rows() if r["action"] == "mitigation.apply" and r["outcome"] == "failure"]


def test_a_failed_rollback_stays_active_and_says_so(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = _limit(admin, session_id)
    runner.fail_on = "-f -"
    with pytest.raises(MitigationError, match="still active"):
        ms.rollback(admin, result["id"], reason="Back to normal")
    assert _stored(result["id"])["status"] == "active"


def test_removing_something_already_gone_counts_as_removed(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch, "tc", "Linux")
    result = _limit(admin, session_id)
    runner.fail_on, runner.stderr = "del", "Error: Cannot find specified filter chain."
    ms.rollback(admin, result["id"], reason="Back to normal")
    assert _stored(result["id"])["status"] == "rolled_back"


def test_expiry_removes_the_rule_and_a_failed_removal_retries_without_flooding_the_audit(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = _limit(admin, session_id)
    later = utc_now() + timedelta(hours=2)
    runner.fail_on = "-f -"
    ms.expire_due(later)
    ms.expire_due(later)
    stored = _stored(result["id"])
    assert stored["status"] == "active" and "Could not be removed" in stored["failure_reason"]
    assert len([r for r in audit_rows() if r["action"] == "mitigation.expire" and r["outcome"] == "failure"]) == 1
    runner.fail_on = None
    ms.expire_due(later)
    assert _stored(result["id"])["status"] == "expired"
    assert runner.loaded_rulesets()[-1] == ""


def test_a_restart_removes_limits_left_in_the_kernel_and_survives_being_unable_to(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = _limit(admin, session_id)
    with database_service.session(write=True) as conn:
        conn.execute("UPDATE monitoring_sessions SET status = 'ERROR', ended_at = ? WHERE id = ?", (to_iso(utc_now()), session_id))
    runner.fail_on = "-f -"
    ms.close_orphans()  # must not stop the app from starting
    assert _stored(result["id"])["status"] == "active"
    runner.fail_on = None
    assert ms.close_orphans() == 1
    assert _stored(result["id"])["status"] == "ended"


# ------------------------------------------------------------------ what may never be a target

@pytest.mark.parametrize("target, action", [("127.0.0.1", "rate_limit"), ("224.0.0.1", "rate_limit"), ("0.0.0.0", "rate_limit"),
                                            (LOCAL, "block")])
def test_targets_refused_for_every_backend(admin, session_id, monkeypatch, target, action):
    runner = _use_backend(monkeypatch)
    extra = {"limit_bps": M} if action == "rate_limit" else {"confirm_target": target}
    result = ms.request_action(admin, session_id, action, target=target, reason="Testing a refusal", **extra)
    assert result["status"] == "failed" and runner.calls == []


def test_this_machine_can_be_limited_because_that_leaves_it_connected(admin, session_id, monkeypatch):
    _use_backend(monkeypatch)
    assert _limit(admin, session_id, target=LOCAL)["status"] == "active"


def test_protected_hosts_are_refused_and_never_proposed(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    settings = settings_service.get_mitigation_settings()
    settings_service.update_mitigation_settings(admin, replace(settings, protected_hosts=(REMOTE,)))
    assert _limit(admin, session_id)["status"] == "failed" and runner.calls == []
    now = utc_now()
    with database_service.session(write=True) as conn:
        for i in range(5):
            conn.execute("INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, intrusion_prediction, provenance) "
                         "VALUES (?, ?, ?, '10.0.0.1', 'DDoS', 'measured')", (session_id, to_iso(now - timedelta(seconds=i)), REMOTE))
    before = len(ms.list_for_session(admin, session_id))
    ms.run_live_interval(session_id, None, [{"host": REMOTE, "sent_bps": 50 * M, "received_bps": 0}], now)
    assert len(ms.list_for_session(admin, session_id)) == before


def test_an_interface_that_is_not_listed_is_refused(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch, interfaces="en1")
    result = _limit(admin, session_id)
    assert result["status"] == "failed" and "not listed" in result["failure_reason"] and runner.calls == []


def test_isolation_needs_a_lab_interface_and_cuts_both_directions(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    arguments = dict(target=REMOTE, reason="Compromised host", confirm_target=REMOTE)
    with pytest.raises(MitigationError, match="lab network"):
        ms.request_action(admin, session_id, "isolate", **arguments)
    assert runner.calls == []
    runner = _use_backend(monkeypatch, lab="en0", runner=runner)
    assert ms.request_action(admin, session_id, "isolate", **arguments)["status"] == "active"
    assert f"from {REMOTE} to any" in runner.loaded_rulesets()[-1] and f"from any to {REMOTE}" in runner.loaded_rulesets()[-1]


def test_prioritizing_on_a_real_link_fails_clearly(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = ms.request_action(admin, session_id, "prioritize", reason="Share by class")
    assert result["status"] == "failed" and "not available on a real link" in result["failure_reason"] and runner.calls == []


def test_a_session_that_is_not_a_live_capture_has_nothing_to_enforce_on(admin, monkeypatch):
    runner = _use_backend(monkeypatch)
    with database_service.session(write=True) as conn:
        replay = conn.execute("INSERT INTO monitoring_sessions (user_id, source_type, status, started_at, configuration_json) "
                              "VALUES (?, 'replay', 'RUNNING', ?, '{}')", (admin.user_id, to_iso(utc_now()))).lastrowid
    result = _limit(admin, replay)
    assert result["status"] == "failed" and "live capture" in result["failure_reason"] and runner.calls == []


def test_only_administrators_can_act(analyst, admin, session_id):
    with pytest.raises(PermissionDenied):
        ms.emergency_disable(analyst, reason="Should not work")
    with pytest.raises(PermissionDenied):
        _limit(analyst, session_id)


def test_host_lists_are_validated(admin):
    settings = settings_service.get_mitigation_settings()
    with pytest.raises(SettingsError, match="not a single IP"):
        settings_service.update_mitigation_settings(admin, replace(settings, protected_hosts=("gateway",)))
    settings_service.update_mitigation_settings(admin, replace(settings, critical_hosts=("10.0.0.1",)))
    assert settings_service.get_mitigation_settings().critical_hosts == ("10.0.0.1",)


# ------------------------------------------------------------------ recovery is only claimed when it can be seen

def _samples(session_id, moment, host, sent, received):
    with database_service.session(write=True) as conn:
        telemetry_repository.insert_many(conn, [(
            session_id, to_iso(moment), "live capture", "en0", 1000.0, 1000.0, 1.0, 1.0, float(sent + received), None, None, None,
            None, "psutil_counters", "measured", "valid", "derived", "unavailable", "unavailable")])
        conn.execute("INSERT INTO host_metrics (session_id, timestamp, host, sent_bps, received_bps, sent_pps, received_pps, "
                     "active_connections, provenance) VALUES (?, ?, ?, ?, ?, 1, 1, 1, 'measured')",
                     (session_id, to_iso(moment), host, sent, received))


def test_incoming_traffic_cannot_be_judged_from_capture_and_says_so(admin, session_id, monkeypatch):
    _use_backend(monkeypatch)
    result = _limit(admin, session_id, target=REMOTE)
    applied = utc_now()
    _samples(session_id, applied + timedelta(seconds=5), REMOTE, 80 * M, 0)  # capture still sees what arrives at the card
    ms._verify_due(session_id, applied + timedelta(seconds=20))
    stored = _stored(result["id"])
    assert stored["recovery_status"] == "unavailable" and "before it acts" in stored["recovery_note"]


def test_outgoing_traffic_from_this_machine_is_judged_from_samples(admin, session_id, monkeypatch):
    _use_backend(monkeypatch)
    result = _limit(admin, session_id, target=LOCAL)
    applied = utc_now()
    _samples(session_id, applied + timedelta(seconds=5), LOCAL, 80 * M, 0)
    ms._verify_due(session_id, applied + timedelta(seconds=20))
    assert _stored(result["id"])["recovery_status"] == "not_recovered"  # a limit that did not hold is reported, not hidden


# ------------------------------------------------------------------ emergency stop

def test_emergency_disable_turns_the_engine_off_and_removes_everything(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    settings = settings_service.get_mitigation_settings()
    settings_service.update_mitigation_settings(admin, replace(settings, policy="auto_rate_limit"))
    first, second = _limit(admin, session_id, target="203.0.113.5"), _limit(admin, session_id, target="203.0.113.6")
    runner.calls.clear()
    result = ms.emergency_disable(admin, reason="Link is misbehaving")
    assert result == {"ended": 2, "failures": []}
    assert settings_service.get_mitigation_settings().policy == "off"
    assert runner.loaded_rulesets()[0] == "" and runner.loaded_rulesets()[-1] == ""
    assert f"{DNCTL} pipe delete {40000 + first['id']}" in runner.commands()
    assert {_stored(first["id"])["status"], _stored(second["id"])["status"]} == {"rolled_back"}
    assert [r for r in audit_rows() if r["action"] == "mitigation.emergency_disable" and r["outcome"] == "success"]


def test_emergency_disable_reports_what_it_could_not_remove(admin, session_id, monkeypatch):
    runner = _use_backend(monkeypatch)
    result = _limit(admin, session_id)
    runner.fail_on = "-f -"
    outcome = ms.emergency_disable(admin, reason="Link is misbehaving")
    assert outcome["ended"] == 0 and len(outcome["failures"]) == 2
    assert _stored(result["id"])["status"] == "active"
    assert [r for r in audit_rows() if r["action"] == "mitigation.emergency_disable" and r["outcome"] == "failure"]


def test_emergency_disable_also_covers_class_shaping(admin, session_id, monkeypatch):
    called = []
    monkeypatch.setenv("SMART_SHIELD_TC_ENABLED", "true")
    monkeypatch.setattr(ms.traffic_shaping_service, "emergency_disable", lambda principal: called.append(principal))
    ms.emergency_disable(admin, reason="Link is misbehaving")
    assert called == [admin]


def test_emergency_disable_needs_a_reason(admin):
    with pytest.raises(MitigationError, match="reason"):
        ms.emergency_disable(admin, reason="")


# ------------------------------------------------------------------ the engine on live capture

AT = 1_700_000_030.0


def _flagging_script(rate=50 * M, capacity=False):
    def script(config):
        yield {"type": "started", "pid": 1, "mode": config["mode"]}
        flows = [{**ddos_flow(i), "src_ip": "172.16.0.9"} for i in range(30)]
        yield {"type": "flows", "flows": flows}
        yield {"type": "metrics", "at": capture_worker._iso(AT), "sample": dict(SAMPLE), "dropped_messages": 0, "active_flows": 3,
               "hosts": [{"host": "172.16.0.9", "sent_bps": rate, "received_bps": 0.0, "sent_pps": 1.0, "received_pps": 1.0,
                          "active_connections": 1},
                         {"host": "192.168.1.50", "sent_bps": 1_000.0, "received_bps": rate, "sent_pps": 1.0, "received_pps": 1.0,
                          "active_connections": 1}]}
    return script


def test_live_capture_reaches_the_engine_and_stopping_ends_its_actions(admin, monitor):
    train_live_model(admin, "live_compatible")
    monitor._worker_target = fake_worker(_flagging_script())
    session_id = monitor.start(admin, "eth0", mode="packets", capacity_bps=100 * M)
    assert wait_for(lambda: ms.list_for_session(admin, session_id))
    [proposal] = ms.list_for_session(admin, session_id)
    assert proposal["origin"] == "real" and proposal["target"] == "172.16.0.9" and proposal["status"] == "proposed"
    assert proposal["action_type"] == "rate_limit" and proposal["limit_bps"] == pytest.approx(5 * M)
    allocation = ms.latest_allocation(admin, session_id)
    assert allocation["provenance"] == "derived" and not allocation["enforced"]
    applied = ms.approve(admin, proposal["id"], reason="Confirmed by a person")
    assert applied["status"] == "active" and applied["adapter"] == es.DRY_RUN and applied["interface_name"] == "eth0"
    monitor.stop(admin)
    assert ms.list_for_session(admin, session_id)[0]["status"] == "ended"


def test_without_a_capacity_no_allocation_is_invented_but_threats_are_still_assessed(admin, monitor):
    train_live_model(admin, "live_compatible")
    monitor._worker_target = fake_worker(_flagging_script())
    session_id = monitor.start(admin, "eth0", mode="packets")
    assert wait_for(lambda: ms.list_for_session(admin, session_id))
    assert ms.latest_allocation(admin, session_id) is None
    assert ms.list_for_session(admin, session_id)[0]["limit_bps"] == pytest.approx(25 * M)  # half the measured rate
    monitor.stop(admin)


def test_no_rate_and_no_capacity_means_no_limit_is_proposed(admin, session_id):
    now = utc_now()
    with database_service.session(write=True) as conn:
        for i in range(5):
            conn.execute("INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, intrusion_prediction, provenance) "
                         "VALUES (?, ?, ?, '10.0.0.1', 'DDoS', 'measured')", (session_id, to_iso(now - timedelta(seconds=i)), REMOTE))
    ms.run_live_interval(session_id, None, [], now)
    assert ms.list_for_session(admin, session_id) == []


def test_a_busy_link_with_no_verdict_starts_nothing_live(admin, session_id):
    busy = [{"host": REMOTE, "sent_bps": 99 * M, "received_bps": 0.0}]
    ms.run_live_interval(session_id, 100 * M, busy, utc_now())
    assert ms.list_for_session(admin, session_id) == []


def test_auto_policy_on_live_capture_applies_only_when_eligible_and_only_a_limit(admin, session_id):
    settings = settings_service.get_mitigation_settings()
    settings_service.update_mitigation_settings(admin, replace(settings, policy="auto_rate_limit"))
    now = utc_now()
    with database_service.session(write=True) as conn:
        for i in range(30):
            conn.execute(
                "INSERT INTO network_flows (session_id, timestamp, src_ip, dst_ip, intrusion_prediction, feature_summary_json, provenance) "
                "VALUES (?, ?, ?, '10.0.0.1', 'DDoS', '{\"model_score_uncalibrated\": 0.95}', 'measured')",
                (session_id, to_iso(now - timedelta(seconds=i * 1.5)), REMOTE))
    ms.run_live_interval(session_id, 100 * M, [{"host": REMOTE, "sent_bps": 50 * M, "received_bps": 0.0}], now)
    [action] = ms.list_for_session(admin, session_id)
    assert action["status"] == "active" and action["action_type"] == "rate_limit" and action["decided_by"] is None
    assert action["adapter"] == es.DRY_RUN  # and even then, by default, nothing on the network changed


def test_an_engine_failure_does_not_stop_the_capture(admin, monitor, monkeypatch):
    train_live_model(admin, "live_compatible")
    monkeypatch.setattr(ms, "run_live_interval", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("engine broke")))
    monitor._worker_target = fake_worker(_flagging_script())
    session_id = monitor.start(admin, "eth0", mode="packets")
    assert wait_for(lambda: monitor.status.engine_error is not None)
    assert "engine broke" in monitor.status.engine_error
    assert monitor.status.running and session_row(session_id)["status"] == "RUNNING"
    monitor.stop(admin)


def test_counter_mode_never_reaches_the_engine(admin, monitor, monkeypatch):
    calls = []
    monkeypatch.setattr(ms, "run_live_interval", lambda *a, **k: calls.append(a))
    session_id = monitor.start(admin, "eth0", mode="counters")
    assert wait_for(lambda: monitor.status.samples >= 2)
    monitor.stop(admin)
    assert calls == [] and session_row(session_id)["status"] == "STOPPED"


# ------------------------------------------------------------------ the self-check and the page

def test_self_check_only_shows_the_plan_unless_asked(monkeypatch):
    runner, lines = FakeRunner(), []
    assert es.self_check("pf", "en0", install=False, runner=runner, output=lines.append)
    assert runner.calls == [] and "Nothing was changed" in lines[-1]


class ReadBackRunner(FakeRunner):
    """Answers a read-back as the kernel would: the block is listed while it is loaded."""
    def __call__(self, argv, stdin):
        result = super().__call__(argv, stdin)
        if "-f" in argv:
            self.loaded = stdin
        if "-s" in argv:
            return subprocess.CompletedProcess(argv, 0, getattr(self, "loaded", ""), "")
        return result


def test_self_check_installs_reads_back_and_removes():
    runner, lines = ReadBackRunner(), []
    assert es.self_check("pf", "en0", install=True, runner=runner, output=lines.append)
    assert runner.loaded == "" and any("-X 4242" in c for c in runner.commands())
    assert "203.0.113" in " ".join(lines) and "passed" in lines[-1]


def test_self_check_removes_its_rules_even_when_installing_fails():
    runner, lines = ReadBackRunner(fail_on="-k"), []
    runner.fail_on = "pipe 59998 config"
    assert not es.self_check("pf", "en0", install=True, runner=runner, output=lines.append)
    assert any("pipe delete" in c for c in runner.commands()) and "FAILED" in lines[-1]


def test_self_check_refuses_when_real_rules_are_active(admin, session_id, monkeypatch):
    from scripts import manage
    _use_backend(monkeypatch)
    _limit(admin, session_id)
    assert manage.main(["enforcement-check", "--backend", "pf", "--interface", "en0", "--install"]) == 1


def _bandwidth_page(user):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state[session_service.USER_ID_KEY] = user.id
    app.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    app.run()
    app.switch_page("views/bandwidth.py")
    app.run()
    return app


def test_the_bandwidth_page_shows_dry_run_and_the_emergency_stop_works(admin_user, admin, session_id):
    app = _bandwidth_page(admin_user)
    assert not app.exception
    assert any("Dry run" in i.value for i in app.info)
    app.text_input(key="emergency_reason").input("Practice run")
    app.button(key="emergency_disable").click()
    app.run()
    assert not app.exception
    assert [e.value for e in app.error] == []
    assert settings_service.get_mitigation_settings().policy == "off"


def test_the_bandwidth_page_shows_an_active_dry_run_with_its_commands(admin_user, admin):
    _bandwidth_page(admin_user)  # the first page of a process closes sessions left over from an earlier process
    with database_service.session(write=True) as conn:
        live_id = conn.execute(
            "INSERT INTO monitoring_sessions (user_id, source_type, status, interface_name, started_at, configuration_json) "
            "VALUES (?, 'live_capture', 'RUNNING', 'en0', ?, '{}')", (admin.user_id, to_iso(utc_now()))).lastrowid
    result = _limit(admin, live_id)
    app = _bandwidth_page(admin_user)
    assert not app.exception
    assert any(f"#{result['id']}" in m.value and "5.00 Mbit/s" in m.value for m in app.markdown)
    assert any("Nothing on the network was changed" in i.value for i in app.info)
    assert any("/" in c.value for c in app.code)
    app.button(key=f"mitigation_rollback_enforce{result['id']}").click()
    app.run()
    assert not app.exception and _stored(result["id"])["status"] == "rolled_back"


# ------------------------------------------------------------------ the real parsers on a Mac (nothing is loaded)

needs_pf = pytest.mark.skipif(not (os.path.exists(PFCTL) and os.path.exists(DNCTL)), reason="needs macOS pfctl and dnctl")


@needs_pf
def test_generated_pf_rules_pass_the_real_pfctl_parser(tmp_path):
    rules = [rule_from(_row()), rule_from(_row(id=8, target_kind="destination", target="203.0.113.6")),
             rule_from(_row(id=9, action_type="block", limit_bps=None, target="203.0.113.7")),
             rule_from(_row(id=10, action_type="isolate", limit_bps=None, target="203.0.113.8")),
             rule_from(_row(id=11, target="2001:db8::1")),
             rule_from(_row(id=12, action_type="block", limit_bps=None, target="2001:db8::2"))]
    path = tmp_path / "rules.conf"
    for text in (PfAdapter.ruleset(rules), ""):
        path.write_text(text)
        result = subprocess.run([PFCTL, "-n", "-a", PF_ANCHOR, "-f", str(path)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr


@needs_pf
def test_generated_dnctl_command_passes_the_real_dnctl_parser():
    [step, *_] = PfAdapter().plan_apply(rule_from(_row()), [])
    result = subprocess.run([step.argv[0], "-n", *step.argv[1:]], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@needs_pf
def test_this_macs_pf_conf_evaluates_the_anchor():
    assert es._pf_conf_has_anchors()
