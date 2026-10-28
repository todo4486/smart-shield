""""How it works": one stored flow traced through every stage of the pipeline.

The walk-through only shows values that are stored for that flow (its 5-tuple, counters, the model's
verdict, the alert and incident it ended up in, the latest forecast for the same data). A stage the flow
never reached says so and why, instead of showing an example value. With no stored flows at all, the
stages are explained without data.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from repositories.incident_repository import IS_REPLAY_ALERT, REPLAY_SOURCE_NAME
from services import data_source, database_service, mitre
from services.authorization import Permission, Principal, require_permission

STAGES: Tuple[Tuple[str, str, str, str], ...] = (
    ("capture", "📡", "Passive capture",
     "Traffic is observed, never changed: interface counters from the OS, and (with permission) a copy of packets. "
     "Nothing is sent, scanned or blocked. Datasets and replays enter here instead of the network."),
    ("flow", "🧩", "Flow extraction",
     "Packets are grouped into flows keyed by the 5-tuple (source IP, source port, destination IP, destination port, "
     "protocol). Each flow gets counters and timing features; a flow ends after an idle or active timeout."),
    ("detect", "🧠", "Smart Shield + PredictNet",
     "Smart Shield scores the flow with the registered Random Forest (attack or not, and which type) and the "
     "Isolation Forest (how unusual). PredictNet forecasts link load from throughput samples, separately."),
    ("correlate", "🔗", "Correlation",
     "Flagged flows of one category in one window become one alert. Alerts close together in network time are "
     "grouped. Congestion alone is never called an attack."),
    ("incident", "🚨", "Incident",
     "The group becomes an incident with a classification, a rationale, measured changes and investigation steps, "
     "shown on the timeline."),
    ("act", "📝", "Act & report",
     "A person acknowledges, assigns and resolves it, writes notes, and exports a report. Bandwidth shaping is "
     "admin-only, confirmed, audited and reversible; nothing is blocked automatically."),
)


@dataclass
class Stage:
    key: str
    icon: str
    title: str
    explanation: str
    facts: List[Tuple[str, str]] = field(default_factory=list)
    reached: bool = True
    note: Optional[str] = None


def _fmt_bytes(value) -> str:
    if value is None:
        return "unavailable"
    value = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1000 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1000
    return f"{value:,.1f} GB"


def _endpoint(ip, port) -> str:
    return f"{ip or '?'}:{port}" if port is not None else str(ip or "?")


def build_trace(flow: Optional[Dict[str, Any]], session: Optional[Dict[str, Any]], alert: Optional[Dict[str, Any]],
                incident: Optional[Dict[str, Any]], forecast: Optional[Dict[str, Any]],
                *, live_running: bool = False) -> List[Stage]:
    """The six stages with the stored facts for one flow (pure; missing pieces are explained, never filled in)."""
    stages = [Stage(*spec) for spec in STAGES]
    by_key = {s.key: s for s in stages}
    if flow is None:
        for stage in stages:
            stage.reached = False
            stage.note = "No flows are stored yet, so this stage is described without data."
        return stages
    summary = json.loads(flow.get("feature_summary_json") or "{}") if isinstance(flow.get("feature_summary_json"), str) \
        else (flow.get("feature_summary_json") or {})

    source = data_source.classify(session.get("source_type") if session else None, live_running=live_running,
                                  live_mode="packets")
    capture = by_key["capture"]
    capture.facts = [("Data source", source.label), ("Session", f"#{flow['session_id']}")]
    if session:
        if session.get("interface_name"):
            capture.facts.append(("Interface", str(session["interface_name"])))
        if session.get("dataset_name"):
            capture.facts.append(("Dataset", str(session["dataset_name"])))
        capture.facts.append(("Session started", str(session.get("started_at"))))
    if source.kind in (data_source.DATASET, data_source.REPLAY):
        capture.note = ("This flow was not captured here: it is a recorded dataset row"
                        + (" being replayed" if source.kind == data_source.REPLAY else "") + ".")

    flow_stage = by_key["flow"]
    flow_stage.facts = [
        ("5-tuple", f"{_endpoint(flow.get('src_ip'), flow.get('src_port'))} → "
                    f"{_endpoint(flow.get('dst_ip'), flow.get('dst_port'))} · {flow.get('protocol') or '?'}"),
        ("Started", str(flow.get("timestamp"))),
        ("Packets", "unavailable" if flow.get("packet_count") is None else f"{int(flow['packet_count']):,}"),
        ("Bytes", _fmt_bytes(flow.get("byte_count"))),
        ("Duration", "unavailable" if flow.get("duration") is None else f"{float(flow['duration']):,.3f} s"),
    ]
    features = summary.get("features") or {}
    for name in list(features)[:4]:
        value = features[name]
        flow_stage.facts.append((f"Feature · {name}", "missing" if value is None else f"{value:,.4g}"))
    if summary.get("end_reason"):
        flow_stage.facts.append(("Flow ended by", str(summary["end_reason"])))
    if summary.get("dataset_row"):
        flow_stage.facts.append(("Dataset row", f"{summary['dataset_row']:,}"))

    detect = by_key["detect"]
    verdict = flow.get("intrusion_prediction")
    detect.facts = [("Smart Shield verdict", verdict or "not flagged (benign by the model)")]
    if summary.get("model_score_uncalibrated") is not None:
        detect.facts.append(("Classifier score", f"{float(summary['model_score_uncalibrated']):.3f} (uncalibrated)"))
    if flow.get("anomaly_score") is not None:
        detect.facts.append(("Isolation Forest score", f"{float(flow['anomaly_score']):.3f} (higher = more normal)"))
    detect.facts.append(("Model", f"#{flow.get('model_id')} · {flow.get('model_version')}" if flow.get("model_version")
                         else "no model scored this flow"))
    if summary.get("dataset_label"):
        detect.facts.append(("Dataset label (ground truth)", str(summary["dataset_label"])))
    if forecast:
        value = (f"{forecast['predicted_utilization_ratio']:.0%} utilization" if forecast.get("predicted_utilization_ratio")
                 is not None else f"{(forecast.get('predicted_throughput_bps') or 0) / 1e6:,.2f} Mbit/s")
        detect.facts.append(("PredictNet", f"{value} in {forecast['forecast_horizon_seconds'] // 60} min · risk "
                                           f"{forecast['congestion_risk']} · model {forecast['model_version']} (predicted)"))
    else:
        detect.facts.append(("PredictNet", "no forecast stored for this data"))
    if not flow.get("model_version"):
        detect.note = "No compatible model was active when this flow was stored, so it was not scored."

    correlate, incident_stage, act = by_key["correlate"], by_key["incident"], by_key["act"]
    if alert is None:
        correlate.reached = incident_stage.reached = act.reached = False
        reason = ("The model did not flag this flow, so it raised no alert." if not verdict else
                  "This flagged flow is not part of a stored alert (for example, it was cleared or its alert window "
                  "has not finished playing).")
        correlate.note = incident_stage.note = act.note = reason
        return stages
    technique = mitre.primary(alert["category"]) if alert["alert_type"] == "security" else None
    flows = (alert.get("evidence") or {}).get("flows")
    correlate.facts = [("Alert", f"#{alert['id']} · {alert['category']}"), ("Severity", alert["severity"]),
                       ("Flows in the alert", f"{flows:,}" if isinstance(flows, int) else "unavailable"),
                       ("Raised", str(alert["created_at"])), ("Alert status", alert["status"])]
    if technique:
        correlate.facts.append(("MITRE ATT&CK", f"{technique.tactic} · {technique.technique_id} {technique.technique}"))
    if incident is None:
        incident_stage.reached = act.reached = False
        incident_stage.note = act.note = ("The alert has not been correlated into an incident yet. Run correlation in "
                                          "the Incident Center.")
        return stages
    incident_stage.facts = [("Incident", f"#{incident['id']} · {incident['title']}"),
                            ("Classification", incident["classification"]
                             + (" (not an attack)" if incident["classification"] == "performance" else "")),
                            ("Window", f"{incident['window_start']} → {incident['window_end']}"),
                            ("Alerts grouped", str(incident.get("alert_count", "?")))]
    act.facts = [("Incident status", incident["status"]),
                 ("Assigned to", incident.get("assigned_email") or "nobody yet"),
                 ("Next", "Acknowledge → assign → resolve in the Incident Center; export a report from Reports.")]
    return stages


def sample_trace(principal: Principal, *, flagged_only: bool = True, offset: int = 0,
                 live_running: bool = False) -> Dict[str, Any]:
    """Pick a stored flow (newest session first; flagged ones preferred) and trace it. `offset` steps through flows."""
    require_permission(principal, Permission.VIEW_ALERTS, action="pipeline.view")
    with database_service.session() as conn:
        session_row = conn.execute(
            "SELECT s.*, d.name AS dataset_name FROM monitoring_sessions s LEFT JOIN datasets d ON d.id = s.dataset_id "
            "WHERE EXISTS (SELECT 1 FROM network_flows f WHERE f.session_id = s.id) ORDER BY s.id DESC LIMIT 1"
        ).fetchone()
        if session_row is None:
            return {"stages": build_trace(None, None, None, None, None), "flow_id": None, "candidates": 0}
        session = dict(session_row)
        where = "session_id = ?" + (" AND intrusion_prediction IS NOT NULL" if flagged_only else "")
        candidates = conn.execute(f"SELECT COUNT(*) FROM network_flows WHERE {where}", (session["id"],)).fetchone()[0]
        if not candidates:
            where, candidates = "session_id = ?", conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE session_id = ?", (session["id"],)).fetchone()[0]
        flow = dict(conn.execute(f"SELECT * FROM network_flows WHERE {where} ORDER BY timestamp DESC, id DESC "
                                 "LIMIT 1 OFFSET ?", (session["id"], int(offset) % max(1, candidates))).fetchone())
        alert = _alert_for(conn, flow) if flow.get("intrusion_prediction") else None
        incident = None
        if alert is not None:
            row = conn.execute(
                "SELECT i.*, u.email AS assigned_email, (SELECT COUNT(*) FROM incident_alerts x "
                "WHERE x.incident_id = i.id) AS alert_count FROM incidents i JOIN incident_alerts ia "
                "ON ia.incident_id = i.id LEFT JOIN users u ON u.id = i.assigned_to WHERE ia.alert_id = ?",
                (alert["id"],)).fetchone()
            incident = dict(row) if row else None
        replay = session["source_type"] == "replay"
        forecast_row = conn.execute(
            "SELECT * FROM congestion_predictions WHERE (source_name = ?) = ? ORDER BY timestamp DESC, id DESC LIMIT 1",
            (REPLAY_SOURCE_NAME, int(replay))).fetchone()
    stages = build_trace(flow, session, alert, incident, dict(forecast_row) if forecast_row else None,
                         live_running=live_running and session["source_type"] == "live_capture")
    return {"stages": stages, "flow_id": flow["id"], "candidates": int(candidates), "flagged_only": flagged_only}


def _alert_for(conn, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The alert of the same session and category whose network-time window contains the flow."""
    rows = conn.execute(
        f"SELECT a.*, {IS_REPLAY_ALERT} AS is_replay FROM alerts a WHERE a.session_id = ? AND a.category = ? "
        "ORDER BY a.id DESC LIMIT 200", (flow["session_id"], flow["intrusion_prediction"])).fetchall()
    moment = pd.to_datetime(flow["timestamp"], utc=True)
    fallback = None
    for row in rows:
        alert = dict(row)
        alert["evidence"] = json.loads(alert["evidence_json"]) if alert["evidence_json"] else {}
        window = alert["evidence"].get("time_window_utc")
        if isinstance(window, list) and len(window) == 2:
            if pd.to_datetime(window[0], utc=True) <= moment <= pd.to_datetime(window[1], utc=True):
                return alert
        elif fallback is None:
            fallback = alert  # alerts without a window cover the whole session
    return fallback
