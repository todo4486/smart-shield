"""Smart Shield Security Center: run detection, triage alerts, review evidence."""
from __future__ import annotations

import json
from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import severity
from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import format_timestamp, kpi_tile, page_header, section_label
from services import alert_service, dataset_service, intrusion_inference_service, model_registry_service
from services.alert_service import AlertError
from services.authorization import Permission, PermissionDenied
from services.intrusion_inference_service import DetectionError, DetectionOptions

principal = require_principal()

SEVERITY_COLORS = {"critical": COLORS["critical"], "high": "#F97316", "medium": COLORS["warn"], "low": COLORS["muted"]}
SECURITY_TYPES = ["security", "anomaly"]

page_header(
    "Smart Shield Security Center",
    "Detections from registered models, grouped into alerts you can investigate. Model scores are uncalibrated "
    "and are never presented as probabilities.",
    eyebrow="Intelligence",
)

classifier = model_registry_service.active_model(principal, "intrusion_classifier")
detector = model_registry_service.active_model(principal, "anomaly_detector")
open_alerts = alert_service.list_alerts(principal, statuses=["open", "acknowledged"], types=SECURITY_TYPES)

c1, c2, c3, c4 = st.columns(4)
with c1:
    kpi_tile("Unresolved security alerts", f"{len(open_alerts):,}", "derived",
             f"{sum(a.severity in ('critical', 'high') for a in open_alerts)} high or critical")
with c2:
    kpi_tile("Active intrusion classifier", classifier.version if classifier else None,
             "configured" if classifier else "unavailable",
             f"{classifier.name} · test F1 {classifier.metrics.get('test', {}).get('f1', 0):.1%}" if classifier
             else "Train one in the ML Laboratory")
with c3:
    kpi_tile("Active anomaly detector", detector.version if detector else None,
             "configured" if detector else "unavailable",
             f"target FPR {detector.metrics.get('target_false_positive_rate', 0):.1%}" if detector
             else "Trained together with the classifier")
with c4:
    test = classifier.metrics.get("test", {}) if classifier else {}
    kpi_tile("Classifier false-positive rate", f"{test['false_positive_rate']:.2%}" if test else None,
             "derived" if test else "unavailable", "Measured on the held-out test set" if test else "No active model")

detect_tab, alerts_tab, rules_tab = st.tabs(["Run detection", "Alerts", "How alerts are raised"])

# ------------------------------------------------------------------ detection
with detect_tab:
    datasets = dataset_service.list_datasets(principal, "intrusion_flows")
    if not principal.has(Permission.RUN_DETECTION):
        st.info("Your role cannot run detection.")
    elif classifier is None:
        st.info("No intrusion classifier is active yet. Train one under **ML Laboratory → Smart Shield models**, "
                "then an administrator activates it.")
    elif not datasets:
        st.info("Register a dataset under **ML Laboratory → Data sources** to score it.")
    else:
        st.markdown("Score a registered dataset (for example a capture day the model was **not** trained on). "
                    "Flagged flows are grouped into one alert per detected category.")
        by_id = {d.id: d for d in datasets}
        trained_on = {d["id"] for d in classifier.training_metadata.get("datasets", [])}
        with st.form("detect_form", border=True):
            dataset_id = st.selectbox(
                "Dataset", list(by_id),
                format_func=lambda i: f"#{i} · {by_id[i].name} ({by_id[i].row_count:,} rows)"
                                      + (" · used in training" if i in trained_on else ""),
            )
            c1, c2, c3 = st.columns(3)
            max_rows = c1.number_input("Max rows to score", 1, intrusion_inference_service.MAX_DETECTION_ROWS,
                                       200_000, step=10_000)
            offset = c2.number_input("UTC offset of file timestamps (hours)", -14.0, 14.0, 0.0, step=0.5)
            use_anomaly = c3.checkbox("Also run the anomaly detector", value=detector is not None,
                                      disabled=detector is None)
            run = st.form_submit_button("Run detection", type="primary", icon=":material/radar:")
        if dataset_id in trained_on:
            st.warning("This dataset was used to train the active model, so results on it overstate real performance.")
        if run:
            try:
                with st.spinner("Checking compatibility and scoring…"):
                    report = intrusion_inference_service.run_detection(principal, DetectionOptions(
                        dataset_id=dataset_id, max_rows=int(max_rows), utc_offset_hours=float(offset),
                        use_anomaly_detector=use_anomaly,
                    ))
            except (DetectionError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.success(f"Scored {report.rows_scored:,} rows with {report.classifier['name']} "
                           f"{report.classifier['version']}. {len(report.alerts_created)} new alert(s)"
                           + (f", {report.alerts_deduplicated} already open (not repeated)." if report.alerts_deduplicated else "."))
                st.caption(report.compatibility["message"])
                for warning in report.warnings:
                    st.warning(warning)
                c1, c2, c3 = st.columns(3)
                c1.metric("Flagged as attack", f"{report.flagged_attack:,}")
                c2.metric("Anomalous only", f"{report.flagged_anomaly_only:,}")
                c3.metric("Flows stored", f"{report.flows_stored:,}")
                if report.by_category:
                    st.dataframe(pd.DataFrame([{"Category": k, "Flows": v} for k, v in report.by_category.items()]),
                                 hide_index=True)
                if report.ground_truth:
                    gt = report.ground_truth
                    st.info(f"{gt['note']} Recall {gt['recall'] or 0:.1%} · precision {gt['precision'] or 0:.1%} · "
                            f"false-positive rate {gt['false_positive_rate'] or 0:.2%}.")

# --------------------------------------------------------------------- alerts
with alerts_tab:
    f1, f2, f3 = st.columns(3)
    statuses = f1.multiselect("Status", list(alert_service.STATUSES), default=["open", "acknowledged"])
    severities = f2.multiselect("Severity", list(alert_service.SEVERITIES), default=list(alert_service.SEVERITIES),
                                 format_func=severity.plain)
    types = f3.multiselect("Type", SECURITY_TYPES, default=SECURITY_TYPES)
    alerts = alert_service.list_alerts(principal, statuses=statuses or None, severities=severities or None,
                                       types=types or None)
    daily = [d for d in alert_service.daily_counts(principal) if d["alert_type"] in SECURITY_TYPES]
    if daily:
        frame = pd.DataFrame(daily)
        fig = go.Figure()
        for alert_type, color in (("security", COLORS["critical"]), ("anomaly", COLORS["warn"])):
            part = frame[frame["alert_type"] == alert_type]
            if not part.empty:
                fig.add_trace(go.Bar(x=part["day"], y=part["n"], name=alert_type.title(), marker_color=color))
        fig.update_layout(title="Alerts raised per day (last 30 days, UTC)", barmode="stack", yaxis_title="Alerts")
        st.plotly_chart(apply_chart_theme(fig, height=260), theme=None)
    if not alerts:
        st.info("No alerts match these filters.")
    else:
        st.dataframe(pd.DataFrame([
            {"ID": a.id, "Severity": severity.plain(a.severity), "Type": a.alert_type, "Category": a.category, "Status": a.status,
             "Flows": a.evidence.get("flows"), "Model": a.model_version or "—", "Raised": format_timestamp(a.created_at)}
            for a in alerts
        ]), hide_index=True)
        by_id = {a.id: a for a in alerts}
        alert_id = st.selectbox("Investigate alert", list(by_id),
                                format_func=lambda i: f"#{i} · {severity.plain(by_id[i].severity)} · {by_id[i].category}")
        alert, events = alert_service.get_alert(principal, alert_id)
        color = SEVERITY_COLORS.get(alert.severity, COLORS["muted"])
        st.markdown(
            f"<div class='ss-card' style='border-left:4px solid {color}'><h4>#{alert.id} · {escape(alert.category)}"
            f" {severity.badge(alert.severity)}</h4><p>{escape(alert.reason)}</p></div>",
            unsafe_allow_html=True,
        )
        left, right = st.columns([3, 2])
        with left:
            section_label("Evidence")
            evidence = dict(alert.evidence)
            scores = evidence.pop("model_score_uncalibrated", None)
            if scores:
                st.caption(f"Model score (uncalibrated): min {scores['min']:.3f} · median {scores['median']:.3f} · "
                           f"max {scores['max']:.3f}")
            for key in ("top_sources", "top_destinations", "top_destination_ports", "dataset_labels_of_flagged_rows"):
                values = evidence.pop(key, None)
                if values:
                    st.markdown(f"**{key.replace('_', ' ').capitalize()}**")
                    st.dataframe(pd.DataFrame(values)[["value", "flows"]].rename(
                        columns={"value": key.split("_")[-1].rstrip("s").capitalize() if key != "dataset_labels_of_flagged_rows"
                                 else "Dataset label", "flows": "Flows"}), hide_index=True)
            if evidence:
                st.json(json.loads(json.dumps(evidence, default=str)), expanded=False)
            st.caption(f"Model {alert.model_version or '—'} · monitoring session #{alert.session_id or '—'}")
        with right:
            section_label("Triage")
            if principal.has(Permission.TRIAGE_ALERTS):
                options = sorted(alert_service.ALLOWED_TRANSITIONS[alert.status])
                with st.form(f"triage_{alert.id}", border=True):
                    st.markdown(f"Current status: **{alert.status}**")
                    target = st.radio("Change to", options, horizontal=True,
                                      format_func=lambda s: s.replace("_", " "))
                    note = st.text_area("Note (optional)", max_chars=alert_service.MAX_NOTE_LENGTH, height=90)
                    if st.form_submit_button("Update status", type="primary"):
                        try:
                            alert_service.change_status(principal, alert.id, target, note)
                        except (AlertError, PermissionDenied) as exc:
                            st.error(str(exc))
                        else:
                            st.toast(f"Alert #{alert.id} is now {target.replace('_', ' ')}.")
                            st.rerun()
                with st.form(f"note_{alert.id}", border=True, clear_on_submit=True):
                    extra = st.text_area("Add investigation note", max_chars=alert_service.MAX_NOTE_LENGTH, height=80)
                    if st.form_submit_button("Add note"):
                        try:
                            alert_service.add_note(principal, alert.id, extra)
                        except (AlertError, PermissionDenied) as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()
            section_label("History")
            st.dataframe(pd.DataFrame([
                {"When": format_timestamp(e["created_at"]), "Event": e["event_type"].replace("_", " "),
                 "Change": f"{e['from_status'] or ''} → {e['to_status']}" if e["to_status"] else "",
                 "By": e["user_email"] or "system", "Note": e["note"] or ""}
                for e in events
            ]), hide_index=True)
            if alert.investigation_notes:
                st.text(alert.investigation_notes)

# ---------------------------------------------------------------------- rules
with rules_tab:
    st.markdown(f"""
**One alert per detected category per run.** Flagged flows are grouped by the attack type the model predicts.
Re-running the same model on the same data does not repeat an alert while the earlier one is still open or acknowledged.

**Severity rules**

| Severity | When |
| --- | --- |
| Critical | Heartbleed, infiltration, botnet or SQL injection, or a potential DDoS with ≥ {intrusion_inference_service.LARGE_GROUP:,} flows |
| High | DoS / DDoS, brute force (Patator), web attacks, a potential DDoS, or any group of ≥ {intrusion_inference_service.LARGE_GROUP:,} flows |
| Medium | Port scans and other attack types |
| Medium / Low | Anomaly-only flows (≥ 100 flows / fewer). These are unusual, not proven malicious |

**Potential DDoS** is flagged when ≥ {intrusion_inference_service.DDOS_MIN_SOURCES} distinct sources send flagged flows to one destination within
{intrusion_inference_service.DDOS_WINDOW_SECONDS} seconds. This needs source/destination IPs and timestamps in the data.

**Compatibility.** A model only runs on data that contains every feature it was trained on. Missing features are never filled
with zeros, so the model is rejected for that data instead.

**Scores.** Classifier scores are the share of trees voting "attack". Anomaly scores come from the Isolation Forest. Neither is
a calibrated probability.
""")
