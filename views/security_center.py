"""Smart Shield Security Center: run detection, triage alerts, review evidence."""
from __future__ import annotations

import json
from html import escape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import explain, mitre, severity
from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import format_timestamp, kpi_tile, page_header, section_label
from services import (
    alert_service, dataset_service, explainability_service, intrusion_inference_service, mitre as mitre_service,
    model_registry_service, suppression_service,
)
from services.suppression_service import SuppressionError
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

detect_tab, alerts_tab, noise_tab, rules_tab = st.tabs(["Run detection", "Alerts", "Noise control",
                                                        "How alerts are raised"])

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
INVESTIGATED_KEY = "security_investigated_alert"
TYPE_LABELS = {None: "Any type", "security": "Security", "anomaly": "Anomaly", "congestion": "Congestion",
               "performance": "Performance"}


def _rule_form(key: str, *, alert_type=None, category="", host="", host_role="source") -> None:
    """Create (admin) or request (analyst) a suppression rule. The service decides what the role may do."""
    is_admin = principal.has(Permission.MANAGE_SETTINGS)
    with st.form(key, border=False, clear_on_submit=True):
        c1, c2 = st.columns(2)
        types = [None, "security", "anomaly", "congestion", "performance"]
        rule_type = c1.selectbox("Alert type", types, index=types.index(alert_type), format_func=TYPE_LABELS.get)
        rule_category = c2.text_input("Category (exact, optional)", value=category or "", max_chars=120)
        c3, c4 = st.columns(2)
        rule_host = c3.text_input("Host IP (optional)", value=host or "", max_chars=64,
                                  help="Only alerts whose flows ALL come from (or go to) this host are suppressed.")
        role = c4.radio("Host is the", ["source", "destination"], index=["source", "destination"].index(host_role),
                        horizontal=True)
        days = st.slider("Expires after (days)", 1, suppression_service.MAX_DAYS, 7)
        reason = st.text_input("Reason (shown to everyone, audited)", max_chars=500,
                               placeholder="e.g. nightly backups from the backup server")
        label = "Create rule" if is_admin else "Request rule (an administrator approves it)"
        if st.form_submit_button(label, type="primary"):
            action = suppression_service.create_rule if is_admin else suppression_service.request_rule
            try:
                rule_id = action(principal, alert_type=rule_type, category=rule_category, host=rule_host,
                                 host_role=role, reason=reason, days=days)
            except (SuppressionError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.toast(f"Suppression rule #{rule_id} {'created' if is_admin else 'requested'}.")
                st.rerun()


def _suppress_popover(alert) -> None:
    if not principal.has(Permission.TRIAGE_ALERTS):
        return
    tops = alert.evidence.get("top_sources") or []
    only_source = tops[0]["value"] if len(tops) == 1 else ""
    with st.popover("Suppress similar alerts…", icon=":material/notifications_off:"):
        st.caption("Future alerts that match are stored but kept out of the queues until the rule expires. "
                   "This alert itself is not changed.")
        _rule_form(f"suppress_{alert.id}", alert_type=alert.alert_type, category=alert.category, host=only_source)


def _technique(alert) -> str:
    technique = mitre_service.primary(alert.category) if alert.alert_type == "security" else None
    return f"{technique.technique_id} {technique.technique}" if technique else "—"


with alerts_tab:
    f1, f2, f3, f4 = st.columns([3, 3, 2, 2])
    statuses = f1.multiselect("Status", list(alert_service.STATUSES), default=["open", "acknowledged"])
    severities = f2.multiselect("Severity", list(alert_service.SEVERITIES), default=list(alert_service.SEVERITIES),
                                 format_func=severity.plain)
    types = f3.multiselect("Type", SECURITY_TYPES, default=SECURITY_TYPES)
    shown = f4.selectbox("Show", ["exclude", "only", "include"],
                         format_func={"exclude": "Active alerts", "only": "Suppressed", "include": "Both"}.get,
                         help="Suppressed alerts are stored and visible here; suppression rules only keep them "
                              "out of the queues and counts.")
    alerts = alert_service.list_alerts(principal, statuses=statuses or None, severities=severities or None,
                                       types=types or None, suppressed=shown)
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
            {"ID": a.id, "Severity": severity.plain(a.severity), "Type": a.alert_type, "Category": a.category,
             "ATT&CK": _technique(a), "Status": a.status + (" · suppressed" if a.suppressed_by_rule else ""),
             "Flows": a.evidence.get("flows"), "Model": a.model_version or "—", "Raised": format_timestamp(a.created_at)}
            for a in alerts
        ]), hide_index=True)
        by_id = {a.id: a for a in alerts}
        # Keep the chosen alert while new ones arrive (a running replay or live capture adds alerts between reruns).
        ids = list(by_id)
        remembered = st.session_state.get(INVESTIGATED_KEY)
        alert_id = st.selectbox("Investigate alert", ids, index=ids.index(remembered) if remembered in by_id else 0,
                                format_func=lambda i: f"#{i} · {severity.plain(by_id[i].severity)} · {by_id[i].category}")
        st.session_state[INVESTIGATED_KEY] = alert_id
        alert, events = alert_service.get_alert(principal, alert_id)
        color = SEVERITY_COLORS.get(alert.severity, COLORS["muted"])
        techniques = mitre.badges(alert.category) if alert.alert_type == "security" else ""
        st.markdown(
            f"<div class='ss-card' style='border-left:4px solid {color}'><h4>#{alert.id} · {escape(alert.category)}"
            f" {severity.badge(alert.severity)}</h4><p>{escape(alert.reason)}</p>"
            + (f"<div style='margin-top:.5rem'>{techniques}</div>" if techniques else "") + "</div>",
            unsafe_allow_html=True,
        )
        if alert.suppressed_by_rule:
            s1, s2 = st.columns([4, 1])
            s1.warning(f"Suppressed by rule #{alert.suppressed_by_rule} (see Noise control). It is kept out of the "
                       "queues and counts, but nothing was deleted.", icon=":material/notifications_off:")
            if s2.button("Unsuppress", key=f"unsuppress_{alert.id}", disabled=not principal.has(Permission.TRIAGE_ALERTS),
                         width="stretch"):
                try:
                    suppression_service.unsuppress_alert(principal, alert.id)
                except (SuppressionError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
        else:
            _suppress_popover(alert)
        if st.toggle("Why was this flagged?", key=f"explain_{alert.id}",
                     help="Feature importances, deviations from benign traffic, the anomaly score and a plain summary."):
            try:
                with st.spinner("Explaining…"):
                    explanation = explainability_service.explain_alert(principal, alert.id)
            except explainability_service.ExplainError as exc:
                st.info(str(exc))
            else:
                explain.render(explanation)
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

# ---------------------------------------------------------------- noise control
with noise_tab:
    is_admin = principal.has(Permission.MANAGE_SETTINGS)
    st.markdown("Suppression rules keep **new** matching alerts out of the queues, counts, correlation and the "
                "network map. Suppressed alerts are still stored and listed under *Show → Suppressed* in Alerts. "
                "Every rule has an author, a reason and an expiry, and every change is audited. "
                + ("" if is_admin else "Analysts can request a rule; an administrator approves it."))
    rules = suppression_service.list_rules(principal)
    pending = [r for r in rules if suppression_service.effective_status(r) == "requested"]
    if is_admin and pending:
        section_label(f"Requests waiting for approval ({len(pending)})")
        for r in pending:
            with st.container(border=True):
                st.markdown(f"**#{r.id}** · {r.describe()} · until {format_timestamp(r.expires_at)} · requested by "
                            f"{r.requested_by_email or '—'}  \n*{r.reason}*")
                note = st.text_input("Note (optional)", key=f"review_note_{r.id}", max_chars=500)
                a, b, _ = st.columns([1, 1, 4])
                for column, approve, text in ((a, True, "Approve"), (b, False, "Reject")):
                    if column.button(text, key=f"review_{r.id}_{approve}", type="primary" if approve else "secondary"):
                        try:
                            suppression_service.review_request(principal, r.id, approve=approve, note=note)
                        except (SuppressionError, PermissionDenied) as exc:
                            st.error(str(exc))
                        else:
                            st.rerun()
    section_label("Rules")
    if rules:
        st.dataframe(pd.DataFrame([{
            "ID": r.id, "Status": suppression_service.effective_status(r), "Suppresses": r.describe(),
            "Reason": r.reason, "Expires": format_timestamp(r.expires_at), "Alerts hidden": r.alerts_suppressed,
            "Requested by": r.requested_by_email or "—", "Reviewed by": r.reviewed_by_email or "—",
            "Review note": r.review_note or ""} for r in rules]), hide_index=True)
        active = [r for r in rules if suppression_service.effective_status(r) == "active"]
        if active:
            c1, c2 = st.columns([3, 1])
            target = c1.selectbox("Revoke an active rule", [r.id for r in active],
                                  format_func=lambda i: f"#{i} · " + next(r.describe() for r in active if r.id == i),
                                  disabled=not is_admin)
            c2.write("")
            if c2.button("Revoke", disabled=not is_admin, help=None if is_admin else "Admin only", width="stretch"):
                try:
                    suppression_service.revoke(principal, target)
                except (SuppressionError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.rerun()
    else:
        st.caption("No suppression rules yet.")
    if principal.has(Permission.TRIAGE_ALERTS):
        section_label("New rule" if is_admin else "Request a rule")
        _rule_form("new_rule")

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
