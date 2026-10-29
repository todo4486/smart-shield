"""Reports: period summaries from persisted data, with CSV and printable HTML exports."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

import pandas as pd
import streamlit as st

from components import charts
from components.guard import require_page_permission, require_principal
from components.ui import format_timestamp, kpi_tile, page_header, section_label
from services import incident_correlation_service, incident_report_service, reporting_service
from services.authorization import Permission, PermissionDenied

principal = require_principal()
require_page_permission(principal, Permission.VIEW_REPORTS)

page_header("Reports", "Reports built only from stored data: a summary of any period, a one-click report for one "
            "incident, and a weekly summary. Export them as CSV or as printable HTML (Print → Save as PDF).",
            eyebrow="Workspace")


def _period_tab() -> None:
    with st.form("report_form", border=True):
        c1, c2, c3 = st.columns([1, 1, 1])
        today = date.today()
        start_day = c1.date_input("From (UTC)", value=today - timedelta(days=30))
        end_day = c2.date_input("To (UTC, inclusive)", value=today)
        c3.write("")
        c3.write("")
        generate = c3.form_submit_button("Generate report", type="primary", icon=":material/description:")
    if generate:
        start = datetime.combine(start_day, time.min, tzinfo=timezone.utc)
        end = datetime.combine(end_day, time.min, tzinfo=timezone.utc) + timedelta(days=1)
        try:
            st.session_state["report"] = reporting_service.build_report(principal, start, end)
        except (ValueError, PermissionDenied) as exc:
            st.error(str(exc))

    report = st.session_state.get("report")
    if report is None:
        st.info("Choose a period and generate a report. Tip: imported sample data is dated September 2026 (telemetry) and "
                "July 2017 (intrusion samples). Alerts are dated when they were raised.")
        return

    for note in report.notes:
        st.caption(f"ℹ️ {note}")
    summary = report.summary
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_tile("Alerts raised", f"{sum(summary['alerts_by_type'].values()):,}", "derived",
                 ", ".join(f"{k}: {v}" for k, v in summary["alerts_by_type"].items()) or "none")
    with c2:
        kpi_tile("Incidents", f"{sum(summary['incidents_by_classification'].values()):,}", "derived",
                 ", ".join(f"{k}: {v}" for k, v in summary["incidents_by_classification"].items()) or "none")
    with c3:
        kpi_tile("Forecasts stored", f"{summary['forecasts']:,}", "predicted" if summary["forecasts"] else "unavailable",
                 ", ".join(f"{k}: {v}" for k, v in summary["forecasts_by_risk"].items()) or "none")
    with c4:
        kpi_tile("Bandwidth recommendations", f"{summary['recommendations']:,}", "derived",
                 f"{summary['enforcement_actions']} enforcement action(s)")

    severity = summary["alerts_by_severity"]
    if severity:
        order = [s for s in ("critical", "high", "medium", "low") if s in severity]
        charts.bar(order, [severity[s] for s in order], title="Alerts by severity", height=260)

    st.download_button(
        "Download printable HTML report", reporting_service.to_html(report),
        file_name=f"smart_shield_report_{report.start[:10]}_{report.end[:10]}.html", mime="text/html",
        icon=":material/download:", help="Self-contained page; use your browser's Print → Save as PDF.",
    )
    for key, title in reporting_service.SECTION_TITLES.items():
        rows = report.sections.get(key, [])
        with st.expander(f"{title} · {len(rows):,}", expanded=key in ("traffic_by_interface", "models") and bool(rows)):
            if not rows:
                st.caption("No records in this period.")
                continue
            st.dataframe(pd.DataFrame(rows), hide_index=True)
            st.download_button(f"Download {title.split(' (')[0].lower()} as CSV", reporting_service.to_csv(rows),
                               file_name=f"{key}_{report.start[:10]}_{report.end[:10]}.csv", mime="text/csv",
                               key=f"csv_{key}")
    section_label("About this report")
    st.caption(f"Generated {report.generated_at[:19].replace('T', ' ')} UTC by {report.generated_by}. Generating a "
               "report is recorded in the audit log.")


def _incident_tab() -> None:
    incidents = incident_correlation_service.list_incidents(principal)
    if not incidents:
        st.info("No incidents yet. Correlate alerts in the Incident Center first.")
        return
    by_id = {i["id"]: i for i in incidents}
    incident_id = st.selectbox("Incident", list(by_id), format_func=lambda i: f"#{i} · {by_id[i]['title']} · "
                               f"{by_id[i]['status']}" + (" · DATASET REPLAY" if by_id[i].get("is_replay") else ""))
    st.caption("Summary, timeline, affected hosts, MITRE ATT&CK mapping, why the alerts were raised, actions taken "
               "(from the audit log) and analyst notes. Generating it is audited.")
    if st.button("Build incident report", type="primary", icon=":material/summarize:"):
        try:
            report = incident_report_service.build_incident_report(principal, incident_id)
        except (PermissionDenied, incident_correlation_service.IncidentError) as exc:
            st.error(str(exc))
            return
        st.session_state["incident_report"] = (incident_id, incident_report_service.incident_report_html(report),
                                               report)
    built = st.session_state.get("incident_report")
    if built and built[0] == incident_id:
        _, html, report = built
        c1, c2, c3 = st.columns(3)
        with c1:
            kpi_tile("Member alerts", f"{len(report.incident.alerts):,}", "derived", report.severity or "no severity")
        with c2:
            kpi_tile("Affected hosts", f"{len(report.hosts):,}" if report.hosts else None,
                     "measured" if report.hosts else "unavailable", ", ".join(report.hosts[:3]))
        with c3:
            kpi_tile("Actions recorded", f"{len(report.actions):,}", "derived", f"{len(report.notes)} note(s)")
        st.download_button("Download incident report (HTML)", html, file_name=f"incident_{incident_id}_report.html",
                           mime="text/html", icon=":material/download:",
                           help="Self-contained page; use your browser's Print → Save as PDF.")
        with st.expander("Preview", expanded=True):
            st.html(html.split("<body>", 1)[1].rsplit("</body>", 1)[0])


def _weekly_tab() -> None:
    c1, c2 = st.columns([1, 2])
    end_day = c1.date_input("Week ending (UTC, inclusive)", value=date.today(), key="weekly_end")
    c2.caption("Covers the 7 days up to and including this date: top incidents, riskiest hosts, congestion events "
               "and how accurate the stored forecasts were. DATASET REPLAY data is left out.")
    if st.button("Build weekly summary", type="primary", icon=":material/date_range:"):
        end = datetime.combine(end_day, time.min, tzinfo=timezone.utc) + timedelta(days=1)
        try:
            st.session_state["weekly_summary"] = incident_report_service.build_weekly_summary(principal, end)
        except PermissionDenied as exc:
            st.error(str(exc))
    summary = st.session_state.get("weekly_summary")
    if summary is None:
        return
    for note in summary.notes:
        st.caption(f"ℹ️ {note}")
    c1, c2, c3 = st.columns(3)
    with c1:
        kpi_tile("Alerts", f"{sum(summary.alerts_by_type.values()):,}", "derived",
                 ", ".join(f"{k}: {v}" for k, v in summary.alerts_by_type.items()) or "none")
    with c2:
        kpi_tile("Incidents (top 5 shown)", f"{len(summary.top_incidents):,}", "derived",
                 f"{format_timestamp(summary.start)[:10]} → {format_timestamp(summary.end)[:10]}")
    with c3:
        matched = sum(a["matched"] for a in summary.accuracy)
        kpi_tile("Forecasts checked", f"{matched:,} of {sum(a['forecasts'] for a in summary.accuracy):,}",
                 "derived" if matched else "unavailable", "matched to a later measurement")
    html = incident_report_service.weekly_summary_html(summary)
    st.download_button("Download weekly summary (HTML)", html,
                       file_name=f"weekly_summary_{summary.end[:10]}.html", mime="text/html",
                       icon=":material/download:")
    with st.expander("Preview", expanded=True):
        st.html(html.split("<body>", 1)[1].rsplit("</body>", 1)[0])


period_tab, incident_tab, weekly_tab = st.tabs(["Period report", "Incident report", "Weekly summary"])
with period_tab:
    _period_tab()
with incident_tab:
    _incident_tab()
with weekly_tab:
    _weekly_tab()
