"""Reports: period summaries from persisted data, with CSV and printable HTML exports."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

import pandas as pd
import streamlit as st

from components import charts
from components.guard import require_page_permission, require_principal
from components.ui import kpi_tile, page_header, section_label
from services import reporting_service
from services.authorization import Permission, PermissionDenied

principal = require_principal()
require_page_permission(principal, Permission.VIEW_REPORTS)

page_header("Reports", "Summaries of a chosen period built only from stored data: alerts, incidents, traffic, "
            "forecasts, bandwidth decisions and model performance. Export them as CSV or a printable HTML report.",
            eyebrow="Workspace")

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
    st.stop()

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
