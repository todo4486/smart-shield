"""ML Laboratory. Phase 2: data sources (telemetry import, intrusion dataset registration).
Model training workspaces arrive in Phases 3 and 4."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components import charts, smart_shield_lab
from components.guard import require_principal
from components.ui import format_timestamp, page_header, planned_notice, section_label
from services import dataset_service, telemetry_service
from services.authorization import Permission, PermissionDenied
from services.dataset_service import DatasetError, FlowImportOptions
from services.telemetry_schema import schema_markdown, template_csv
from services.telemetry_service import TelemetryImportError, TelemetryImportOptions

principal = require_principal()
can_upload = principal.has(Permission.MANAGE_DATASETS)
can_delete = principal.has(Permission.DELETE_DATA)

page_header(
    "ML Laboratory",
    "Bring in data, then train and evaluate models. Every model will be labelled with its purpose, version, "
    "training data and evaluation results.",
    eyebrow="Intelligence",
)

data_tab, shield_tab, predict_tab = st.tabs(["Data sources", "Smart Shield models", "PredictNet models"])


def _size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024 or unit == "GB":
            return f"{num_bytes:,.0f} {unit}" if unit == "B" else f"{num_bytes:,.1f} {unit}"
        num_bytes /= 1024
    return ""


def _show_telemetry_report(report: telemetry_service.TelemetryImportReport) -> None:
    st.success(
        f"Imported {report.rows_imported:,} of {report.rows_read:,} rows from **{report.filename}** "
        f"into monitoring session #{report.session_id}."
    )
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rows imported", f"{report.rows_imported:,}")
    c2.metric("Rows rejected", f"{report.rows_rejected:,}")
    c3.metric("Duplicates skipped", f"{report.duplicate_rows:,}")
    c4.metric("Interfaces", len(report.interfaces))
    for warning in report.warnings:
        st.warning(warning)
    if report.rejection_reasons:
        section_label("Rejected rows")
        st.dataframe(
            pd.DataFrame([
                {"Reason": reason, "Rows": count,
                 "Example line numbers": ", ".join(str(n) for n in report.rejection_examples.get(reason, []))}
                for reason, count in sorted(report.rejection_reasons.items(), key=lambda kv: -kv[1])
            ]),
            hide_index=True,
        )
    section_label("Sampling")
    st.dataframe(
        pd.DataFrame([
            {"Interface": s.interface, "Samples": s.samples, "From": format_timestamp(s.start),
             "To": format_timestamp(s.end),
             "Median interval": f"{s.median_interval_seconds:,.0f} s" if s.median_interval_seconds else "—",
             "Gaps (> 2× interval)": s.gaps}
            for s in report.sampling
        ]),
        hide_index=True,
    )
    derived = {k: v for k, v in report.derived_counts.items() if v}
    if derived:
        st.caption("Derived values (labelled as derived, not measured): "
                   + ", ".join(f"{k}: {v:,} rows" for k, v in derived.items()))
    st.page_link("views/live_monitoring.py", label="Open this session in Live Monitoring", icon=":material/monitoring:")


def _show_dataset_report(report: dataset_service.DatasetReport) -> None:
    st.success(f"Registered **{report.name}** as dataset #{report.dataset_id} ({report.row_count:,} rows).")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rows", f"{report.row_count:,}")
    c2.metric("Columns", len(report.columns))
    c3.metric("Label values", len(report.label_distribution))
    c4.metric("Flows imported", f"{report.flows_imported:,}")
    for warning in report.warnings:
        st.warning(warning)
    left, right = st.columns(2)
    with left:
        labels = list(report.label_distribution)[:15]
        charts.bar(labels, [report.label_distribution[l] for l in labels], title="Label distribution (ground truth)",
                   horizontal=True, height=max(260, 30 * len(labels) + 90))
    with right:
        section_label("Data quality")
        st.markdown(
            f"- **Identifier / leakage columns** (dropped before training): "
            f"{', '.join(report.identifier_columns) or 'none found'}\n"
            f"- **Columns with infinite values:** {len(report.infinite_values)} "
            f"({sum(report.infinite_values.values()):,} cells)\n"
            f"- **Columns with missing values:** {len(report.missing_values)} "
            f"({sum(report.missing_values.values()):,} cells)\n"
            f"- **Timestamps present:** {'yes' if report.has_timestamps else 'no'}"
        )
        if report.renamed_columns:
            with st.expander(f"{len(report.renamed_columns)} column names were normalized"):
                st.dataframe(pd.DataFrame(
                    [{"Original": o, "Normalized": n} for o, n in report.renamed_columns.items()]
                ), hide_index=True)
        if report.flows_skipped:
            st.caption("Flows skipped: " + ", ".join(f"{k}: {v:,}" for k, v in report.flows_skipped.items()))
    if report.flow_session_id:
        st.page_link("views/live_monitoring.py", label="View imported flows in Live Monitoring",
                     icon=":material/monitoring:")


with data_tab:
    telemetry_tab, intrusion_tab, registry_tab = st.tabs(
        ["Import telemetry", "Register intrusion dataset", "Registered data"]
    )

    # ------------------------------------------------------------ telemetry
    with telemetry_tab:
        st.markdown(
            "Upload historical network performance measurements (CSV). They become a monitoring session that "
            "the dashboards and PredictNet use. Values are stored as **measured**; anything the importer "
            "calculates is stored as **derived**."
        )
        with st.expander("CSV schema and template", icon=":material/table:"):
            st.markdown(schema_markdown())
            st.markdown("Timestamps must be ISO-8601, e.g. `2026-10-01T14:05:00Z` or `2026-10-01T19:35:00+05:30`.")
            st.download_button("Download header-only template", template_csv(), "telemetry_template.csv",
                               mime="text/csv", icon=":material/download:")
        if not can_upload:
            st.info("Your role cannot import data.")
        else:
            upload = st.file_uploader(
                "Telemetry CSV", type=["csv"], key="telemetry_upload",
                help=f"Up to {telemetry_service.MAX_TELEMETRY_BYTES // (1024 * 1024)} MB and "
                     f"{telemetry_service.MAX_TELEMETRY_ROWS:,} rows per file.",
            )
            with st.form("telemetry_form", border=True):
                c1, c2 = st.columns(2)
                default_source = upload.name.rsplit(".", 1)[0] if upload else ""
                source_name = c1.text_input("Source name", value=default_source, max_chars=100,
                                            help="Where these measurements came from, e.g. 'campus-core-router'.")
                default_interface = c2.text_input("Interface for rows without one", max_chars=100,
                                                  placeholder="e.g. eth0 (optional)")
                c3, c4, c5 = st.columns(3)
                naive_utc = c3.checkbox("Timestamps without a timezone are UTC", value=False,
                                        help="Leave off to reject timestamps that do not say their timezone.")
                util_unit = c4.radio("utilization_ratio is in", ["ratio", "percent"], horizontal=True)
                loss_unit = c5.radio("packet_loss_ratio is in", ["ratio", "percent"], horizontal=True)
                known_capacity = st.checkbox("I know the link capacity for rows that don't include it")
                capacity_mbps = st.number_input("Configured link capacity (Mbit/s)", min_value=0.0, value=0.0,
                                                step=10.0, help="Stored as a configured value, never as a measurement.")
                submitted = st.form_submit_button("Import telemetry", type="primary", icon=":material/upload:")
            if submitted:
                if upload is None:
                    st.error("Choose a CSV file first.")
                elif known_capacity and capacity_mbps <= 0:
                    st.error("Enter a capacity greater than 0, or untick the capacity box.")
                else:
                    options = TelemetryImportOptions(
                        source_name=source_name, default_interface=default_interface or None,
                        naive_timestamps_are_utc=naive_utc, utilization_unit=util_unit, packet_loss_unit=loss_unit,
                        capacity_override_bps=capacity_mbps * 1_000_000 if known_capacity else None,
                    )
                    try:
                        with st.spinner("Validating and importing…"):
                            report = telemetry_service.import_telemetry_csv(
                                principal, upload.getvalue(), upload.name, options
                            )
                    except (TelemetryImportError, PermissionDenied) as exc:
                        st.error(str(exc))
                    else:
                        _show_telemetry_report(report)

    # ------------------------------------------------------------ intrusion
    with intrusion_tab:
        st.markdown(
            "Register a labelled flow dataset such as a **CIC-IDS2017** CSV. The file is stored unchanged and "
            "profiled; Smart Shield trains on it in Phase 3. Labels are ground truth from the dataset, not detections."
        )
        if not can_upload:
            st.info("Your role cannot register datasets.")
        else:
            dataset_upload = st.file_uploader(
                "Labelled flow CSV", type=["csv"], key="dataset_upload",
                help=f"Up to {dataset_service.MAX_DATASET_BYTES // (1024 * 1024)} MB per file. CIC-IDS2017 ships "
                     "one CSV per capture day; register each file separately.",
            )
            with st.form("dataset_form", border=True):
                default_name = dataset_upload.name.rsplit(".", 1)[0] if dataset_upload else ""
                name = st.text_input("Dataset name", value=default_name, max_chars=200)
                import_flows = st.checkbox(
                    "Also add timestamped flows to shared telemetry",
                    help="Copies each row's 5-tuple, packets, bytes and duration into network flows so they "
                         "appear in Live Monitoring. Requires a Timestamp column.",
                )
                c1, c2, c3 = st.columns(3)
                dayfirst = c1.checkbox("Dates are day-first (3/7/2017 = 3 July)", value=True)
                offset = c2.number_input("UTC offset of file timestamps (hours)", min_value=-14.0, max_value=14.0,
                                         value=0.0, step=0.5,
                                         help="CIC-IDS2017 was captured in New Brunswick, Canada (UTC-3 in July).")
                max_rows = c3.number_input("Max flows to import", min_value=1,
                                           max_value=dataset_service.MAX_FLOW_IMPORT_ROWS,
                                           value=50_000, step=1000)
                registered = st.form_submit_button("Register dataset", type="primary", icon=":material/upload:")
            if registered:
                if dataset_upload is None:
                    st.error("Choose a CSV file first.")
                else:
                    options = FlowImportOptions(enabled=import_flows, dayfirst=dayfirst,
                                                utc_offset_hours=float(offset), max_rows=int(max_rows))
                    try:
                        with st.spinner("Profiling dataset…"):
                            report = dataset_service.register_intrusion_dataset(
                                principal, dataset_upload.getvalue(), dataset_upload.name, name, options
                            )
                    except (DatasetError, PermissionDenied) as exc:
                        st.error(str(exc))
                    else:
                        _show_dataset_report(report)

    # -------------------------------------------------------------- registry
    with registry_tab:
        datasets = dataset_service.list_datasets(principal)
        if not datasets:
            st.info("No data has been imported or registered yet.")
        else:
            st.dataframe(
                pd.DataFrame([
                    {"ID": d.id, "Name": d.name,
                     "Type": "Telemetry" if d.kind == "telemetry" else "Intrusion flows",
                     "File": d.original_filename, "Size": _size(d.size_bytes), "Rows": d.row_count,
                     "Labels": ", ".join(f"{k} ({v:,})" for k, v in list(d.label_distribution.items())[:4]) or "—",
                     "Uploaded": format_timestamp(d.uploaded_at), "By": d.uploaded_by_email or "—"}
                    for d in datasets
                ]),
                hide_index=True,
            )
            if can_delete:
                with st.form("delete_dataset_form", border=True):
                    st.markdown("**Remove a dataset record**")
                    by_id = {d.id: d for d in datasets}
                    chosen = st.selectbox("Dataset", list(by_id), format_func=lambda i: f"#{i} · {by_id[i].name}")
                    st.caption("Deletes the record and its stored file. Telemetry already imported from it stays in "
                               "its monitoring session (delete the session in Live Monitoring to remove it).")
                    confirm = st.checkbox("I understand this cannot be undone")
                    if st.form_submit_button("Delete dataset"):
                        if not confirm:
                            st.warning("Tick the confirmation box first.")
                        else:
                            try:
                                dataset_service.delete_dataset(principal, chosen)
                            except (DatasetError, PermissionDenied) as exc:
                                st.error(str(exc))
                            else:
                                st.toast(f"Dataset #{chosen} deleted.")
                                st.rerun()

with shield_tab:
    smart_shield_lab.render(principal)

with predict_tab:
    planned_notice(
        "Phase 4", "PredictNet model workspace",
        "Forecast utilization from imported telemetry with chronological splits and baseline comparison.",
        ["Time-series inspection and minimum-history checks", "Last-value and moving-average baselines",
         "Random Forest / HistGradientBoosting forecasters", "MAE, RMSE, R² and per-horizon error"],
    )
