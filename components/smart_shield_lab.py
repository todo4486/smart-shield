"""ML Laboratory → Smart Shield workspace: train, evaluate and register intrusion models."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from components import charts
from components.models import registry_section
from components.ui import section_label
from services import dataset_service, intrusion_training_service
from services.authorization import Permission, PermissionDenied, Principal
from services.intrusion_features import FEATURE_SETS
from services.intrusion_training_service import IntrusionTrainingOptions, TrainingError


def _pct(value) -> str:
    return "—" if value is None else f"{value:.1%}"


def show_training_report(report: intrusion_training_service.IntrusionTrainingReport) -> None:
    meta = report.metadata
    st.success(f"Trained version **{report.version}** in {meta.get('training_seconds', 0):,.0f} s "
               f"on {meta['rows_used']:,} rows ({meta['feature_count']} features, {meta['split'].replace('_', ' ')} split)."
               + (" Both models are now active." if report.activated else ""))
    for warning in report.warnings:
        st.warning(warning)

    test = report.classifier_metrics["test"]
    section_label("Random Forest intrusion classifier · test set")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", _pct(test["precision"]), help="Of the flows flagged as attacks, the share that really were.")
    c2.metric("Recall", _pct(test["recall"]), help="Of the real attacks, the share that were flagged.")
    c3.metric("F1 score", _pct(test["f1"]), help="Balance of precision and recall.")
    c4.metric("False-positive rate", _pct(test["false_positive_rate"]),
              help="Share of benign flows wrongly flagged. Lower is better.")
    left, right = st.columns(2)
    with left:
        cm = test["confusion_matrix"]
        charts.confusion_heatmap([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]], ["Benign", "Attack"],
                                 title="Confusion matrix (test)", height=320)
    with right:
        per_type = report.classifier_metrics["per_type_test"]
        rows = [{"Ground-truth type": name, "Test rows": v["rows"],
                 "Flagged as attack": _pct(v["flagged_share"])} for name, v in per_type.items()]
        st.dataframe(pd.DataFrame(rows), hide_index=True)
        st.caption("For BENIGN, 'flagged' is the false-positive rate. For attack types, it is the detection rate.")
    importance = report.classifier_metrics["feature_importance"][:12]
    charts.bar([f["feature"] for f in importance], [f["importance"] for f in importance], horizontal=True,
               title="Most influential features", text_format=".3f", height=max(280, 28 * len(importance) + 90))

    if report.multiclass_metrics:
        mc = report.multiclass_metrics
        section_label(f"Attack-type classifier · test set · macro F1 {mc['macro_f1']:.1%}")
        left, right = st.columns(2)
        with left:
            st.dataframe(pd.DataFrame([
                {"Type": c, "Precision": _pct(v["precision"]), "Recall": _pct(v["recall"]), "F1": _pct(v["f1"]),
                 "Support": v["support"]} for c, v in mc["per_class"].items()
            ]), hide_index=True)
        with right:
            charts.confusion_heatmap(mc["confusion_matrix"], mc["classes"], title="Attack-type confusion matrix",
                                     height=max(320, 40 * len(mc["classes"]) + 120))

    anomaly = report.anomaly_metrics
    section_label("Isolation Forest anomaly detector · test set")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Precision", _pct(anomaly["test"]["precision"]))
    c2.metric("Recall", _pct(anomaly["test"]["recall"]))
    c3.metric("F1 score", _pct(anomaly["test"]["f1"]))
    c4.metric("False-positive rate", _pct(anomaly["test"]["false_positive_rate"]),
              help=f"Target set on benign validation data: {anomaly['target_false_positive_rate']:.1%}.")
    st.caption(anomaly["threshold_note"] + " The detector never saw attack labels; it only learned what benign "
               "traffic looks like.")
    with st.expander("Training details: label map, dropped columns, split sizes"):
        st.markdown("**Label map** (raw dataset label → benign/attack and type)")
        st.dataframe(pd.DataFrame([{"Raw label": k, "Binary": "attack" if v["binary"] else "benign", "Type": v["type"]}
                                   for k, v in meta["label_map"].items()]), hide_index=True)
        st.markdown("**Dropped columns**")
        st.dataframe(pd.DataFrame([{"Column": k, "Reason": v} for k, v in meta["dropped_columns"].items()]),
                     hide_index=True)
        st.markdown(f"**Split sizes:** {meta['split_sizes']}")
        if meta.get("split_periods"):
            st.markdown(f"**Periods:** {meta['split_periods']}")
        st.caption(report.classifier_metrics["score_note"])


def render(principal: Principal) -> None:
    st.markdown(
        "Train the **Random Forest intrusion classifier** and the **Isolation Forest anomaly detector** on registered "
        "labelled datasets. Data is split into training, validation and test sets before anything is fitted, so the "
        "test scores below come from flows the models never saw."
    )
    datasets = [d for d in dataset_service.list_datasets(principal, "intrusion_flows")]
    train_tab, registry_tab = st.tabs(["Train", "Model registry"])
    with train_tab:
        if not principal.has(Permission.TRAIN_MODELS):
            st.info("Your role cannot train models.")
        elif not datasets:
            st.info("Register a labelled intrusion dataset under **Data sources** first.")
        else:
            by_id = {d.id: d for d in datasets}
            with st.form("intrusion_train_form", border=True):
                chosen = st.multiselect(
                    "Datasets", list(by_id), default=[datasets[0].id],
                    format_func=lambda i: f"#{i} · {by_id[i].name} ({by_id[i].row_count:,} rows)",
                    help="Selecting several capture days combines them (only columns present in all are used).",
                )
                c1, c2 = st.columns(2)
                feature_set = c1.radio("Feature set", list(FEATURE_SETS), format_func=lambda k: k.replace("_", " "),
                                       captions=list(FEATURE_SETS.values()))
                split = c2.radio("Split", ["auto", "time", "stratified"],
                                 captions=["Chronological when timestamps exist, otherwise stratified",
                                           "Chronological only (requires timestamps)",
                                           "Stratified random (optimistic if flows from one capture are correlated)"])
                c3, c4, c5 = st.columns(3)
                max_rows = c3.number_input("Max training rows", 1_000, intrusion_training_service.MAX_TRAINING_ROWS,
                                           intrusion_training_service.DEFAULT_TRAINING_ROWS, step=10_000)
                trees = c4.number_input("Trees per forest", 10, 500, 100, step=10)
                target_fpr = c5.number_input("Anomaly target false-positive rate (%)", 0.1, 20.0, 1.0, step=0.5)
                multiclass = st.checkbox("Also train the attack-type classifier", value=True)
                activate = False
                if principal.has(Permission.ACTIVATE_MODELS):
                    activate = st.checkbox("Activate both models if training succeeds")
                submitted = st.form_submit_button("Train models", type="primary", icon=":material/model_training:")
            if submitted:
                options = IntrusionTrainingOptions(
                    dataset_ids=tuple(chosen), feature_set=feature_set, split_strategy=split, max_rows=int(max_rows),
                    train_multiclass=multiclass, n_estimators=int(trees), anomaly_target_fpr=target_fpr / 100,
                    activate=activate,
                )
                bar = st.progress(0.0, text="Starting")
                try:
                    report = intrusion_training_service.train_intrusion_models(
                        principal, options, progress=lambda message, fraction: bar.progress(fraction, text=message)
                    )
                except (TrainingError, PermissionDenied) as exc:
                    bar.empty()
                    st.error(str(exc))
                else:
                    bar.empty()
                    show_training_report(report)
    with registry_tab:
        def metric_columns(m):
            test = m.metrics.get("test", {})
            return {"Features": m.training_metadata.get("feature_set", "—"),
                    "Test F1": _pct(test.get("f1")), "Test FPR": _pct(test.get("false_positive_rate")),
                    "Training rows": f"{m.training_metadata.get('split_sizes', {}).get('train', 0):,}"}

        registry_section(principal, ["intrusion_classifier", "anomaly_detector"], metric_columns, key="shield")
