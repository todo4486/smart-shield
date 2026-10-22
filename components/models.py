"""Model registry table and activation controls, shared by the ML Laboratory tabs."""
from __future__ import annotations

from typing import List

import pandas as pd
import streamlit as st

from components.ui import format_timestamp
from services import model_registry_service
from services.authorization import Permission, PermissionDenied, Principal


def registry_section(principal: Principal, families: List[str], metric_columns, key: str) -> None:
    models = [m for family in families for m in model_registry_service.list_models(principal, family)]
    if not models:
        st.info("No models have been trained yet.")
        return
    rows = []
    for m in models:
        row = {"ID": m.id, "Active": "● active" if m.is_active else "", "Purpose": model_registry_service.FAMILY_LABELS[m.family],
               "Model": m.name, "Version": m.version, "Trained": format_timestamp(m.trained_at),
               "By": m.created_by_email or "—"}
        row.update(metric_columns(m))
        rows.append(row)
    st.dataframe(pd.DataFrame(rows), hide_index=True)
    st.caption("Each version stores its training data, feature schema, parameters and evaluation metrics. "
               "Artifacts are loaded only when their SHA-256 matches the registry.")
    if principal.has(Permission.ACTIVATE_MODELS):
        by_id = {m.id: m for m in models}
        with st.form(f"activate_{key}", border=True):
            chosen = st.selectbox("Activate a model", list(by_id),
                                  format_func=lambda i: f"#{i} · {by_id[i].name} · {by_id[i].version}"
                                                        + (" (active)" if by_id[i].is_active else ""))
            st.caption("Activation verifies the artifact hash and replaces the current active model of the same "
                       "purpose. Only one model per purpose is active.")
            if st.form_submit_button("Activate", type="primary"):
                try:
                    record = model_registry_service.activate(principal, chosen)
                except (model_registry_service.ModelRegistryError, PermissionDenied) as exc:
                    st.error(str(exc))
                else:
                    st.toast(f"{record.name} {record.version} is now active.")
                    st.rerun()
    else:
        st.caption("An administrator activates models for live use.")
