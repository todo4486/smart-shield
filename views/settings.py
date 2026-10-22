"""Settings: PredictNet thresholds, horizons and alert behaviour. Admins edit; everyone can read."""
from __future__ import annotations

import streamlit as st

from components.guard import require_principal
from components.ui import page_header, planned_notice, provenance_chip
from services import settings_service
from services.authorization import Permission, PermissionDenied
from services.settings_service import PredictNetSettings, SettingsError

principal = require_principal()
can_edit = principal.has(Permission.MANAGE_SETTINGS)

page_header("Settings", "Configuration used by PredictNet. These are starting points for your network, not universal "
            "standards. Every change is validated and recorded in the audit log.", eyebrow="Workspace")

current = settings_service.get_predictnet_settings()
source = settings_service.settings_source()
st.markdown(f"PredictNet settings {provenance_chip('configured')} "
            + ("· using built-in defaults" if source == "default" else "· saved by an administrator"),
            unsafe_allow_html=True)

with st.form("predictnet_settings", border=True):
    st.markdown("**Congestion thresholds** (utilization)")
    c1, c2, c3 = st.columns(3)
    elevated = c1.number_input("Elevated from (%)", 1.0, 99.0, current.elevated_threshold * 100, step=1.0, disabled=not can_edit)
    high = c2.number_input("High from (%)", 1.0, 99.5, current.high_threshold * 100, step=1.0, disabled=not can_edit)
    critical = c3.number_input("Critical from (%)", 1.0, 100.0, current.critical_threshold * 100, step=1.0, disabled=not can_edit)
    st.markdown("**Forecasting**")
    c1, c2 = st.columns(2)
    horizons = c1.multiselect("Default forecast horizons (minutes)", [1, 2, 5, 10, 15, 30, 60, 120, 240],
                              default=[m for m in current.horizons_minutes if m in (1, 2, 5, 10, 15, 30, 60, 120, 240)],
                              disabled=not can_edit, help="Horizons must be multiples of the sampling interval at training time.")
    min_samples = c2.number_input("Minimum training samples", 50, 100_000, current.min_training_samples, step=50,
                                  disabled=not can_edit, help="Training is refused below this many complete samples.")
    st.markdown("**Congestion alerts**")
    c1, c2, c3 = st.columns(3)
    cooldown = c1.number_input("Cooldown between identical alerts (min)", 1, 1440, current.alert_cooldown_minutes,
                               disabled=not can_edit)
    rise = c2.number_input("Rapid rise (% utilization per hour)", 1.0, 100.0, current.rapid_rise_per_hour * 100,
                           step=1.0, disabled=not can_edit)
    sustained = c3.number_input("Sustained high: consecutive samples", 1, 100, current.sustained_high_samples,
                                disabled=not can_edit)
    saved = st.form_submit_button("Save settings", type="primary", disabled=not can_edit)
if not can_edit:
    st.caption("Only administrators can change settings.")
if saved:
    try:
        settings_service.update_predictnet_settings(principal, PredictNetSettings(
            elevated_threshold=elevated / 100, high_threshold=high / 100, critical_threshold=critical / 100,
            horizons_minutes=tuple(horizons), alert_cooldown_minutes=int(cooldown), rapid_rise_per_hour=rise / 100,
            sustained_high_samples=int(sustained), min_training_samples=int(min_samples),
        ))
    except (SettingsError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.toast("Settings saved.")
        st.rerun()

st.write("")
st.caption("Link capacity and traffic classes are configured per policy under **Bandwidth Management**. The "
           "traffic-shaping backend is configured only through `.env` on the server and is off by default.")
planned_notice("Phase 8", "More settings", "Further configuration arrives with the features that use it.",
               ["Data retention", "Live-monitoring interface allow-list (Phase 7)"])
