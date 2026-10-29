"""Settings: PredictNet thresholds, horizons and alert behaviour. Admins edit; everyone can read."""
from __future__ import annotations

import streamlit as st

from components.guard import require_principal
from components.ui import page_header, planned_notice, provenance_chip, section_label
from services import interface_counters, preferences_service, settings_service
from services.authorization import Permission, PermissionDenied
from services.settings_service import PredictNetSettings, SettingsError

principal = require_principal()
can_edit = principal.has(Permission.MANAGE_SETTINGS)

page_header("Settings", "Configuration used by PredictNet. These are starting points for your network, not universal "
            "standards. Every change is validated and recorded in the audit log.", eyebrow="Workspace")

section_label("Your display")
with st.container(border=True):
    left, right = st.columns([3, 2])
    with left:
        reduce = st.toggle(
            "Reduce motion", value=preferences_service.get_preferences(principal).reduce_motion,
            help="Turns off transitions, pulsing markers and moving particles on the network map. Saved for your account.")
        if reduce != st.session_state.get("reduce_motion", False):
            preferences_service.set_reduce_motion(principal, reduce)
            st.rerun()
    with right:
        st.caption("**Light or dark theme:** open the app menu (⋮, top right) → **Settings** → **Choose app theme**. "
                   "Your browser remembers the choice.")

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
st.subheader("Monitoring")
monitoring = settings_service.get_monitoring_settings()
detected = [i["name"] for i in interface_counters.list_interfaces()]
with st.form("monitoring_settings", border=True):
    allowed = st.multiselect(
        "Interfaces authorised for live monitoring", sorted(set(detected) | set(monitoring.allowed_interfaces)),
        default=list(monitoring.allowed_interfaces), disabled=not can_edit,
        help="Nothing is authorised by default. Only authorise networks you are permitted to observe.")
    c1, c2, c3 = st.columns(3)
    latency_target = c1.text_input("Latency target (host:port, optional)", value=monitoring.latency_target,
                                   disabled=not can_edit,
                                   help="If set, latency is measured as TCP connect time to this one target each "
                                        "sample. If empty, latency is shown as unavailable.")
    interval = c2.number_input("Default counter interval (s)", 1, 60, monitoring.default_interval_seconds,
                               disabled=not can_edit)
    max_flows = c3.number_input("Max flows stored per session", 1_000, 1_000_000, monitoring.max_flows_per_session,
                                step=1_000, disabled=not can_edit)
    saved_monitoring = st.form_submit_button("Save monitoring settings", type="primary", disabled=not can_edit)
if saved_monitoring:
    try:
        settings_service.update_monitoring_settings(principal, settings_service.MonitoringSettings(
            tuple(allowed), latency_target, int(interval), int(max_flows)))
    except (SettingsError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.toast("Monitoring settings saved.")
        st.rerun()

st.subheader("Model health")
drift_settings = settings_service.get_drift_settings()
with st.form("drift_settings", border=True):
    c1, c2 = st.columns(2)
    psi_threshold = c1.number_input("Warn when a feature's PSI reaches", 0.05, 2.0, drift_settings.psi_threshold,
                                    step=0.05, disabled=not can_edit,
                                    help="Population Stability Index. A common rule of thumb: under 0.10 stable, "
                                         "0.10–0.25 moderate shift, over 0.25 significant shift.")
    top_features = c2.number_input("Features to check (most important first)", 3, 50, drift_settings.top_features,
                                   disabled=not can_edit)
    saved_drift = st.form_submit_button("Save model health settings", type="primary", disabled=not can_edit)
if saved_drift:
    try:
        settings_service.update_drift_settings(principal, settings_service.DriftSettings(float(psi_threshold),
                                                                                         int(top_features)))
    except (SettingsError, PermissionDenied) as exc:
        st.error(str(exc))
    else:
        st.toast("Model health settings saved.")
        st.rerun()

st.write("")
st.caption("Link capacity and traffic classes are configured per policy under **Bandwidth Management**. The "
           "traffic-shaping backend is configured only through `.env` on the server and is off by default.")
planned_notice("Phase 8", "More settings", "Further configuration arrives with the features that use it.",
               ["Data retention"])
