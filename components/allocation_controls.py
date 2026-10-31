"""What an administrator can change about allocation, and an honest account of what each change reaches."""
from __future__ import annotations

from dataclasses import replace

import streamlit as st

from components.ui import section_label
from services import live_network_service, mitigation_service, settings_service
from services.authorization import Permission, PermissionDenied, Principal
from services.settings_service import SettingsError


def _services() -> list:
    return sorted(set(live_network_service.SERVICE_PORTS.values()))


def render(principal: Principal) -> None:
    settings = settings_service.get_mitigation_settings()
    can_change = principal.has(Permission.MANAGE_SETTINGS)
    enforcing = mitigation_service.enforcement_status(principal).enforcing
    st.markdown("**What these reach.** On the simulated link, the shares below decide what each sender gets while "
                "*Prioritize critical traffic* is active. On a real link they decide the engine's plan and the limits it "
                "proposes; what is enforced there is each approved limit, block or isolation, plus any class policy in "
                "*Enforcement*. A class share on a real link is not itself enforced.")
    st.caption("Real enforcement is on." if enforcing else "Real enforcement is off: this server is in dry run.")
    if not can_change:
        st.caption("Only an administrator can change these.")
    with st.form("allocation_controls"):
        adaptive = st.toggle("Adaptive allocation", settings.adaptive_enabled, disabled=not can_change,
                             help="Off: no allocation is calculated and prioritizing stops. Threat assessment follows the mitigation policy, not this.")
        section_label("Critical applications")
        c1, c2, c3 = st.columns(3)
        critical_min = c1.slider("Guaranteed minimum (%)", 0, 100, round(settings.critical_min_share * 100), disabled=not can_change, key="critical_min")
        critical_max = c2.slider("Maximum (%)", 0, 100, round(settings.critical_max_share * 100), disabled=not can_change, key="critical_max")
        critical_weight = c3.slider("Priority", 1, 10, round(settings.critical_weight), disabled=not can_change, key="critical_weight",
                                    help="How capacity left after the minimums is shared: 6 against 3 gets twice as much.")
        section_label("Normal users")
        c1, c2, c3 = st.columns(3)
        normal_min = c1.slider("Guaranteed minimum (%)", 0, 100, round(settings.normal_min_share * 100), disabled=not can_change, key="normal_min")
        normal_max = c2.slider("Maximum (%)", 0, 100, round(settings.normal_max_share * 100), disabled=not can_change, key="normal_max")
        normal_weight = c3.slider("Priority", 1, 10, round(settings.normal_weight), disabled=not can_change, key="normal_weight")
        section_label("Limits")
        c1, c2, c3 = st.columns(3)
        suspicious_max = c1.slider("Suspicious hosts maximum (%)", 0, 100, round(settings.suspicious_max_share * 100), disabled=not can_change)
        limit_share = c2.slider("Proposed limit (% of link)", 1, 50, max(1, round(settings.rate_limit_share * 100)), disabled=not can_change)
        margin = c3.slider("Safety margin (%)", 0, 50, round(settings.safety_margin * 100), disabled=not can_change)
        section_label("Application priorities")
        known = _services()
        services = st.multiselect("Services treated as critical", known, [s for s in settings.critical_services if s in known],
                                  disabled=not can_change,
                                  help="Recognised by well-known destination port, which is not proof of the application.")
        st.caption("Per-host limits are set in Live network → Manage a host. They always expire, like every mitigation.")
        saved = st.form_submit_button("Save", type="primary", disabled=not can_change)
    if saved:
        try:
            settings_service.update_mitigation_settings(principal, replace(
                settings, adaptive_enabled=adaptive, critical_min_share=critical_min / 100, critical_max_share=critical_max / 100,
                critical_weight=float(critical_weight), normal_min_share=normal_min / 100, normal_max_share=normal_max / 100,
                normal_weight=float(normal_weight), suspicious_max_share=suspicious_max / 100, rate_limit_share=limit_share / 100,
                safety_margin=margin / 100, critical_services=tuple(services)))
        except (SettingsError, PermissionDenied) as exc:
            st.error(str(exc))
        else:
            st.toast("Allocation controls saved")
    if st.button("Restore defaults", disabled=not can_change, icon=":material/restart_alt:",
                 help="All of these, and the mitigation policy, back to defaults. Critical and protected host lists are kept."):
        try:
            settings_service.restore_mitigation_defaults(principal)
        except PermissionDenied as exc:
            st.error(str(exc))
        else:
            for key in ("critical_min", "critical_max", "critical_weight", "normal_min", "normal_max", "normal_weight"):
                st.session_state.pop(key, None)
            st.rerun()
