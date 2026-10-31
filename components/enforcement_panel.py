"""Real-network enforcement: what this server can do, what is in force, the protected lists, and the emergency stop."""
from __future__ import annotations

from dataclasses import replace
from typing import Tuple

import streamlit as st

from components import mitigation_panel
from components.ui import section_label
from services import live_monitor_service, mitigation_service, settings_service, simulation_service
from services.authorization import Permission, PermissionDenied, Principal
from services.mitigation_service import MitigationError
from services.settings_service import SettingsError

SETUP_HELP = """
Do this only on a network you are allowed to change, ideally a lab.

**macOS (`pf` + `dnctl`)**
1. In `.env`, set `SMART_SHIELD_ENFORCEMENT_BACKEND=pf` and `SMART_SHIELD_ENFORCEMENT_INTERFACES=en0`.
2. Try it first on a reserved test address, which no real traffic uses:
   `sudo .venv/bin/python -m scripts.manage enforcement-check --backend pf --interface en0 --install`
3. Start the app as root: `sudo .venv/bin/streamlit run app.py`. Files it creates will belong to root; afterwards run
   `sudo chown -R "$USER" data artifacts`.

**Linux (`tc`)**: the same steps with `SMART_SHIELD_ENFORCEMENT_BACKEND=tc` and `--backend tc`. Root or `CAP_NET_ADMIN` is enough.

**Recovery without the app.** Limits outlive the app until a reboot, so if it was killed, remove them by hand:
- macOS: `echo "" | sudo pfctl -a com.apple/smart_shield -f -`
- Linux: `sudo tc qdisc del dev <interface> clsact`
"""


def _parse_hosts(text: str) -> Tuple[str, ...]:
    return tuple(part.strip() for part in text.replace("\n", ",").split(",") if part.strip())


def _render_capability(principal: Principal) -> None:
    state = mitigation_service.enforcement_status(principal)
    if state.enforcing:
        st.warning(f"**Real enforcement is on, using `{state.backend}`.** Approved actions change traffic on: "
                   f"{', '.join(state.interfaces)}.", icon=":material/warning:")
    else:
        st.info("**Dry run: nothing on the network is changed.** Approving an action on a live capture records it and "
                "shows the exact commands that would run.", icon=":material/science:")
        for reason in state.reasons:
            st.markdown(f"- {reason}")
    lab = ", ".join(state.lab_interfaces) or "none"
    st.caption(f"Backend requested in the server's configuration: {state.requested} · Lab interfaces, where isolation is "
               f"allowed: {lab}. These can only be changed on the server, not from this page.")
    with st.expander("How to turn on real enforcement"):
        st.markdown(SETUP_HELP)


def _render_host_lists(principal: Principal) -> None:
    settings = settings_service.get_mitigation_settings()
    if not principal.has(Permission.MANAGE_SETTINGS):
        st.caption(f"Critical hosts: {', '.join(settings.critical_hosts) or 'none'} · "
                   f"Protected hosts: {', '.join(settings.protected_hosts) or 'none'}")
        return
    with st.form("mitigation_host_lists"):
        critical = st.text_input("Critical hosts", ", ".join(settings.critical_hosts),
                                 help="Comma-separated addresses. They get the critical class, and the engine will not limit them by itself.")
        protected = st.text_input("Protected hosts", ", ".join(settings.protected_hosts),
                                  help="Comma-separated addresses that are never proposed or enforced on. Add your gateway and DNS server.")
        if st.form_submit_button("Save host lists"):
            try:
                settings_service.update_mitigation_settings(
                    principal, replace(settings, critical_hosts=_parse_hosts(critical), protected_hosts=_parse_hosts(protected)))
            except (SettingsError, PermissionDenied) as exc:
                st.error(str(exc))
            else:
                st.toast("Host lists saved")


def _render_in_force(principal: Principal) -> None:
    actions = mitigation_service.list_active_real(principal)
    if not actions:
        st.caption("No mitigation is active on a real interface.")
        return
    for m in actions:
        mitigation_panel.render_action(principal, m, key_prefix="enforce")


def _render_emergency(principal: Principal) -> None:
    if not principal.has(Permission.APPLY_TRAFFIC_POLICY):
        st.caption("Only an administrator can use the emergency stop.")
        return
    st.caption("Sets the mitigation policy to Off, so the engine cannot re-apply anything, then removes every limit and "
               "block on every backend, including class policies.")
    reason = st.text_input("Reason", key="emergency_reason", placeholder="Why, at least 5 characters")
    if st.button("Emergency disable: remove all enforcement", type="primary", icon=":material/emergency_home:",
                 key="emergency_disable"):
        try:
            result = mitigation_service.emergency_disable(principal, reason=reason)
        except (MitigationError, PermissionDenied, SettingsError) as exc:
            st.error(str(exc))
            return
        if result["failures"]:
            st.error("Not everything could be removed:\n\n" + "\n".join(f"- {f}" for f in result["failures"]))
        else:
            st.success(f"Everything was removed ({result['ended']} action(s) ended). The mitigation policy is now Off.")


def render(principal: Principal) -> None:
    """The top of the Enforce tab."""
    section_label("Threat mitigation enforcement")
    _render_capability(principal)
    section_label("In force on real interfaces")
    _render_in_force(principal)
    section_label("Critical and protected hosts")
    _render_host_lists(principal)
    section_label("Emergency stop")
    _render_emergency(principal)


def _live_section(principal: Principal) -> None:
    status = live_monitor_service.get_monitor().status
    simulation = simulation_service.status_copy()
    if not status.running and simulation.running:
        mitigation_panel.render_session(principal, simulation.session_id)
        return
    if not status.running or status.session_id is None:
        st.caption("Start a live capture in Live Monitoring to run the engine on real traffic. Monitor → Simulation shows "
                   "the same engine on a simulated link.")
        return
    if status.mode != "packets":
        st.caption("This capture uses interface counters only, so there are no flows for the models to judge and the "
                   "engine has nothing to act on. Packet capture is needed.")
        return
    if not status.detection.get("enabled"):
        st.warning(status.detection.get("reason") or "Live detection is off, so the engine has nothing to act on.")
    if status.engine_error:
        st.error(f"The mitigation engine hit a problem (capture carries on): {status.engine_error}")
    mitigation_panel.render_session(principal, status.session_id, provenance="measured")


def render_live(principal: Principal) -> None:
    """The engine on the running capture, below the Live network panel."""
    section_label("Threat mitigation")
    live_running = live_monitor_service.get_monitor().status.running
    running = live_running or simulation_service.status_copy().running
    if live_running and not mitigation_service.enforcement_status(principal).enforcing:
        st.caption("Dry run: actions here are recorded and show their commands, but nothing on the network is changed.")
    mitigation_panel.render_policy(principal, key="mitigation_policy_live")
    st.fragment(_live_section, run_every=2 if running else None)(principal)
