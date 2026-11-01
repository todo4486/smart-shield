"""Page transitions: they must play on a page change only, and leave the header and live panels alone."""
from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from components import page_motion
from services import session_service
from services.timeutil import utc_now

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "assets" / "styles.css").read_text(encoding="utf-8")


def test_the_animation_changes_only_when_the_page_does():
    state = {}
    assert page_motion.next_variant(state, "overview") is None  # the first page: no move to show
    assert page_motion.next_variant(state, "overview") is None  # and a rerun of it starts nothing
    first = page_motion.next_variant(state, "network_map")
    assert first in ("a", "b")
    assert page_motion.next_variant(state, "network_map") == first  # a rerun or widget change does not replay it
    second = page_motion.next_variant(state, "live_monitoring")
    assert second != first and page_motion.next_variant(state, "overview") == first


def test_only_what_follows_the_marker_moves():
    css = page_motion.page_css("a")
    assert "ss-page-in-a" in css and "ss-page-bar-a" in css and ":has(.ss-page-motion) ~ *" in css
    assert "@keyframes" not in css
    assert "<style>" not in page_motion.page_css(None)


def test_both_variants_exist_and_the_top_line_cannot_block_anything():
    for name in ("ss-page-in-a", "ss-page-in-b", "ss-page-bar-a", "ss-page-bar-b", "ss-tab-in"):
        assert f"@keyframes {name} " in CSS
    bar = CSS[CSS.index(".stApp::before"):]
    assert "pointer-events: none" in bar[:bar.index("}")] and "opacity: 0" in bar[:bar.index("}")]


def test_moving_between_pages_works_and_changes_the_animation(admin_user):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state[session_service.USER_ID_KEY] = admin_user.id
    app.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    app.run()
    assert not any("animation: ss-page-in" in m.value for m in app.markdown)
    app.switch_page("views/network_map.py")
    app.run()
    assert not app.exception
    moved = next(m.value for m in app.markdown if "animation: ss-page-in" in m.value)
    app.switch_page("views/live_monitoring.py")
    app.run()
    assert not app.exception
    assert next(m.value for m in app.markdown if "animation: ss-page-in" in m.value) != moved
