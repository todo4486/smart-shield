"""The sign-in intro: it must show once, carry its text safely, and never get in the way of signing in."""
from __future__ import annotations

import re
from pathlib import Path

from streamlit.testing.v1 import AppTest

from components import intro
from services import session_service

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "assets" / "styles.css").read_text(encoding="utf-8")


def _app():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    return app


def _intro_shown(app, marker="ss-intro-stage"):
    return any(marker in m.value for m in app.markdown)


def _sign_in(app):
    app.text_input(key="login_email").input("ada@example.com")
    app.text_input(key="login_password").input("CorrectHorse42")
    app.button[0].click()
    app.run()


def test_the_overlay_cannot_block_the_form_or_outlive_its_animation():
    base = re.search(r"\.ss-intro \{(.*?)\}", CSS, re.S).group(1)
    assert "pointer-events: none" in base  # clicks and typing reach the form during the intro
    assert "visibility: hidden" in base and "opacity: 0" in base  # without animations it never shows
    assert re.search(r"@keyframes ss-intro-show \{.*?100% \{ visibility: hidden; opacity: 0; \}", CSS)
    assert re.search(r"\.ss-intro \{.*?both;", CSS, re.S)  # it stays hidden after the last frame


def test_every_letter_of_the_name_is_animated_and_decorative():
    html = intro.intro_html()
    assert "".join(re.findall(r">([^<>]*)</span>", html)).replace("&nbsp;", " ") == "Smart Shield"
    assert "aria-hidden='true'" in html and "POWERED BY PREDICTNET" in html


def test_a_name_cannot_inject_markup():
    html = intro.welcome_html("<script>x</script> Admin")
    assert "<script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html
    assert "Welcome, back" in intro.welcome_html("   ")
    assert "Welcome, Ada" in intro.welcome_html("Ada Admin")


def test_the_intro_is_on_the_sign_in_page_and_the_form_still_works(admin_user):
    app = _app()
    assert not app.exception and _intro_shown(app)
    _sign_in(app)
    assert not app.exception and not any(e.value for e in app.error)
    assert app.session_state[session_service.USER_ID_KEY] == admin_user.id


def test_the_welcome_shows_once_after_signing_in(admin_user):
    app = _app()
    _sign_in(app)
    assert _intro_shown(app, "Welcome, Ada")
    app.run()
    assert not _intro_shown(app, "Welcome, Ada") and not app.exception


def test_a_failed_sign_in_gives_no_welcome(admin_user):
    app = _app()
    app.text_input(key="login_email").input("ada@example.com")
    app.text_input(key="login_password").input("WrongPassword99")
    app.button[0].click()
    app.run()
    assert app.error and not _intro_shown(app, "Welcome,") and _intro_shown(app)


def test_reduce_motion_skips_the_welcome(admin_user, admin):
    from services import preferences_service

    preferences_service.set_reduce_motion(admin, True)
    app = _app()
    _sign_in(app)
    assert not app.exception and not _intro_shown(app, "Welcome,")


def test_the_intro_shows_only_the_brand_and_no_figures():
    """It looks like a radar, so it must not look like a reading: no invented hosts, counts or statuses."""
    visible = re.sub(r"<[^>]+>", "", re.sub(r"<defs>.*?</defs>", "", intro.intro_html())).replace("&nbsp;", " ")
    assert visible == "Smart ShieldPOWERED BY PREDICTNET"
    assert not re.search(r"\d", visible)


def test_the_sign_in_page_keeps_its_name_as_a_real_heading():
    app = _app()
    assert any("<h1>Smart Shield</h1>" in m.value for m in app.markdown)

