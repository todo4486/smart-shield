"""Streamlit AppTest: routing and the login gate."""
from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from services import session_service
from services.timeutil import utc_now

APP = str(Path(__file__).resolve().parent.parent / "app.py")
TIMEOUT = 30


def _all_text(at: AppTest) -> str:
    parts = [m.value for m in at.markdown] + [i.value for i in at.info] + [e.value for e in at.error]
    parts += [h.value for h in at.header] + [s.value for s in at.subheader] + [c.value for c in at.caption]
    return "\n".join(str(p) for p in parts)


def _signed_in(user) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.session_state[session_service.USER_ID_KEY] = user.id
    at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    return at.run()


def test_anonymous_user_sees_only_login_page():
    at = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    assert not at.exception
    labels = {t.label for t in at.text_input}
    assert {"Email", "Password"} <= labels
    text = _all_text(at)
    assert "first account you create becomes the **administrator**" in text
    assert "Overview" not in text and "Administration" not in text
    assert "Sign out" not in [b.label for b in at.button]


@pytest.mark.parametrize(
    "page", ["views/overview.py", "views/administration.py", "views/security_center.py", "views/settings.py"]
)
def test_anonymous_user_cannot_switch_to_protected_pages(page):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.switch_page(page)
    at.run()
    text = _all_text(at)
    # Only the login page is registered, so the router falls back to it.
    assert "Email" in {t.label for t in at.text_input}
    assert "Network health across Smart Shield" not in text
    assert "Manage accounts and roles" not in text
    assert "Planned for" not in text


def test_signed_in_admin_sees_overview_empty_state(admin_user):
    at = _signed_in(admin_user)
    assert not at.exception
    text = _all_text(at)
    assert "No network data yet" in text
    assert "Set up your team" in text
    assert "Sign out" in [b.label for b in at.button]


def test_analyst_overview_hides_admin_step_and_admin_page_is_guarded(analyst_user):
    at = _signed_in(analyst_user)
    assert not at.exception
    assert "Set up your team" not in _all_text(at)
    at.switch_page("views/administration.py")
    at.run()
    assert "Manage accounts and roles" not in _all_text(at)


def test_admin_can_open_administration(admin_user):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT)
    at.session_state[session_service.USER_ID_KEY] = admin_user.id
    at.session_state[session_service.LAST_ACTIVITY_KEY] = utc_now()
    at.switch_page("views/administration.py")
    at.run()
    assert not at.exception
    assert "Manage accounts and roles" in _all_text(at)


def test_login_through_the_form(admin_user):
    at = AppTest.from_file(APP, default_timeout=TIMEOUT).run()
    at.text_input(key="login_email").input("ada@example.com")
    at.text_input(key="login_password").input("CorrectHorse42")
    at.button[0].click()  # first form submit button on the page is "Sign in"
    at.run()
    assert not at.exception
    assert "Network health across Smart Shield" in _all_text(at)
