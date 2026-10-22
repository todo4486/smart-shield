from __future__ import annotations

from datetime import timedelta

import pytest

from services import auth_service, database_service, session_service
from services.authorization import Role
from services.timeutil import utc_now
from tests.conftest import STRONG_PASSWORD, audit_rows


def test_first_user_is_admin_and_later_users_are_analysts():
    first = auth_service.register("First", "first@example.com", STRONG_PASSWORD)
    second = auth_service.register("Second", "second@example.com", STRONG_PASSWORD)
    assert first.role is Role.ADMIN
    assert second.role is Role.ANALYST


def test_registration_stores_argon2_hash_not_password():
    user = auth_service.register("Hash Check", "hash@example.com", STRONG_PASSWORD)
    with database_service.session() as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user.id,)).fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert STRONG_PASSWORD not in stored


def test_registration_normalizes_email_and_is_audited():
    user = auth_service.register("Mixed Case", "  Mixed.Case@Example.COM ", STRONG_PASSWORD)
    assert user.email == "mixed.case@example.com"
    assert len(audit_rows("auth.register", "success")) == 1


def test_duplicate_email_rejected_case_insensitively(admin_user):
    with pytest.raises(auth_service.RegistrationError, match="already exists"):
        auth_service.register("Copy", "ADA@example.com", STRONG_PASSWORD)
    assert len(audit_rows("auth.register", "failure")) == 1


@pytest.mark.parametrize(
    "password, missing",
    [
        ("Short1A", "at least 10 characters"),
        ("alllowercase123", "an uppercase letter"),
        ("ALLUPPERCASE123", "a lowercase letter"),
        ("NoDigitsHereAtAll", "a digit"),
        ("Aa1" + "x" * 130, "at most 128 characters"),
    ],
)
def test_weak_passwords_rejected(password, missing):
    with pytest.raises(auth_service.RegistrationError, match=missing):
        auth_service.register("Weak", "weak@example.com", password)
    assert not auth_service.has_any_users()


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "two@@example.com", "spa ce@example.com"])
def test_invalid_emails_rejected(email):
    with pytest.raises(auth_service.RegistrationError):
        auth_service.register("Bad Email", email, STRONG_PASSWORD)


def test_self_registration_can_be_disabled_after_first_user(monkeypatch, admin_user):
    monkeypatch.setenv("SMART_SHIELD_ALLOW_SELF_REGISTRATION", "false")
    assert not auth_service.registration_open()
    with pytest.raises(auth_service.RegistrationError, match="disabled"):
        auth_service.register("Late", "late@example.com", STRONG_PASSWORD)


def test_login_success_updates_last_login(admin_user):
    user = auth_service.login("ADA@example.com", STRONG_PASSWORD)
    assert user.id == admin_user.id
    assert user.last_login_at is not None
    assert len(audit_rows("auth.login", "success")) == 1


def test_login_wrong_password_and_unknown_email_give_same_generic_error(admin_user):
    with pytest.raises(auth_service.LoginError) as wrong_pw:
        auth_service.login("ada@example.com", "WrongPassword9")
    with pytest.raises(auth_service.LoginError) as unknown:
        auth_service.login("nobody@example.com", "WrongPassword9")
    assert str(wrong_pw.value) == str(unknown.value) == auth_service.GENERIC_LOGIN_ERROR
    assert len(audit_rows("auth.login", "failure")) == 2


def test_inactive_user_cannot_log_in(admin, analyst_user):
    from services import user_admin_service

    user_admin_service.set_active(admin, analyst_user.id, False)
    with pytest.raises(auth_service.LoginError, match="Invalid email or password"):
        auth_service.login("alan@example.com", STRONG_PASSWORD)


def test_lockout_after_max_failures_blocks_even_correct_password(admin_user):
    for _ in range(5):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("ada@example.com", "WrongPassword9")
    with pytest.raises(auth_service.AccountLockedError):
        auth_service.login("ada@example.com", STRONG_PASSWORD)
    assert len(audit_rows("auth.login", "denied")) == 1


def test_lockout_expires_after_window(admin_user):
    start = utc_now() - timedelta(minutes=30)
    for _ in range(5):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("ada@example.com", "WrongPassword9", now=start)
    # 30 minutes later the 15-minute window has passed.
    assert auth_service.login("ada@example.com", STRONG_PASSWORD).id == admin_user.id


def test_lockout_tracked_for_nonexistent_email():
    for _ in range(5):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("ghost@example.com", "WrongPassword9")
    with pytest.raises(auth_service.AccountLockedError):
        auth_service.login("Ghost@Example.com", "WrongPassword9")


def test_successful_login_resets_failure_count(admin_user):
    for _ in range(4):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("ada@example.com", "WrongPassword9")
    auth_service.login("ada@example.com", STRONG_PASSWORD)
    for _ in range(4):
        with pytest.raises(auth_service.LoginError):
            auth_service.login("ada@example.com", "WrongPassword9")
    assert auth_service.login("ada@example.com", STRONG_PASSWORD).id == admin_user.id


def test_rehash_on_login_when_parameters_change(admin_user, monkeypatch):
    from argon2 import PasswordHasher

    with database_service.session(write=True) as conn:
        weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(STRONG_PASSWORD)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (weak, admin_user.id))
    auth_service.login("ada@example.com", STRONG_PASSWORD)
    with database_service.session() as conn:
        new_hash = conn.execute("SELECT password_hash FROM users WHERE id = ?", (admin_user.id,)).fetchone()[0]
    assert new_hash != weak
    assert not PasswordHasher().check_needs_rehash(new_hash)


def test_session_idle_timeout_and_reload(admin_user):
    state = {}
    now = utc_now()
    session_service.start(state, admin_user, now=now)
    assert session_service.resolve(state, now=now + timedelta(minutes=5)).user_id == admin_user.id
    assert session_service.resolve(state, now=now + timedelta(minutes=40)) is None
    assert session_service.USER_ID_KEY not in state
    assert "expired" in session_service.pop_flash(state)


def test_session_drops_deactivated_user(admin, analyst_user):
    from services import user_admin_service

    state = {}
    session_service.start(state, analyst_user)
    user_admin_service.set_active(admin, analyst_user.id, False)
    assert session_service.resolve(state) is None


def test_logout_clears_session_and_is_audited(admin_user):
    state = {}
    session_service.start(state, admin_user)
    session_service.logout(state)
    assert session_service.resolve(state) is None
    assert len(audit_rows("auth.logout", "success")) == 1
