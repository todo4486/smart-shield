"""Registration, login and password policy.

* argon2id hashing (argon2-cffi), rehashed on login when parameters change.
* Lockout per normalized email key, tracked even for emails with no account;
  unknown emails still run a dummy verify so timing doesn't reveal accounts.
* The first registered user becomes admin (decided inside BEGIN IMMEDIATE);
  everyone after that is an analyst.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from config import get_settings
from repositories import login_attempt_repository, user_repository
from services import audit_service, database_service
from services.authorization import Principal, Role
from services.timeutil import to_iso, utc_now

PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
NAME_MAX_LENGTH = 100
EMAIL_MAX_LENGTH = 254
# Deliberately simple: one @, no spaces, a dot in the domain.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

GENERIC_LOGIN_ERROR = "Invalid email or password."
LOCKED_LOGIN_ERROR = "Too many failed sign-in attempts. Please wait and try again later."

_hasher = PasswordHasher()
_dummy_hash: Optional[str] = None


class AuthError(Exception):
    """A user-facing authentication or registration failure."""


class RegistrationError(AuthError):
    pass


class LoginError(AuthError):
    pass


class AccountLockedError(LoginError):
    pass


@dataclass(frozen=True)
class User:
    id: int
    name: str
    email: str
    role: Role
    is_active: bool
    created_at: str
    last_login_at: Optional[str]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        return cls(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            role=Role(row["role"]),
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            last_login_at=row["last_login_at"],
        )

    def to_principal(self) -> Principal:
        return Principal(user_id=self.id, name=self.name, email=self.email, role=self.role)


# ------------------------------------------------------------------ helpers

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_email(email: str) -> Optional[str]:
    if not email:
        return "Email is required."
    if len(email) > EMAIL_MAX_LENGTH or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    return None


def password_policy_errors(password: str) -> List[str]:
    """Return every unmet rule (empty list means the password is acceptable)."""
    errors = []
    password = password or ""
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"at most {PASSWORD_MAX_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a digit")
    return errors


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _verify(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _dummy_verify(password: str) -> None:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(32))
    _verify(_dummy_hash, password)


# ------------------------------------------------------------- registration

def registration_open() -> bool:
    """True when self-registration is allowed (always true before the first user)."""
    if get_settings().allow_self_registration:
        return True
    return not has_any_users()


def has_any_users() -> bool:
    with database_service.session() as conn:
        return user_repository.count_users(conn) > 0


def register(
    name: str, email: str, password: str, *, force_role: Optional[Role] = None, actor: str = "self"
) -> User:
    """Create an account. The first account ever created becomes admin.

    ``force_role`` is only used by the operator CLI (``create-admin``).
    """
    name = (name or "").strip()
    email = normalize_email(email)
    if not name:
        raise RegistrationError("Name is required.")
    if len(name) > NAME_MAX_LENGTH:
        raise RegistrationError(f"Name must be at most {NAME_MAX_LENGTH} characters.")
    email_error = validate_email(email)
    if email_error:
        raise RegistrationError(email_error)
    policy_errors = password_policy_errors(password)
    if policy_errors:
        raise RegistrationError("Password must contain " + ", ".join(policy_errors) + ".")

    password_hash = hash_password(password)  # slow; done before taking the write lock
    now = to_iso(utc_now())
    try:
        with database_service.session(write=True) as conn:
            existing_users = user_repository.count_users(conn)
            if force_role is None and existing_users > 0 and not get_settings().allow_self_registration:
                raise RegistrationError("Self-registration is disabled. Ask an administrator for an account.")
            if force_role is not None:
                role = force_role
            else:
                role = Role.ADMIN if existing_users == 0 else Role.ANALYST
            user_id = user_repository.insert_user(
                conn, name=name, email=email, password_hash=password_hash, role=role.value, now=now
            )
            audit_service.record(
                conn,
                user_id=user_id,
                action="auth.register",
                details={"role": role.value, "first_user": existing_users == 0, "via": actor},
            )
            row = user_repository.get_by_id(conn, user_id)
    except sqlite3.IntegrityError as exc:
        if "users.email" in str(exc):
            audit_service.record_standalone(
                user_id=None, action="auth.register", outcome="failure", details={"reason": "duplicate_email"}
            )
            raise RegistrationError("An account with this email already exists.") from exc
        raise
    return User.from_row(row)


# -------------------------------------------------------------------- login

def _lockout_window_start(now: datetime) -> str:
    return to_iso(now - timedelta(minutes=get_settings().lockout_minutes))


def is_locked_out(conn: sqlite3.Connection, email_key: str, now: datetime) -> bool:
    failures = login_attempt_repository.recent_failures(conn, email_key, _lockout_window_start(now))
    return failures >= get_settings().lockout_max_attempts


def login(email: str, password: str, *, now: Optional[datetime] = None) -> User:
    """Verify credentials and return the user, or raise LoginError (generic)."""
    now = now or utc_now()
    now_iso = to_iso(now)
    email_key = normalize_email(email)[:EMAIL_MAX_LENGTH] or "<empty>"

    with database_service.session() as conn:
        locked = is_locked_out(conn, email_key, now)
        row = None if locked else user_repository.get_by_email(conn, email_key)

    if locked:
        audit_service.record_standalone(
            user_id=None, action="auth.login", outcome="denied", details={"reason": "locked_out"}
        )
        raise AccountLockedError(LOCKED_LOGIN_ERROR)

    if row is None:
        _dummy_verify(password or "")
        ok = False
        reason = "unknown_email"
    else:
        ok = _verify(row["password_hash"], password or "")
        reason = "bad_password" if not ok else ("inactive" if not row["is_active"] else "")
        if ok and not row["is_active"]:
            ok = False

    with database_service.session(write=True) as conn:
        login_attempt_repository.record_attempt(conn, email_key, ok, now_iso)
        if not ok:
            audit_service.record(
                conn,
                user_id=row["id"] if row is not None else None,
                action="auth.login",
                outcome="failure",
                details={"reason": reason},
            )
        else:
            user_repository.update_last_login(conn, row["id"], now_iso)
            if _hasher.check_needs_rehash(row["password_hash"]):
                user_repository.update_password_hash(conn, row["id"], hash_password(password), now_iso)
            audit_service.record(conn, user_id=row["id"], action="auth.login", outcome="success")
            fresh = user_repository.get_by_id(conn, row["id"])

    if not ok:
        raise LoginError(GENERIC_LOGIN_ERROR)
    return User.from_row(fresh)


def get_user(user_id: int) -> Optional[User]:
    with database_service.session() as conn:
        row = user_repository.get_by_id(conn, user_id)
    return User.from_row(row) if row else None


def record_logout(principal: Principal, reason: str = "user") -> None:
    audit_service.record_standalone(
        user_id=principal.user_id, action="auth.logout", outcome="success", details={"reason": reason}
    )
