"""Shared fixtures: every test gets its own temporary SQLite database."""
from __future__ import annotations

import pytest

from services import auth_service, database_service

STRONG_PASSWORD = "CorrectHorse42"


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_smart_shield.db"
    monkeypatch.setenv("SMART_SHIELD_DB_PATH", str(db_path))
    monkeypatch.setenv("SMART_SHIELD_DATASET_DIR", str(tmp_path / "datasets"))
    monkeypatch.setenv("SMART_SHIELD_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("SMART_SHIELD_LOCKOUT_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("SMART_SHIELD_LOCKOUT_MINUTES", "15")
    monkeypatch.setenv("SMART_SHIELD_SESSION_IDLE_MINUTES", "30")
    monkeypatch.setenv("SMART_SHIELD_ALLOW_SELF_REGISTRATION", "true")
    database_service.run_migrations()
    return db_path


@pytest.fixture
def admin_user():
    return auth_service.register("Ada Admin", "ada@example.com", STRONG_PASSWORD)


@pytest.fixture
def analyst_user(admin_user):
    return auth_service.register("Alan Analyst", "alan@example.com", STRONG_PASSWORD)


@pytest.fixture
def admin(admin_user):
    return admin_user.to_principal()


@pytest.fixture
def analyst(analyst_user):
    return analyst_user.to_principal()


def audit_rows(action=None, outcome=None):
    with database_service.session() as conn:
        sql = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if outcome:
            sql += " AND outcome = ?"
            params.append(outcome)
        return conn.execute(sql + " ORDER BY id", params).fetchall()
