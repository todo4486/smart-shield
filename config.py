"""Application settings read from the environment (and an optional .env file).

Settings are re-read on every call to ``get_settings()`` so tests can override
values with ``monkeypatch.setenv`` without reloading modules.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
MIGRATIONS_DIR = PROJECT_ROOT / "database" / "migrations"
SCHEMA_FILE = PROJECT_ROOT / "database" / "schema.sql"
ASSETS_DIR = PROJECT_ROOT / "assets"

# Values already in the process environment win over .env.
load_dotenv(PROJECT_ROOT / ".env", override=False)

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(ValueError):
    """Raised when an environment setting is present but invalid."""


@dataclass(frozen=True)
class Settings:
    db_path: Path
    dataset_dir: Path
    artifact_dir: Path
    tc_enabled: bool
    tc_interfaces: tuple
    tc_binary: str
    session_idle_minutes: int
    lockout_max_attempts: int
    lockout_minutes: int
    allow_self_registration: bool
    log_level: str


def _int_setting(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _bool_setting(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _path_setting(name: str, default: str) -> Path:
    raw = os.environ.get(name, "").strip() or default
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def get_settings() -> Settings:
    log_level = os.environ.get("SMART_SHIELD_LOG_LEVEL", "INFO").strip().upper() or "INFO"
    if log_level not in VALID_LOG_LEVELS:
        raise ConfigError(f"SMART_SHIELD_LOG_LEVEL must be one of {VALID_LOG_LEVELS}, got {log_level!r}")
    return Settings(
        db_path=_path_setting("SMART_SHIELD_DB_PATH", "data/smart_shield.db"),
        dataset_dir=_path_setting("SMART_SHIELD_DATASET_DIR", "data/datasets"),
        artifact_dir=_path_setting("SMART_SHIELD_ARTIFACT_DIR", "artifacts"),
        tc_enabled=_bool_setting("SMART_SHIELD_TC_ENABLED", False),
        tc_interfaces=tuple(i.strip() for i in os.environ.get("SMART_SHIELD_TC_INTERFACES", "").split(",") if i.strip()),
        tc_binary=os.environ.get("SMART_SHIELD_TC_BINARY", "/sbin/tc").strip() or "/sbin/tc",
        session_idle_minutes=_int_setting("SMART_SHIELD_SESSION_IDLE_MINUTES", 30, 1, 24 * 60),
        lockout_max_attempts=_int_setting("SMART_SHIELD_LOCKOUT_MAX_ATTEMPTS", 5, 1, 100),
        lockout_minutes=_int_setting("SMART_SHIELD_LOCKOUT_MINUTES", 15, 1, 24 * 60),
        allow_self_registration=_bool_setting("SMART_SHIELD_ALLOW_SELF_REGISTRATION", True),
        log_level=log_level,
    )
