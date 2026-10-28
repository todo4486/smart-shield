"""SQLite access: connections, transactions, migrations and schema dumps.

Connections are opened in autocommit mode (``isolation_level=None``); all
writes go through ``session(write=True)``, which wraps the block in
``BEGIN IMMEDIATE`` ... ``COMMIT`` (or ``ROLLBACK`` on any exception).
A new connection is opened per session, which keeps Streamlit's threaded
reruns safe without sharing connection objects across threads.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional, Tuple, Union

from config import MIGRATIONS_DIR, get_settings
from services.timeutil import utc_now_iso

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000
MIGRATION_FILE_RE = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")
# A migration that rebuilds a parent table starts with this line. Foreign keys are switched off for it
# (PRAGMA foreign_keys cannot change inside a transaction), so DROP TABLE does not cascade to child rows,
# and PRAGMA foreign_key_check must come back empty before it commits.
FOREIGN_KEYS_OFF_MARKER = "-- requires: foreign_keys_off"

SCHEMA_HEADER = (
    "-- GENERATED FILE. DO NOT EDIT.\n"
    "-- Produced by `python -m scripts.manage dump-schema` from database/migrations/.\n"
    "-- tests/test_database.py fails if this file drifts from the migrations.\n"
)

PathLike = Union[str, Path]


class MigrationError(RuntimeError):
    pass


def resolve_db_path(db_path: Optional[PathLike] = None) -> str:
    if db_path is not None:
        return str(db_path)
    return str(get_settings().db_path)


def connect(db_path: Optional[PathLike] = None) -> sqlite3.Connection:
    path = resolve_db_path(db_path)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None, check_same_thread=True)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def session(write: bool = False, db_path: Optional[PathLike] = None) -> Iterator[sqlite3.Connection]:
    """Open a connection and run the block inside one transaction."""
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        else:
            if conn.in_transaction:
                conn.execute("COMMIT")
    finally:
        conn.close()


# ---------------------------------------------------------------- migrations

def discover_migrations(directory: Path = MIGRATIONS_DIR) -> List[Tuple[str, str, Path]]:
    """Return (version, name, path) for each migration, sorted by version."""
    found = []
    for path in sorted(directory.glob("*.sql")):
        match = MIGRATION_FILE_RE.match(path.name)
        if not match:
            raise MigrationError(f"Migration file name must look like 001_name.sql: {path.name}")
        found.append((match.group(1), match.group(2), path))
    versions = [v for v, _, _ in found]
    if len(versions) != len(set(versions)):
        raise MigrationError("Duplicate migration version numbers found")
    return found


def split_sql_statements(script: str) -> List[str]:
    """Split a script into complete statements (trigger bodies stay intact)."""
    statements: List[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if _strip_sql_comments(statement):
                statements.append(statement)
            buffer = ""
    if _strip_sql_comments(buffer):
        raise MigrationError("Migration ends with an incomplete SQL statement")
    return statements


def _strip_sql_comments(text: str) -> str:
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("--")]
    return "\n".join(lines).strip().rstrip(";").strip()


def _ensure_migrations_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version TEXT PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )


def applied_versions(conn: sqlite3.Connection) -> List[str]:
    _ensure_migrations_table(conn)
    return [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]


def run_migrations(db_path: Optional[PathLike] = None, directory: Path = MIGRATIONS_DIR) -> List[str]:
    """Apply pending migrations in order. Each runs in its own transaction.

    Idempotent: re-running applies nothing. Returns the versions applied now.
    """
    conn = connect(db_path)
    newly_applied: List[str] = []
    try:
        _ensure_migrations_table(conn)
        for version, name, path in discover_migrations(directory):
            text = path.read_text(encoding="utf-8")
            statements = split_sql_statements(text)
            fk_off = _needs_foreign_keys_off(text)
            if fk_off:
                conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Re-check inside the write lock in case another process just applied it.
                already = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
                ).fetchone()
                if already:
                    conn.execute("ROLLBACK")
                    continue
                for statement in statements:
                    conn.execute(statement)
                if fk_off:
                    _check_foreign_keys(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, utc_now_iso()),
                )
                conn.execute("COMMIT")
            except Exception as exc:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise MigrationError(f"Migration {path.name} failed: {exc}") from exc
            finally:
                if fk_off:
                    conn.execute("PRAGMA foreign_keys = ON")
            logger.info("Applied migration %s_%s", version, name)
            newly_applied.append(version)
    finally:
        conn.close()
    return newly_applied


def _needs_foreign_keys_off(text: str) -> bool:
    return text.lstrip().startswith(FOREIGN_KEYS_OFF_MARKER)


def _check_foreign_keys(conn: sqlite3.Connection) -> None:
    broken = conn.execute("PRAGMA foreign_key_check").fetchall()
    if broken:
        raise MigrationError(f"Foreign key check failed after a table rebuild ({len(broken)} row(s), first: "
                             f"{tuple(broken[0])}); nothing was changed.")


def current_schema_version(db_path: Optional[PathLike] = None) -> Optional[str]:
    conn = connect(db_path)
    try:
        versions = applied_versions(conn)
    finally:
        conn.close()
    return versions[-1] if versions else None


# ------------------------------------------------------------- schema dump

_TYPE_ORDER = {"table": 0, "index": 1, "trigger": 2, "view": 3}


def dump_schema_from_connection(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    ordered = sorted(rows, key=lambda r: (_TYPE_ORDER.get(r["type"], 9), r["name"]))
    body = "\n\n".join(row["sql"].strip() + ";" for row in ordered)
    return SCHEMA_HEADER + "\n" + body + "\n"


def generate_schema_sql(directory: Path = MIGRATIONS_DIR) -> str:
    """Build the schema from scratch in memory and return it as SQL text."""
    conn = connect(":memory:")
    try:
        _ensure_migrations_table(conn)
        for _, _, path in discover_migrations(directory):
            text = path.read_text(encoding="utf-8")
            conn.execute(f"PRAGMA foreign_keys = {'OFF' if _needs_foreign_keys_off(text) else 'ON'}")
            for statement in split_sql_statements(text):
                conn.execute(statement)
        return dump_schema_from_connection(conn)
    finally:
        conn.close()
