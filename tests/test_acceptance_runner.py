"""The acceptance runner must never write to the database it was pointed at."""
from __future__ import annotations

import sqlite3

from scripts import acceptance


def test_the_working_copy_is_separate_and_complete(tmp_path):
    source = tmp_path / "real.db"
    with sqlite3.connect(source) as conn:
        conn.execute("CREATE TABLE t (v)")
        conn.execute("INSERT INTO t VALUES (1)")
    work = tmp_path / "work"
    work.mkdir()
    copy = acceptance.working_copy(source, work)
    assert copy != source
    with sqlite3.connect(copy) as conn:
        conn.execute("INSERT INTO t VALUES (2)")
    with sqlite3.connect(source) as conn:
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1


def test_every_acceptance_test_is_named():
    assert sorted(acceptance.NAMES) == list(range(1, 13))
