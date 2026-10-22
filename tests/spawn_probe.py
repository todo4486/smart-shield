"""Test helper: a worker target importable by spawned processes."""
from __future__ import annotations


def touch(path: str) -> None:
    with open(path, "w") as handle:
        handle.write("worker ran")
