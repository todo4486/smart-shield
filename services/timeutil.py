"""UTC timestamp helpers. All persisted timestamps use one fixed ISO-8601 format,
so they sort and compare correctly as strings."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("naive datetimes are not allowed; use an aware UTC datetime")
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def utc_now_iso() -> str:
    return to_iso(utc_now())


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
