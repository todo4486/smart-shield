"""Alert noise control: suppression (allow-list) rules with an author, a reason and an expiry.

* A rule narrows by alert type, category and/or host, and lasts 1–MAX_DAYS days.
* Administrators create rules directly. Analysts can only REQUEST one; an administrator approves or rejects
  it. Rules are revoked, never deleted. Every step is audited.
* Rules apply to alerts raised while the rule is active (alert_service.create_alert asks find_rule()).
  A suppressed alert is still stored with its status, evidence and history, gets a note saying which rule
  suppressed it, and is listed under the "Suppressed" filter. It is left out of the unresolved counts, the
  header, correlation and the network map.
* Host matching is strict: a host rule only matches when EVERY flow of the alert comes from (or goes to) that
  host, as counted in the alert's own evidence. An alert that merely includes the host is never hidden, and
  an alert whose evidence names no hosts never matches a host rule.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from services import audit_service, database_service
from services.authorization import Permission, Principal, require_permission
from services.timeutil import parse_iso, to_iso, utc_now, utc_now_iso

MAX_DAYS = 90
TYPES = ("security", "anomaly", "congestion", "performance")
ROLES = ("source", "destination")


class SuppressionError(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    id: Optional[int]
    alert_type: Optional[str]
    category: Optional[str]
    host: Optional[str]
    host_role: str
    reason: str
    status: str
    expires_at: str
    created_at: Optional[str] = None
    requested_by_email: Optional[str] = None
    reviewed_by_email: Optional[str] = None
    review_note: Optional[str] = None
    alerts_suppressed: int = 0

    @classmethod
    def from_row(cls, row) -> "Rule":
        keys = row.keys()
        return cls(row["id"], row["alert_type"], row["category"], row["host"], row["host_role"], row["reason"],
                   row["status"], row["expires_at"], row["created_at"],
                   row["requested_by_email"] if "requested_by_email" in keys else None,
                   row["reviewed_by_email"] if "reviewed_by_email" in keys else None,
                   row["review_note"], row["alerts_suppressed"] if "alerts_suppressed" in keys else 0)

    def describe(self) -> str:
        what = f"{self.alert_type} alerts" if self.alert_type else "alerts"
        if self.category:
            what += f" in category '{self.category}'"
        if self.host:
            what += f" {'from' if self.host_role == 'source' else 'to'} {self.host}"
        return what


# ------------------------------------------------------------------ pure matching

def is_active(rule: Rule, now: datetime) -> bool:
    expires = parse_iso(rule.expires_at)
    return rule.status == "active" and expires is not None and now < expires


def _host_only(value: str) -> str:
    """'10.0.0.5:443' → '10.0.0.5'; IPv6 and bare addresses are returned unchanged."""
    text = str(value).strip()
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        head = text.rsplit(":", 1)[0]
        return head.strip("[]")


def host_accounts_for_all(host: str, role: str, evidence: Mapping[str, Any]) -> bool:
    """True only if the evidence shows every flow of the alert came from / went to `host` (pure)."""
    total = evidence.get("flows")
    entries = evidence.get("top_sources" if role == "source" else "top_destinations")
    if not isinstance(total, int) or total <= 0 or not isinstance(entries, list):
        return False
    matched = sum(int(e.get("flows", 0)) for e in entries
                  if isinstance(e, Mapping) and _host_only(e.get("value", "")) == host)
    return matched >= total


def matches(rule: Rule, alert_type: str, category: str, evidence: Mapping[str, Any]) -> bool:
    """Whether a rule covers an alert (activity is checked separately) (pure)."""
    if rule.alert_type and rule.alert_type != alert_type:
        return False
    if rule.category and rule.category.strip().lower() != (category or "").strip().lower():
        return False
    if rule.host and not host_accounts_for_all(rule.host, rule.host_role, evidence):
        return False
    return True


def find_rule(conn: sqlite3.Connection, alert_type: str, category: str,
              evidence: Mapping[str, Any]) -> Optional[Rule]:
    """The oldest active rule that covers a new alert (called inside the alert's own transaction)."""
    now = utc_now()
    rows = conn.execute("SELECT * FROM suppression_rules WHERE status = 'active' AND expires_at > ? ORDER BY id",
                        (to_iso(now),)).fetchall()
    for row in rows:
        rule = Rule.from_row(row)
        if is_active(rule, now) and matches(rule, alert_type, category, evidence):
            return rule
    return None


# ------------------------------------------------------------------ validation

def _clean(alert_type: Optional[str], category: Optional[str], host: Optional[str], host_role: str, reason: str,
           days: int) -> Dict[str, Any]:
    alert_type = alert_type or None
    category = (category or "").strip() or None
    host = (host or "").strip() or None
    reason = (reason or "").strip()
    if alert_type is not None and alert_type not in TYPES:
        raise SuppressionError("Unknown alert type.")
    if host_role not in ROLES:
        raise SuppressionError("Host role must be source or destination.")
    if host is not None:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise SuppressionError("Host must be a single IP address, e.g. 10.0.0.5.") from exc
    if category is not None and len(category) > 120:
        raise SuppressionError("Category is too long.")
    if not (alert_type or category or host):
        raise SuppressionError("A rule must narrow by alert type, category or host. Suppressing everything is not "
                               "allowed.")
    if not 5 <= len(reason) <= 500:
        raise SuppressionError("Give a reason of 5–500 characters (it is shown to everyone and audited).")
    if not 1 <= int(days) <= MAX_DAYS:
        raise SuppressionError(f"Rules expire after 1–{MAX_DAYS} days.")
    now = utc_now()
    return {"alert_type": alert_type, "category": category, "host": host, "host_role": host_role, "reason": reason,
            "created_at": to_iso(now), "expires_at": to_iso(now + timedelta(days=int(days)))}


def _insert(conn, values: Dict[str, Any], status: str, principal: Principal) -> int:
    cursor = conn.execute(
        "INSERT INTO suppression_rules (alert_type, category, host, host_role, reason, status, requested_by, "
        "created_at, expires_at, reviewed_by, reviewed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (values["alert_type"], values["category"], values["host"], values["host_role"], values["reason"], status,
         principal.user_id, values["created_at"], values["expires_at"],
         principal.user_id if status == "active" else None, values["created_at"] if status == "active" else None))
    return int(cursor.lastrowid)


# ------------------------------------------------------------------ service API

def create_rule(principal: Principal, *, alert_type: Optional[str] = None, category: Optional[str] = None,
                host: Optional[str] = None, host_role: str = "source", reason: str, days: int) -> int:
    """Administrators: create an active rule."""
    require_permission(principal, Permission.MANAGE_SETTINGS, action="suppression.create")
    values = _clean(alert_type, category, host, host_role, reason, days)
    with database_service.session(write=True) as conn:
        rule_id = _insert(conn, values, "active", principal)
        audit_service.record(conn, user_id=principal.user_id, action="suppression.create",
                             details={"rule_id": rule_id, **{k: values[k] for k in
                                                             ("alert_type", "category", "host", "host_role",
                                                              "expires_at", "reason")}})
    return rule_id


def request_rule(principal: Principal, *, alert_type: Optional[str] = None, category: Optional[str] = None,
                 host: Optional[str] = None, host_role: str = "source", reason: str, days: int) -> int:
    """Analysts: ask an administrator for a rule. It does nothing until approved."""
    require_permission(principal, Permission.TRIAGE_ALERTS, action="suppression.request")
    values = _clean(alert_type, category, host, host_role, reason, days)
    with database_service.session(write=True) as conn:
        rule_id = _insert(conn, values, "requested", principal)
        audit_service.record(conn, user_id=principal.user_id, action="suppression.request",
                             details={"rule_id": rule_id, "reason": values["reason"], "host": values["host"],
                                      "category": values["category"], "alert_type": values["alert_type"]})
    return rule_id


def review_request(principal: Principal, rule_id: int, *, approve: bool, note: Optional[str] = None) -> None:
    require_permission(principal, Permission.MANAGE_SETTINGS, action="suppression.review", details={"rule_id": rule_id})
    note = (note or "").strip()[:500] or None
    with database_service.session(write=True) as conn:
        row = conn.execute("SELECT * FROM suppression_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise SuppressionError("Rule not found.")
        if row["status"] != "requested":
            raise SuppressionError(f"This rule is already {row['status']}.")
        now = utc_now_iso()
        if approve and row["expires_at"] <= now:
            raise SuppressionError("This request has already expired. Ask for a new one.")
        conn.execute("UPDATE suppression_rules SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ? "
                     "WHERE id = ?", ("active" if approve else "rejected", principal.user_id, now, note, rule_id))
        audit_service.record(conn, user_id=principal.user_id,
                             action="suppression.approve" if approve else "suppression.reject",
                             details={"rule_id": rule_id, "note": note})


def revoke(principal: Principal, rule_id: int, note: Optional[str] = None) -> None:
    """End an active rule now. Alerts it already suppressed stay suppressed and keep the link to the rule."""
    require_permission(principal, Permission.MANAGE_SETTINGS, action="suppression.revoke", details={"rule_id": rule_id})
    with database_service.session(write=True) as conn:
        row = conn.execute("SELECT status FROM suppression_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise SuppressionError("Rule not found.")
        if row["status"] != "active":
            raise SuppressionError(f"Only an active rule can be revoked (this one is {row['status']}).")
        conn.execute("UPDATE suppression_rules SET status = 'revoked', reviewed_by = ?, reviewed_at = ?, "
                     "review_note = ? WHERE id = ?",
                     (principal.user_id, utc_now_iso(), (note or "").strip()[:500] or None, rule_id))
        audit_service.record(conn, user_id=principal.user_id, action="suppression.revoke", details={"rule_id": rule_id})


def unsuppress_alert(principal: Principal, alert_id: int, note: Optional[str] = None) -> None:
    """Bring one suppressed alert back into the queues (for example, if a rule hid something important)."""
    require_permission(principal, Permission.TRIAGE_ALERTS, action="suppression.unsuppress_alert",
                       details={"alert_id": alert_id})
    with database_service.session(write=True) as conn:
        row = conn.execute("SELECT suppressed_by_rule FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None or row["suppressed_by_rule"] is None:
            raise SuppressionError("That alert is not suppressed.")
        conn.execute("UPDATE alerts SET suppressed_by_rule = NULL WHERE id = ?", (alert_id,))
        conn.execute("INSERT INTO alert_events (alert_id, event_type, note, user_id, created_at) VALUES "
                     "(?, 'note', ?, ?, ?)", (alert_id, f"Unsuppressed (was hidden by rule #{row['suppressed_by_rule']})"
                                              + (f": {note.strip()[:400]}" if note and note.strip() else ""),
                                              principal.user_id, utc_now_iso()))
        audit_service.record(conn, user_id=principal.user_id, action="suppression.unsuppress_alert",
                             details={"alert_id": alert_id, "rule_id": row["suppressed_by_rule"]})


def list_rules(principal: Principal) -> List[Rule]:
    require_permission(principal, Permission.VIEW_ALERTS, action="suppression.list")
    with database_service.session() as conn:
        rows = conn.execute(
            "SELECT r.*, ru.email AS requested_by_email, rv.email AS reviewed_by_email, "
            "(SELECT COUNT(*) FROM alerts a WHERE a.suppressed_by_rule = r.id) AS alerts_suppressed "
            "FROM suppression_rules r LEFT JOIN users ru ON ru.id = r.requested_by "
            "LEFT JOIN users rv ON rv.id = r.reviewed_by ORDER BY r.id DESC").fetchall()
    return [Rule.from_row(r) for r in rows]


def effective_status(rule: Rule, now: Optional[datetime] = None) -> str:
    """'expired' for an active or requested rule past its expiry; otherwise the stored status (pure)."""
    now = now or utc_now()
    expires = parse_iso(rule.expires_at)
    if rule.status in ("active", "requested") and expires is not None and now >= expires:
        return "expired"
    return rule.status
