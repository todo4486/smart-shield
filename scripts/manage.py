"""Operator CLI.

    python -m scripts.manage init-db
    python -m scripts.manage create-admin [--name NAME] [--email EMAIL]
    python -m scripts.manage reset-password --email EMAIL
    python -m scripts.manage apply-retention [--dry-run]
    python -m scripts.manage dump-schema [--check]

Passwords are only read interactively (never from arguments, which end up in
shell history).
"""
from __future__ import annotations

import argparse
import getpass
import sys
from typing import Callable, List, Optional

from config import SCHEMA_FILE, get_settings
from services import auth_service, database_service
from services.authorization import Role


def cmd_init_db(_: argparse.Namespace) -> int:
    path = get_settings().db_path
    applied = database_service.run_migrations()
    version = database_service.current_schema_version()
    if applied:
        print(f"Applied migrations {', '.join(applied)} to {path}")
    else:
        print(f"Database {path} is already up to date")
    print(f"Schema version: {version}")
    return 0


def create_admin(
    name: str, email: str, password: str
) -> auth_service.User:
    database_service.run_migrations()
    return auth_service.register(name, email, password, force_role=Role.ADMIN, actor="cli")


def cmd_create_admin(
    args: argparse.Namespace,
    *,
    prompt: Callable[[str], str] = input,
    secret: Callable[[str], str] = getpass.getpass,
) -> int:
    name = args.name or prompt("Name: ")
    email = args.email or prompt("Email: ")
    print("Password must be 10-128 characters with an uppercase letter, a lowercase letter and a digit.")
    password = secret("Password: ")
    if password != secret("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        user = create_admin(name, email, password)
    except auth_service.AuthError as exc:
        print(f"Could not create admin: {exc}", file=sys.stderr)
        return 1
    print(f"Created admin account #{user.id} for {user.email}")
    return 0


def cmd_reset_password(
    args: argparse.Namespace,
    *,
    secret: Callable[[str], str] = getpass.getpass,
) -> int:
    print("Password must be 10-128 characters with an uppercase letter, a lowercase letter and a digit.")
    password = secret("New password: ")
    if password != secret("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        user = auth_service.reset_password_cli(args.email, password)
    except auth_service.AuthError as exc:
        print(f"Could not reset password: {exc}", file=sys.stderr)
        return 1
    print(f"Password reset for {user.email}; failed sign-in attempts were cleared.")
    return 0


def cmd_apply_retention(args: argparse.Namespace) -> int:
    from services import retention_service

    database_service.run_migrations()
    try:
        result = retention_service.run(dry_run=args.dry_run, actor_user_id=None, force=args.dry_run)
    except retention_service.RetentionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    verb = "Would delete" if args.dry_run else "Deleted"
    for name, count in result.counts.items():
        print(f"{verb} {count:,} {name.replace('_', ' ')} (older than {result.cutoffs[name][:10]})")
    return 0


def cmd_dump_schema(args: argparse.Namespace) -> int:
    generated = database_service.generate_schema_sql()
    if args.check:
        current = SCHEMA_FILE.read_text(encoding="utf-8") if SCHEMA_FILE.exists() else ""
        if current != generated:
            print(f"{SCHEMA_FILE} is out of date. Run: python -m scripts.manage dump-schema", file=sys.stderr)
            return 1
        print(f"{SCHEMA_FILE} is up to date")
        return 0
    SCHEMA_FILE.write_text(generated, encoding="utf-8")
    print(f"Wrote {SCHEMA_FILE}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m scripts.manage", description="Smart Shield operator commands")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create or migrate the database").set_defaults(func=cmd_init_db)
    admin = sub.add_parser("create-admin", help="create an administrator account")
    admin.add_argument("--name")
    admin.add_argument("--email")
    admin.set_defaults(func=cmd_create_admin)
    reset = sub.add_parser("reset-password", help="reset a user's password (operator recovery)")
    reset.add_argument("--email", required=True)
    reset.set_defaults(func=cmd_reset_password)
    retention = sub.add_parser("apply-retention", help="delete data older than the configured retention ages")
    retention.add_argument("--dry-run", action="store_true", help="only count what would be deleted")
    retention.set_defaults(func=cmd_apply_retention)
    dump = sub.add_parser("dump-schema", help="regenerate database/schema.sql from the migrations")
    dump.add_argument("--check", action="store_true", help="exit 1 if schema.sql is out of date")
    dump.set_defaults(func=cmd_dump_schema)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
