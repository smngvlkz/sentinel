"""
Set or reset the dashboard password: `make password`.

Run it on the machine running SentinelAI, or over SSH to it. It asks for the
new password twice, replaces any old one, logs out every session and clears
the lockout after wrong passwords. Alerts and device names aren't touched.
It doesn't ask for the old password: anyone who can run this can already read
the whole database, so being on the machine is the proof of ownership.
"""

from __future__ import annotations

import getpass
import sys

import psycopg2

from common.migrations import migrate

from . import auth
from .main import _DB_DSN


def reset(conn, password: str) -> None:
    """Replace the password, log everyone out, clear the lockout."""
    migrate(conn)
    conn.autocommit = True
    with conn.cursor() as cur:
        auth.set_password(cur, password)


def main() -> int:
    password = getpass.getpass("New dashboard password: ")
    problem = auth.problem_with(password)
    if problem:
        print(problem, file=sys.stderr)
        return 1
    if getpass.getpass("Type it again: ") != password:
        print("The two didn't match; nothing changed.", file=sys.stderr)
        return 1
    try:
        conn = psycopg2.connect(**_DB_DSN)
    except psycopg2.OperationalError as e:
        print(f"Can't reach the database ({e}). Is SentinelAI running? Start it with make up.", file=sys.stderr)
        return 1
    try:
        reset(conn, password)
    finally:
        conn.close()
    print("Password set. Every session was logged out, so log in again with the new password.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
