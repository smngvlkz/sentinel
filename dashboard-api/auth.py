"""
The dashboard's one admin password (roadmap 1.3).

Until a password is set, the dashboard works as before: open, on this
machine only. Once one is set, every API request needs a login session. It
can be set from the dashboard on first run, but only while the dashboard is
reachable from this machine alone (so nobody else on the network can claim
it first), or at any time with `make password`, which is also the reset for
a forgotten one.

Sessions are random tokens in an HttpOnly cookie; only their SHA-256 is
stored. Repeated wrong passwords lock logins for a while, doubling each time,
up to 15 minutes. `make password` clears that too.
"""

from __future__ import annotations

import hashlib
import os
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

COOKIE = "sentinel_session"
SESSION_SECONDS = 14 * 86_400
MIN_LENGTH = 8
MAX_LENGTH = 256
# Wrong passwords allowed before logins lock; each further one doubles the lock.
FREE_ATTEMPTS = 5
FIRST_LOCK_SECONDS = 60
MAX_LOCK_SECONDS = 15 * 60

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_hasher = PasswordHasher()


def exposed() -> bool:
    """Whether the dashboard listens beyond this machine (DASHBOARD_BIND, default 127.0.0.1)."""
    return os.getenv("DASHBOARD_BIND", "127.0.0.1").strip().lower() not in _LOOPBACK


def problem_with(password: str) -> str | None:
    """Why a new password isn't acceptable, or None."""
    if len(password) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    return None


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def stored_hash(cur) -> str | None:
    cur.execute("SELECT password_hash FROM admin_password WHERE id = 1")
    row = cur.fetchone()
    return row[0] if row else None


def password_matches(cur, password: str) -> bool:
    stored = stored_hash(cur)
    if stored is None:
        return False
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def claim_password(cur, password: str) -> bool:
    """First-run setup: store the password only if none is set yet (atomically)."""
    cur.execute(
        "INSERT INTO admin_password (id, password_hash) VALUES (1, %s) ON CONFLICT (id) DO NOTHING RETURNING id",
        [_hasher.hash(password)],
    )
    return cur.fetchone() is not None


def set_password(cur, password: str) -> None:
    """Store a new password; log out every session and clear the lockout."""
    cur.execute(
        """INSERT INTO admin_password (id, password_hash) VALUES (1, %s)
           ON CONFLICT (id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()""",
        [_hasher.hash(password)],
    )
    cur.execute("DELETE FROM sessions")
    cur.execute("DELETE FROM login_lockout")


def new_session(cur) -> str:
    """Start a session and return its token (the cookie value)."""
    token = secrets.token_urlsafe(32)
    cur.execute("DELETE FROM sessions WHERE expires_at <= NOW()")
    cur.execute(
        "INSERT INTO sessions (token_hash, expires_at) VALUES (%s, NOW() + make_interval(secs => %s))",
        [token_hash(token), SESSION_SECONDS],
    )
    return token


def session_valid(cur, token: str | None) -> bool:
    if not token:
        return False
    cur.execute("SELECT 1 FROM sessions WHERE token_hash = %s AND expires_at > NOW()", [token_hash(token)])
    return cur.fetchone() is not None


def end_session(cur, token: str | None) -> None:
    if token:
        cur.execute("DELETE FROM sessions WHERE token_hash = %s", [token_hash(token)])


def locked_for(cur) -> int:
    """Seconds until logins are allowed again (0 if they are)."""
    cur.execute(
        "SELECT CEIL(EXTRACT(EPOCH FROM locked_until - NOW()))::int FROM login_lockout "
        "WHERE id = 1 AND locked_until > NOW()"
    )
    row = cur.fetchone()
    return max(0, row[0]) if row else 0


def lock_seconds(failures: int) -> int:
    """How long logins lock after this many consecutive wrong passwords."""
    if failures < FREE_ATTEMPTS:
        return 0
    return min(FIRST_LOCK_SECONDS * 2 ** (failures - FREE_ATTEMPTS), MAX_LOCK_SECONDS)


def record_failure(cur) -> int:
    """Count a wrong password; returns how long logins are now locked for."""
    cur.execute(
        """INSERT INTO login_lockout (id, failures) VALUES (1, 1)
           ON CONFLICT (id) DO UPDATE SET failures = login_lockout.failures + 1
           RETURNING failures"""
    )
    seconds = lock_seconds(cur.fetchone()[0])
    if seconds:
        cur.execute(
            "UPDATE login_lockout SET locked_until = NOW() + make_interval(secs => %s) WHERE id = 1", [seconds]
        )
    return seconds


def record_success(cur) -> None:
    cur.execute("DELETE FROM login_lockout")
