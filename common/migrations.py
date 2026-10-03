"""
Database migrations: numbered SQL files in database/migrations, applied in
order, each exactly once, each in its own transaction.

Both the analyzer and the API call migrate() when they connect. A Postgres
advisory lock lets only one of them apply migrations at a time; the other
waits, then finds nothing left to do. Applied versions are recorded in
schema_migrations, so an existing install only runs what's new and keeps
its alerts.

To change the schema, add the next file (e.g. 0003_add_x.sql). Never edit a
migration that has shipped: installs that already ran it won't run it again.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "database" / "migrations"
# Any fixed number, shared by everything that migrates this database.
LOCK_KEY = 71_419_004
_FILENAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


def available(directory: Path = MIGRATIONS_DIR) -> list[tuple[int, str, Path]]:
    """(version, name, path) for every migration file, in order."""
    found: dict[int, tuple[int, str, Path]] = {}
    for path in sorted(directory.glob("*.sql")):
        match = _FILENAME.match(path.name)
        if match is None:
            raise ValueError(f"migration file name must look like 0001_name.sql: {path.name}")
        version = int(match.group(1))
        if version in found:
            raise ValueError(f"two migrations numbered {version:04d}: {found[version][2].name}, {path.name}")
        found[version] = (version, match.group(2), path)
    return [found[v] for v in sorted(found)]


def migrate(conn, directory: Path = MIGRATIONS_DIR) -> list[int]:
    """
    Apply every migration not yet recorded. Returns the versions applied now.
    `conn` must not be in the middle of a transaction: migrate() won't commit
    or roll back someone else's work.
    """
    pending_files = available(directory)
    if not conn.autocommit and getattr(getattr(conn, "info", None), "transaction_status", 0) != 0:
        raise ValueError("migrate() needs a connection with no transaction in progress")
    autocommit = conn.autocommit
    conn.autocommit = True
    applied_now: list[int] = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", [LOCK_KEY])
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS schema_migrations (
                           version INT PRIMARY KEY,
                           name TEXT NOT NULL,
                           applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"""
                )
                cur.execute("SELECT version FROM schema_migrations")
                done = {row[0] for row in cur.fetchall()}
            conn.autocommit = False
            for version, name, path in pending_files:
                if version in done:
                    continue
                try:
                    with conn.cursor() as cur:
                        cur.execute(path.read_text())
                        cur.execute(
                            "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)", [version, name]
                        )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    log.error("database migration %04d_%s failed; nothing from it was applied", version, name)
                    raise
                applied_now.append(version)
                log.info("applied database migration %04d_%s", version, name)
        finally:
            # Also released when the connection closes, so a failure here
            # mustn't hide whatever went wrong above.
            try:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", [LOCK_KEY])
            except Exception as e:
                log.warning("could not release the migration lock: %s", e)
    finally:
        conn.autocommit = autocommit
    return applied_now
