"""
Send a test notification to every channel that's turned on, and say whether
each one got through: `python -m notifier.send_test` (`make notify-test`).

It asks the running notifier to send it, the same way the dashboard's button
does, so it tests the real thing: settings, secrets and the network path.
"""

from __future__ import annotations

import os
import sys
import time

import psycopg2

WAIT_SECONDS = 30


def main() -> int:
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "sentinel_ai"),
        user=os.getenv("POSTGRES_USER", "sentinel"),
        password=os.getenv("POSTGRES_PASSWORD", "changeme"),
    )
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("INSERT INTO notification_tests DEFAULT VALUES RETURNING id, requested_at")
        test_id, requested_at = cur.fetchone()
    print("Asked the notifier to send a test notification...")

    deadline = time.monotonic() + WAIT_SECONDS
    handled = False
    rows: list[tuple] = []
    while time.monotonic() < deadline:
        with conn.cursor() as cur:
            cur.execute("SELECT handled_at IS NOT NULL FROM notification_tests WHERE id = %s", [test_id])
            row = cur.fetchone()
            handled = bool(row and row[0])
            cur.execute(
                """SELECT channel, status, attempts, last_error FROM notifications
                   WHERE kind = 'test' AND created_at >= %s::timestamptz - interval '5 seconds'
                   ORDER BY channel""",
                [requested_at],
            )
            rows = cur.fetchall()
        if handled and rows and all(status != "pending" or attempts > 0 for _, status, attempts, _ in rows):
            break
        time.sleep(1)

    if not handled:
        print("The notifier didn't pick it up. Is it running? Check: make status, then make logs")
        return 1
    if not rows:
        print("No channel is turned on, or notifications.toml has a problem. Check: make logs")
        return 1
    ok = True
    for channel, status, _, error in rows:
        if status == "sent":
            print(f"  {channel}: sent")
        else:
            ok = False
            print(f"  {channel}: failed: {error}" + (" (will retry)" if status == "pending" else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
