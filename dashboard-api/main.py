"""
Dashboard REST API.

Serves alert data, traffic statistics, and system health to the
monitoring dashboard over HTTP, and lets the dashboard mark alerts as
reviewed and give devices friendly names.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Generator, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
import psycopg2
import psycopg2.extras
import psycopg2.pool
import redis
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

VERSION = "0.3.0"

STREAM_NAME = "packet_stream"
HEARTBEAT_KEY = "sentinel:analyzer:heartbeat"
# Traffic older than this means capture has stopped or the network is silent.
CAPTURE_LIVE_SECONDS = 15

# How urgent each threat type is. Unknown types count as low.
# Keep in sync with dashboard/src/lib/threats.ts.
SEVERITY: dict[str, str] = {
    "SYN_FLOOD": "high",
    "PORT_SCAN": "medium",
    "HIGH_FREQUENCY": "medium",
    "ANOMALY": "medium",
    "LARGE_PAYLOAD": "low",
    "REQUEST_FLOOD": "high",
    "DISTRIBUTED_FLOOD": "high",
    "NETWORK_SWEEP": "medium",
    "BEACONING": "medium",
}
SEVERITIES = ("high", "medium", "low")
Severity = Literal["high", "medium", "low"]
ReviewStatus = Literal["all", "unreviewed", "reviewed"]

app = FastAPI(title="SentinelAI", version=VERSION)

ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3001").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

_db_pool: psycopg2.pool.ThreadedConnectionPool | None = None

_DB_DSN = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "dbname": os.getenv("POSTGRES_DB", "sentinel_ai"),
    "user": os.getenv("POSTGRES_USER", "sentinel"),
    "password": os.getenv("POSTGRES_PASSWORD", "changeme"),
}

redis_pool = redis.ConnectionPool(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
)


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _db_pool
    if _db_pool is None or _db_pool.closed:
        _db_pool = psycopg2.pool.ThreadedConnectionPool(minconn=2, maxconn=10, **_DB_DSN)
        log.info("postgresql connection pool created")
        # Columns added after the first install (schema.sql only runs on a fresh volume).
        conn = _db_pool.getconn()
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_name TEXT")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS destination_name TEXT")
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS device_names (
                           ip TEXT PRIMARY KEY,
                           name TEXT NOT NULL,
                           updated_at TIMESTAMPTZ DEFAULT NOW())"""
                )
        finally:
            _db_pool.putconn(conn)
    return _db_pool


@contextmanager
def get_db() -> Generator[Any, None, None]:
    pool = _get_pool()
    conn = pool.getconn()
    conn.autocommit = True
    try:
        yield conn
    finally:
        pool.putconn(conn)


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=redis_pool)


def stream_entry_age(entry_id: str | None, now: float) -> float | None:
    """Seconds since a Redis stream entry was written, from its `<ms>-<seq>` id."""
    if not entry_id:
        return None
    return max(0.0, now - int(entry_id.split("-", 1)[0]) / 1000)


def _types_with(severity: str) -> list[str]:
    return [t for t, s in SEVERITY.items() if s == severity]


def severity_sql() -> tuple[str, list[Any]]:
    """SQL expression that maps threat_type to its severity."""
    return (
        "CASE WHEN threat_type = ANY(%s) THEN 'high' WHEN threat_type = ANY(%s) THEN 'medium' ELSE 'low' END",
        [_types_with("high"), _types_with("medium")],
    )


def alert_select(sev_expr: str) -> str:
    """SELECT … FROM for alert rows, with each end's friendly device name if one is set."""
    return f"""SELECT alerts.*, sd.name AS source_device, dd.name AS destination_device,
                      {sev_expr} AS severity
               FROM alerts
               LEFT JOIN device_names sd ON sd.ip = alerts.source_ip
               LEFT JOIN device_names dd ON dd.ip = alerts.destination_ip"""


def alert_filter(
    hours: int,
    severity: Severity | None = None,
    status: ReviewStatus = "all",
) -> tuple[str, list[Any]]:
    """WHERE clause (without the keyword) and params for the common alert filters."""
    clauses = ["timestamp > NOW() - make_interval(hours => %s)"]
    params: list[Any] = [hours]
    if severity == "low":
        # Low also covers any threat type not listed in SEVERITY.
        clauses.append("threat_type <> ALL(%s)")
        params.append(_types_with("high") + _types_with("medium"))
    elif severity:
        clauses.append("threat_type = ANY(%s)")
        params.append(_types_with(severity))
    if status == "unreviewed":
        clauses.append("reviewed_at IS NULL")
    elif status == "reviewed":
        clauses.append("reviewed_at IS NOT NULL")
    return " AND ".join(clauses), params


def check_mutation_headers(origin: str | None, content_type: str | None) -> None:
    """
    Guard for endpoints that change data. The API has no authentication, so
    without this any web page open in the browser could post to localhost and
    mark alerts as reviewed. Browsers always send Origin on cross-site POSTs,
    and requiring JSON forces a CORS preflight that other origins fail.
    """
    if origin is not None and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Origin not allowed")
    if not (content_type or "").startswith("application/json"):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")


def require_trusted_request(request: Request) -> None:
    check_mutation_headers(request.headers.get("origin"), request.headers.get("content-type"))


def _check_database() -> dict[str, Any]:
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        return {"ok": True}
    except psycopg2.Error as e:
        log.warning("health: database check failed: %s", e)
        return {"ok": False, "error": "Cannot reach PostgreSQL"}


def _check_redis_and_pipeline() -> dict[str, Any]:
    r = get_redis()
    try:
        r.ping()
    except redis.exceptions.RedisError as e:
        log.warning("health: redis check failed: %s", e)
        down = {"ok": False, "error": "Cannot reach Redis"}
        return {"redis": down, "capture": {"state": "unknown"}, "analyzer": {"running": False}}

    try:
        last = r.xrevrange(STREAM_NAME, count=1)
    except redis.exceptions.ResponseError:
        last = []
    age = stream_entry_age(last[0][0] if last else None, time.time())
    if age is None:
        capture = {"state": "never", "last_packet_seconds_ago": None}
    else:
        state = "live" if age <= CAPTURE_LIVE_SECONDS else "idle"
        capture = {"state": state, "last_packet_seconds_ago": round(age, 1)}

    beat = r.get(HEARTBEAT_KEY)
    if beat:
        b = json.loads(beat)
        analyzer = {
            "running": True,
            "model_loaded": b.get("model_loaded", False),
            "packets_processed": b.get("processed", 0),
        }
    else:
        analyzer = {"running": False}

    return {"redis": {"ok": True}, "capture": capture, "analyzer": analyzer}


@app.get("/health")
def health() -> dict[str, Any]:
    services = {"database": _check_database(), **_check_redis_and_pipeline()}
    healthy = services["database"]["ok"] and services["redis"]["ok"]
    return {"status": "ok" if healthy else "degraded", "version": VERSION, "services": services}


@app.get("/stats")
def stats(hours: int = Query(24, ge=1, le=168)) -> dict[str, Any]:
    """
    Totals for the window, per-severity counts, and `attention`: the most
    severe level that still has unreviewed alerts, with its latest alert.
    """
    sev_expr, sev_params = severity_sql()
    where, params = alert_filter(hours)
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""SELECT COUNT(*) AS total_alerts,
                          COUNT(DISTINCT source_ip) AS unique_sources,
                          MAX(timestamp) AS last_alert_at
                   FROM alerts WHERE {where}""",
                params,
            )
            totals = cur.fetchone()

            cur.execute(
                f"""SELECT {sev_expr} AS severity,
                          COUNT(*) AS total,
                          COUNT(*) FILTER (WHERE reviewed_at IS NULL) AS unreviewed
                   FROM alerts WHERE {where} GROUP BY 1""",
                sev_params + params,
            )
            by_severity = {s: {"total": 0, "unreviewed": 0} for s in SEVERITIES}
            for row in cur.fetchall():
                by_severity[row["severity"]] = {"total": row["total"], "unreviewed": row["unreviewed"]}

            attention = None
            worst = next((s for s in SEVERITIES if by_severity[s]["unreviewed"] > 0), None)
            if worst:
                w_where, w_params = alert_filter(hours, worst, "unreviewed")
                cur.execute(
                    f"{alert_select(sev_expr)} WHERE {w_where} ORDER BY timestamp DESC LIMIT 1",
                    sev_params + w_params,
                )
                attention = {
                    "severity": worst,
                    "count": by_severity[worst]["unreviewed"],
                    "latest": cur.fetchone(),
                }

    return {"window_hours": hours, **totals, "by_severity": by_severity, "attention": attention}


@app.get("/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    threat_type: str | None = None,
    hours: int = Query(24, ge=1, le=168),
    severity: Severity | None = None,
    status: ReviewStatus = "all",
) -> dict[str, Any]:
    sev_expr, sev_params = severity_sql()
    where, params = alert_filter(hours, severity, status)
    if threat_type:
        where += " AND threat_type = %s"
        params.append(threat_type)

    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"{alert_select(sev_expr)} WHERE {where} ORDER BY timestamp DESC LIMIT %s",
                sev_params + params + [limit],
            )
            rows = cur.fetchall()

    return {"alerts": rows, "count": len(rows)}


class ReviewRequest(BaseModel):
    """Mark alerts reviewed (or back to unreviewed), either by id or by filter."""

    reviewed: bool = True
    ids: list[int] | None = Field(None, max_length=1000)
    hours: int | None = Field(None, ge=1, le=168)
    severity: Severity | None = None

    @model_validator(mode="after")
    def one_target(self) -> ReviewRequest:
        if (self.ids is None) == (self.hours is None):
            raise ValueError("pass either ids, or hours (with an optional severity)")
        return self


@app.post("/alerts/review", dependencies=[Depends(require_trusted_request)])
def review_alerts(body: ReviewRequest) -> dict[str, int]:
    # Reviewing keeps the first review time; un-reviewing clears it.
    set_clause = "reviewed_at = COALESCE(reviewed_at, NOW())" if body.reviewed else "reviewed_at = NULL"
    if body.ids is not None:
        where, params = "id = ANY(%s)", [body.ids]
    else:
        status: ReviewStatus = "unreviewed" if body.reviewed else "reviewed"
        where, params = alert_filter(body.hours, body.severity, status)

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(f"UPDATE alerts SET {set_clause} WHERE {where}", params)
        updated = cur.rowcount
    return {"updated": updated}


MAX_DEVICE_NAME = 64


class DeviceNameRequest(BaseModel):
    """Name a device by IP. An empty or missing name removes it."""

    ip: str
    name: str | None = None

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        try:
            # Normalised so "::FFFF:1" and "::ffff:1" are the same device.
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("not an IP address") from None

    @field_validator("name")
    @classmethod
    def clean_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        cleaned = " ".join("".join(c for c in v if c.isprintable()).split())
        if len(cleaned) > MAX_DEVICE_NAME:
            raise ValueError(f"name must be {MAX_DEVICE_NAME} characters or fewer")
        return cleaned or None


@app.get("/devices")
def list_devices() -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT ip, name, updated_at FROM device_names ORDER BY name")
            rows = cur.fetchall()
    return {"devices": rows}


@app.post("/devices/name", dependencies=[Depends(require_trusted_request)])
def name_device(body: DeviceNameRequest) -> dict[str, Any]:
    with get_db() as conn, conn.cursor() as cur:
        if body.name is None:
            cur.execute("DELETE FROM device_names WHERE ip = %s", [body.ip])
        else:
            cur.execute(
                """INSERT INTO device_names (ip, name) VALUES (%s, %s)
                   ON CONFLICT (ip) DO UPDATE SET name = EXCLUDED.name, updated_at = NOW()""",
                [body.ip, body.name],
            )
    return {"ip": body.ip, "name": body.name}


@app.get("/alerts/summary")
def alert_summary(hours: int = Query(24, ge=1, le=168)) -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT threat_type, COUNT(*) as count, AVG(confidence) as avg_confidence
                   FROM alerts WHERE timestamp > NOW() - make_interval(hours => %s)
                   GROUP BY threat_type ORDER BY count DESC""",
                [hours],
            )
            rows = cur.fetchall()
    return {"summary": rows}


@app.get("/top-ips")
def top_ips(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=168),
) -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT source_ip, MAX(d.name) AS source_device, COUNT(*) as alert_count,
                          ARRAY_AGG(DISTINCT threat_type) as threat_types
                   FROM alerts LEFT JOIN device_names d ON d.ip = alerts.source_ip
                   WHERE timestamp > NOW() - make_interval(hours => %s)
                   GROUP BY source_ip ORDER BY alert_count DESC LIMIT %s""",
                [hours, limit],
            )
            rows = cur.fetchall()
    return {"top_ips": rows}


@app.get("/traffic/live")
def live_traffic() -> dict[str, Any]:
    r = get_redis()
    try:
        info = r.xinfo_stream(STREAM_NAME)
        return {
            "stream_length": info["length"],
            "first_entry": info.get("first-entry"),
            "last_entry": info.get("last-entry"),
        }
    except redis.exceptions.ResponseError:
        return {"stream_length": 0, "first_entry": None, "last_entry": None}
