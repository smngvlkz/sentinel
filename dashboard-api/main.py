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
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Generator, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
import psycopg2
import psycopg2.extras
import psycopg2.pool
import redis
from dotenv import load_dotenv

from common.migrations import migrate

from . import auth

load_dotenv()

log = logging.getLogger(__name__)

VERSION = "0.5.0"

STREAM_NAME = "packet_stream"
HEARTBEAT_KEY = "sentinel:analyzer:heartbeat"
# Must match the analyzer's consumer group and capture's stats key.
CONSUMER_GROUP = "analyzers"
CAPTURE_STATS_KEY = "sentinel:capture:stats"
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
    "RESOURCE_PRESSURE": "high",
}
SEVERITIES = ("high", "medium", "low")
Severity = Literal["high", "medium", "low"]
ReviewStatus = Literal["all", "unreviewed", "reviewed"]

# Reachable without logging in: only what the login screen needs.
PUBLIC_PATHS = {"/auth/status", "/auth/login", "/auth/setup"}


def require_login(request: Request) -> None:
    """
    Once a password is set, every endpoint needs a login session; before that
    the dashboard is open, on this machine only, as it always was. Applied to
    the whole app, so a new endpoint is protected without anyone remembering.
    """
    if request.url.path in PUBLIC_PATHS:
        return
    try:
        with get_db() as conn, conn.cursor() as cur:
            if auth.stored_hash(cur) is None:
                if auth.exposed():
                    # Only reachable if the password went missing after startup.
                    raise HTTPException(status_code=503, detail=auth.NO_PASSWORD_WHILE_EXPOSED)
                return
            if auth.session_valid(cur, request.cookies.get(auth.COOKIE)):
                return
    except psycopg2.Error:
        # Can't check a login without the database: refuse, except /health,
        # which is how the dashboard says the database is down.
        if request.url.path == "/health":
            return
        raise HTTPException(status_code=503, detail="Database unavailable")
    raise HTTPException(status_code=401, detail="Log in first")


def startup_problem() -> str | None:
    """
    Why the API mustn't start: other devices can reach the dashboard
    (DASHBOARD_BIND) and there's no password yet. None if it may start,
    including when the database can't be checked: then every request is
    refused anyway until it can (require_login).
    """
    if not auth.exposed():
        return None
    try:
        with get_db() as conn, conn.cursor() as cur:
            password_set = auth.stored_hash(cur) is not None
    except psycopg2.Error:
        return None
    return None if password_set else auth.NO_PASSWORD_WHILE_EXPOSED


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    problem = startup_problem()
    if problem:
        log.error("not starting: %s", problem)
        raise RuntimeError(problem)
    yield


app = FastAPI(title="SentinelAI", version=VERSION, lifespan=lifespan, dependencies=[Depends(require_login)])

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
        # Bring the schema up to date (database/migrations); the analyzer
        # does the same, and whichever starts second finds nothing to do.
        conn = _db_pool.getconn()
        try:
            migrate(conn)
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


def _same_host(origin: str, forwarded_host: str | None) -> bool:
    return bool(forwarded_host) and urlsplit(origin).netloc.lower() == forwarded_host.lower()


def check_mutation_headers(
    origin: str | None, content_type: str | None, forwarded_host: str | None = None
) -> None:
    """
    Guard for endpoints that change data: a page on another site, open in the
    same browser, mustn't be able to post here. Browsers always send Origin on
    cross-site POSTs. Allowed origins are the dashboard's own address (it
    forwards /api here and passes on the address it was loaded from as
    X-Forwarded-Host, overwriting any the browser sent) and CORS_ORIGINS.
    Requiring JSON forces a CORS preflight, which other origins fail, so they
    can't send X-Forwarded-Host themselves either.
    """
    if origin is not None and origin not in ALLOWED_ORIGINS and not _same_host(origin, forwarded_host):
        raise HTTPException(status_code=403, detail="Origin not allowed")
    if not (content_type or "").startswith("application/json"):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")


def require_trusted_request(request: Request) -> None:
    check_mutation_headers(
        request.headers.get("origin"), request.headers.get("content-type"), request.headers.get("x-forwarded-host")
    )


def _check_database() -> dict[str, Any]:
    """
    Reachable, and how big: size on disk, roughly how many alerts (Postgres's
    estimate; counting exactly on every health check would scan the table),
    and when the oldest kept alert is from. Retention keeps all three bounded.
    """
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT pg_database_size(current_database()),
                          (SELECT reltuples::bigint FROM pg_class WHERE relname = 'alerts'),
                          (SELECT min(timestamp) FROM alerts)"""
            )
            size, estimate, oldest = cur.fetchone()
            if estimate is None or estimate < 0:
                # Never analyzed yet (a new install): small, so count exactly.
                cur.execute("SELECT count(*) FROM alerts")
                estimate = cur.fetchone()[0]
        return {
            "ok": True,
            "size_bytes": size,
            "alerts_estimate": estimate,
            "oldest_alert": oldest.isoformat() if oldest else None,
        }
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

    stats = r.get(CAPTURE_STATS_KEY)
    if stats:
        capture["names_dropped_total"] = json.loads(stats).get("names_dropped_total")

    beat = r.get(HEARTBEAT_KEY)
    if beat:
        b = json.loads(beat)
        analyzer = {
            "running": True,
            "model_loaded": b.get("model_loaded", False),
            "packets_processed": b.get("processed", 0),
            **_stream_backlog(r),
            "packets_lost_unread": b.get("lost_unread"),
            "tables": b.get("tables", {}),
        }
    else:
        analyzer = {"running": False}

    return {"redis": {"ok": True}, "capture": capture, "analyzer": analyzer}


def _stream_backlog(r: redis.Redis) -> dict[str, int | None]:
    """
    How far the analyzer is behind capture, live from Redis: `lag` packets
    not yet read, `pending` read but not finished.
    """
    try:
        groups = r.xinfo_groups(STREAM_NAME)
    except redis.exceptions.ResponseError:
        return {"lag": None, "pending": None}
    for group in groups:
        if group.get("name") == CONSUMER_GROUP:
            return {"lag": group.get("lag"), "pending": group.get("pending")}
    return {"lag": None, "pending": None}


class PasswordRequest(BaseModel):
    password: str = Field(max_length=auth.MAX_LENGTH)


class ChangePasswordRequest(BaseModel):
    current: str = Field(max_length=auth.MAX_LENGTH)
    new: str = Field(max_length=auth.MAX_LENGTH)


def _start_session(cur, response: Response) -> None:
    response.set_cookie(
        auth.COOKIE, auth.new_session(cur), max_age=auth.SESSION_SECONDS, path="/", httponly=True, samesite="strict"
    )


def _locked(seconds: int) -> HTTPException:
    minutes = -(-seconds // 60)
    return HTTPException(
        status_code=429,
        detail=f"Too many wrong passwords. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
        headers={"Retry-After": str(seconds)},
    )


@app.get("/auth/status")
def auth_status(request: Request) -> dict[str, bool]:
    """What the dashboard should show: the login screen, the first-run setup offer, or nothing."""
    with get_db() as conn, conn.cursor() as cur:
        password_set = auth.stored_hash(cur) is not None
        logged_in = password_set and auth.session_valid(cur, request.cookies.get(auth.COOKIE))
    return {"password_set": password_set, "logged_in": logged_in, "setup_allowed": not password_set and not auth.exposed()}


@app.post("/auth/setup", dependencies=[Depends(require_trusted_request)])
def auth_setup(body: PasswordRequest, response: Response) -> dict[str, bool]:
    """
    First run: set the password from the dashboard. Only while the dashboard is
    reachable from this machine alone, so nobody else on the network can claim
    it first; otherwise use `make password`.
    """
    if auth.exposed():
        raise HTTPException(status_code=403, detail="Set the password with make password on the machine running SentinelAI.")
    problem = auth.problem_with(body.password)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    with get_db() as conn, conn.cursor() as cur:
        if not auth.claim_password(cur, body.password):
            raise HTTPException(status_code=409, detail="A password is already set.")
        _start_session(cur, response)
    return {"ok": True}


@app.post("/auth/login", dependencies=[Depends(require_trusted_request)])
def auth_login(body: PasswordRequest, response: Response) -> dict[str, bool]:
    with get_db() as conn, conn.cursor() as cur:
        if auth.stored_hash(cur) is None:
            raise HTTPException(status_code=409, detail="No password is set yet.")
        wait = auth.locked_for(cur)
        if wait:
            raise _locked(wait)
        if not auth.password_matches(cur, body.password):
            wait = auth.record_failure(cur)
            if wait:
                raise _locked(wait)
            raise HTTPException(status_code=401, detail="Wrong password.")
        auth.record_success(cur)
        _start_session(cur, response)
    return {"ok": True}


@app.post("/auth/logout", dependencies=[Depends(require_trusted_request)])
def auth_logout(request: Request, response: Response) -> dict[str, bool]:
    with get_db() as conn, conn.cursor() as cur:
        auth.end_session(cur, request.cookies.get(auth.COOKIE))
    response.delete_cookie(auth.COOKIE, path="/", httponly=True, samesite="strict")
    return {"ok": True}


@app.post("/auth/password", dependencies=[Depends(require_trusted_request)])
def auth_change_password(body: ChangePasswordRequest, response: Response) -> dict[str, bool]:
    """Change the password: needs the current one; logs out every other session."""
    with get_db() as conn, conn.cursor() as cur:
        if auth.stored_hash(cur) is None:
            raise HTTPException(status_code=409, detail="No password is set yet.")
        wait = auth.locked_for(cur)
        if wait:
            raise _locked(wait)
        if not auth.password_matches(cur, body.current):
            wait = auth.record_failure(cur)
            if wait:
                raise _locked(wait)
            raise HTTPException(status_code=401, detail="The current password is wrong.")
        problem = auth.problem_with(body.new)
        if problem:
            raise HTTPException(status_code=422, detail=problem)
        auth.set_password(cur, body.new)  # logs every session out...
        _start_session(cur, response)  # ...then this browser back in
    return {"ok": True}


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
