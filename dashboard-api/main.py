"""
Dashboard REST API.

Serves alert data, traffic statistics, and system health
to the monitoring dashboard over HTTP.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any, Generator

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
import psycopg2.pool
import redis
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

app = FastAPI(title="SentinelAI", version="1.0.0")

ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3001").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET"],
    allow_headers=["*"],
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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/alerts")
def get_alerts(
    limit: int = Query(50, le=500),
    threat_type: str | None = None,
    hours: int = Query(24, le=168),
) -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            query = "SELECT * FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'"
            params: list[Any] = [hours]

            if threat_type:
                query += " AND threat_type = %s"
                params.append(threat_type)

            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()

    return {"alerts": rows, "count": len(rows)}


@app.get("/alerts/summary")
def alert_summary(hours: int = Query(24, le=168)) -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT threat_type, COUNT(*) as count, AVG(confidence) as avg_confidence
                   FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'
                   GROUP BY threat_type ORDER BY count DESC""",
                [hours],
            )
            rows = cur.fetchall()
    return {"summary": rows}


@app.get("/top-ips")
def top_ips(
    limit: int = Query(10, le=50),
    hours: int = Query(24, le=168),
) -> dict[str, Any]:
    with get_db() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT source_ip, COUNT(*) as alert_count,
                          ARRAY_AGG(DISTINCT threat_type) as threat_types
                   FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'
                   GROUP BY source_ip ORDER BY alert_count DESC LIMIT %s""",
                [hours, limit],
            )
            rows = cur.fetchall()
    return {"top_ips": rows}


@app.get("/traffic/live")
def live_traffic() -> dict[str, Any]:
    r = get_redis()
    try:
        info = r.xinfo_stream("packet_stream")
        return {
            "stream_length": info["length"],
            "first_entry": info.get("first-entry"),
            "last_entry": info.get("last-entry"),
        }
    except redis.exceptions.ResponseError:
        return {"stream_length": 0, "first_entry": None, "last_entry": None}
