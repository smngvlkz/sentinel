"""Dashboard API - FastAPI endpoints for the monitoring dashboard."""

import os
import json
from datetime import datetime, timedelta

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
import redis
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SentinelAI Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

POSTGRES_DSN = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "dbname": os.getenv("POSTGRES_DB", "sentinel_ai"),
    "user": os.getenv("POSTGRES_USER", "sentinel"),
    "password": os.getenv("POSTGRES_PASSWORD", "changeme"),
}


def get_db():
    conn = psycopg2.connect(**POSTGRES_DSN)
    conn.autocommit = True
    return conn


def get_redis():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/alerts")
def get_alerts(
    limit: int = Query(50, le=500),
    threat_type: str | None = None,
    hours: int = Query(24, le=168),
):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        query = "SELECT * FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'"
        params = [hours]

        if threat_type:
            query += " AND threat_type = %s"
            params.append(threat_type)

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()

    conn.close()
    return {"alerts": rows, "count": len(rows)}


@app.get("/alerts/summary")
def alert_summary(hours: int = Query(24, le=168)):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT threat_type, COUNT(*) as count, AVG(confidence) as avg_confidence
               FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'
               GROUP BY threat_type ORDER BY count DESC""",
            [hours],
        )
        rows = cur.fetchall()
    conn.close()
    return {"summary": rows}


@app.get("/top-ips")
def top_ips(limit: int = Query(10, le=50), hours: int = Query(24, le=168)):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT source_ip, COUNT(*) as alert_count,
                      ARRAY_AGG(DISTINCT threat_type) as threat_types
               FROM alerts WHERE timestamp > NOW() - INTERVAL '%s hours'
               GROUP BY source_ip ORDER BY alert_count DESC LIMIT %s""",
            [hours, limit],
        )
        rows = cur.fetchall()
    conn.close()
    return {"top_ips": rows}


@app.get("/traffic/live")
def live_traffic():
    """Get current packet stream stats from Redis."""
    r = get_redis()
    stream_info = r.xinfo_stream("packet_stream")
    return {
        "stream_length": stream_info["length"],
        "first_entry": stream_info.get("first-entry"),
        "last_entry": stream_info.get("last-entry"),
    }
