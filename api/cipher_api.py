"""
CIPHER API — bridges Postgres to the React frontend.

React can't talk to Postgres directly (no client-side DB driver), so this
exposes the exact same data the Streamlit dashboard already queries, as
JSON over HTTP. Run this alongside Kafka/Postgres; point the React app's
API base URL at wherever this ends up running.

Run with: uvicorn cipher_api:app --reload --host 0.0.0.0 --port 8000
"""

from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

PG_CONFIG = dict(
    host="localhost",
    port=5432,
    dbname="security_events",
    user="secuser",
    password="secpass",
)

app = FastAPI(title="CIPHER API")

# Allow the React dev server (and any origin, for simplicity during dev)
# to call this API. Tighten this before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    return psycopg2.connect(**PG_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)


def row_to_json(row):
    """Convert datetime fields to ISO strings so they serialize cleanly."""
    out = dict(row)
    for key, value in out.items():
        if isinstance(value, datetime):
            out[key] = value.isoformat()
    return out


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/events")
def get_events(limit: int = Query(50, le=500), attack_type: Optional[str] = None):
    conn = get_connection()
    with conn.cursor() as cur:
        if attack_type:
            cur.execute(
                """
                SELECT id, event_timestamp, flow_id, source_ip, destination_ip,
                       attack_type, confidence, malicious_probability, anomaly_score,
                       severity, top_features, response_status
                FROM security_events
                WHERE attack_type = %s
                ORDER BY event_timestamp DESC
                LIMIT %s
                """,
                (attack_type, limit),
            )
        else:
            cur.execute(
                """
                SELECT id, event_timestamp, flow_id, source_ip, destination_ip,
                       attack_type, confidence, malicious_probability, anomaly_score,
                       severity, top_features, response_status
                FROM security_events
                ORDER BY event_timestamp DESC
                LIMIT %s
                """,
                (limit,),
            )
        rows = cur.fetchall()
    conn.close()
    return [row_to_json(r) for r in rows]


@app.get("/api/windows")
def get_windows(limit: int = Query(50, le=500)):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT window_start, window_end, total_flows, malicious_flows,
                   ddos_count, portscan_count, anomaly_count,
                   avg_confidence, highest_severity, top_attack_source
            FROM window_stats
            ORDER BY window_start DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    conn.close()
    # Return oldest-first so charts plot left-to-right correctly
    return [row_to_json(r) for r in reversed(rows)]


@app.get("/api/summary")
def get_summary():
    """Pre-aggregated KPIs — mirrors the Streamlit dashboard's top-row metrics."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS total FROM security_events")
        total_flows = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS c FROM security_events WHERE attack_type != 'BENIGN'")
        malicious_flows = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM security_events WHERE response_status LIKE 'blocked%%'")
        blocked = cur.fetchone()["c"]

        cur.execute(
            "SELECT severity FROM security_events ORDER BY event_timestamp DESC LIMIT 1"
        )
        latest = cur.fetchone()
        current_threat = latest["severity"] if latest else "n/a"
    conn.close()

    return {
        "total_flows": total_flows,
        "malicious_flows": malicious_flows,
        "blocked": blocked,
        "current_threat_level": current_threat,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }
