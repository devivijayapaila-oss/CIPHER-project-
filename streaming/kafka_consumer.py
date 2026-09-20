"""
Kafka Consumer — replaces Microsoft Sentinel ingestion + the Azure
Logic App playbook.

For each incoming security event:
  1. Insert it into Postgres (security_events table)
  2. Run it through a simple response policy (simulated IP block)
  3. Print a SOC-style status line

Run this alongside kafka_producer.py — start the consumer first so it's
ready to receive.
"""

import json
import time
from datetime import datetime, timezone

import psycopg2
from kafka import KafkaConsumer

KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
TOPIC_NAME = "network-events"
WINDOW_SECONDS = 10

PG_CONFIG = dict(
    host="localhost",
    port=5432,
    dbname="security_events",
    user="secuser",
    password="secpass",
)

# Response policy — tune these thresholds to taste
BLOCK_THRESHOLD_CONFIDENCE = 0.85
BLOCKED_IPS = set()


def get_db_connection():
    return psycopg2.connect(**PG_CONFIG)


def insert_event(conn, event):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO security_events (
                flow_id, source_ip, destination_ip, attack_type,
                confidence, malicious_probability, anomaly_score,
                severity, top_features, response_status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                event.get("flow_id"),
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("attack_type"),
                event.get("attack_confidence"),
                event.get("malicious_probability"),
                event.get("anomaly_score"),
                event.get("severity"),
                json.dumps(event.get("top_features", [])),
                "none",
            ),
        )
        event_id = cur.fetchone()[0]
    conn.commit()
    return event_id


def apply_response_policy(conn, event_id, event):
    """Simulated automated response — the Logic App / NSG replacement."""
    attack_type = event.get("attack_type", "BENIGN")
    confidence = event.get("attack_confidence", 0) or 0
    source_ip = event.get("source_ip") or f"flow-{event.get('flow_id', 'unknown')}"

    if attack_type == "BENIGN":
        return "none"

    if confidence >= BLOCK_THRESHOLD_CONFIDENCE:
        BLOCKED_IPS.add(source_ip)
        status = f"blocked:{source_ip}"
        print(f"  🛡️  {source_ip} BLOCKED (confidence {confidence:.2%})")
    else:
        status = "flagged"
        print(f"  ⚠️  Flagged for review (confidence {confidence:.2%})")

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE security_events SET response_status = %s WHERE id = %s",
            (status, event_id),
        )
    conn.commit()
    return status


def new_window_state(start_time):
    return {
        "window_start": start_time,
        "total_flows": 0,
        "malicious_flows": 0,
        "ddos_count": 0,
        "portscan_count": 0,
        "anomaly_count": 0,
        "confidence_sum": 0.0,
        "highest_severity": "Low",
        "attack_sources": {},  # ip -> count, for "top_attack_source"
    }


SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def update_window(window, event):
    window["total_flows"] += 1
    attack_type = event.get("attack_type", "BENIGN")
    confidence = event.get("attack_confidence", 0) or 0
    severity = event.get("severity", "Low")
    source_ip = event.get("source_ip") or f"flow-{event.get('flow_id', 'unknown')}"

    if attack_type != "BENIGN":
        window["malicious_flows"] += 1
        if source_ip:
            window["attack_sources"][source_ip] = window["attack_sources"].get(source_ip, 0) + 1

    if attack_type == "DDoS":
        window["ddos_count"] += 1
    elif attack_type == "PortScan":
        window["portscan_count"] += 1

    if event.get("is_anomaly"):
        window["anomaly_count"] += 1

    window["confidence_sum"] += confidence

    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(window["highest_severity"], 0):
        window["highest_severity"] = severity


def flush_window(conn, window, end_time):
    if window["total_flows"] == 0:
        return  # nothing happened this window, skip the insert

    avg_confidence = window["confidence_sum"] / window["total_flows"]
    top_source = max(window["attack_sources"], key=window["attack_sources"].get) if window["attack_sources"] else None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO window_stats (
                window_start, window_end, total_flows, malicious_flows,
                ddos_count, portscan_count, anomaly_count,
                avg_confidence, highest_severity, top_attack_source
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                window["window_start"], end_time, window["total_flows"], window["malicious_flows"],
                window["ddos_count"], window["portscan_count"], window["anomaly_count"],
                avg_confidence, window["highest_severity"], top_source,
            ),
        )
    conn.commit()

    print(
        f"  📊 [window] {window['total_flows']} flows | "
        f"{window['malicious_flows']} malicious | "
        f"highest={window['highest_severity']} | "
        f"top_source={top_source}"
    )


def run_consumer():
    consumer = KafkaConsumer(
        TOPIC_NAME,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="earliest",
        consumer_timeout_ms=1000,  # lets the loop check window expiry even when idle
    )

    conn = get_db_connection()

    print(f"Listening on topic: {TOPIC_NAME}")
    print("-" * 70)

    window_start = datetime.now(timezone.utc)
    window = new_window_state(window_start)

    while True:
        for message in consumer:
            event = message.value
            event_id = insert_event(conn, event)

            severity = event.get("severity", "n/a")
            attack_type = event.get("attack_type", "UNKNOWN")
            print(f"[{event_id}] {attack_type:12} | severity={severity}")

            apply_response_policy(conn, event_id, event)
            update_window(window, event)

            if (datetime.now(timezone.utc) - window_start).total_seconds() >= WINDOW_SECONDS:
                now = datetime.now(timezone.utc)
                flush_window(conn, window, now)
                window_start = now
                window = new_window_state(window_start)

        # Consumer poll timed out (no messages) — still check if window expired
        if (datetime.now(timezone.utc) - window_start).total_seconds() >= WINDOW_SECONDS:
            now = datetime.now(timezone.utc)
            flush_window(conn, window, now)
            window_start = now
            window = new_window_state(window_start)


if __name__ == "__main__":
    run_consumer()