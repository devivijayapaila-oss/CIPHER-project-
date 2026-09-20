CREATE TABLE IF NOT EXISTS security_events (
    id                  SERIAL PRIMARY KEY,
    event_timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
    flow_id             TEXT,
    source_ip           TEXT,
    destination_ip      TEXT,
    attack_type         TEXT NOT NULL,
    confidence          DOUBLE PRECISION,
    malicious_probability DOUBLE PRECISION,
    anomaly_score       DOUBLE PRECISION,
    severity            TEXT,
    top_features        JSONB,
    response_status     TEXT DEFAULT 'none'
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events (event_timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_attack_type ON security_events (attack_type);

-- 10-second window rollups, populated by the consumer's windowing logic
CREATE TABLE IF NOT EXISTS window_stats (
    id                  SERIAL PRIMARY KEY,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    total_flows         INTEGER,
    malicious_flows     INTEGER,
    ddos_count          INTEGER,
    portscan_count      INTEGER,
    anomaly_count       INTEGER,
    avg_confidence      DOUBLE PRECISION,
    highest_severity    TEXT,
    top_attack_source   TEXT
);
