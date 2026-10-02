CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    threat_type TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    source_port TEXT,
    destination_port TEXT,
    confidence FLOAT DEFAULT 0,
    detection_source TEXT,
    features JSONB,
    -- Hostnames learned from DNS answers / HTTP Host / TLS SNI (optional).
    -- Stored only on alerts; learned names never get a standing table.
    source_name TEXT,
    destination_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_unreviewed ON alerts (timestamp DESC) WHERE reviewed_at IS NULL;

-- Friendly names people give their own devices, e.g. "Living room TV".
-- Joined onto alerts when they're read, so a rename applies to old alerts too.
CREATE TABLE IF NOT EXISTS device_names (
    ip TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    window_seconds INT DEFAULT 60,
    total_packets BIGINT,
    total_bytes BIGINT,
    unique_sources INT,
    unique_destinations INT,
    alerts_triggered INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats (timestamp DESC);
