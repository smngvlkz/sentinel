-- The schema as of 0.4.0, safe to run on a fresh database or on any earlier
-- install: everything is created only if missing, and columns added after
-- 0.1.0 are added to existing tables.

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
    created_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

-- Hostnames learned from DNS answers / HTTP Host / TLS SNI (optional, 0.3.0).
-- Stored only on alerts; learned names never get a standing table.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_name TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS destination_name TEXT;

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_unreviewed ON alerts (timestamp DESC) WHERE reviewed_at IS NULL;

-- Friendly names people give their own devices, e.g. "Living room TV" (0.3.0).
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
