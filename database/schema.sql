CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    threat_type TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    source_port TEXT,
    destination_port TEXT,
    confidence FLOAT DEFAULT 0,
    detection_source TEXT,
    features JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    window_seconds INT DEFAULT 60,
    total_packets BIGINT,
    total_bytes BIGINT,
    unique_sources INT,
    unique_destinations INT,
    alerts_triggered INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats (timestamp DESC);
