-- AI triage (roadmap Part 2). A local model's opinion on each group of
-- alerts: the alerts with the same rule and ends (with "*" on the side that
-- changes, as the alert manager groups them), joined while each comes within
-- 10 minutes of the last. A group is triaged once it has been quiet for 10
-- minutes. The opinion is stored only here: triage never writes to alerts.

-- Where triage has got to in the alerts table. One row; created on triage's
-- first start at the newest alert then, so turning triage on doesn't triage
-- everything already recorded.
CREATE TABLE IF NOT EXISTS triage_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_alert_id BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS triage (
    id BIGSERIAL PRIMARY KEY,
    threat_type TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    first_alert_id BIGINT NOT NULL UNIQUE,
    last_alert_id BIGINT NOT NULL,
    first_at TIMESTAMPTZ NOT NULL,
    last_at TIMESTAMPTZ NOT NULL,
    alert_count INT NOT NULL,
    -- open: still collecting alerts. waiting: quiet, to be triaged (or tried
    -- again, if the model couldn't be reached). triaged: has a verdict.
    -- not triaged: the model's reply didn't fit the format. skipped: low
    -- severity, or waited too long.
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'waiting', 'triaged', 'not triaged', 'skipped')),
    verdict TEXT CHECK (verdict IN ('likely harmless', 'worth checking', 'likely an attack')),
    reason TEXT,
    model TEXT,
    digest TEXT,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    triaged_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_triage_key ON triage (threat_type, source_ip, destination_ip, last_alert_id DESC);
CREATE INDEX IF NOT EXISTS idx_triage_pending ON triage (status) WHERE status IN ('open', 'waiting');
CREATE INDEX IF NOT EXISTS idx_triage_last_at ON triage (last_at);
