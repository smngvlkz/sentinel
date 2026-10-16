-- Notifications (roadmap 1.6). The notifier reads new alerts by id and sends
-- them to the channels set up in config/notifications.toml.

-- Where the notifier has got to in the alerts table. One row; created on the
-- notifier's first start at the newest alert then, so turning notifications
-- on doesn't send everything already recorded.
CREATE TABLE IF NOT EXISTS notifier_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_alert_id BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per message per channel. The message is stored as sent, so a retry
-- sends exactly the same text. kind: alert, digest or test.
CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    channel TEXT NOT NULL,
    alert_ids BIGINT[] NOT NULL DEFAULT '{}',
    message JSONB NOT NULL,
    -- pending (not sent yet, or waiting to retry), sent, or failed (gave up)
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
);
CREATE SEQUENCE IF NOT EXISTS notification_message_seq;
CREATE INDEX IF NOT EXISTS idx_notifications_pending ON notifications (next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications (created_at);

-- Alerts held back by quiet hours or the hourly limit, summarised in the
-- next digest.
CREATE TABLE IF NOT EXISTS notification_digest (
    alert_id BIGINT PRIMARY KEY,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- "Send a test notification" from the dashboard: the API adds a row, the
-- notifier sends the test and marks it handled.
CREATE TABLE IF NOT EXISTS notification_tests (
    id BIGSERIAL PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    handled_at TIMESTAMPTZ
);
