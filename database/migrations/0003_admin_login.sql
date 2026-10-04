-- One admin password for the dashboard (roadmap 1.3), its login sessions,
-- and the lockout after repeated wrong passwords. All empty until a password
-- is set; until then the dashboard stays open on this machine, as before.

-- At most one row. argon2id hash, never the password.
CREATE TABLE IF NOT EXISTS admin_password (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    password_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The browser holds a random token in a cookie; only its SHA-256 is stored,
-- so a copy of the database can't be used to log in.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- Consecutive wrong passwords and how long logins are refused for. One row:
-- it's a one-user tool, so the limit is on all login attempts together.
CREATE TABLE IF NOT EXISTS login_lockout (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    failures INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ
);
