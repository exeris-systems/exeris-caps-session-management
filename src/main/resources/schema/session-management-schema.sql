-- DDL Schema for exeris-caps-session-management
-- ADR-099: Layer 5 Domain Primitive session storage & refresh token rotation

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    user_agent VARCHAR(512),
    ip_address VARCHAR(64),
    transition_until TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_subject_active
    ON sessions (subject_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    transition_until TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session
    ON refresh_tokens (session_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash
    ON refresh_tokens (token_hash);
