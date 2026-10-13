-- exeris-caps-session-management V1: sessions and refresh tokens (ADR-099). Idempotent DDL.
--
-- This is the first migration of record: no earlier schema for this capability was applied by any
-- released artefact, so nothing here alters or drops an existing table.
--
-- Tenancy: these tables carry no tenant_id and no row-level security policy. ADR-099 obligation 10
-- keys session records by subject, and subjects are per deployment; tenant membership lives in
-- multi-tenancy and rbac-policy. A session is created at sign-in and rotated by presenting a refresh
-- token, and neither request has a verified tenant to scope by. Isolation between subjects is enforced
-- by the capability's API, whose subject-scoped operations take the subject from the verified
-- principal and put it in every WHERE clause. Deploy these tables in the identity deployment's own
-- schema or database, not beside tenant-scoped tables that other capabilities reach.
--
-- Raw refresh tokens are never stored; token_hash is the lowercase hex SHA-256 of the raw value.

-- Fails fast on a sessions table from a pre-release layout (it has transition_until); IF NOT EXISTS
-- below would otherwise skip it and the repository would fail on its first statement.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema()
                 AND table_name = 'sessions' AND column_name = 'transition_until') THEN
        RAISE EXCEPTION 'sessions has a transition_until column: pre-release layout, recreate the table before applying V1';
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS sessions (
    id                UUID PRIMARY KEY,
    subject_id        UUID         NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    expires_at        TIMESTAMPTZ  NOT NULL,
    last_active_at    TIMESTAMPTZ  NOT NULL,
    revoked_at        TIMESTAMPTZ,
    revocation_reason VARCHAR(32),
    user_agent        VARCHAR(512),
    ip_address        VARCHAR(64),
    CONSTRAINT chk_sessions_lifetime CHECK (expires_at > created_at),
    CONSTRAINT chk_sessions_revocation CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_sessions_subject_active
    ON sessions (subject_id, created_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY,
    session_id  UUID        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash  CHAR(64)    NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session
    ON refresh_tokens (session_id);
