-- Minimal seed for testing parallax/001 + parallax/002 migrations.
-- Mirrors the production mcp_client_tokens definition from the entity
-- skema container's init-db.sql so the ALTER TABLE in parallax/001 has
-- the expected base columns to extend.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS mcp_client_tokens (
    id              SERIAL PRIMARY KEY,
    entity_id       INT NOT NULL,
    name            TEXT NOT NULL,
    token_hash      BYTEA NOT NULL,
    url_handle      TEXT NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT ARRAY['shape'],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_mcp_token_hash_active
    ON mcp_client_tokens (token_hash) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_mcp_handle_active
    ON mcp_client_tokens (url_handle) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_entity
    ON mcp_client_tokens (entity_id) WHERE revoked_at IS NULL;
