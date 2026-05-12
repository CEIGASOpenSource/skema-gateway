-- ════════════════════════════════════════════════════════════════════════
-- Skema Gateway · Parallax DB · 001_mcp_client_tokens_operator_columns.sql
--
-- Target: per-entity `parallax` database, inside each skema container.
--         Currently bootstrapped from /app/init-db.sql in the skema image.
--         Run against each existing entity's parallax DB and against fresh
--         containers via image rebuild.
--
-- Purpose: Extend the existing `mcp_client_tokens` table with operator-
--          class fields. The table already binds an MCP client to an entity
--          with scope grants; these columns add identity for the operator
--          (which kind of client, anchored to which machine, etc.) so the
--          synaptive handler + CEIGAS gate can authorize against the right
--          actor.
--
-- Idempotent: each ALTER guarded by IF NOT EXISTS. Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE mcp_client_tokens
    ADD COLUMN IF NOT EXISTS operator_kind TEXT;
        -- Values: gateway | claude_code | claude_desktop | lm_studio | cursor | other
        -- NULL for legacy tokens minted before this migration. Should be
        -- backfilled by an out-of-band script reading existing token names.

ALTER TABLE mcp_client_tokens
    ADD COLUMN IF NOT EXISTS machine_anchor_id BIGINT;
        -- Soft ref to privatae.machine_anchors.anchor_id (cross-DB; cannot
        -- be a hard FK because that table lives in privatae, this lives in
        -- per-entity parallax). Token traceability for revoke-by-machine.

ALTER TABLE mcp_client_tokens
    ADD COLUMN IF NOT EXISTS hardware_fingerprint TEXT;
        -- Captured at token bind time. Should match
        -- machine_anchors.hardware_fingerprint on privatae side. Validated
        -- on every gateway request: connecting client's fingerprint must
        -- match the recorded fingerprint, or refuse the call.

ALTER TABLE mcp_client_tokens
    ADD COLUMN IF NOT EXISTS notes JSONB NOT NULL DEFAULT '{}'::jsonb;
        -- Free-form metadata for the operator binding (install OS,
        -- agent version, last-seen-at, etc.).

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_operator_kind
    ON mcp_client_tokens(operator_kind) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_mcp_tokens_anchor
    ON mcp_client_tokens(machine_anchor_id) WHERE revoked_at IS NULL;

COMMENT ON COLUMN mcp_client_tokens.operator_kind IS
    'Type of MCP client: gateway | claude_code | claude_desktop | lm_studio | cursor | other';
COMMENT ON COLUMN mcp_client_tokens.machine_anchor_id IS
    'Soft FK to privatae.machine_anchors.anchor_id — token is bound to that machine';
COMMENT ON COLUMN mcp_client_tokens.hardware_fingerprint IS
    'Machine identity captured at token bind time; verified on each gateway request';
