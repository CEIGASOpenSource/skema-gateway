-- Skema Gateway · Local DB · 002_operator_profiles.sql
--
-- Human-readable identity layer for operators (MCP clients calling
-- through the gateway). The existing operator_audit_log records
-- operator_id (UUID) per call; this table gives each one a
-- display_name + icon_slug so the dashboard can show "Claude Code @ home"
-- instead of a UUID prefix.
--
-- Auto-populated on first /mcp call: any operator_id that lands in
-- operator_audit_log without a profiles row gets a placeholder row
-- inserted (display_name = 'operator-<8 chars>', icon_slug = null).
-- The user renames + assigns icon via the dashboard.

CREATE TABLE IF NOT EXISTS operator_profiles (
    operator_id  UUID PRIMARY KEY,
    display_name TEXT NOT NULL,
    icon_slug    TEXT,                       -- 'claude-code' | 'codex' | 'openclaw' | 'hermes' | null
    kind         TEXT,                       -- mirrors mcp_client_tokens.operator_kind
    notes        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operator_profiles_icon
    ON operator_profiles (icon_slug) WHERE icon_slug IS NOT NULL;

COMMENT ON TABLE  operator_profiles IS 'Human-readable display name + icon per operator_id seen by the gateway.';
COMMENT ON COLUMN operator_profiles.icon_slug IS 'Well-known: claude-code, codex, openclaw, hermes. Else null → generic icon.';
