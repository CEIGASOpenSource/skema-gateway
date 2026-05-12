-- ════════════════════════════════════════════════════════════════════════
-- Skema Gateway · Privatae DB · 001_machine_anchors.sql
--
-- Target: the central `privatae` database (alongside users, operator_entities,
--         entity_endpoints, enrollment_tokens, etc.)
--
-- Purpose: Machine-anchor flow for Skema Gateway installs.
--          When a user signs up at privatae.ai and reaches the install step,
--          the checkout page mints a short-TTL anchor code. The Skema
--          Gateway installer on the user's machine redeems that code in
--          exchange for a machine-bound, CA-signed cert. One row per mint.
--
-- Lifecycle:
--   1. User completes checkout → row INSERT with status='pending',
--      expires_at=now+10min, anchor_code_hash=sha256(displayed_code)
--   2. User pastes code into installer → installer POSTs to edge with
--      (code, hardware_fingerprint) → edge validates code+TTL → row UPDATE:
--      status='redeemed', redeemed_at=now(), redeemed_from_ip,
--      hardware_fingerprint, issued_cert_serial, issued_cert_subject_cn
--   3. Anchor codes that expire without redemption → status='expired'
--      (via scheduled job over expires_at < now() AND status='pending')
--   4. Revocation: operator pulls cert + sets status='revoked'.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS machine_anchors (
    anchor_id              BIGSERIAL     PRIMARY KEY,

    -- Who's anchoring (FK to existing users + soft ref to operator_entities)
    user_id                INTEGER       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_email             TEXT          NOT NULL,                         -- denormalized for fast lookup / debug
    entity_id              INTEGER       NOT NULL,                         -- which entity this machine binds to (soft ref — entities live on parallax side)

    -- The anchor code itself (one-time, short-lived, hashed)
    anchor_code_hash       TEXT          NOT NULL,                         -- sha256(plaintext code); plaintext never stored
    issued_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    expires_at             TIMESTAMPTZ   NOT NULL,                         -- ~10 min TTL from issued_at

    -- Redemption state
    status                 TEXT          NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','redeemed','expired','revoked')),
    redeemed_at            TIMESTAMPTZ,
    redeemed_from_ip       INET,
    hardware_fingerprint   TEXT,                                            -- captured at redemption from the installer

    -- Cert minted on redemption
    issued_cert_serial     TEXT,                                            -- CA-signed cert serial number
    issued_cert_subject_cn TEXT,                                            -- e.g. "operator:<uuid>"

    -- Operator class binding (matches mcp_client_tokens.operator_kind on parallax side)
    operator_kind          TEXT,                                            -- gateway | claude_code | claude_desktop | lm_studio | cursor | other
    metadata               JSONB         NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_machine_anchors_code_pending
    ON machine_anchors(anchor_code_hash) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_machine_anchors_user
    ON machine_anchors(user_id);
CREATE INDEX IF NOT EXISTS idx_machine_anchors_entity
    ON machine_anchors(entity_id);
CREATE INDEX IF NOT EXISTS idx_machine_anchors_status
    ON machine_anchors(status);
CREATE INDEX IF NOT EXISTS idx_machine_anchors_expires_pending
    ON machine_anchors(expires_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_machine_anchors_cert_serial
    ON machine_anchors(issued_cert_serial) WHERE issued_cert_serial IS NOT NULL;

COMMENT ON TABLE machine_anchors IS
    'One-time anchor codes minted at privatae.ai checkout; redeemed by Skema Gateway installer to receive a machine-bound CA-signed cert. Pairs with mcp_client_tokens on each parallax-side skema container (cross-DB soft ref via anchor_id <-> machine_anchor_id).';
COMMENT ON COLUMN machine_anchors.anchor_code_hash IS
    'sha256(plaintext code shown to user). Plaintext NEVER stored. Lookup by hash on redemption.';
COMMENT ON COLUMN machine_anchors.entity_id IS
    'Soft ref to the entity this machine binds to. Entities live on parallax-side DBs (different database from this table).';
