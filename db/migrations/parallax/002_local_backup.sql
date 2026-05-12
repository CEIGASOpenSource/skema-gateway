-- ════════════════════════════════════════════════════════════════════════
-- Skema Gateway · Parallax DB · 002_local_backup.sql
--
-- Target: per-entity `parallax` database, inside each skema container.
--
-- Purpose: Encrypted backup of the user's local-PG world model. The hosted
--          side stores ciphertext only; it cannot read user data even under
--          subpoena or compromise. Recovery on a new machine requires the
--          user's passphrase OR their offline recovery code.
--
-- Cryptography:
--   passphrase  ─argon2id(salt, params)─►  KEK ──► wraps DEK (AES-256-GCM)
--   recovery    ─argon2id(salt, params)─►  KEK'──► wraps the same DEK
--   DEK ──► encrypts every backed-up row (AES-256-GCM, per-row nonce)
--
-- Recovery requires only what lives on this hosted side: the wrapped DEK,
-- the KDF salt and params, and the encrypted row blobs. No plaintext key
-- material is stored anywhere on the server.
--
-- DEK rotation (re-encrypting all blobs under a new DEK) is out of scope
-- for v1. Passphrase / recovery-code rotation (re-wrapping the same DEK
-- under a new KEK) is supported via `is_active` + `superseded_at`.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- ════════════════════════════════════════════════════════════════════════


-- ────────────────────────────────────────────────────────────────────────
-- LOCAL_BACKUP_ENVELOPE — one row per active wrapping of the DEK.
-- v1 expects exactly two active rows per entity:
--   - kdf_source = 'passphrase'      (user's chosen passphrase)
--   - kdf_source = 'recovery_code'   (offline code printed at install)
-- Either row unlocks the same DEK. After a rotation, the prior row stays
-- with is_active=FALSE for forensic/audit purposes.
-- ────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS local_backup_envelope (
    envelope_id      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    kdf_source       TEXT            NOT NULL
        CHECK (kdf_source IN ('passphrase','recovery_code')),

    -- Wrapped DEK and the AEAD bits needed to unwrap it
    wrapped_dek      BYTEA           NOT NULL,
    wrap_nonce       BYTEA           NOT NULL,
    wrap_auth_tag    BYTEA           NOT NULL,
    wrap_algo        TEXT            NOT NULL DEFAULT 'aes-256-gcm',

    -- KDF parameters (per-row, so we can upgrade defaults later without
    -- forcing every user to re-derive). v1 default: argon2id m=256MiB t=3 p=1
    kdf_algo         TEXT            NOT NULL DEFAULT 'argon2id',
    kdf_salt         BYTEA           NOT NULL,
    kdf_params       JSONB           NOT NULL,
        -- {"m_kib": 262144, "t": 3, "p": 1} for argon2id v1 defaults

    is_active        BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    superseded_at    TIMESTAMPTZ
);

-- Exactly one active envelope per kdf_source. Rotation = mark old inactive,
-- then insert new. Partial unique index gives us this for free.
CREATE UNIQUE INDEX IF NOT EXISTS idx_local_backup_envelope_active
    ON local_backup_envelope(kdf_source)
    WHERE is_active = TRUE;

COMMENT ON TABLE local_backup_envelope IS
    'Wrapped DEKs for the user''s local-PG backup. One active row per kdf_source. Recovery reads kdf_salt+kdf_params, the user supplies passphrase or recovery code, the KEK is derived locally, and the DEK is unwrapped client-side.';
COMMENT ON COLUMN local_backup_envelope.kdf_params IS
    'Argon2id parameters: m_kib (memory in KiB), t (iterations), p (parallelism). v1 defaults: m_kib=262144, t=3, p=1.';
COMMENT ON COLUMN local_backup_envelope.is_active IS
    'FALSE after rotation. Inactive rows kept for audit; superseded_at records when.';


-- ────────────────────────────────────────────────────────────────────────
-- LOCAL_BACKUP_BLOB — per-row encrypted backup of mutable local-PG rows.
-- One blob per source row. Sync layer reads local PG, encrypts each
-- changed row under the active DEK, and INSERTs the resulting blob here.
-- On restore, the gateway decrypts each blob and INSERTs into a fresh
-- local PG.
--
-- Versioning: row_version is monotonic per (resource_kind, resource_pk).
-- A new version supersedes the prior one via superseded_at. Old versions
-- are retained for now (point-in-time restore + forensics); a retention
-- policy is future work.
--
-- Note: blob_path-referenced binary files on local (PDFs, videos) are
-- NOT backed up by this table in v1. They live under /var/lib/skema/blobs/
-- and are the user's responsibility until that decision is taken.
-- ────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS local_backup_blob (
    blob_id           BIGSERIAL       PRIMARY KEY,

    resource_kind     TEXT            NOT NULL,
        -- memories | sources | source_chunks | memory_links | memory_shares |
        -- user_context | provisioning | operator_audit_log | principals
    resource_pk       TEXT            NOT NULL,
        -- canonical PK of the source row serialized to text
        -- (UUID for most, composite "memory_id:t_observed" for memories hypertable)

    -- AES-256-GCM ciphertext over the serialized plaintext row
    nonce             BYTEA           NOT NULL,
    ciphertext        BYTEA           NOT NULL,
    auth_tag          BYTEA           NOT NULL,
    enc_algo          TEXT            NOT NULL DEFAULT 'aes-256-gcm',

    -- Sync metadata
    plaintext_hash    BYTEA           NOT NULL,
        -- sha256(plaintext) — sync diff without server-side decrypt
    row_version       BIGINT          NOT NULL,
        -- monotonic per (resource_kind, resource_pk); conflict detection

    created_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    superseded_at     TIMESTAMPTZ,

    UNIQUE (resource_kind, resource_pk, row_version)
);

CREATE INDEX IF NOT EXISTS idx_local_backup_blob_resource
    ON local_backup_blob(resource_kind, resource_pk, row_version DESC);
CREATE INDEX IF NOT EXISTS idx_local_backup_blob_active
    ON local_backup_blob(resource_kind, created_at DESC)
    WHERE superseded_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_local_backup_blob_plaintext_hash
    ON local_backup_blob(plaintext_hash);

COMMENT ON TABLE local_backup_blob IS
    'Per-row encrypted backup of the user''s local PG. Hosted side stores only ciphertext + sync metadata; cannot decrypt without the user''s passphrase or recovery code.';
COMMENT ON COLUMN local_backup_blob.resource_pk IS
    'PK of the source row, serialized to text. UUID for most tables; composite "<memory_id>:<t_observed>" for the memories hypertable.';
COMMENT ON COLUMN local_backup_blob.plaintext_hash IS
    'sha256 of plaintext, computed locally before encryption. Lets the sync layer diff what has changed without the server decrypting anything.';
