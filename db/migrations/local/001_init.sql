-- ════════════════════════════════════════════════════════════════════════
-- Skema Gateway · Local PG · 001_init.sql
--
-- Purpose:  The user's world model. Local-only schema for the personal
--           cloud gateway. Source of truth for the user's memory, context,
--           and operator audit. Never holds codebooks, proprietary skema
--           logic, or hosted-side state.
--
-- Scope:    The four actor classes from the Skema architecture:
--             human     — principal, OAuth-authenticated
--             entity    — user's reflection on hosted skema container
--             operator  — MCP-aware client (CC, Claude Desktop, LM Studio, ...)
--             external  — connector sources (YouTube, Gmail, GitHub, ...)
--
-- Embedding strategy (dual, per testing):
--             memories       semantic + purpose   →  nomic-embed-text (768)
--             source_chunks  semantic (long)      →  mxbai-embed-large (1024)
--             source_chunks  purpose (short)      →  nomic-embed-text (768)
--
-- Extensions: pgcrypto, vector, timescaledb
-- ════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS timescaledb;


-- ════════════════════════════════════════════════════════════════════════
-- PRINCIPALS — actor identities participating in this user's world model.
-- Replaces the plain-text "owned_by" pattern. Multi-user / multi-entity /
-- future-circles all key off this table without schema rewrite.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE principals (
    principal_id     UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    kind             TEXT            NOT NULL CHECK (kind IN ('human','entity','operator','external')),
    identifier       TEXT            NOT NULL,
    display_name     TEXT,
    metadata         JSONB           NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ,
    UNIQUE (kind, identifier)
);
CREATE INDEX idx_principals_kind ON principals(kind);

COMMENT ON TABLE principals IS
    'Four actor classes — human, entity, operator, external — participating in this world model';


-- ════════════════════════════════════════════════════════════════════════
-- SOURCES — the things memories come FROM.
-- Polymorphic by (kind, modality). Large blobs live on disk under
-- /var/lib/skema/blobs/<sha-prefix>/<sha256>, referenced here by hash.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE sources (
    source_id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    kind                   TEXT         NOT NULL,
        -- cc_session | pdf | url | email | file | transcript | youtube |
        -- github | calendar | image | audio | video | screenshot | voice_note |
        -- chat_episode | sketch | code_snippet | ...
    modality               TEXT         NOT NULL DEFAULT 'text'
        CHECK (modality IN ('text','image','audio','video','mixed')),

    identifier             TEXT         NOT NULL,                            -- canonical id within kind
    title                  TEXT,
    uri                    TEXT,                                             -- original URL or file path
    blob_path              TEXT,                                             -- filesystem path to raw blob
    blob_sha256            TEXT,                                             -- integrity + dedupe
    byte_size              BIGINT,
    mime_type              TEXT,
    metadata               JSONB        NOT NULL DEFAULT '{}'::jsonb,        -- source-kind-specific fields

    owner_principal_id     UUID         NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    creator_principal_id   UUID                  REFERENCES principals(principal_id) ON DELETE SET NULL,

    t_source               TIMESTAMPTZ,                                       -- when the source itself was created
    t_ingested             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    status                 TEXT         NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','archived','deleted')),

    UNIQUE (kind, identifier)
);
CREATE INDEX idx_sources_owner       ON sources(owner_principal_id);
CREATE INDEX idx_sources_kind        ON sources(kind);
CREATE INDEX idx_sources_modality    ON sources(modality);
CREATE INDEX idx_sources_t_source    ON sources(t_source DESC);
CREATE INDEX idx_sources_blob_sha    ON sources(blob_sha256) WHERE blob_sha256 IS NOT NULL;
CREATE INDEX idx_sources_active      ON sources(status) WHERE status = 'active';


-- ════════════════════════════════════════════════════════════════════════
-- SOURCE_CHUNKS — embeddable units of large sources.
-- Always text-anchored: every chunk has text content, however derived.
-- Visual-native embeddings reserved for v2 (sibling table or added column).
-- Dual embeddings: mxbai for content (long), nomic for purpose context (short).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE source_chunks (
    chunk_id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id           UUID         NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
    chunk_idx           INT          NOT NULL,
    content             TEXT         NOT NULL,

    modality            TEXT         NOT NULL DEFAULT 'text'
        CHECK (modality IN ('text','image','audio','video','mixed')),
    derived_from        TEXT,
        -- native_text | ocr | asr_transcript | caption | frame_extract | summary

    locator             JSONB        NOT NULL DEFAULT '{}'::jsonb,
        -- page#, line range, timestamp range, bbox, etc.

    embedding_semantic  VECTOR(1024),                                         -- mxbai-embed-large
    embedding_purpose   VECTOR(768),                                          -- nomic-embed-text

    UNIQUE (source_id, chunk_idx)
);
CREATE INDEX idx_chunks_source     ON source_chunks(source_id);
CREATE INDEX idx_chunks_modality   ON source_chunks(modality);
CREATE INDEX idx_chunks_emb_sem    ON source_chunks USING hnsw (embedding_semantic vector_cosine_ops);
CREATE INDEX idx_chunks_emb_pur    ON source_chunks USING hnsw (embedding_purpose  vector_cosine_ops);


-- ════════════════════════════════════════════════════════════════════════
-- MEMORIES — distilled observations, claims, decisions, principles.
-- What the entity (or user) KNOWS, not what's been READ.
-- Bi-temporal (t_valid_from/t_valid_to/superseded_by) for "what was true on
-- date X" queries. TimescaleDB hypertable on t_observed; PK is composite
-- (memory_id, t_observed) — see superseded_by/memory_links/memory_shares
-- which use soft references because hypertables don't support FK to a
-- non-time-key column.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE memories (
    memory_id              UUID         NOT NULL DEFAULT gen_random_uuid(),

    kind                   TEXT         NOT NULL,
        -- teaching | decision | preference | relationship | fact | idea |
        -- goal | principle | observation | emotion | hard_rule | coding_pattern

    content                TEXT         NOT NULL,

    -- Dual embeddings: both nomic, memory content is always short.
    embedding_semantic     VECTOR(768),                                       -- on content
    embedding_purpose      VECTOR(768),                                       -- on purpose+tags+scope+kind

    -- Provenance — who owns it, who created it, what source it came from, why
    owner_principal_id     UUID         NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    creator_principal_id   UUID                  REFERENCES principals(principal_id) ON DELETE SET NULL,
    source_id              UUID                  REFERENCES sources(source_id) ON DELETE SET NULL,
    purpose                TEXT,
        -- learning | decision_log | reference | preference | principle |
        -- planning | reflection | metacognition

    -- Bi-temporal
    t_observed             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    t_valid_from           TIMESTAMPTZ,                                       -- when fact became true
    t_valid_to             TIMESTAMPTZ,                                       -- NULL = currently valid
    superseded_by          UUID,                                              -- soft ref to memories.memory_id

    -- Quality / state
    confidence             TEXT         NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('low','medium','high')),
    status                 TEXT         NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','archived','resolved','retracted')),
    importance             REAL         NOT NULL DEFAULT 1.0,

    -- Free-form
    tags                   TEXT[],
    metadata               JSONB        NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (memory_id, t_observed)
);

-- TimescaleDB hypertable
SELECT create_hypertable('memories', 't_observed',
    chunk_time_interval => INTERVAL '1 month',
    if_not_exists       => TRUE);

CREATE INDEX idx_memories_owner       ON memories(owner_principal_id, t_observed DESC);
CREATE INDEX idx_memories_kind        ON memories(kind, t_observed DESC);
CREATE INDEX idx_memories_t_valid     ON memories(t_valid_from, t_valid_to);
CREATE INDEX idx_memories_source      ON memories(source_id);
CREATE INDEX idx_memories_active      ON memories(status, t_observed DESC)
    WHERE status = 'active' AND t_valid_to IS NULL;
CREATE INDEX idx_memories_purpose     ON memories(purpose) WHERE purpose IS NOT NULL;
CREATE INDEX idx_memories_tags        ON memories USING gin (tags);
CREATE INDEX idx_memories_emb_sem     ON memories USING hnsw (embedding_semantic vector_cosine_ops);
CREATE INDEX idx_memories_emb_pur     ON memories USING hnsw (embedding_purpose  vector_cosine_ops);


-- ════════════════════════════════════════════════════════════════════════
-- MEMORY_LINKS — typed graph edges between memories.
-- Direction convention: from_memory is the LATER fact, to_memory is EARLIER.
-- A 'supersedes' edge from F2 to F1 means F2 replaces F1.
-- Soft references because memories is a hypertable.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE memory_links (
    link_id         UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    from_memory     UUID            NOT NULL,                                  -- soft ref → memories.memory_id
    to_memory       UUID            NOT NULL,                                  -- soft ref → memories.memory_id
    kind            TEXT            NOT NULL
        CHECK (kind IN ('supersedes','contradicts','refines','references','derived_from','relates_to')),
    confidence      REAL            NOT NULL DEFAULT 0.8,
    rationale       TEXT,
    detected_by     TEXT,                                                      -- which pipeline / pass / agent created this edge
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    UNIQUE (from_memory, to_memory, kind)
);
CREATE INDEX idx_memory_links_from    ON memory_links(from_memory);
CREATE INDEX idx_memory_links_to      ON memory_links(to_memory);
CREATE INDEX idx_memory_links_kind    ON memory_links(kind);


-- ════════════════════════════════════════════════════════════════════════
-- MEMORY_SHARES — explicit cross-principal sharing.
-- Empty in single-user installs. Circles module flips this on by inserting
-- rows; retrieval API checks: owner_principal_id = ? OR EXISTS(memory_shares).
-- Soft ref on memory_id (memories is a hypertable).
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE memory_shares (
    memory_id       UUID            NOT NULL,                                  -- soft ref → memories.memory_id
    shared_with     UUID            NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    permission      TEXT            NOT NULL
        CHECK (permission IN ('read','write','comment')),
    granted_by      UUID            NOT NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
    granted_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    PRIMARY KEY (memory_id, shared_with)
);


-- ════════════════════════════════════════════════════════════════════════
-- USER_CONTEXT — operating state, not memory.
-- Scope reflects the four-actor model: global / principal / operator / session.
-- Used for preferences, recent selections, dashboard state, etc.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE user_context (
    key                         TEXT          NOT NULL,
    scope                       TEXT          NOT NULL,                        -- global | principal:<id> | operator:<id> | session:<id>
    value                       JSONB         NOT NULL,
    updated_at                  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_by_principal_id     UUID          REFERENCES principals(principal_id) ON DELETE SET NULL,
    PRIMARY KEY (key, scope)
);


-- ════════════════════════════════════════════════════════════════════════
-- PROVISIONING — machine anchoring + cached offline auth.
-- Gateway owns reads/writes. Keys: machine_cert, anchor_state, bound_entity,
-- offline_auth_cache, last_online_at, ...
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE provisioning (
    key             TEXT            PRIMARY KEY,
    value           JSONB           NOT NULL,
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);


-- ════════════════════════════════════════════════════════════════════════
-- OPERATOR_AUDIT_LOG — tamper-evident local mirror of every gateway-authorized
-- action. Each row signed with HMAC over preceding fields. Hypertable.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE operator_audit_log (
    log_id              BIGSERIAL,
    operator_id         UUID            NOT NULL,
    entity_id           TEXT            NOT NULL,
    source_domain       TEXT            NOT NULL,
    target_domain       TEXT            NOT NULL,
    action              TEXT            NOT NULL,
    params              JSONB,
    result              JSONB,
    ceigas_crossing_id  UUID,
    signature           TEXT,                                                  -- HMAC-SHA256 over preceding fields
    occurred_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (log_id, occurred_at)
);
SELECT create_hypertable('operator_audit_log', 'occurred_at',
    chunk_time_interval => INTERVAL '1 week',
    if_not_exists       => TRUE);

CREATE INDEX idx_audit_operator    ON operator_audit_log(operator_id, occurred_at DESC);
CREATE INDEX idx_audit_entity      ON operator_audit_log(entity_id, occurred_at DESC);
CREATE INDEX idx_audit_action      ON operator_audit_log(action, occurred_at DESC);


-- ════════════════════════════════════════════════════════════════════════
-- SYNC_STATE — incremental sync tracking between local PG and hosted skema.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE sync_state (
    resource_kind   TEXT            NOT NULL,                                  -- memories | sources | source_chunks
    direction       TEXT            NOT NULL
        CHECK (direction IN ('pull','push')),
    last_sync_at    TIMESTAMPTZ,
    last_cursor     TEXT,
    status          TEXT            NOT NULL DEFAULT 'idle'
        CHECK (status IN ('idle','running','error','paused')),
    error_detail    TEXT,
    PRIMARY KEY (resource_kind, direction)
);


-- ════════════════════════════════════════════════════════════════════════
-- SEED — the user's own principal row.
-- Gateway anchor flow UPDATEs identifier/display_name on first successful auth.
-- ════════════════════════════════════════════════════════════════════════
INSERT INTO principals (kind, identifier, display_name, metadata)
VALUES ('human', 'self', 'self', '{"seed":"init_pending_anchor"}'::jsonb)
ON CONFLICT (kind, identifier) DO NOTHING;
