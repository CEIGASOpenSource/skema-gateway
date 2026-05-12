-- Minimal seed for testing privatae/001_machine_anchors.sql.
-- machine_anchors has a FK to users(id), so we create a minimal users
-- table sufficient to satisfy the constraint and test inserts.

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
