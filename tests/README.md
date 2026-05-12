# Tests

Test layers for skema-gateway. Each layer is independent and runnable on its
own. Higher layers depend on code that has not been written yet.

## Layer 1 — Migration sanity (`migrations/`)

Spins up three ephemeral postgres containers, applies the four migrations
under `db/migrations/`, and asserts:

- All expected tables exist
- TimescaleDB hypertables created
- Foreign keys enforce as intended
- `parallax/001` correctly extends the existing `mcp_client_tokens` schema
- All migrations are idempotent (re-apply is a no-op)

Requires Docker. Containers are named `skema-test-*` and torn down on exit.

```sh
cd tests/migrations
./run.sh
```

## Layer 2 — Key hierarchy round-trip (`crypto/`)

Validates the encryption design in `db/migrations/parallax/002_local_backup.sql`
using pure cryptographic primitives. No database required.

Tests:

- Passphrase derives KEK via Argon2id (v1: m=256 MiB, t=3, p=1)
- Recovery code path wraps the same DEK
- Wrong passphrase / tampered ciphertext rejected by AES-256-GCM auth tag
- Row round-trip through DEK
- Passphrase rotation re-wraps DEK; existing row ciphertext is untouched
- KDF param upgrade — old envelopes with weaker params still decryptable
- Compromise simulation — auditor with salt + params + ciphertext cannot
  unlock the DEK without the passphrase or recovery code

```sh
cd tests/crypto
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python test_key_hierarchy.py
```

Each Argon2id derivation takes ~1 second on a modern machine. Full test run
is ~20 seconds.

## Layers 3-5 — deferred

- **Layer 3** — backup/restore end-to-end through a sync layer (needs gateway
  daemon code)
- **Layer 4** — compromise-simulation against full backup blob set (needs
  Layer 3 fixtures)
- **Layer 5** — trust-path tests (mTLS, SNI proxy, anchor flow — need
  gateway daemon and edge config)
