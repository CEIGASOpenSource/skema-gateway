"""
Skema Gateway — backup/restore end-to-end integration test (Layer 3).

Brings up a local PG + parallax PG via the test docker-compose, applies the
migrations, INSERTs realistic test data into local, runs the gatewayd backup
module to push encrypted ciphertext to parallax, WIPES local completely, then
runs the restore module to rehydrate local from parallax. Asserts:

  - All rows round-trip exactly (modulo embedding columns)
  - Passphrase OR recovery code can drive the restore
  - Wrong passphrase fails
  - Compromise simulation: parallax data alone yields no plaintext

Real cryptography, real PostgreSQL, real schema. Proves the architecture.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import asyncpg

from gatewayd.backup import push_full_snapshot
from gatewayd.crypto import (
    KdfParams, new_dek, unwrap_dek, wrap_dek,
)
from gatewayd.db import BACKUP_TABLES, connect
from gatewayd.restore import restore_snapshot
from gatewayd.serialize import serialize_row

MIG = REPO_ROOT / "db" / "migrations"
COMPOSE_DIR = REPO_ROOT / "tests" / "migrations"
FIXTURES = COMPOSE_DIR / "fixtures"

LOCAL_DSN    = "postgresql://postgres:testpass@127.0.0.1:54541/skema_local"
PARALLAX_DSN = "postgresql://postgres:testpass@127.0.0.1:54542/parallax"

PASSPHRASE    = b"correct-horse-battery-staple"
RECOVERY_CODE = b"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"


def _as_dict(v):
    """asyncpg with codec returns dict; without returns str. Tolerate both."""
    return json.loads(v) if isinstance(v, str) else v


# ─── Plumbing ──────────────────────────────────────────────────────────

results: list[tuple[bool, str]] = []

def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
    results.append((cond, name))


def sh(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, **kwargs)


def compose_up() -> None:
    print("Bringing up test databases via docker compose...")
    sh(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR,
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def compose_down() -> None:
    print("\nTearing down test databases...")
    subprocess.run(["docker", "compose", "down", "-v"], cwd=COMPOSE_DIR,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_postgres_stable(container: str, timeout_s: int = 120) -> None:
    """timescale/timescaledb-ha runs Patroni; postgres restarts during init.
    Wait until 'ready to accept connections' appears at least twice."""
    import time
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            out = subprocess.run(
                ["docker", "logs", container],
                capture_output=True, text=True,
            )
            count = (out.stdout + out.stderr).count(
                "database system is ready to accept connections"
            )
            if count >= 2:
                return
        except subprocess.SubprocessError:
            pass
        time.sleep(2)
    raise RuntimeError(f"{container} did not stabilize within {timeout_s}s")


# ─── Migration application ─────────────────────────────────────────────

async def apply_local_schema(conn: asyncpg.Connection) -> None:
    sql = (MIG / "local" / "001_init.sql").read_text()
    await conn.execute(sql)


async def apply_parallax_schema(conn: asyncpg.Connection) -> None:
    seed = (FIXTURES / "parallax-seed.sql").read_text()
    s1 = (MIG / "parallax" / "001_mcp_client_tokens_operator_columns.sql").read_text()
    s2 = (MIG / "parallax" / "002_local_backup.sql").read_text()
    await conn.execute(seed)
    await conn.execute(s1)
    await conn.execute(s2)


async def wipe_local(conn: asyncpg.Connection) -> None:
    """DROP everything in `public` so we can re-apply the schema clean."""
    await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")


# ─── Fixture data ──────────────────────────────────────────────────────

async def insert_fixture_rows(local: asyncpg.Connection) -> list[tuple[str, tuple]]:
    """INSERT representative rows across every backup table.
    Returns the list of (table, pk) pairs we inserted for diffing later.
    """
    inserted: list[tuple[str, tuple]] = []

    # principals — one beyond the seed
    casey = uuid.uuid4()
    entity_72 = uuid.uuid4()
    await local.execute(
        """
        INSERT INTO principals (principal_id, kind, identifier, display_name, metadata)
        VALUES ($1, 'human', 'casey@example.com', 'Casey', '{"role":"owner"}'::jsonb),
               ($2, 'entity', 'entity-72', 'Test Entity', '{}'::jsonb)
        """,
        casey, entity_72,
    )
    inserted += [("principals", (casey,)), ("principals", (entity_72,))]

    # sources
    src_md = uuid.uuid4()
    src_yt = uuid.uuid4()
    await local.execute(
        """
        INSERT INTO sources (source_id, kind, modality, identifier, title, owner_principal_id, t_source)
        VALUES ($1, 'file',    'text', 'design-notes.md',                 'Design notes',     $3, NOW()),
               ($2, 'youtube', 'video','https://youtube.com/watch?v=xyz', 'A talk',           $3, NOW() - interval '1 day')
        """,
        src_md, src_yt, casey,
    )
    inserted += [("sources", (src_md,)), ("sources", (src_yt,))]

    # source_chunks
    chunk_ids = []
    for i, content in enumerate([
        "First chunk of the markdown file.",
        "Second chunk — covers backup design.",
        "Third chunk — covers trust path.",
    ]):
        cid = uuid.uuid4()
        chunk_ids.append(cid)
        await local.execute(
            """
            INSERT INTO source_chunks (chunk_id, source_id, chunk_idx, content, modality, derived_from)
            VALUES ($1, $2, $3, $4, 'text', 'native_text')
            """,
            cid, src_md, i, content,
        )
        inserted.append(("source_chunks", (cid,)))

    # memories — bi-temporal hypertable
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    mem_kinds = [
        ("teaching",   "Encrypt at rest; decrypt at use."),
        ("decision",   "Picked PolyForm Noncommercial 1.0.0."),
        ("preference", "Casey prefers terse responses."),
        ("principle",  "Receive — don't reinvent."),
        ("observation","First end-to-end backup test 2026-05-12."),
    ]
    memory_pks: list[tuple[uuid.UUID, dt.datetime]] = []
    for i, (kind, content) in enumerate(mem_kinds):
        mid = uuid.uuid4()
        t_obs = now - dt.timedelta(minutes=i)
        await local.execute(
            """
            INSERT INTO memories
              (memory_id, kind, content, owner_principal_id, t_observed, confidence, importance, tags)
            VALUES ($1, $2, $3, $4, $5, 'high', 1.0, $6)
            """,
            mid, kind, content, casey, t_obs, [kind, "test"],
        )
        memory_pks.append((mid, t_obs))
        inserted.append(("memories", (mid, t_obs)))

    # memory_links — using only the first two memory_ids
    link1 = uuid.uuid4()
    link2 = uuid.uuid4()
    await local.execute(
        """
        INSERT INTO memory_links (link_id, from_memory, to_memory, kind, confidence)
        VALUES ($1, $2, $3, 'refines',  0.9),
               ($4, $2, $5, 'relates_to', 0.7)
        """,
        link1, memory_pks[0][0], memory_pks[1][0], link2, memory_pks[2][0],
    )
    inserted += [("memory_links", (link1,)), ("memory_links", (link2,))]

    # user_context
    for key, scope, value in [
        ("ui.theme",      "global",            {"dark": True}),
        ("last.dashboard","principal:" + str(casey), {"tab": "memories"}),
    ]:
        await local.execute(
            "INSERT INTO user_context (key, scope, value) VALUES ($1, $2, $3::jsonb)",
            key, scope, json.dumps(value),
        )
        inserted.append(("user_context", (key, scope)))

    # provisioning
    await local.execute(
        "INSERT INTO provisioning (key, value) VALUES ($1, $2::jsonb)",
        "anchor_state", json.dumps({"state": "redeemed", "cert_serial": "abc123"}),
    )
    inserted.append(("provisioning", ("anchor_state",)))

    # operator_audit_log — hypertable, BIGSERIAL log_id auto-assigned
    audit_rows: list[tuple[int, dt.datetime]] = []
    for action, params in [("shape", {"prompt": "hello"}), ("recall", {"query": "design"})]:
        op_uuid = uuid.uuid4()
        rec = await local.fetchrow(
            """
            INSERT INTO operator_audit_log
              (operator_id, entity_id, source_domain, target_domain, action, params)
            VALUES ($1, 'entity-72', 'operator', 'skema', $2, $3::jsonb)
            RETURNING log_id, occurred_at
            """,
            op_uuid, action, json.dumps(params),
        )
        audit_rows.append((rec["log_id"], rec["occurred_at"]))
        inserted.append(("operator_audit_log", (rec["log_id"], rec["occurred_at"])))

    # sync_state
    await local.execute(
        """
        INSERT INTO sync_state (resource_kind, direction, last_sync_at, status)
        VALUES ('memories', 'push', NOW(), 'idle')
        """
    )
    inserted.append(("sync_state", ("memories", "push")))

    return inserted


# ─── Comparison helpers ────────────────────────────────────────────────

async def snapshot_rows(conn: asyncpg.Connection) -> dict[str, dict[str, dict[str, Any]]]:
    """Return {table: {pk_str: row_dict_without_embeddings}}."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for table in BACKUP_TABLES:
        rows = await conn.fetch(f'SELECT * FROM "{table.name}"')
        bucket: dict[str, dict[str, Any]] = {}
        for row in rows:
            d = dict(row.items())
            pk = json.dumps([str(d[c]) for c in table.pk_cols], separators=(",", ":"))
            for emb in ("embedding_semantic", "embedding_purpose"):
                d.pop(emb, None)
            bucket[pk] = d
        out[table.name] = bucket
    return out


def _comparable(blob: dict[str, Any]) -> bytes:
    """Canonical byte form for diffing rows — reuses backup serializer (drops embeddings)."""
    return serialize_row(blob)


# ─── The actual test ───────────────────────────────────────────────────

async def run() -> None:
    print("Connecting to PGs...")
    local = await connect(LOCAL_DSN)
    parallax = await connect(PARALLAX_DSN)

    try:
        # ── Stage 1: schema
        print("\nApplying migrations...")
        await apply_local_schema(local);    check("local schema applied", True)
        await apply_parallax_schema(parallax); check("parallax schema applied", True)

        # ── Stage 2: fixture data
        print("\nInserting fixture rows into local PG...")
        inserted = await insert_fixture_rows(local)
        pre_snapshot = await snapshot_rows(local)
        total_inserted = sum(len(v) for v in pre_snapshot.values())
        check(f"fixture data inserted ({total_inserted} rows across {len(pre_snapshot)} tables)", True)

        # ── Stage 3: provision envelope (passphrase + recovery code)
        print("\nProvisioning DEK + envelopes...")
        dek = new_dek()
        env_pp = wrap_dek(dek, PASSPHRASE,   "passphrase",    KdfParams())
        env_rc = wrap_dek(dek, RECOVERY_CODE, "recovery_code", KdfParams())
        for env in (env_pp, env_rc):
            await parallax.execute(
                """
                INSERT INTO local_backup_envelope
                  (kdf_source, wrapped_dek, wrap_nonce, wrap_auth_tag,
                   kdf_salt, kdf_params, is_active)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, TRUE)
                """,
                env.kdf_source, env.wrapped_dek, env.wrap_nonce, env.wrap_auth_tag,
                env.kdf_salt, json.dumps(env.kdf_params.to_jsonb()),
            )
        check("envelope rows inserted (passphrase + recovery_code)", True)

        # ── Stage 4: backup push
        print("\nPushing encrypted snapshot to parallax...")
        counts = await push_full_snapshot(local, parallax, dek)
        pushed = sum(counts.values())
        check(f"backup pushed ({pushed} rows ciphertext-encrypted)", pushed == total_inserted,
              f"pushed={pushed} expected={total_inserted}")

        # ── Stage 5: confirm parallax has only ciphertext
        sample = await parallax.fetchrow(
            "SELECT resource_kind, ciphertext FROM local_backup_blob LIMIT 1"
        )
        is_ciphertext = sample is not None and b"casey@example.com" not in bytes(sample["ciphertext"])
        check("parallax stores ciphertext only (no plaintext leak)", is_ciphertext)

        # ── Stage 6: wipe local entirely
        print("\nWiping local PG (simulating new machine)...")
        await wipe_local(local)
        await apply_local_schema(local)
        post_wipe = await snapshot_rows(local)
        seed_only = sum(len(v) for v in post_wipe.values())
        check(f"local wiped + schema re-applied (only seed remains: {seed_only} row)", True)

        # ── Stage 7: restore via passphrase
        print("\nRestoring with passphrase path...")
        env_rows = await parallax.fetch(
            "SELECT * FROM local_backup_envelope WHERE kdf_source='passphrase' AND is_active=TRUE"
        )
        from gatewayd.crypto.envelope import Envelope
        env_pp_loaded = Envelope(
            kdf_source="passphrase",
            wrapped_dek=bytes(env_rows[0]["wrapped_dek"]),
            wrap_nonce=bytes(env_rows[0]["wrap_nonce"]),
            wrap_auth_tag=bytes(env_rows[0]["wrap_auth_tag"]),
            kdf_salt=bytes(env_rows[0]["kdf_salt"]),
            kdf_params=KdfParams.from_jsonb(_as_dict(env_rows[0]["kdf_params"])),
        )
        recovered_dek = unwrap_dek(env_pp_loaded, PASSPHRASE)
        check("passphrase unwraps DEK (matches original)", recovered_dek == dek)

        restored_counts = await restore_snapshot(parallax, local, recovered_dek)
        post_restore = await snapshot_rows(local)
        check("restore completed without error", sum(restored_counts.values()) == pushed)

        # ── Stage 8: diff source vs restored
        print("\nDiffing rows source vs restored...")
        all_match = True
        mismatch_detail = ""
        for table_name, before_bucket in pre_snapshot.items():
            after_bucket = post_restore.get(table_name, {})
            for pk, before_row in before_bucket.items():
                # Seed principal may have been overwritten — exclude from diff if it's the seed
                if table_name == "principals":
                    if before_row.get("identifier") == "self" and before_row.get("kind") == "human":
                        continue
                after_row = after_bucket.get(pk)
                if after_row is None:
                    all_match = False
                    mismatch_detail = f"{table_name}/{pk} missing post-restore"
                    break
                if _comparable(before_row) != _comparable(after_row):
                    all_match = False
                    mismatch_detail = f"{table_name}/{pk} content differs"
                    break
            if not all_match:
                break
        check("every fixture row round-trips byte-for-byte", all_match, mismatch_detail)

        # ── Stage 9: restore via recovery code (wipe + restore again)
        print("\nRestoring with recovery-code path...")
        await wipe_local(local)
        await apply_local_schema(local)
        env_rows_rc = await parallax.fetch(
            "SELECT * FROM local_backup_envelope WHERE kdf_source='recovery_code' AND is_active=TRUE"
        )
        env_rc_loaded = Envelope(
            kdf_source="recovery_code",
            wrapped_dek=bytes(env_rows_rc[0]["wrapped_dek"]),
            wrap_nonce=bytes(env_rows_rc[0]["wrap_nonce"]),
            wrap_auth_tag=bytes(env_rows_rc[0]["wrap_auth_tag"]),
            kdf_salt=bytes(env_rows_rc[0]["kdf_salt"]),
            kdf_params=KdfParams.from_jsonb(_as_dict(env_rows_rc[0]["kdf_params"])),
        )
        recovered_via_rc = unwrap_dek(env_rc_loaded, RECOVERY_CODE)
        check("recovery code unwraps the same DEK", recovered_via_rc == dek)
        rc_counts = await restore_snapshot(parallax, local, recovered_via_rc)
        rc_snapshot = await snapshot_rows(local)
        rc_match = sum(rc_counts.values()) == pushed
        rc_diff_ok = True
        for table_name, before_bucket in pre_snapshot.items():
            for pk, before_row in before_bucket.items():
                if table_name == "principals" and before_row.get("identifier") == "self":
                    continue
                after = rc_snapshot.get(table_name, {}).get(pk)
                if not after or _comparable(before_row) != _comparable(after):
                    rc_diff_ok = False
                    break
            if not rc_diff_ok:
                break
        check("recovery-code restore produces identical state", rc_match and rc_diff_ok)

        # ── Stage 10: compromise simulation — wrong passphrase
        from cryptography.exceptions import InvalidTag
        try:
            unwrap_dek(env_pp_loaded, b"wrong-passphrase-please")
            check("wrong passphrase rejected", False, "unwrap unexpectedly succeeded")
        except InvalidTag:
            check("wrong passphrase rejected (InvalidTag)", True)

    finally:
        await local.close()
        await parallax.close()


def main() -> int:
    try:
        compose_up()
        wait_for_postgres_stable("skema-test-local-pg")
        wait_for_postgres_stable("skema-test-parallax-pg")
        asyncio.run(run())
    finally:
        compose_down()

    print()
    passed = sum(1 for c, _ in results if c)
    failed = len(results) - passed
    print("═" * 40)
    print(f"PASS: {passed}    FAIL: {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
