#!/usr/bin/env bash
# Skema Gateway · migration tests (Layer 1)
#
# Spins up three ephemeral postgres containers, applies the migrations from
# db/migrations/, and asserts schema sanity, hypertable creation, FK works,
# and idempotency. Tears down on exit.

set -euo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0
ok() { echo "  ✓ $1"; PASS=$((PASS+1)); }
nok() { echo "  ✗ $1${2:+  ($2)}"; FAIL=$((FAIL+1)); }

cleanup() {
    echo
    echo "Tearing down test databases..."
    docker compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

MIG=../../db/migrations

echo "Bringing up test databases..."
docker compose up -d >/dev/null
echo
echo "Waiting for health..."
for svc in local-pg parallax-pg privatae-pg; do
    container="skema-test-${svc}"
    for i in $(seq 1 60); do
        status=$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo none)
        if [ "$status" = "healthy" ]; then
            ok "$container healthy"
            break
        fi
        if [ "$i" = "60" ]; then
            nok "$container failed to become healthy"
        fi
        sleep 2
    done
done

# timescaledb-ha runs Patroni and does a postgres restart after the initial
# healthcheck. Wait until "ready to accept connections" appears at least twice
# in the log (or 60s elapses) before applying SQL.
echo
echo "Waiting for Patroni restart cycle to settle..."
for container in skema-test-local-pg skema-test-parallax-pg; do
    for i in $(seq 1 30); do
        ready_count=$(docker logs "$container" 2>&1 | grep -c "database system is ready to accept connections" || true)
        if [ "$ready_count" -ge 2 ]; then
            ok "$container post-restart stable"
            break
        fi
        if [ "$i" = "30" ]; then
            nok "$container restart cycle did not settle (ready_count=$ready_count)"
        fi
        sleep 2
    done
done

PSQL_LOCAL=(docker exec -i skema-test-local-pg psql -U postgres -d skema_local -v ON_ERROR_STOP=1 -q)
PSQL_PARALLAX=(docker exec -i skema-test-parallax-pg psql -U postgres -d parallax -v ON_ERROR_STOP=1 -q)
PSQL_PRIVATAE=(docker exec -i skema-test-privatae-pg psql -U postgres -d privatae -v ON_ERROR_STOP=1 -q)

# ─── LOCAL ──────────────────────────────────────────────────────────────
echo
echo "── local/001_init.sql ─────────────────────"
if "${PSQL_LOCAL[@]}" < "$MIG/local/001_init.sql" > /tmp/test-local.log 2>&1; then
    ok "local/001_init.sql applied"
else
    nok "local/001_init.sql failed"
    tail -40 /tmp/test-local.log
fi

for t in principals sources source_chunks memories memory_links memory_shares \
         user_context provisioning operator_audit_log sync_state; do
    found=$("${PSQL_LOCAL[@]}" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='$t';")
    [ "$found" = "1" ] && ok "table $t exists" || nok "table $t missing"
done

for h in memories operator_audit_log; do
    found=$("${PSQL_LOCAL[@]}" -tAc "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name='$h';")
    [ "$found" = "1" ] && ok "hypertable $h" || nok "hypertable $h missing"
done

seed=$("${PSQL_LOCAL[@]}" -tAc "SELECT COUNT(*) FROM principals WHERE kind='human' AND identifier='self';")
[ "$seed" = "1" ] && ok "seed principal row inserted" || nok "seed principal missing (count=$seed)"

# ─── PARALLAX ───────────────────────────────────────────────────────────
echo
echo "── parallax (seed + 001 + 002) ────────────"
"${PSQL_PARALLAX[@]}" < fixtures/parallax-seed.sql > /tmp/test-parallax.log 2>&1 \
    && ok "parallax seed applied" \
    || { nok "parallax seed failed"; tail -30 /tmp/test-parallax.log; }

"${PSQL_PARALLAX[@]}" < "$MIG/parallax/001_mcp_client_tokens_operator_columns.sql" >> /tmp/test-parallax.log 2>&1 \
    && ok "parallax/001 applied" \
    || { nok "parallax/001 failed"; tail -30 /tmp/test-parallax.log; }

"${PSQL_PARALLAX[@]}" < "$MIG/parallax/002_local_backup.sql" >> /tmp/test-parallax.log 2>&1 \
    && ok "parallax/002 applied" \
    || { nok "parallax/002 failed"; tail -30 /tmp/test-parallax.log; }

for col in operator_kind machine_anchor_id hardware_fingerprint notes; do
    found=$("${PSQL_PARALLAX[@]}" -tAc "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='mcp_client_tokens' AND column_name='$col';")
    [ "$found" = "1" ] && ok "mcp_client_tokens.$col added" || nok "mcp_client_tokens.$col missing"
done

for t in local_backup_envelope local_backup_blob; do
    found=$("${PSQL_PARALLAX[@]}" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='$t';")
    [ "$found" = "1" ] && ok "table $t exists" || nok "table $t missing"
done

# Idempotency
"${PSQL_PARALLAX[@]}" < "$MIG/parallax/001_mcp_client_tokens_operator_columns.sql" >> /tmp/test-parallax.log 2>&1 \
    && ok "parallax/001 re-apply clean" || nok "parallax/001 re-apply failed"
"${PSQL_PARALLAX[@]}" < "$MIG/parallax/002_local_backup.sql" >> /tmp/test-parallax.log 2>&1 \
    && ok "parallax/002 re-apply clean" || nok "parallax/002 re-apply failed"

# ─── PRIVATAE ───────────────────────────────────────────────────────────
echo
echo "── privatae (seed + 001) ──────────────────"
"${PSQL_PRIVATAE[@]}" < fixtures/privatae-seed.sql > /tmp/test-privatae.log 2>&1 \
    && ok "privatae seed applied" || { nok "privatae seed failed"; tail -20 /tmp/test-privatae.log; }

"${PSQL_PRIVATAE[@]}" < "$MIG/privatae/001_machine_anchors.sql" >> /tmp/test-privatae.log 2>&1 \
    && ok "privatae/001 applied" || { nok "privatae/001 failed"; tail -20 /tmp/test-privatae.log; }

# FK enforcement: insert depends on user row first
"${PSQL_PRIVATAE[@]}" -c "INSERT INTO users (email) VALUES ('test@example.com');" > /dev/null
ins=$("${PSQL_PRIVATAE[@]}" -tAc "INSERT INTO machine_anchors (user_id, user_email, entity_id, anchor_code_hash, expires_at) VALUES (1, 'test@example.com', 1, 'deadbeef', NOW() + INTERVAL '10 minutes') RETURNING anchor_id;" 2>&1)
[[ "$ins" =~ ^[0-9]+$ ]] && ok "machine_anchors insert (FK satisfied)" || nok "machine_anchors insert failed" "$ins"

# FK violation: insert with non-existent user_id should fail
if "${PSQL_PRIVATAE[@]}" -c "INSERT INTO machine_anchors (user_id, user_email, entity_id, anchor_code_hash, expires_at) VALUES (999, 'ghost@example.com', 1, 'deadbeef2', NOW() + INTERVAL '10 minutes');" >/dev/null 2>&1; then
    nok "machine_anchors FK NOT enforced (orphan user_id accepted)"
else
    ok "machine_anchors FK rejects orphan user_id"
fi

# Idempotency
"${PSQL_PRIVATAE[@]}" < "$MIG/privatae/001_machine_anchors.sql" >> /tmp/test-privatae.log 2>&1 \
    && ok "privatae/001 re-apply clean" || nok "privatae/001 re-apply failed"

# ─── Summary ────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════"
echo "PASS: $PASS    FAIL: $FAIL"
[ "$FAIL" = "0" ]
