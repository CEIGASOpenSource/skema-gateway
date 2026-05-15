"""
Localhost dashboard for the gateway daemon.

Bound to 127.0.0.1 alongside the /mcp relay. No external authentication —
the user owns the process. Read-only over local state plus a handful of
ceremony endpoints (passphrase setup, manual sync trigger).

Endpoints (all under /api/gateway/):
  GET  /status                 — overall daemon status, upstream reachability
  GET  /audit/entries          — paginated local audit log rows
  GET  /audit/verify           — walk the HMAC chain, report any breaks
  GET  /operators              — recent /mcp callers grouped by operator_id
  GET  /anchors                — anchor redemption history (from `provisioning`)
  GET  /backup/state           — passphrase set? last sync?
  POST /backup/set-passphrase  — first-time setup ceremony
  POST /backup/sync-now        — manually trigger push_full_snapshot

Static files (/dashboard/*) are served from gatewayd/dashboard/static/.
Root (/) returns the dashboard HTML.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiohttp import web

log = logging.getLogger("gatewayd.dashboard")

DASHBOARD_STATIC = Path(__file__).resolve().parent / "static"

VERSION = "0.1.0"


# ── State helpers ──────────────────────────────────────────────────


def _state(request: web.Request):
    return request.app["state"]


async def _provisioning_get(pool, key: str) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT value FROM provisioning WHERE key = $1", key,
        )
        if row is None:
            return None
        v = row["value"]
        return json.loads(v) if isinstance(v, str) else v


async def _provisioning_set(pool, key: str, value: dict) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO provisioning (key, value, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
            """,
            key, json.dumps(value),
        )


# ── Status ─────────────────────────────────────────────────────────


_last_upstream_check: dict[str, Any] = {"at": None, "ok": None, "err": ""}


async def _probe_upstream(state) -> bool:
    """Best-effort upstream health probe via the existing session."""
    try:
        # GET /health on the upstream — same host, just a different path
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(state.cfg.upstream.url)
        health = urlunsplit((parts.scheme, parts.netloc, "/api/system/health", "", ""))
        if state.upstream._session is None:
            return False
        async with state.upstream._session.get(health, timeout=3) as r:
            ok = r.status == 200
            _last_upstream_check["at"] = datetime.now(timezone.utc).isoformat()
            _last_upstream_check["ok"] = ok
            _last_upstream_check["err"] = "" if ok else f"HTTP {r.status}"
            return ok
    except Exception as e:
        _last_upstream_check["at"] = datetime.now(timezone.utc).isoformat()
        _last_upstream_check["ok"] = False
        _last_upstream_check["err"] = f"{type(e).__name__}: {e}"
        return False


async def status_handler(request: web.Request) -> web.Response:
    state = _state(request)
    bonded = await _provisioning_get(state.local, "bound_entity")
    machine_cert = await _provisioning_get(state.local, "machine_cert")

    reachable = await _probe_upstream(state)

    checks = []
    # Local PG
    try:
        async with state.local.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks.append({"name": "local PG", "ok": True, "detail": state.cfg.backup.local_dsn})
    except Exception as e:
        checks.append({"name": "local PG", "ok": False, "detail": str(e)})
    # Audit HMAC key loaded
    key_env = state.cfg.audit.audit_key_env
    checks.append({
        "name": "audit HMAC key",
        "ok": bool(os.environ.get(key_env)),
        "detail": f"env: {key_env}",
    })
    # Cert files
    cert = state.cfg.upstream.cert_path
    key = state.cfg.upstream.key_path
    cert_ok = bool(cert and Path(cert).exists() and key and Path(key).exists())
    checks.append({
        "name": "mTLS client cert",
        "ok": cert_ok,
        "detail": cert or "(not configured)",
    })

    return web.json_response({
        "version": VERSION,
        "listen_host": state.cfg.mcp.listen_host,
        "listen_port": state.cfg.mcp.listen_port,
        "upstream_url": state.cfg.upstream.url,
        "cert_fingerprint": (machine_cert or {}).get("fingerprint"),
        "bonded_at": (bonded or {}).get("bonded_at"),
        "bonded_handle": (bonded or {}).get("handle"),
        "upstream_reachable": reachable,
        "upstream_last_check": _last_upstream_check["at"],
        "upstream_reachable_err": _last_upstream_check["err"],
        "checks": checks,
    })


# ── Audit ──────────────────────────────────────────────────────────


async def audit_entries_handler(request: web.Request) -> web.Response:
    state = _state(request)
    try:
        limit = max(1, min(int(request.query.get("limit", "50")), 500))
    except ValueError:
        limit = 50
    before = request.query.get("before")
    try:
        before_i = int(before) if before else None
    except ValueError:
        before_i = None

    async with state.local.acquire() as conn:
        if before_i is not None:
            rows = await conn.fetch(
                """
                SELECT log_id, operator_id, entity_id, source_domain, target_domain,
                       action, params, result, ceigas_crossing_id, occurred_at
                  FROM operator_audit_log
                 WHERE log_id < $1
                 ORDER BY log_id DESC
                 LIMIT $2
                """,
                before_i, limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT log_id, operator_id, entity_id, source_domain, target_domain,
                       action, params, result, ceigas_crossing_id, occurred_at
                  FROM operator_audit_log
                 ORDER BY log_id DESC
                 LIMIT $1
                """,
                limit,
            )

    entries = [{
        "log_id":             int(r["log_id"]),
        "operator_id":        str(r["operator_id"]),
        "entity_id":          r["entity_id"],
        "source_domain":      r["source_domain"],
        "target_domain":      r["target_domain"],
        "action":             r["action"],
        "params":             r["params"],
        "result":             r["result"],
        "ceigas_crossing_id": str(r["ceigas_crossing_id"]) if r["ceigas_crossing_id"] else None,
        "occurred_at":        r["occurred_at"].isoformat() if r["occurred_at"] else None,
    } for r in rows]

    return web.json_response({
        "entries": entries,
        "next_before": entries[-1]["log_id"] if entries and len(entries) >= limit else None,
    })


async def audit_verify_handler(request: web.Request) -> web.Response:
    """Walk the HMAC chain front-to-back and report the first broken row, if any.

    Reuses gatewayd.audit._signature so the chain math stays in one place.
    """
    state = _state(request)
    key_hex = os.environ.get(state.cfg.audit.audit_key_env, "")
    if not key_hex:
        return web.json_response(
            {"ok": False, "error": "audit HMAC key not loaded"},
            status=503,
        )
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return web.json_response(
            {"ok": False, "error": "audit HMAC key not hex"},
            status=503,
        )

    from gatewayd.audit import _signature  # internal helper, single source of truth

    async with state.local.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT log_id, operator_id, entity_id, source_domain, target_domain,
                   action, params, result, ceigas_crossing_id, signature
              FROM operator_audit_log
             ORDER BY log_id ASC
            """
        )

    prev_sig = b""
    checked = 0
    for r in rows:
        params_json = json.dumps(r["params"] or {}, sort_keys=True, separators=(",", ":"))
        result_json = json.dumps(r["result"] or {}, sort_keys=True, separators=(",", ":"))
        fields = [
            str(r["operator_id"]), r["entity_id"], r["source_domain"], r["target_domain"],
            r["action"], params_json, result_json,
            str(r["ceigas_crossing_id"] or ""),
            prev_sig.hex(),
        ]
        expected = _signature(key, fields)
        actual = bytes.fromhex(r["signature"]) if r["signature"] else b""
        if not hmac.compare_digest(expected, actual):
            return web.json_response({
                "ok": False,
                "broken_at": int(r["log_id"]),
                "checked": checked,
            })
        prev_sig = actual
        checked += 1

    return web.json_response({"ok": True, "checked": checked})


# ── Operators ─────────────────────────────────────────────────────


async def operators_handler(request: web.Request) -> web.Response:
    """Operator tiles enriched with display_name + icon_slug.

    Auto-seeds a placeholder profile for any operator_id seen in the audit
    log without one — first sight gets 'operator-<8 hex>' and no icon.
    User renames via PATCH /operators/<id>.
    """
    state = _state(request)
    async with state.local.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO operator_profiles (operator_id, display_name)
                SELECT DISTINCT a.operator_id,
                       'operator-' || substr(a.operator_id::text, 1, 8)
                  FROM operator_audit_log a
                 LEFT JOIN operator_profiles p ON p.operator_id = a.operator_id
                 WHERE a.source_domain = 'operator' AND p.operator_id IS NULL
                ON CONFLICT (operator_id) DO NOTHING
                """
            )

            rows = await conn.fetch(
                """
                SELECT a.operator_id::TEXT AS operator_id,
                       p.display_name,
                       p.icon_slug,
                       p.kind,
                       COUNT(*)::BIGINT AS call_count,
                       MAX(a.occurred_at) AS last_seen,
                       (
                         SELECT string_agg(action || '(' || cnt || ')', ', ')
                           FROM (
                             SELECT action, COUNT(*)::BIGINT AS cnt
                               FROM operator_audit_log a2
                              WHERE a2.operator_id = a.operator_id
                              GROUP BY action
                              ORDER BY cnt DESC
                              LIMIT 3
                           ) top3
                       ) AS actions_top
                  FROM operator_audit_log a
                  LEFT JOIN operator_profiles p ON p.operator_id = a.operator_id
                 WHERE a.source_domain = 'operator'
                 GROUP BY a.operator_id, p.display_name, p.icon_slug, p.kind
                 ORDER BY MAX(a.occurred_at) DESC
                 LIMIT 50
                """
            )

    return web.json_response({
        "operators": [
            {
                "operator_id":  r["operator_id"],
                "display_name": r["display_name"] or ("operator-" + r["operator_id"][:8]),
                "icon_slug":    r["icon_slug"],
                "kind":         r["kind"],
                "call_count":   int(r["call_count"]),
                "last_seen":    r["last_seen"].isoformat() if r["last_seen"] else None,
                "actions_top":  r["actions_top"] or "",
            }
            for r in rows
        ],
        "listen_port": state.cfg.mcp.listen_port,
    })


async def operator_activity_handler(request: web.Request) -> web.Response:
    """Human-readable activity feed for one operator. Last 100 calls."""
    state = _state(request)
    op_id = request.match_info["operator_id"]
    import re as _re
    if not _re.fullmatch(r"[0-9a-fA-F-]{36}", op_id):
        return web.json_response({"error": "bad_operator_id"}, status=400)

    async with state.local.acquire() as conn:
        profile = await conn.fetchrow(
            "SELECT display_name, icon_slug, kind, notes "
            "FROM operator_profiles WHERE operator_id = $1::uuid",
            op_id,
        )
        rows = await conn.fetch(
            """
            SELECT log_id, occurred_at, action,
                   source_domain, target_domain,
                   entity_id, outcome, latency_ms, error_summary
            FROM operator_audit_log
            WHERE operator_id = $1::uuid AND source_domain = 'operator'
            ORDER BY occurred_at DESC
            LIMIT 100
            """,
            op_id,
        )

    return web.json_response({
        "operator_id": op_id,
        "profile": dict(profile) if profile else None,
        "activity": [
            {
                "log_id":         str(r["log_id"]),
                "occurred_at":    r["occurred_at"].isoformat() if r["occurred_at"] else None,
                "action":         r["action"],
                "target_domain":  r["target_domain"],
                "entity_id":      r["entity_id"],
                "outcome":        r["outcome"],
                "latency_ms":     r["latency_ms"],
                "error_summary":  r["error_summary"],
            }
            for r in rows
        ],
    })


async def operator_rename_handler(request: web.Request) -> web.Response:
    """PATCH /operators/<id> — update display_name and/or icon_slug.
    Body: {"display_name": "...", "icon_slug": "claude-code"} (both optional)."""
    state = _state(request)
    op_id = request.match_info["operator_id"]
    import re as _re
    if not _re.fullmatch(r"[0-9a-fA-F-]{36}", op_id):
        return web.json_response({"error": "bad_operator_id"}, status=400)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad_json"}, status=400)

    fields: dict[str, str | None] = {}
    if "display_name" in body and isinstance(body["display_name"], str) and body["display_name"].strip():
        fields["display_name"] = body["display_name"].strip()
    if "icon_slug" in body:
        v = body["icon_slug"]
        if v in (None, ""):
            fields["icon_slug"] = None
        elif isinstance(v, str) and _re.fullmatch(r"[a-z][a-z0-9_\-]{0,31}", v):
            fields["icon_slug"] = v
        else:
            return web.json_response({"error": "bad_icon_slug"}, status=400)
    if not fields:
        return web.json_response({"error": "no_fields"}, status=400)

    set_clauses = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(fields.keys()))
    set_clauses += ", updated_at = NOW()"
    args: list = [op_id, *fields.values()]

    async with state.local.acquire() as conn:
        await conn.execute(
            f"UPDATE operator_profiles SET {set_clauses} WHERE operator_id = $1::uuid",
            *args,
        )
    return web.json_response({"updated": list(fields.keys())})


# ── Anchors ────────────────────────────────────────────────────────


async def anchors_handler(request: web.Request) -> web.Response:
    """List anchor redemption history from the local `provisioning` table.

    The gateway records each successful anchor redemption under
    provisioning.anchors[i]. Format: list of {handle, cert_fingerprint,
    redeemed_at, revoked_at}.
    """
    state = _state(request)
    history = await _provisioning_get(state.local, "anchors") or {"history": []}
    return web.json_response({"anchors": history.get("history", [])})


# ── Backup ─────────────────────────────────────────────────────────


async def backup_state_handler(request: web.Request) -> web.Response:
    state = _state(request)
    meta = await _provisioning_get(state.local, "backup_state") or {}
    return web.json_response({
        "passphrase_set":  bool(meta.get("passphrase_set")),
        "recovery_set":    bool(meta.get("recovery_set")),
        "last_sync_at":    meta.get("last_sync_at"),
        "blob_count":      meta.get("blob_count", 0),
        "blob_bytes":      meta.get("blob_bytes", 0),
        "kdf_algo":        meta.get("kdf_algo", "argon2id"),
        "kdf_params":      meta.get("kdf_params"),
    })


async def backup_set_passphrase_handler(request: web.Request) -> web.Response:
    """Generate DEK, derive KEK from passphrase via argon2id, wrap DEK,
    generate recovery code + 2nd wrapped DEK, push envelopes to upstream
    container, record state locally.

    v0.1: records state locally so the dashboard can render "configured";
    actual KEK derivation + envelope push wiring lives in
    gatewayd.crypto + the container's POST /api/backup/envelope/set
    endpoint (still being wired). The recovery code IS generated and
    returned — that's not a stub. The wrapped DEK push is stubbed pending
    the container-side envelope ingest endpoint.
    """
    state = _state(request)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "body must be JSON"}, status=400)

    passphrase = body.get("passphrase") or ""
    if len(passphrase) < 8:
        return web.json_response(
            {"error": "passphrase must be at least 8 characters"}, status=400,
        )

    existing = await _provisioning_get(state.local, "backup_state") or {}
    if existing.get("passphrase_set"):
        return web.json_response(
            {"error": "passphrase already set; rotation is a separate ceremony"},
            status=409,
        )

    # Recovery code: 24 base32 chars (~120 bits), grouped in fours for legibility.
    raw = secrets.token_bytes(15)
    import base64
    raw_b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    recovery_code = "-".join(raw_b32[i:i+4] for i in range(0, len(raw_b32), 4))

    kdf_params = {"m_kib": 262144, "t": 3, "p": 1}

    # Record local state. The actual encryption material lives in the OS
    # keychain (or env var in dev). Provisioning row says "configured".
    await _provisioning_set(state.local, "backup_state", {
        "passphrase_set":     True,
        "recovery_set":       True,
        "kdf_algo":           "argon2id",
        "kdf_params":         kdf_params,
        "passphrase_set_at":  datetime.now(timezone.utc).isoformat(),
        "last_sync_at":       None,
        "blob_count":         0,
        "blob_bytes":         0,
    })

    log.info("backup passphrase set (recovery code generated)")
    return web.json_response({
        "ok": True,
        "recovery_code": recovery_code,
        "kdf_algo": "argon2id",
        "kdf_params": kdf_params,
        "next": "envelope push to container is the follow-on ceremony; this row records the local commit",
    })


async def backup_sync_now_handler(request: web.Request) -> web.Response:
    """Trigger push_full_snapshot. Requires backup_state.passphrase_set."""
    state = _state(request)
    meta = await _provisioning_get(state.local, "backup_state") or {}
    if not meta.get("passphrase_set"):
        return web.json_response(
            {"error": "passphrase not set — run /backup/set-passphrase first"},
            status=409,
        )

    # v0.1: actual push_full_snapshot needs the parallax DSN and unwrapped
    # DEK. Both are gateway-side wiring still in flight. Report what we'd
    # do, mark state as "sync stubbed" so the UI can show truthful empty.
    return web.json_response({
        "rows":  0,
        "bytes": 0,
        "note":  "sync wiring pending: this endpoint records intent but the "
                 "encrypt/push path needs parallax DSN discovery + DEK unwrap "
                 "(both in skema-gateway crypto module — next ship)",
    })


# ── Tiles (multi-container picker) ─────────────────────────────────


async def tiles_containers_handler(request: web.Request) -> web.Response:
    """Return the list of registered container tiles.

    Each entry: {name, display_name, kind, url, active, has_wallpaper}
    The dashboard renders one tile per entry, fetches the wallpaper via
    /api/gateway/tiles/wallpaper/<name>, and POSTs to /api/gateway/select
    when the user clicks.
    """
    from gatewayd.wallpaper import find_cached
    state = _state(request)
    registry = state.registry
    active = registry.active
    out = []
    for name, cfg in registry.configs().items():
        out.append({
            "name": name,
            "display_name": cfg.display_name or name,
            "kind": cfg.kind,
            "url": cfg.url,
            "icon_slug": cfg.icon_slug,
            "active": (name == active),
            "has_wallpaper": find_cached(name) is not None,
        })
    return web.json_response({"tiles": out, "active": active})


async def tiles_wallpaper_handler(request: web.Request) -> web.Response:
    """Serve the cached wallpaper for an upstream. Same-origin so the
    browser's <img> tag works without CORS dance.

    Filename whitelist mirrors what we built on the skema-security side
    (alnum + ._-, no path traversal). The wallpaper cache directory is
    the only filesystem touch.
    """
    from gatewayd.wallpaper import find_cached
    name = request.match_info["name"]
    import re as _re
    if name in (".", "..") or not _re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return web.json_response({"error": "bad_name"}, status=400)
    path = find_cached(name)
    if path is None:
        return web.json_response({"error": "not_cached"}, status=404)
    ct = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".webp": "image/webp", ".gif": "image/gif",
    }.get(path.suffix.lower(), "application/octet-stream")
    return web.FileResponse(path=str(path), headers={
        "Content-Type": ct,
        "Cache-Control": "private, max-age=3600",
    })


async def tiles_select_handler(request: web.Request) -> web.Response:
    """Flip the active container tile. JSON body: {"name": "..."}.

    Persists the choice in `provisioning.active_upstream` so the daemon
    boots into the same tile next time.
    """
    state = _state(request)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad_json"}, status=400)
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        return web.json_response({"error": "missing_name"}, status=400)
    try:
        state.registry.select(name)
    except KeyError:
        return web.json_response({"error": "unknown_upstream", "name": name}, status=404)
    try:
        await _provisioning_set(state.local, "active_upstream", {"name": name})
    except Exception as e:
        log.warning("failed to persist active_upstream: %s", e)
    log.info("active upstream selected: %s (persisted)", name)
    return web.json_response({"active": state.registry.active})


# ── Static + boot ──────────────────────────────────────────────────


async def index_handler(request: web.Request) -> web.Response:
    return web.FileResponse(DASHBOARD_STATIC / "index.html")


def register_routes(app: web.Application) -> None:
    """Mount the dashboard alongside /mcp + /health in the same Application."""
    # Page entry
    app.router.add_get("/", index_handler)

    # Static (CSS, JS)
    app.router.add_static("/dashboard/", path=str(DASHBOARD_STATIC), show_index=False)

    # API
    api = "/api/gateway"
    app.router.add_get(f"{api}/status",               status_handler)
    app.router.add_get(f"{api}/audit/entries",        audit_entries_handler)
    app.router.add_get(f"{api}/audit/verify",         audit_verify_handler)
    app.router.add_get(f"{api}/operators",            operators_handler)
    app.router.add_get(f"{api}/anchors",              anchors_handler)
    app.router.add_get(f"{api}/backup/state",         backup_state_handler)
    app.router.add_post(f"{api}/backup/set-passphrase", backup_set_passphrase_handler)
    app.router.add_post(f"{api}/backup/sync-now",     backup_sync_now_handler)

    # Multi-container tile grid (Containers section of the dashboard)
    app.router.add_get(f"{api}/tiles/containers",        tiles_containers_handler)
    app.router.add_get(f"{api}/tiles/wallpaper/{{name}}", tiles_wallpaper_handler)
    app.router.add_post(f"{api}/select",                  tiles_select_handler)

    # Operators — per-operator activity log + rename/icon
    app.router.add_get (f"{api}/operators/{{operator_id}}/activity", operator_activity_handler)
    app.router.add_patch(f"{api}/operators/{{operator_id}}",          operator_rename_handler)
