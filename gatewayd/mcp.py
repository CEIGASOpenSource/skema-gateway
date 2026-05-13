"""Local MCP server.

Per project_skema_trust_path invariant #2: the gateway daemon hosts the MCP
server on 127.0.0.1. Operator clients (Claude Code, Claude Desktop, Cursor,
LM Studio, ...) connect to localhost — never to a Privatae-side relay.

The gateway is a transparent JSON-RPC 2.0 proxy that mirrors the synaptive
MCP contract at /opt/privatae/skema/server/routes/mcp.py:

  methods:   initialize, notifications/initialized, ping, tools/list,
             tools/call, prompts/list, prompts/get
  tools:     shape(message), recall(query, limit?, include_knowledge?),
             signal(user_message, model_response, model?)
  prompts:   synaptive_identity

Per call:
  1. Authenticates the operator with a bearer secret (local shared secret)
  2. Logs an in-flight audit row
  3. Forwards the JSON-RPC envelope verbatim to the upstream container's
     `/mcp` endpoint (with the upstream's bearer token substituted)
  4. Logs the completed audit row with result + ceigas_crossing_id (if any)
  5. Returns the upstream's response envelope verbatim
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

import aiohttp
import asyncpg
from aiohttp import web

from gatewayd.audit import AuditEntry, write_entry
from gatewayd.config import GatewayConfig
from gatewayd.transport.mtls import UpstreamClient

logger = logging.getLogger("gatewayd.mcp")


def _operator_secret(cfg: GatewayConfig) -> str:
    secret = os.environ.get(cfg.mcp.operator_secret_env, "")
    if not secret:
        raise RuntimeError(
            f"operator secret not set; export {cfg.mcp.operator_secret_env}"
        )
    return secret


def _audit_key(cfg: GatewayConfig) -> bytes:
    raw = os.environ.get(cfg.audit.audit_key_env, "")
    if not raw:
        raise RuntimeError(
            f"audit HMAC key not set; export {cfg.audit.audit_key_env} (hex)"
        )
    return bytes.fromhex(raw)


def _action_for_audit(method: str, params: dict) -> str:
    """Derive the audit `action` from a JSON-RPC request.

    For tools/call we record the tool name (`shape`, `recall`, `signal`).
    For everything else we record the method.
    """
    if method == "tools/call":
        tool = params.get("name") if isinstance(params, dict) else None
        if isinstance(tool, str) and tool:
            return f"tools/call:{tool}"
    return method


def _extract_crossing_id(envelope: dict[str, Any]) -> uuid.UUID | None:
    """Some shape() results carry a ceigas_crossing_id. Best-effort dig."""
    try:
        result = envelope.get("result")
        if not isinstance(result, dict):
            return None
        content = result.get("content")
        if isinstance(content, list) and content:
            text = content[0].get("text")
            if isinstance(text, str):
                # Tool results are JSON-stringified text; try a shallow parse.
                try:
                    parsed = json.loads(text)
                except Exception:
                    return None
                cid = parsed.get("ceigas_crossing_id") if isinstance(parsed, dict) else None
                if isinstance(cid, str):
                    return uuid.UUID(cid)
        # Some responses may have ceigas_crossing_id at the top of result.
        cid = result.get("ceigas_crossing_id")
        if isinstance(cid, str):
            return uuid.UUID(cid)
    except Exception:
        return None
    return None


class _State:
    """Shared app state attached to the aiohttp Application."""
    def __init__(self, cfg: GatewayConfig, local: asyncpg.Pool,
                 upstream: UpstreamClient):
        self.cfg              = cfg
        self.local            = local
        self.upstream         = upstream
        self.audit_key        = _audit_key(cfg)
        self.operator_secret  = _operator_secret(cfg)


async def _handle_mcp(request: web.Request) -> web.Response:
    state: _State = request.app["state"]

    # ── operator auth ──
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != state.operator_secret:
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        envelope = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)

    if not isinstance(envelope, dict):
        # JSON-RPC supports batch arrays too; not yet implemented in the gateway.
        return web.json_response(
            {"error": "batch requests not yet supported by this gateway"},
            status=400,
        )

    method   = envelope.get("method") or ""
    params   = envelope.get("params") or {}
    rid      = envelope.get("id", 1)

    # ── operator + entity binding from headers ──
    op_header = request.headers.get("X-Operator-Id")
    operator_id = uuid.UUID(op_header) if op_header else uuid.uuid4()
    entity_id   = request.headers.get("X-Entity-Id", "unknown")

    action_for_audit = _action_for_audit(method, params)

    # ── audit: in-flight ──
    async with state.local.acquire() as conn:
        await write_entry(conn, state.audit_key, AuditEntry(
            operator_id=operator_id, entity_id=entity_id,
            source_domain="operator", target_domain="skema",
            action=action_for_audit, params=params,
        ))

    # ── forward verbatim ──
    try:
        response_envelope = await state.upstream.forward(envelope)
    except aiohttp.ClientResponseError as e:
        logger.warning("upstream HTTP %s: %s", e.status, e.message)
        return web.json_response(
            {"jsonrpc": "2.0", "id": rid,
             "error": {"code": -32603, "message": f"upstream HTTP {e.status}"}},
            status=502,
        )
    except Exception as e:
        logger.warning("upstream call failed: %s", e)
        return web.json_response(
            {"jsonrpc": "2.0", "id": rid,
             "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}},
            status=502,
        )

    # Notification path: upstream returned 202/204 with no body. Pass through.
    if response_envelope is None:
        return web.Response(status=204)

    # ── audit: completed ──
    async with state.local.acquire() as conn:
        await write_entry(conn, state.audit_key, AuditEntry(
            operator_id=operator_id, entity_id=entity_id,
            source_domain="skema", target_domain="operator",
            action=action_for_audit,
            result=response_envelope.get("result") if isinstance(response_envelope.get("result"), dict) else {},
            ceigas_crossing_id=_extract_crossing_id(response_envelope),
        ))

    return web.json_response(response_envelope)


async def _handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def build_app(cfg: GatewayConfig, local: asyncpg.Pool,
              upstream: UpstreamClient) -> web.Application:
    app = web.Application()
    app["state"] = _State(cfg, local, upstream)
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/health", _handle_health)
    return app
