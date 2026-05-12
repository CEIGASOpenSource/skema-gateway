"""Local MCP server.

Per project_skema_trust_path invariant #2: the gateway daemon hosts the MCP
server on 127.0.0.1. Operators (Claude Code, Claude Desktop, LM Studio, ...)
connect to localhost, NOT to a Privatae-side relay. Every call:

  1. Authenticates the operator (bearer secret in dev v1)
  2. Logs an in-flight audit row to local PG
  3. Forwards via mTLS to the user's hosted skema container
  4. Logs the completed audit row with the result + ceigas_crossing_id
  5. Returns the result to the operator

This is JSON-RPC 2.0 over HTTP POST at /mcp. MCP-protocol tools/list and
tools/call are exposed by name (`shape`, `recall`, etc.).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import asyncpg
from aiohttp import web

from gatewayd.audit import AuditEntry, write_entry
from gatewayd.config import GatewayConfig
from gatewayd.transport.mtls import UpstreamClient, UpstreamError


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


class _State:
    """Shared app state attached to the aiohttp Application."""
    def __init__(self, cfg: GatewayConfig, local: asyncpg.Pool,
                 upstream: UpstreamClient):
        self.cfg      = cfg
        self.local    = local
        self.upstream = upstream
        self.audit_key      = _audit_key(cfg)
        self.operator_secret = _operator_secret(cfg)


async def _handle_mcp(request: web.Request) -> web.Response:
    state: _State = request.app["state"]

    # ─── auth ───
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != state.operator_secret:
        return web.json_response({"error": "unauthorized"}, status=401)

    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)

    method = body.get("method")
    params = body.get("params") or {}
    req_id = body.get("id", 1)
    if not method:
        return web.json_response(
            {"jsonrpc": "2.0", "id": req_id,
             "error": {"code": -32600, "message": "method required"}},
            status=400,
        )

    operator_id = uuid.UUID(request.headers.get("X-Operator-Id", str(uuid.uuid4())))
    entity_id   = request.headers.get("X-Entity-Id", "unknown")

    # ─── audit: in-flight ───
    async with state.local.acquire() as conn:
        await write_entry(conn, state.audit_key, AuditEntry(
            operator_id=operator_id, entity_id=entity_id,
            source_domain="operator", target_domain="skema",
            action=method, params=params,
        ))

    # ─── forward ───
    try:
        result = await state.upstream.call(method, params)
    except UpstreamError as e:
        return web.json_response(
            {"jsonrpc": "2.0", "id": req_id, "error": e.payload},
            status=502,
        )
    except Exception as e:
        return web.json_response(
            {"jsonrpc": "2.0", "id": req_id,
             "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}},
            status=502,
        )

    crossing_id = uuid.UUID(result["ceigas_crossing_id"]) \
        if isinstance(result, dict) and "ceigas_crossing_id" in result else None

    # ─── audit: completed ───
    async with state.local.acquire() as conn:
        await write_entry(conn, state.audit_key, AuditEntry(
            operator_id=operator_id, entity_id=entity_id,
            source_domain="skema", target_domain="operator",
            action=method, result=result, ceigas_crossing_id=crossing_id,
        ))

    return web.json_response({"jsonrpc": "2.0", "id": req_id, "result": result})


async def _handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


def build_app(cfg: GatewayConfig, local: asyncpg.Pool,
              upstream: UpstreamClient) -> web.Application:
    app = web.Application()
    app["state"] = _State(cfg, local, upstream)
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/health", _handle_health)
    return app
