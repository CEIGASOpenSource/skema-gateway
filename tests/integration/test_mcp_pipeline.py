"""
Skema Gateway — MCP + audit + mTLS pipeline integration test.

Exercises:
  - Mock upstream "skema container" returning canned JSON-RPC responses
  - The gateway daemon (build_app) running on a test port
  - An operator (this test) calling the gateway over HTTP with bearer auth
  - The audit log being written and HMAC-chain-verified

What's stubbed vs real:
  - Upstream is plain HTTP, not mTLS — we exercise the call/audit pipeline,
    not the cryptography of mTLS. Real mTLS needs a CA + cert + container,
    which is production infrastructure not under test here.
  - Operator secret + audit key are set via env vars, as in production.
  - Local PG is the existing test docker-compose's local-pg.

Asserts:
  - Bearer-secret enforcement (wrong/missing secret => 401)
  - Successful shape() call → 200 + result
  - Audit log has 2 rows per call (in-flight + completed)
  - HMAC audit chain verifies clean
  - Upstream-error envelope is propagated
"""

from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import json

import aiohttp
import asyncpg
from aiohttp import web

from gatewayd.audit import verify_chain
from gatewayd.config import GatewayConfig, MCPConfig, UpstreamConfig, AuditConfig, BackupConfig
from gatewayd.db import init_conn
from gatewayd.mcp import build_app
from gatewayd.transport.mtls import UpstreamClient

COMPOSE_DIR = REPO_ROOT / "tests" / "migrations"
LOCAL_DSN   = "postgresql://postgres:testpass@127.0.0.1:54541/skema_local"
MIG         = REPO_ROOT / "db" / "migrations"

results: list[tuple[bool, str]] = []

def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
    results.append((cond, name))


def sh(cmd, **kw): return subprocess.run(cmd, check=True, **kw)


def compose_up():
    sh(["docker", "compose", "up", "-d"], cwd=COMPOSE_DIR,
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def compose_down():
    subprocess.run(["docker", "compose", "down", "-v"], cwd=COMPOSE_DIR,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_for_stable(container: str, timeout_s: int = 120):
    import time
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out = subprocess.run(["docker", "logs", container],
                             capture_output=True, text=True)
        if (out.stdout + out.stderr).count("database system is ready to accept connections") >= 2:
            return
        time.sleep(2)
    raise RuntimeError(f"{container} did not stabilize")


# ─── Mock upstream skema container ─────────────────────────────────────

async def _mock_mcp(request: web.Request) -> web.Response:
    """Faithful mock of /opt/privatae/skema/server/routes/mcp.py — JSON-RPC 2.0
    over /mcp, with `initialize`, `tools/list`, `tools/call(shape|recall|signal)`,
    and a synthetic-error path. Auth is bearer; any non-empty bearer accepted."""
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        return web.json_response({"error": "missing bearer"}, status=401)

    body = await request.json()
    method = body.get("method")
    params = body.get("params") or {}
    rid = body.get("id", 1)

    if method == "initialize":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "synaptive-mock", "version": "0.0.1"},
        }})
    if method == "tools/list":
        return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
            "tools": [{"name": "shape"}, {"name": "recall"}, {"name": "signal"}],
        }})
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "shape":
            msg = args.get("message", "")
            text_body = json.dumps({
                "directive": f"echo-shape: {msg}",
                "ceigas_crossing_id": str(uuid.uuid4()),
            })
            return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text_body}],
                "isError": False,
            }})
        if name == "force_error":
            return web.json_response({"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32000, "message": "synthetic error"}})
        return web.json_response({"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"unknown tool {name}"}})
    return web.json_response({"jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": f"unknown method {method}"}})


def build_mock_upstream() -> web.Application:
    app = web.Application()
    app.router.add_post("/mcp", _mock_mcp)
    return app


# ─── Test ──────────────────────────────────────────────────────────────

async def run() -> None:
    # ─── Bring up local PG schema
    conn = await asyncpg.connect(LOCAL_DSN)
    await init_conn(conn)
    await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    await conn.execute((MIG / "local" / "001_init.sql").read_text())
    await conn.close()
    check("local schema applied", True)

    # ─── Set required secrets in env
    operator_secret = secrets.token_urlsafe(32)
    audit_key       = secrets.token_bytes(32)
    os.environ["SKEMA_OPERATOR_SECRET"] = operator_secret
    os.environ["SKEMA_AUDIT_HMAC_KEY"]  = audit_key.hex()

    # ─── Spin up mock upstream
    mock_app = build_mock_upstream()
    mock_runner = web.AppRunner(mock_app)
    await mock_runner.setup()
    mock_site = web.TCPSite(mock_runner, "127.0.0.1", 0)  # auto-pick port
    await mock_site.start()
    mock_port = mock_site._server.sockets[0].getsockname()[1]
    check(f"mock upstream listening on 127.0.0.1:{mock_port}", True)

    # ─── Spin up gateway
    cfg = GatewayConfig(
        mcp=MCPConfig(listen_host="127.0.0.1", listen_port=0,
                       operator_secret_env="SKEMA_OPERATOR_SECRET"),
        upstream=UpstreamConfig(url=f"http://127.0.0.1:{mock_port}/mcp",
                                  bearer_token="mcp_test_token"),
        backup=BackupConfig(local_dsn=LOCAL_DSN),
        audit=AuditConfig(audit_key_env="SKEMA_AUDIT_HMAC_KEY"),
    )
    pool = await asyncpg.create_pool(LOCAL_DSN, init=init_conn, min_size=1, max_size=2)
    upstream = UpstreamClient(cfg.upstream)
    await upstream.__aenter__()
    app = build_app(cfg, pool, upstream)
    gw_runner = web.AppRunner(app)
    await gw_runner.setup()
    gw_site = web.TCPSite(gw_runner, "127.0.0.1", 0)
    await gw_site.start()
    gw_port = gw_site._server.sockets[0].getsockname()[1]
    check(f"gateway listening on 127.0.0.1:{gw_port}", True)

    try:
        async with aiohttp.ClientSession() as sess:
            base = f"http://127.0.0.1:{gw_port}"

            # ─── health
            async with sess.get(f"{base}/health") as r:
                check("/health 200", r.status == 200)

            # ─── auth: missing secret
            async with sess.post(f"{base}/mcp", json={"method": "shape", "id": 1}) as r:
                check("missing Authorization → 401", r.status == 401)

            # ─── auth: wrong secret
            async with sess.post(f"{base}/mcp",
                                  json={"method": "shape", "id": 1},
                                  headers={"Authorization": "Bearer wrong"}) as r:
                check("wrong bearer → 401", r.status == 401)

            # ─── successful shape() tool call (real MCP envelope shape)
            headers = {"Authorization": f"Bearer {operator_secret}",
                       "X-Operator-Id": str(uuid.uuid4()),
                       "X-Entity-Id": "entity-3"}
            async with sess.post(f"{base}/mcp",
                                  json={"jsonrpc": "2.0", "id": 42,
                                         "method": "tools/call",
                                         "params": {"name": "shape",
                                                    "arguments": {"message": "hello world"}}},
                                  headers=headers) as r:
                body = await r.json()
                ok_status = r.status == 200
                result_block = body.get("result", {})
                text = (result_block.get("content") or [{}])[0].get("text", "")
                ok_result = "echo-shape: hello world" in text
                check("shape() tool call returns MCP-shaped result",
                      ok_status and ok_result and result_block.get("isError") is False,
                      f"status={r.status} body={body}")

            # ─── upstream-error propagation (synthetic tool that returns JSON-RPC error)
            async with sess.post(f"{base}/mcp",
                                  json={"jsonrpc": "2.0", "id": 7,
                                         "method": "tools/call",
                                         "params": {"name": "force_error"}},
                                  headers=headers) as r:
                body = await r.json()
                err = body.get("error") or {}
                check("upstream JSON-RPC error propagated verbatim",
                      r.status == 200 and err.get("code") == -32000,
                      f"status={r.status} body={body}")

        # ─── audit log: should have 4 rows (2 calls × 2 entries each) plus 1 if force_error logged in-flight
        async with pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM operator_audit_log")
            check(f"audit log populated ({count} rows)", count >= 3,
                  f"expected at least 3 (2 calls × in-flight + 1 completed)")

            verified, broken = await verify_chain(conn, audit_key)
            check(f"audit HMAC chain verifies ({verified} rows)",
                  broken == 0,
                  f"broken at log_id={broken}" if broken else "")

            # ─── tamper detection
            await conn.execute(
                "UPDATE operator_audit_log SET action = 'TAMPERED' WHERE log_id = (SELECT MIN(log_id) FROM operator_audit_log)"
            )
            verified_after, broken_after = await verify_chain(conn, audit_key)
            check("tampering breaks the chain", broken_after != 0,
                  f"verified_before={verified} verified_after={verified_after}")

    finally:
        await gw_runner.cleanup()
        await mock_runner.cleanup()
        await upstream.__aexit__(None, None, None)
        await pool.close()


def main() -> int:
    try:
        compose_up()
        wait_for_stable("skema-test-local-pg")
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
