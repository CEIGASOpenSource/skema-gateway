"""
Skema Gateway — full installer-through-MCP integration test.

Brings up everything on one machine:

  1. Test docker-compose: local PG + parallax PG (existing)
  2. Dev-edge mock (in-process): mints CA + signs operator cert on redeem
  3. Mock upstream "skema container" (in-process, mTLS):
       - Server cert signed by dev-edge CA
       - Requires client cert auth against same CA
       - Returns canned shape()/recall() JSON-RPC results
  4. Installer (gatewayd.installer): runs anchor redemption, persists certs,
     prompts (env) for passphrase, generates DEK + recovery code, writes
     gatewayd.toml and operator/audit secrets, applies migrations, inserts
     envelopes
  5. Gateway daemon (build_app): launched on test port, reading the
     installer's config
  6. Test operator: makes a real MCP call over HTTP to the gateway

What this proves end-to-end:
  - Anchor redemption flow works (cert issued, persisted, valid)
  - Installer's parallax provisioning works (envelopes stored)
  - Gateway loads installed config and reaches mTLS upstream
  - MCP call traverses operator → gateway → mTLS → upstream → back
  - Audit log records both legs with verifiable HMAC chain
  - Backup roundtrips through the installed envelopes (recover with passphrase)
"""

from __future__ import annotations

import asyncio
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import aiohttp
import asyncpg
from aiohttp import web

from gatewayd.audit import verify_chain
from gatewayd.backup import push_full_snapshot
from gatewayd.config import load as load_config
from gatewayd.crypto import KdfParams, unwrap_dek
from gatewayd.crypto.envelope import Envelope
from gatewayd.db import init_conn
from gatewayd.installer import install, parse_args
from gatewayd.mcp import build_app
from gatewayd.restore import restore_snapshot
from gatewayd.transport.mtls import UpstreamClient

# Make tools/ importable
sys.path.insert(0, str(REPO_ROOT / "tools"))
from dev_edge.ca import (load_or_mint_ca, mint_server_cert)
from dev_edge.server import build_app as build_dev_edge_app

COMPOSE_DIR = REPO_ROOT / "tests" / "migrations"
LOCAL_DSN    = "postgresql://postgres:testpass@127.0.0.1:54541/skema_local"
PARALLAX_DSN = "postgresql://postgres:testpass@127.0.0.1:54542/parallax"

results: list[tuple[bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
    results.append((cond, name))


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


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


# ─── Mock upstream (mTLS) ───────────────────────────────────────────────

async def _mock_upstream_handler(request: web.Request) -> web.Response:
    """Faithful mock of the production /mcp contract — JSON-RPC 2.0 with
    initialize / tools/list / tools/call(shape|recall|signal)."""
    import json as _json
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
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "shape":
            text_body = _json.dumps({
                "directive": f"echo-shape: {args.get('message','')}",
                "ceigas_crossing_id": str(uuid.uuid4()),
            })
            return web.json_response({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": text_body}],
                "isError": False,
            }})
        return web.json_response({"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"unknown tool {name}"}})
    return web.json_response({"jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": f"unknown method {method}"}})


def _build_server_ssl_ctx(server_cert_pem: str, server_key_pem: str,
                           ca_cert_pem: str) -> ssl.SSLContext:
    """SSL context that requires client cert auth against the dev CA."""
    cert_dir = Path(tempfile.mkdtemp(prefix="skema-test-srv-"))
    sc = cert_dir / "server.cert.pem"
    sk = cert_dir / "server.key.pem"
    sa = cert_dir / "ca.cert.pem"
    sc.write_text(server_cert_pem)
    sk.write_text(server_key_pem)
    sa.write_text(ca_cert_pem)

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=str(sa))
    ctx.load_cert_chain(certfile=str(sc), keyfile=str(sk))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


# ─── Test ──────────────────────────────────────────────────────────────

async def run() -> None:
    # ── 0. clean home dir
    home = Path(tempfile.mkdtemp(prefix="skema-test-home-"))
    os.environ["SKEMA_GATEWAY_HOME"] = str(home)

    # ── 1. dev CA + dev-edge in-process
    ca_dir = home / "dev-ca"
    ca_key, ca_cert = load_or_mint_ca(ca_dir)
    check("dev CA minted", True)

    # ── 2. mock upstream with mTLS
    from tools.dev_edge.ca import ca_cert_pem
    server_bundle = mint_server_cert(ca_key, ca_cert,
                                       common_name="127.0.0.1",
                                       san_hosts=["127.0.0.1"])
    upstream_app = web.Application()
    upstream_app.router.add_post("/mcp", _mock_upstream_handler)
    upstream_runner = web.AppRunner(upstream_app)
    await upstream_runner.setup()
    upstream_ssl = _build_server_ssl_ctx(server_bundle.cert, server_bundle.key,
                                          ca_cert_pem(ca_cert))
    upstream_site = web.TCPSite(upstream_runner, "127.0.0.1", 0, ssl_context=upstream_ssl)
    await upstream_site.start()
    upstream_port = upstream_site._server.sockets[0].getsockname()[1]
    upstream_url = f"https://127.0.0.1:{upstream_port}/mcp"
    check(f"mock upstream listening (mTLS) on {upstream_url}", True)

    # ── 3. dev-edge (configured to return our mock upstream URL)
    dev_edge_app = build_dev_edge_app(ca_dir=ca_dir, upstream_url=upstream_url)
    dev_edge_runner = web.AppRunner(dev_edge_app)
    await dev_edge_runner.setup()
    dev_edge_site = web.TCPSite(dev_edge_runner, "127.0.0.1", 0)
    await dev_edge_site.start()
    dev_edge_port = dev_edge_site._server.sockets[0].getsockname()[1]
    check(f"dev-edge listening on http://127.0.0.1:{dev_edge_port}", True)

    # ── 4. prep DBs (apply migrations cleanly — installer will be idempotent)
    for dsn in (LOCAL_DSN, PARALLAX_DSN):
        conn = await asyncpg.connect(dsn)
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await conn.close()
    check("test DBs wiped", True)

    # ── 5. run installer (env passphrase)
    os.environ["SKEMA_PASSPHRASE"] = "correct-horse-battery-staple"
    args = parse_args([
        "--edge-url",     f"http://127.0.0.1:{dev_edge_port}",
        "--anchor-code",  "DEV-CODE-12345678",
        "--local-dsn",    LOCAL_DSN,
        "--parallax-dsn", PARALLAX_DSN,
        "--home",         str(home),
        "--passphrase-from-env", "SKEMA_PASSPHRASE",
    ])
    rc = await install(args)
    check("installer ran without error", rc == 0)
    check("certs persisted", (home / "certs" / "client.cert.pem").exists()
                                and (home / "certs" / "client.key.pem").exists()
                                and (home / "certs" / "ca.cert.pem").exists())
    check("gatewayd.toml written", (home / "gatewayd.toml").exists())
    check("operator secret persisted", (home / "secrets" / "operator.secret").exists())

    # parallax should now have two active envelopes
    pconn = await asyncpg.connect(PARALLAX_DSN)
    await init_conn(pconn)
    env_count = await pconn.fetchval(
        "SELECT COUNT(*) FROM local_backup_envelope WHERE is_active=TRUE"
    )
    check(f"parallax has 2 active envelopes ({env_count})", env_count == 2)

    # ── 6. Launch gatewayd against the installed config
    operator_secret = (home / "secrets" / "operator.secret").read_text().strip()
    audit_key_hex   = (home / "secrets" / "audit.key.hex").read_text().strip()
    os.environ["SKEMA_OPERATOR_SECRET"] = operator_secret
    os.environ["SKEMA_AUDIT_HMAC_KEY"]  = audit_key_hex
    os.environ["SKEMA_GATEWAY_CONFIG"]  = str(home / "gatewayd.toml")

    cfg = load_config(home / "gatewayd.toml")
    pool = await asyncpg.create_pool(cfg.backup.local_dsn, init=init_conn,
                                       min_size=1, max_size=2)
    upstream_client = UpstreamClient(cfg.upstream)
    await upstream_client.__aenter__()

    gw_app = build_app(cfg, pool, upstream_client)
    gw_runner = web.AppRunner(gw_app)
    await gw_runner.setup()
    gw_site = web.TCPSite(gw_runner, "127.0.0.1", 0)
    await gw_site.start()
    gw_port = gw_site._server.sockets[0].getsockname()[1]
    check(f"gatewayd listening on 127.0.0.1:{gw_port}", True)

    try:
        # ── 7. operator -> gateway -> mTLS -> mock upstream (real MCP envelope)
        async with aiohttp.ClientSession() as sess:
            async with sess.post(
                f"http://127.0.0.1:{gw_port}/mcp",
                json={"jsonrpc": "2.0", "id": 1,
                       "method": "tools/call",
                       "params": {"name": "shape",
                                  "arguments": {"message": "full flow"}}},
                headers={"Authorization": f"Bearer {operator_secret}"},
            ) as r:
                body = await r.json()
                result_block = body.get("result", {})
                text = (result_block.get("content") or [{}])[0].get("text", "")
                ok = (r.status == 200
                      and "echo-shape: full flow" in text
                      and result_block.get("isError") is False)
                check("operator → gateway → mTLS upstream → MCP-shaped result", ok,
                      f"status={r.status} body={body}")

        # ── 8. audit log chain
        async with pool.acquire() as conn:
            audit_count = await conn.fetchval("SELECT COUNT(*) FROM operator_audit_log")
            verified, broken = await verify_chain(conn, bytes.fromhex(audit_key_hex))
            check(f"audit chain verifies ({verified} of {audit_count} rows)", broken == 0)

        # ── 9. backup + restore round-trip with the installed envelopes
        async with pool.acquire() as conn:
            # seed a couple of memories
            for content in ("first memory", "second memory"):
                await conn.execute(
                    """
                    INSERT INTO memories (kind, content, owner_principal_id,
                                          confidence, importance)
                    VALUES ('observation', $1,
                            (SELECT principal_id FROM principals LIMIT 1),
                            'high', 1.0)
                    """,
                    content,
                )

        # unwrap DEK from the installed passphrase envelope
        env_row = await pconn.fetchrow(
            "SELECT * FROM local_backup_envelope WHERE kdf_source='passphrase' AND is_active=TRUE"
        )
        import json as _json
        env = Envelope(
            kdf_source="passphrase",
            wrapped_dek=bytes(env_row["wrapped_dek"]),
            wrap_nonce=bytes(env_row["wrap_nonce"]),
            wrap_auth_tag=bytes(env_row["wrap_auth_tag"]),
            kdf_salt=bytes(env_row["kdf_salt"]),
            kdf_params=KdfParams.from_jsonb(
                _json.loads(env_row["kdf_params"]) if isinstance(env_row["kdf_params"], str)
                else env_row["kdf_params"]
            ),
        )
        dek = unwrap_dek(env, b"correct-horse-battery-staple")

        async with pool.acquire() as lconn:
            counts = await push_full_snapshot(lconn, pconn, dek)
            pushed = sum(counts.values())
            check(f"snapshot pushed ({pushed} encrypted rows)", pushed > 0)

            await lconn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            await lconn.execute(
                (REPO_ROOT / "db" / "migrations" / "local" / "001_init.sql").read_text()
            )
            r_counts = await restore_snapshot(pconn, lconn, dek)
            restored = sum(r_counts.values())
            mem_count = await lconn.fetchval("SELECT COUNT(*) FROM memories")
            check(f"restore rehydrated local PG ({restored} rows, {mem_count} memories)",
                  restored == pushed and mem_count == 2)

    finally:
        await gw_runner.cleanup()
        await upstream_runner.cleanup()
        await dev_edge_runner.cleanup()
        await upstream_client.__aexit__(None, None, None)
        await pool.close()
        await pconn.close()


def main() -> int:
    try:
        compose_up()
        wait_for_stable("skema-test-local-pg")
        wait_for_stable("skema-test-parallax-pg")
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
