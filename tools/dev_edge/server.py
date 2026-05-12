"""Dev-edge HTTP server — mocks the Privatae-FW anchor redemption endpoint.

NOT for production. Use to bring up the full install flow on one machine.

Endpoints:
    POST /v1/anchors/redeem
        Body:  {"code": "...", "hardware_fingerprint": "..."}
        Reply: {"cert": "...", "key": "...", "ca": "...", "upstream_url": "..."}

The default upstream URL points at 127.0.0.1:7879/mcp (matches the test mock
upstream that ships in tests/integration). Override via DEV_EDGE_UPSTREAM env.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

# Allow `python tools/dev-edge/server.py` from the repo root
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from aiohttp import web

from ca import ca_cert_pem, load_or_mint_ca, mint_operator_cert

DEFAULT_CA_DIR       = Path(os.environ.get("DEV_EDGE_CA_DIR",       "/tmp/skema-dev-edge-ca"))
DEFAULT_UPSTREAM_URL = os.environ.get("DEV_EDGE_UPSTREAM",         "http://127.0.0.1:7879/")
DEFAULT_LISTEN_HOST  = os.environ.get("DEV_EDGE_HOST",             "127.0.0.1")
DEFAULT_LISTEN_PORT  = int(os.environ.get("DEV_EDGE_PORT",         "8443"))


async def handle_redeem(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)

    code = body.get("code")
    fp   = body.get("hardware_fingerprint")
    if not code or not fp:
        return web.json_response(
            {"error": "missing 'code' or 'hardware_fingerprint'"}, status=400
        )

    state = request.app["state"]
    bundle = mint_operator_cert(
        state["ca_key"], state["ca_cert"],
        operator_uuid=str(uuid.uuid4()),
        hardware_fingerprint=fp,
    )

    return web.json_response({
        "cert":         bundle.cert,
        "key":          bundle.key,
        "ca":           ca_cert_pem(state["ca_cert"]),
        "upstream_url": state["upstream_url"],
    })


async def handle_root(request: web.Request) -> web.Response:
    return web.json_response({
        "service":      "skema-dev-edge",
        "endpoints":    ["POST /v1/anchors/redeem"],
        "upstream_url": request.app["state"]["upstream_url"],
        "warning":      "DEV ONLY — accepts any anchor code, do not deploy.",
    })


def build_app(ca_dir: Path = DEFAULT_CA_DIR,
              upstream_url: str = DEFAULT_UPSTREAM_URL) -> web.Application:
    key, cert = load_or_mint_ca(ca_dir)
    app = web.Application()
    app["state"] = {"ca_key": key, "ca_cert": cert, "upstream_url": upstream_url}
    app.router.add_get("/",                     handle_root)
    app.router.add_post("/v1/anchors/redeem",   handle_redeem)
    return app


async def _run(host: str, port: int, ca_dir: Path, upstream_url: str) -> None:
    app = build_app(ca_dir, upstream_url)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[dev-edge] listening on http://{host}:{port}")
    print(f"[dev-edge] CA at {ca_dir}")
    print(f"[dev-edge] upstream will be {upstream_url}")
    await asyncio.Event().wait()


def main() -> int:
    try:
        asyncio.run(_run(
            DEFAULT_LISTEN_HOST, DEFAULT_LISTEN_PORT,
            DEFAULT_CA_DIR, DEFAULT_UPSTREAM_URL,
        ))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
