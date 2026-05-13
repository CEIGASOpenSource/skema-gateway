"""
Skema Gateway — connectivity smoke test.

Run after `gatewayd.installer` finishes and the daemon is up. Probes:

  1. Local /health endpoint on the daemon
  2. JSON-RPC `initialize` handshake against the daemon's /mcp
     (which proxies to the upstream skema container over mTLS)
  3. tools/list — confirms the upstream container responded with the
     expected tool surface (shape, recall, signal)
  4. Optional: tools/call shape with a 1-token message (only if
     --shape is passed)

Exits 0 on full success; non-zero on first failure with a clear cause.

Usage:
    SKEMA_OPERATOR_SECRET=$(cat ~/.config/skema/secrets/operator.secret) \\
    python -m gatewayd.check
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _post(url: str, body: dict, headers: dict, timeout: float = 15.0) -> tuple[int, dict | None, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            try:
                return r.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return r.status, None, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return e.code, None, raw
    except urllib.error.URLError as e:
        return 0, None, f"connection error: {e}"


def _get(url: str, timeout: float = 5.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return 0, f"connection error: {e}"


def fail(msg: str) -> int:
    print(f"  ✗ {msg}")
    return 1


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="gatewayd.check")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:7878",
                        help="base URL of the local gateway (default 127.0.0.1:7878)")
    parser.add_argument("--shape", action="store_true",
                        help="also exercise tools/call shape with a tiny message")
    args = parser.parse_args()

    secret = os.environ.get("SKEMA_OPERATOR_SECRET", "").strip()
    if not secret:
        return fail("SKEMA_OPERATOR_SECRET not set in env — read it from ~/.config/skema/secrets/operator.secret")

    print("Skema Gateway connectivity check")
    print(f"  gateway base: {args.gateway_url}")
    print()

    # 1. Health
    code, body = _get(args.gateway_url + "/health")
    if code != 200:
        return fail(f"/health returned {code}: {body}")
    ok("/health 200")

    # 2. initialize
    headers = {"Authorization": f"Bearer {secret}"}
    code, env, raw = _post(args.gateway_url + "/mcp",
                            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                            headers)
    if code != 200 or not env:
        return fail(f"initialize returned {code}: {raw[:200]}")
    pv = (env.get("result") or {}).get("protocolVersion")
    si = (env.get("result") or {}).get("serverInfo") or {}
    if not pv:
        return fail(f"initialize result missing protocolVersion: {env}")
    ok(f"initialize ok — upstream is {si.get('name','?')} {si.get('version','?')} (protocol {pv})")

    # 3. tools/list
    code, env, raw = _post(args.gateway_url + "/mcp",
                            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                            headers)
    if code != 200 or not env:
        return fail(f"tools/list returned {code}: {raw[:200]}")
    tools = [t.get("name") for t in (env.get("result") or {}).get("tools", [])]
    expected = {"shape", "recall", "signal"}
    missing = expected - set(tools)
    if missing:
        return fail(f"tools/list missing expected tools: {missing} (got {tools})")
    ok(f"tools/list returned {sorted(tools)}")

    # 4. Optional shape() exercise
    if args.shape:
        code, env, raw = _post(args.gateway_url + "/mcp",
                                {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "shape", "arguments": {"message": "ping from gatewayd.check"}}},
                                headers)
        if code != 200 or not env:
            return fail(f"shape returned {code}: {raw[:300]}")
        result = env.get("result") or {}
        if result.get("isError"):
            return fail(f"shape returned isError: {result}")
        content = (result.get("content") or [{}])[0].get("text", "")
        ok(f"shape ok — first 80 chars of directive: {content[:80]!r}")

    print()
    print("All checks passed.")
    print("Add to your Claude Code / Claude Desktop MCP config:")
    print(f"    url:    {args.gateway_url}/mcp")
    print(f"    header: Authorization: Bearer <contents of ~/.config/skema/secrets/operator.secret>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
