"""Outbound mTLS client to the user's hosted skema container.

The gateway acts as a TLS *client* with a CA-signed cert obtained via the
anchor redemption flow. The remote side is the user's container; its cert
is verified against the provisioning CA.

Per project_skema_trust_path: the edge (Privatae-FW) is a pure SNI TCP proxy
in production — TLS terminates AT the container, not at the edge. So this
client's TLS session is end-to-end with the container.

The hardware fingerprint is sent as a header on every request; the container
side validates it against `mcp_client_tokens.hardware_fingerprint`. A modified
gateway cannot forge a fingerprint that matches the recorded value.
"""

from __future__ import annotations

import json
import ssl
from typing import Any

import aiohttp

from gatewayd.config import UpstreamConfig
from gatewayd.transport.fingerprint import fingerprint


def _build_ssl_context(cfg: UpstreamConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cfg.ca_path or None)
    ctx.load_cert_chain(certfile=cfg.cert_path, keyfile=cfg.key_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


class UpstreamClient:
    """Async mTLS client for calling the hosted skema container."""

    def __init__(self, cfg: UpstreamConfig):
        self.cfg = cfg
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "UpstreamClient":
        if self.cfg.cert_path and self.cfg.key_path:
            ssl_ctx: ssl.SSLContext | bool = _build_ssl_context(self.cfg)
        else:
            # Dev/test mode: no client cert. Real installs MUST configure mTLS.
            ssl_ctx = False
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout_s)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC 2.0 request to the upstream container and return its result."""
        if self._session is None:
            raise RuntimeError("UpstreamClient must be used as async context manager")

        payload = {
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params or {},
        }
        headers = {
            "Content-Type":               "application/json",
            "X-Skema-Hardware-Fingerprint": fingerprint(),
        }

        async with self._session.post(
            self.cfg.url, data=json.dumps(payload), headers=headers
        ) as resp:
            resp.raise_for_status()
            body = await resp.json()

        if "error" in body and body["error"] is not None:
            raise UpstreamError(body["error"])
        return body.get("result", {})


class UpstreamError(RuntimeError):
    """The upstream container returned a JSON-RPC error envelope."""
    def __init__(self, err: dict[str, Any]):
        super().__init__(f"upstream error {err.get('code')}: {err.get('message')}")
        self.payload = err
