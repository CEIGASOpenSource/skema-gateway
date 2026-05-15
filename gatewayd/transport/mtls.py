"""Outbound mTLS client to the user's hosted skema container.

The gateway acts as a TLS *client* with a CA-signed cert obtained via the
anchor redemption flow. Per project_skema_trust_path, mTLS terminates AT
the container (edge is a pure SNI TCP proxy in production), so the TLS
session is end-to-end.

The container's MCP server requires both:
  - mTLS client cert (proves machine identity; matches hardware_fingerprint
    recorded in `mcp_client_tokens.hardware_fingerprint`)
  - Bearer token (proves entity binding; SHA-256 hash matches
    `mcp_client_tokens.token_hash`)

Two trust layers, defense in depth.

The gateway is a transparent JSON-RPC 2.0 proxy. It forwards the operator's
envelope verbatim to the upstream container's `/mcp` endpoint and returns
the upstream's response envelope verbatim. Audit happens around the call.
"""

from __future__ import annotations

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
    """Async mTLS JSON-RPC client for the user's hosted skema container."""

    def __init__(self, cfg: UpstreamConfig):
        self.cfg = cfg
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "UpstreamClient":
        if self.cfg.cert_path and self.cfg.key_path:
            ssl_ctx: ssl.SSLContext | bool = _build_ssl_context(self.cfg)
        else:
            # Dev/test: plain HTTP. Real installs MUST configure mTLS.
            ssl_ctx = False
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=self.cfg.timeout_s)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def forward(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        """Forward a JSON-RPC envelope to the upstream `/mcp` endpoint verbatim.

        Returns the upstream's response envelope verbatim, or None if the
        request was a notification (JSON-RPC msg without `id`) and the
        upstream responded 202/204 with no body. Caller is responsible
        for stripping operator-side credentials and substituting the upstream
        bearer before invoking this.
        """
        if self._session is None:
            raise RuntimeError("UpstreamClient must be used as async context manager")

        headers = {
            "Content-Type":                  "application/json",
            "Authorization":                 f"Bearer {self.cfg.bearer_token}",
            "X-Skema-Hardware-Fingerprint":  fingerprint(),
        }

        async with self._session.post(self.cfg.url, json=envelope, headers=headers) as resp:
            # MCP notifications (no `id` field) get 202/204 from upstream — no body to decode.
            if resp.status in (202, 204):
                return None
            # JSON-RPC servers SHOULD return 200 even for protocol-level errors;
            # 4xx/5xx is for HTTP-level failures.
            resp.raise_for_status()
            return await resp.json()

    async def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        """POST a JSON body to an arbitrary upstream path on the same mTLS
        session. Used for sidecar pushes (audit ingest, backup blob sync)
        that ride the same gateway authentication as the MCP forward path.
        """
        if self._session is None:
            raise RuntimeError("UpstreamClient must be used as async context manager")

        # Build the absolute URL from the configured MCP endpoint's scheme+host.
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(self.cfg.url)
        target = urlunsplit((parts.scheme, parts.netloc, path, "", ""))

        headers = {
            "Content-Type":                  "application/json",
            "Authorization":                 f"Bearer {self.cfg.bearer_token}",
            "X-Skema-Hardware-Fingerprint":  fingerprint(),
        }
        async with self._session.post(target, json=body, headers=headers) as resp:
            if resp.status in (202, 204):
                return None
            resp.raise_for_status()
            try:
                return await resp.json()
            except aiohttp.ContentTypeError:
                return None


class UpstreamError(RuntimeError):
    """The upstream returned a JSON-RPC error envelope or an HTTP failure."""
    def __init__(self, err: dict[str, Any]):
        super().__init__(f"upstream error {err.get('code')}: {err.get('message')}")
        self.payload = err


class UpstreamRegistry:
    """Holds one UpstreamClient per registered container.

    Each tile in the dashboard corresponds to one entry here. The active
    tile is the one whose client the MCP relay will route through.
    """

    def __init__(self, upstreams: dict[str, UpstreamConfig], default_name: str = ""):
        self._configs = upstreams
        self._clients: dict[str, UpstreamClient] = {}
        # Resolve initial active selection: configured default, or first key,
        # or empty if no upstreams registered.
        self._active: str = default_name or (next(iter(upstreams)) if upstreams else "")

    @property
    def active(self) -> str:
        return self._active

    def names(self) -> list[str]:
        return list(self._configs.keys())

    def config(self, name: str) -> UpstreamConfig:
        return self._configs[name]

    def configs(self) -> dict[str, UpstreamConfig]:
        return dict(self._configs)

    def select(self, name: str) -> None:
        if name not in self._configs:
            raise KeyError(f"unknown upstream: {name!r}")
        self._active = name

    def active_client(self) -> "UpstreamClient":
        if not self._active:
            raise RuntimeError("no active upstream — none registered")
        return self._clients[self._active]

    async def __aenter__(self) -> "UpstreamRegistry":
        # Open a session for each registered upstream. Sessions are
        # long-lived; switching active tile just routes new requests
        # through a different one.
        for name, cfg in self._configs.items():
            client = UpstreamClient(cfg)
            await client.__aenter__()
            self._clients[name] = client
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        for client in self._clients.values():
            try:
                await client.__aexit__(exc_type, exc, tb)
            except Exception:
                pass
        self._clients.clear()
