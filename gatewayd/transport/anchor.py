"""Anchor-code redemption — installer-side.

The user reaches privatae.ai checkout, completes signup, and is shown a
one-time anchor code with a ~10-minute TTL. They paste it into the gateway
installer, which:

  1. Reads the local hardware fingerprint
  2. POSTs (code, fingerprint) to the edge redemption endpoint over TLS
  3. Receives a CA-signed client cert + key + the upstream URL for their
     hosted skema container
  4. Stores the cert+key in the OS keychain / config dir
  5. Writes the upstream URL into the gateway config

This module handles step 2 and 3 — the HTTP exchange. Persistence (4, 5) is
the installer's responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass

import aiohttp

from gatewayd.transport.fingerprint import fingerprint


@dataclass
class RedemptionResult:
    cert_pem:     str
    key_pem:      str
    ca_pem:       str
    upstream_url: str


class RedemptionError(RuntimeError):
    """Anchor code was rejected — expired, already redeemed, or unknown."""


async def redeem(edge_url: str, anchor_code: str,
                 *, timeout_s: float = 30.0) -> RedemptionResult:
    """POST (code + fingerprint) to the edge; receive cert material on success.

    Edge endpoint contract (to be implemented server-side):
      POST {edge_url}/v1/anchors/redeem
      Body:    {"code": "...", "hardware_fingerprint": "..."}
      200 OK   {"cert": "...", "key": "...", "ca": "...", "upstream_url": "..."}
      4xx     {"error": "expired"|"unknown"|"already_redeemed"|"fingerprint_mismatch"}
    """
    payload = {
        "code":                 anchor_code,
        "hardware_fingerprint": fingerprint(),
    }
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(f"{edge_url}/v1/anchors/redeem", json=payload) as resp:
            body = await resp.json()
            if resp.status != 200:
                raise RedemptionError(body.get("error", f"HTTP {resp.status}"))

    return RedemptionResult(
        cert_pem=body["cert"],
        key_pem=body["key"],
        ca_pem=body["ca"],
        upstream_url=body["upstream_url"],
    )
