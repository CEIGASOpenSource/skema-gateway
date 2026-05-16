"""Tamper-evident local audit log writer.

Every gateway-authorized action gets two rows in `operator_audit_log`:
the in-flight entry (params, no result) and the completed entry (result,
ceigas_crossing_id). Both are HMAC-signed over the preceding signature
plus this row's fields, forming a chain. Tampering with any row breaks
the chain at that row.

The authoritative audit log is server-side (in the user's hosted container);
this local mirror is a transparency guarantee for the user.

The HMAC key is derived from gateway-internal material — NOT the user's
backup passphrase. Compromising the key only breaks local audit integrity,
not backup confidentiality.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from typing import Any

import asyncpg


@dataclass
class AuditEntry:
    operator_id:        uuid.UUID
    entity_id:          str
    source_domain:      str
    target_domain:      str
    action:             str
    params:             dict[str, Any] | None = None
    result:             dict[str, Any] | None = None
    ceigas_crossing_id: uuid.UUID | None = None
    # Routing tag — which gateway tile/upstream this call routed through.
    # NOT part of the HMAC chain (see migration 003 + write_entry below).
    upstream_name:      str | None = None


def _signature(key: bytes, fields: list[str]) -> bytes:
    """HMAC-SHA256 over a canonical concatenation of the row's fields."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for f in fields:
        h.update(f.encode("utf-8"))
        h.update(b"\x1e")  # record separator
    return h.digest()


async def write_entry(local: asyncpg.Connection,
                      audit_key: bytes,
                      entry: AuditEntry) -> int:
    """Append an audit row; returns the assigned `log_id`."""
    prev_sig = await local.fetchval(
        "SELECT signature FROM operator_audit_log ORDER BY log_id DESC LIMIT 1"
    ) or b""

    import json as _json
    params_text = _json.dumps(entry.params or {}, sort_keys=True, separators=(",", ":"))
    result_text = _json.dumps(entry.result or {}, sort_keys=True, separators=(",", ":"))

    prev_sig_hex = prev_sig if isinstance(prev_sig, str) else (bytes(prev_sig).hex() if prev_sig else "")
    sig = _signature(audit_key, [
        prev_sig_hex,
        str(entry.operator_id),
        entry.entity_id,
        entry.source_domain,
        entry.target_domain,
        entry.action,
        params_text,
        result_text,
        str(entry.ceigas_crossing_id or ""),
    ])

    # The schema stores `signature` as TEXT; hex-encode the HMAC bytes.
    # upstream_name is intentionally outside the HMAC — it's routing metadata,
    # so a forged value can only mislead the UI, not invalidate the signed chain.
    rec = await local.fetchrow(
        """
        INSERT INTO operator_audit_log
          (operator_id, entity_id, source_domain, target_domain,
           action, params, result, ceigas_crossing_id, signature, upstream_name)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10)
        RETURNING log_id
        """,
        entry.operator_id, entry.entity_id, entry.source_domain, entry.target_domain,
        entry.action, params_text, result_text, entry.ceigas_crossing_id, sig.hex(),
        entry.upstream_name,
    )
    return rec["log_id"]


async def verify_chain(local: asyncpg.Connection, audit_key: bytes) -> tuple[int, int]:
    """Walk the audit log forward and verify every signature.

    Returns (verified_count, first_broken_log_id_or_zero). If the second value
    is 0, the entire chain verifies.
    """
    import json as _json
    rows = await local.fetch(
        """
        SELECT log_id, operator_id, entity_id, source_domain, target_domain,
               action, params, result, ceigas_crossing_id, signature
          FROM operator_audit_log
         ORDER BY log_id ASC
        """
    )
    prev_sig_hex = ""
    verified = 0
    for r in rows:
        params = r["params"] if isinstance(r["params"], (dict, list)) else _json.loads(r["params"] or "{}")
        result = r["result"] if isinstance(r["result"], (dict, list)) else _json.loads(r["result"] or "{}")
        params_text = _json.dumps(params, sort_keys=True, separators=(",", ":"))
        result_text = _json.dumps(result, sort_keys=True, separators=(",", ":"))

        expected_hex = _signature(audit_key, [
            prev_sig_hex,
            str(r["operator_id"]),
            r["entity_id"],
            r["source_domain"],
            r["target_domain"],
            r["action"],
            params_text,
            result_text,
            str(r["ceigas_crossing_id"] or ""),
        ]).hex()
        stored_hex = r["signature"] or ""
        if not hmac.compare_digest(expected_hex, stored_hex):
            return verified, r["log_id"]
        verified += 1
        prev_sig_hex = stored_hex
    return verified, 0
