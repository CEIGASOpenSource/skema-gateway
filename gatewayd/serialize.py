"""Canonical serialization of PostgreSQL rows for backup.

Rows are converted to a stable JSON form before encryption, with type-aware
encoding for non-JSON-native types (UUID, datetime, bytes, vector). Stable
ordering of keys is enforced so that plaintext_hash is deterministic.

Embeddings (`VECTOR(...)`) are explicitly NOT serialized — they are excluded
from backup per project_skema_backup_recovery (recomputed locally on restore).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import json
import uuid
from decimal import Decimal
from typing import Any

EMBEDDING_COLUMNS = {"embedding_semantic", "embedding_purpose"}


def _encode_value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return v
    if isinstance(v, _dt.datetime):
        return {"__t__": "datetime", "v": v.isoformat()}
    if isinstance(v, _dt.date):
        return {"__t__": "date", "v": v.isoformat()}
    if isinstance(v, _dt.time):
        return {"__t__": "time", "v": v.isoformat()}
    if isinstance(v, _dt.timedelta):
        return {"__t__": "timedelta", "s": v.total_seconds()}
    if isinstance(v, uuid.UUID):
        return {"__t__": "uuid", "v": str(v)}
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"__t__": "bytes", "v": base64.b64encode(bytes(v)).decode("ascii")}
    if isinstance(v, Decimal):
        return {"__t__": "decimal", "v": str(v)}
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                      ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return {"__t__": "inet", "v": str(v)}
    if isinstance(v, (list, tuple)):
        return [_encode_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _encode_value(val) for k, val in v.items()}
    return {"__t__": "repr", "v": repr(v)}


def _decode_value(v: Any) -> Any:
    if isinstance(v, dict) and "__t__" in v:
        t = v["__t__"]
        if t == "datetime": return _dt.datetime.fromisoformat(v["v"])
        if t == "date":     return _dt.date.fromisoformat(v["v"])
        if t == "time":     return _dt.time.fromisoformat(v["v"])
        if t == "timedelta": return _dt.timedelta(seconds=v["s"])
        if t == "uuid":     return uuid.UUID(v["v"])
        if t == "bytes":    return base64.b64decode(v["v"])
        if t == "decimal":  return Decimal(v["v"])
        if t == "inet":     return v["v"]   # stored as text; asyncpg accepts str on INSERT
        return v
    if isinstance(v, list):
        return [_decode_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _decode_value(val) for k, val in v.items()}
    return v


def serialize_row(row: dict[str, Any]) -> bytes:
    """Encode a row dict to canonical JSON bytes (sorted keys, no whitespace).

    Embedding columns are dropped before serialization. The result is what
    gets encrypted and what plaintext_hash is computed over.
    """
    clean = {k: _encode_value(v) for k, v in row.items() if k not in EMBEDDING_COLUMNS}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_row(blob: bytes) -> dict[str, Any]:
    """Inverse of serialize_row. Returns a dict ready to INSERT (after embedding gen)."""
    raw = json.loads(blob.decode("utf-8"))
    return {k: _decode_value(v) for k, v in raw.items()}


def plaintext_hash(blob: bytes) -> bytes:
    """sha256 over the canonical serialized plaintext. Used for sync diff."""
    return hashlib.sha256(blob).digest()
