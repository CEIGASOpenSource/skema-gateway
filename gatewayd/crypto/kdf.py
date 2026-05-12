"""Argon2id KDF wrapper.

v1 defaults are locked in `project_skema_backup_recovery` memory:
    m_kib = 262144   (256 MiB)
    t     = 3
    p     = 1

Stored per-envelope-row in `local_backup_envelope.kdf_params` so defaults can
be upgraded later without forcing global rotation.
"""

from __future__ import annotations

from argon2.low_level import Type, hash_secret_raw

KDF_DEFAULTS = {
    "algo":   "argon2id",
    "m_kib":  262144,   # 256 MiB
    "t":      3,
    "p":      1,
}

KEK_LEN = 32  # 256-bit AES key


def derive_kek(secret: bytes, salt: bytes, *,
               m_kib: int = KDF_DEFAULTS["m_kib"],
               t:     int = KDF_DEFAULTS["t"],
               p:     int = KDF_DEFAULTS["p"]) -> bytes:
    """Derive a 256-bit KEK from a passphrase or recovery code.

    Argon2id is memory-hard; raising `m_kib` is the primary defense against
    GPU/ASIC offline attacks on a captured wrapped DEK + salt + params.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt must be bytes of length >= 8")

    return hash_secret_raw(
        secret=bytes(secret),
        salt=bytes(salt),
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=KEK_LEN,
        type=Type.ID,
    )
