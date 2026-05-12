"""Cryptographic primitives for the gateway daemon.

Implements the key hierarchy locked in project_skema_backup_recovery:

    passphrase  ──argon2id(salt₁, params)──►  KEK₁ ──wraps──┐
                                                            │
                                                            ├──► DEK (random, 256-bit)
                                                            │           │
    recovery code  ──argon2id(salt₂, params)──►  KEK₂ ──wraps──┘        │
                                                                        │  AES-256-GCM, per-row nonce
                                                                        ▼
                                                                 backed-up rows
"""

from gatewayd.crypto.aead import aead_decrypt, aead_encrypt
from gatewayd.crypto.envelope import (
    Envelope,
    KdfParams,
    new_dek,
    unwrap_dek,
    wrap_dek,
)
from gatewayd.crypto.kdf import KDF_DEFAULTS, derive_kek

__all__ = [
    "aead_encrypt", "aead_decrypt",
    "Envelope", "KdfParams",
    "new_dek", "wrap_dek", "unwrap_dek",
    "KDF_DEFAULTS", "derive_kek",
]
