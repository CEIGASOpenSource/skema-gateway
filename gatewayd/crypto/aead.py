"""AES-256-GCM AEAD wrapper.

GCM is used for two purposes in this codebase:
  1. Wrapping the DEK with the passphrase/recovery KEK (in envelope.py)
  2. Encrypting individual serialized rows for backup (in backup.py)

GCM nonces MUST be unique per (key, nonce) pair. We use 96-bit random nonces
generated at encryption time; with 256-bit keys this is safe for the volumes
this daemon will ever produce.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GCM_NONCE_LEN = 12  # 96 bits, per NIST SP 800-38D
GCM_TAG_LEN   = 16  # 128 bits, fixed by spec


def aead_encrypt(key: bytes, plaintext: bytes,
                 aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext under `key` with a fresh nonce.

    Returns (nonce, ciphertext_with_tag). The auth tag is the last 16 bytes
    of `ciphertext_with_tag` per the cryptography library's convention.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = secrets.token_bytes(GCM_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                 aad: bytes | None = None) -> bytes:
    """Decrypt and authenticate.

    Raises `cryptography.exceptions.InvalidTag` if the ciphertext, nonce, or
    AAD has been tampered with, or the key is wrong.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(nonce) != GCM_NONCE_LEN:
        raise ValueError(f"nonce must be {GCM_NONCE_LEN} bytes")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def split_tag(ciphertext_with_tag: bytes) -> tuple[bytes, bytes]:
    """Split combined output into (ciphertext, tag) for storage that wants them apart."""
    if len(ciphertext_with_tag) < GCM_TAG_LEN:
        raise ValueError("ciphertext shorter than auth tag length")
    return ciphertext_with_tag[:-GCM_TAG_LEN], ciphertext_with_tag[-GCM_TAG_LEN:]


def join_tag(ciphertext: bytes, tag: bytes) -> bytes:
    """Inverse of split_tag — combine for AEAD library consumption."""
    if len(tag) != GCM_TAG_LEN:
        raise ValueError(f"tag must be {GCM_TAG_LEN} bytes")
    return ciphertext + tag
