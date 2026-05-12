"""DEK wrapping / unwrapping — the `local_backup_envelope` table rows in code.

A DEK (data encryption key, 256-bit random) encrypts every backed-up row.
The DEK itself is wrapped by a KEK derived from either:
  - the user's passphrase
  - the user's offline recovery code

Two envelope rows wrap the same DEK; either path unlocks. Rotation of either
secret = unwrap with old KEK, wrap with new KEK, mark old row inactive. DEK
itself never changes (no need to re-encrypt blobs).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Literal

from gatewayd.crypto.aead import aead_decrypt, aead_encrypt, split_tag
from gatewayd.crypto.kdf import KDF_DEFAULTS, derive_kek

DEK_LEN = 32  # 256-bit
SALT_LEN = 16

KdfSource = Literal["passphrase", "recovery_code"]


@dataclass
class KdfParams:
    """Parameters needed to reproduce a KEK from a secret."""
    algo:   str = KDF_DEFAULTS["algo"]
    m_kib:  int = KDF_DEFAULTS["m_kib"]
    t:      int = KDF_DEFAULTS["t"]
    p:      int = KDF_DEFAULTS["p"]

    def to_jsonb(self) -> dict:
        return {"m_kib": self.m_kib, "t": self.t, "p": self.p}

    @classmethod
    def from_jsonb(cls, data: dict, algo: str = "argon2id") -> "KdfParams":
        return cls(algo=algo, m_kib=data["m_kib"], t=data["t"], p=data["p"])


@dataclass
class Envelope:
    """One row of `local_backup_envelope` in code form."""
    kdf_source:    KdfSource
    wrapped_dek:   bytes
    wrap_nonce:    bytes
    wrap_auth_tag: bytes
    kdf_salt:      bytes
    kdf_params:    KdfParams = field(default_factory=KdfParams)
    wrap_algo:     str = "aes-256-gcm"

    def ciphertext_with_tag(self) -> bytes:
        return self.wrapped_dek + self.wrap_auth_tag


def new_dek() -> bytes:
    """Generate a fresh 256-bit DEK."""
    return secrets.token_bytes(DEK_LEN)


def wrap_dek(dek: bytes, secret: bytes, source: KdfSource,
             params: KdfParams | None = None) -> Envelope:
    """Wrap `dek` under a KEK derived from `secret` (passphrase or recovery code).

    Generates a fresh salt for each call. The Envelope returned contains
    everything needed to unwrap later given the same `secret`.
    """
    if len(dek) != DEK_LEN:
        raise ValueError(f"DEK must be {DEK_LEN} bytes")
    params = params or KdfParams()
    salt = secrets.token_bytes(SALT_LEN)
    kek = derive_kek(secret, salt, m_kib=params.m_kib, t=params.t, p=params.p)
    nonce, ct = aead_encrypt(kek, dek)
    ct_only, tag = split_tag(ct)
    return Envelope(
        kdf_source=source,
        wrapped_dek=ct_only,
        wrap_nonce=nonce,
        wrap_auth_tag=tag,
        kdf_salt=salt,
        kdf_params=params,
    )


def unwrap_dek(env: Envelope, secret: bytes) -> bytes:
    """Derive KEK from `secret` + envelope salt/params and recover the DEK.

    Raises `cryptography.exceptions.InvalidTag` if `secret` is wrong.
    """
    kek = derive_kek(
        secret, env.kdf_salt,
        m_kib=env.kdf_params.m_kib,
        t=env.kdf_params.t,
        p=env.kdf_params.p,
    )
    return aead_decrypt(kek, env.wrap_nonce, env.ciphertext_with_tag())
