"""
Skema Gateway — backup/recovery key hierarchy round-trip tests (Layer 2).

Validates the encryption design in db/migrations/parallax/002_local_backup.sql:
- Argon2id KDF with locked v1 params (m_kib=262144, t=3, p=1)
- AES-256-GCM for both DEK wrapping and row encryption
- Two unlock paths (passphrase + recovery code) wrapping the SAME DEK
- Passphrase rotation (re-wrap DEK without re-encrypting blobs)
- KDF param upgrade (old params stored per-row, still decryptable)
- Auth-tag tamper detection
- Compromise simulation (auditor with ciphertext + params + salt, no passphrase)

No DB required. Pure cryptographic primitives.
"""

import secrets
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# v1 KDF defaults (locked 2026-05-12 in project_skema_backup_recovery)
ARGON2ID_M_KIB = 262144  # 256 MiB
ARGON2ID_T = 3
ARGON2ID_P = 1
KEY_LEN = 32  # 256-bit


def derive_kek(secret: bytes, salt: bytes,
               m_kib: int = ARGON2ID_M_KIB,
               t: int = ARGON2ID_T,
               p: int = ARGON2ID_P) -> bytes:
    return hash_secret_raw(
        secret=secret, salt=salt,
        time_cost=t, memory_cost=m_kib, parallelism=p,
        hash_len=KEY_LEN, type=Type.ID,
    )


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


results: list[tuple[bool, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "✓" if cond else "✗"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
    results.append((cond, name))


# ─── Setup ──────────────────────────────────────────────────────────────
print("Setup: simulating a fresh install...")
passphrase = b"correct-horse-battery-staple"
recovery_code = b"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"
salt_pp = secrets.token_bytes(16)
salt_rc = secrets.token_bytes(16)
dek = secrets.token_bytes(KEY_LEN)

kek_pp = derive_kek(passphrase, salt_pp)
kek_rc = derive_kek(recovery_code, salt_rc)
nonce_pp, wrapped_pp = aead_encrypt(kek_pp, dek)
nonce_rc, wrapped_rc = aead_encrypt(kek_rc, dek)
print(f"  DEK wrapped via passphrase ({len(wrapped_pp)}B) and recovery code ({len(wrapped_rc)}B)")


# ─── Test 1: passphrase unlocks DEK ─────────────────────────────────────
print("\nTest 1: passphrase unlocks DEK")
recovered_pp = aead_decrypt(derive_kek(passphrase, salt_pp), nonce_pp, wrapped_pp)
check("DEK recovered via passphrase matches original", recovered_pp == dek)


# ─── Test 2: recovery code unlocks the SAME DEK ─────────────────────────
print("\nTest 2: recovery code unlocks the SAME DEK")
recovered_rc = aead_decrypt(derive_kek(recovery_code, salt_rc), nonce_rc, wrapped_rc)
check("DEK recovered via recovery code matches original", recovered_rc == dek)
check("both paths produce identical DEK bytes", recovered_pp == recovered_rc)


# ─── Test 3: wrong passphrase rejected ──────────────────────────────────
print("\nTest 3: wrong passphrase rejected")
try:
    aead_decrypt(derive_kek(b"wrong-passphrase", salt_pp), nonce_pp, wrapped_pp)
    check("wrong passphrase rejected", False, "decrypt unexpectedly succeeded")
except Exception as e:
    check("wrong passphrase rejected", True, type(e).__name__)


# ─── Test 4: row encrypt / decrypt round-trip ───────────────────────────
print("\nTest 4: row encrypt / decrypt round-trip")
row = b'{"memory_id": "abc-123", "content": "this is a test memory"}'
n, ct = aead_encrypt(dek, row)
check("row plaintext round-trip", aead_decrypt(dek, n, ct) == row)


# ─── Test 5: tampered ciphertext refused ────────────────────────────────
print("\nTest 5: tampered ciphertext refused")
tampered = bytearray(ct); tampered[0] ^= 0x01
try:
    aead_decrypt(dek, n, bytes(tampered))
    check("tampered ciphertext rejected", False, "decrypt unexpectedly succeeded")
except Exception as e:
    check("tampered ciphertext rejected", True, type(e).__name__)


# ─── Test 6: passphrase rotation re-wraps DEK; rows untouched ───────────
print("\nTest 6: passphrase rotation re-wraps DEK without re-encrypting rows")
row_nonce, row_ct = aead_encrypt(dek, row)
new_pp = b"new-passphrase-please-friend"
new_salt = secrets.token_bytes(16)
new_kek = derive_kek(new_pp, new_salt)
new_nonce, new_wrapped = aead_encrypt(new_kek, dek)
restored_dek = aead_decrypt(derive_kek(new_pp, new_salt), new_nonce, new_wrapped)
check("DEK recoverable via new passphrase after rotation", restored_dek == dek)
check("existing row still decrypts with same DEK", aead_decrypt(restored_dek, row_nonce, row_ct) == row)


# ─── Test 7: KDF param upgrade ──────────────────────────────────────────
print("\nTest 7: KDF param upgrade — old per-row params still decryptable")
old_m, old_t, old_p = 65536, 2, 1  # 64 MiB, t=2 — older defaults
old_salt = secrets.token_bytes(16)
old_kek = derive_kek(passphrase, old_salt, m_kib=old_m, t=old_t, p=old_p)
old_nonce, old_wrapped = aead_encrypt(old_kek, dek)
# Restore by remembering the params stored alongside this envelope row
restored = aead_decrypt(
    derive_kek(passphrase, old_salt, m_kib=old_m, t=old_t, p=old_p),
    old_nonce, old_wrapped
)
check("old-params wrapped DEK recoverable when params remembered", restored == dek)


# ─── Test 8: compromise simulation ──────────────────────────────────────
print("\nTest 8: compromise simulation — hosted-side data alone yields nothing")
# Auditor has: salt_pp, KDF params, wrapped DEK ciphertext, nonce_pp,
# encrypted row, row nonce.
# Auditor lacks: passphrase, recovery code, DEK.
# We assert that common password guesses do not unlock.
guesses = [b"password", b"123456", b"admin", b"skema", b"privatae",
           b"qwerty", b"letmein", b"correct-horse", b""]
auditor_succeeded = False
for guess in guesses:
    try:
        aead_decrypt(derive_kek(guess, salt_pp), nonce_pp, wrapped_pp)
        auditor_succeeded = True
        break
    except Exception:
        pass
check("common-password guesses cannot unlock wrapped DEK", not auditor_succeeded,
      f"tried {len(guesses)} guesses")


# ─── Summary ────────────────────────────────────────────────────────────
print()
passed = sum(1 for c, _ in results if c)
failed = len(results) - passed
print(f"{'═' * 40}")
print(f"PASS: {passed}    FAIL: {failed}")
sys.exit(0 if failed == 0 else 1)
