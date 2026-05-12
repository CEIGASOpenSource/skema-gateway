"""Restore: parallax-side ciphertext → fresh local PG.

Pulls the latest non-superseded blob for each (resource_kind, resource_pk),
decrypts, deserializes, and INSERTs into the freshly initialized local PG.
Insertion follows BACKUP_TABLES order so FKs resolve.

The envelope (passphrase or recovery code → wrapped DEK) is handled by
the caller; this module just consumes the unwrapped DEK.
"""

from __future__ import annotations

import asyncpg

from gatewayd.crypto import aead_decrypt
from gatewayd.crypto.aead import join_tag
from gatewayd.db import BACKUP_TABLES, TABLES_BY_NAME, insert_row
from gatewayd.serialize import deserialize_row


async def restore_snapshot(parallax: asyncpg.Connection,
                           local: asyncpg.Connection,
                           dek: bytes) -> dict[str, int]:
    """Restore every backed-up row into `local` in dependency order.

    Restore is rehydrate-from-snapshot: the destination tables are truncated
    first (the schema's auto-inserted seed rows would otherwise collide with
    backed-up rows on secondary unique constraints). Reads the latest
    (max `row_version`, `superseded_at IS NULL`) blob per (resource_kind,
    resource_pk) and INSERTs after decrypt.

    Returns per-table row counts restored.
    """
    counts: dict[str, int] = {}

    # Wipe destination tables. CASCADE handles the FK web; RESTART IDENTITY
    # resets BIGSERIAL sequences (e.g. operator_audit_log.log_id) so that
    # post-restore activity doesn't collide with explicitly-restored ids.
    table_list = ", ".join(f'"{t.name}"' for t in BACKUP_TABLES)
    await local.execute(f"TRUNCATE TABLE {table_list} RESTART IDENTITY CASCADE")

    for table in BACKUP_TABLES:
        rows = await parallax.fetch(
            """
            SELECT resource_pk, nonce, ciphertext, auth_tag
              FROM local_backup_blob
             WHERE resource_kind = $1
               AND superseded_at IS NULL
             ORDER BY resource_pk, row_version DESC
            """,
            table.name,
        )

        # Dedupe by resource_pk in case multiple non-superseded rows exist
        seen: set[str] = set()
        ordered = []
        for r in rows:
            if r["resource_pk"] in seen:
                continue
            seen.add(r["resource_pk"])
            ordered.append(r)

        for r in ordered:
            ct_with_tag = join_tag(bytes(r["ciphertext"]), bytes(r["auth_tag"]))
            plaintext = aead_decrypt(dek, bytes(r["nonce"]), ct_with_tag)
            row_dict = deserialize_row(plaintext)
            await insert_row(local, TABLES_BY_NAME[table.name], row_dict)

        counts[table.name] = len(ordered)
    return counts
