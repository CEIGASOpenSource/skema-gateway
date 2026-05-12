"""Encrypted backup writer.

Reads every row from the local-PG backup tables, serializes, encrypts with
the DEK, and INSERTs the ciphertext into the parallax `local_backup_blob`
table on the hosted side.

v0.1: full snapshot each call. Incremental sync (changed-rows-only via
`plaintext_hash` diff) is straightforward to add later — the schema and
this code already track `row_version` per (resource_kind, resource_pk).
"""

from __future__ import annotations

import asyncpg

from gatewayd.crypto import aead_encrypt
from gatewayd.crypto.aead import split_tag
from gatewayd.db import BACKUP_TABLES, encode_pk, fetch_all
from gatewayd.serialize import plaintext_hash, serialize_row


async def push_full_snapshot(local: asyncpg.Connection,
                             parallax: asyncpg.Connection,
                             dek: bytes) -> dict[str, int]:
    """Walk every backup table, encrypt each row, INSERT into parallax.

    Returns per-table row counts pushed.
    """
    counts: dict[str, int] = {}
    for table in BACKUP_TABLES:
        rows = await fetch_all(local, table)
        for row in rows:
            row_dict = dict(row.items())
            pk = tuple(row_dict[c] for c in table.pk_cols)
            resource_pk = encode_pk(pk)

            plaintext = serialize_row(row_dict)
            ph = plaintext_hash(plaintext)

            # row_version = (max existing for this (kind, pk)) + 1
            row_version = await _next_row_version(parallax, table.name, resource_pk)

            nonce, ct_with_tag = aead_encrypt(dek, plaintext)
            ciphertext, auth_tag = split_tag(ct_with_tag)

            await parallax.execute(
                """
                INSERT INTO local_backup_blob
                    (resource_kind, resource_pk, nonce, ciphertext, auth_tag,
                     plaintext_hash, row_version)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                table.name, resource_pk, nonce, ciphertext, auth_tag,
                ph, row_version,
            )

            # Supersede prior versions
            if row_version > 1:
                await parallax.execute(
                    """
                    UPDATE local_backup_blob
                       SET superseded_at = NOW()
                     WHERE resource_kind = $1
                       AND resource_pk   = $2
                       AND row_version  < $3
                       AND superseded_at IS NULL
                    """,
                    table.name, resource_pk, row_version,
                )

        counts[table.name] = len(rows)
    return counts


async def _next_row_version(parallax: asyncpg.Connection, kind: str, pk: str) -> int:
    """Smallest row_version not yet taken for (kind, pk)."""
    cur = await parallax.fetchval(
        """
        SELECT COALESCE(MAX(row_version), 0)
          FROM local_backup_blob
         WHERE resource_kind = $1
           AND resource_pk   = $2
        """,
        kind, pk,
    )
    return int(cur) + 1
