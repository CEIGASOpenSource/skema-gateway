"""Database connection helpers + schema knowledge.

The backup/restore code needs to know:
  - Which tables to back up
  - The primary key columns of each (for `resource_pk` serialization)
  - The dependency order for restore (to satisfy FKs)

Embedding columns are NOT backed up — they're regenerated on the user's
machine after restore.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import asyncpg


async def init_conn(conn: asyncpg.Connection) -> None:
    """Register codecs so JSONB/JSON come back as dicts (not text)."""
    for typ in ("jsonb", "json"):
        await conn.set_type_codec(
            typ,
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )


async def connect(dsn: str) -> asyncpg.Connection:
    """Open a connection with the JSON codecs pre-registered."""
    conn = await asyncpg.connect(dsn)
    await init_conn(conn)
    return conn


@dataclass(frozen=True)
class BackupTable:
    name:        str
    pk_cols:     tuple[str, ...]
    # Tables we INSERT after this one will reference this one via FK.
    # Used to order restore; backup itself can run in any order.


# Order = restore dependency order (parents first, children after).
# - principals: no deps
# - sources, user_context: FK → principals
# - source_chunks: FK → sources
# - memories: FK → principals + sources (hypertable; PK is composite)
# - memory_links / memory_shares: soft and hard refs to memories+principals
# - provisioning / operator_audit_log / sync_state: no FK
BACKUP_TABLES: tuple[BackupTable, ...] = (
    BackupTable("principals",         ("principal_id",)),
    BackupTable("sources",            ("source_id",)),
    BackupTable("source_chunks",      ("chunk_id",)),
    BackupTable("memories",           ("memory_id", "t_observed")),
    BackupTable("memory_links",       ("link_id",)),
    BackupTable("memory_shares",      ("memory_id", "shared_with")),
    BackupTable("user_context",       ("key", "scope")),
    BackupTable("provisioning",       ("key",)),
    BackupTable("operator_audit_log", ("log_id", "occurred_at")),
    BackupTable("sync_state",         ("resource_kind", "direction")),
)

TABLES_BY_NAME = {t.name: t for t in BACKUP_TABLES}


def encode_pk(values: tuple) -> str:
    """Canonical text form of a row PK for storage in `local_backup_blob.resource_pk`."""
    return json.dumps([str(v) for v in values], separators=(",", ":"))


async def fetch_all(conn: asyncpg.Connection, table: BackupTable) -> list[asyncpg.Record]:
    """Read every row from a backup table. Plain SELECT; ordering not significant."""
    return await conn.fetch(f'SELECT * FROM "{table.name}"')


async def insert_row(conn: asyncpg.Connection, table: BackupTable, row: dict) -> None:
    """INSERT a deserialized row into the target table.

    Uses ON CONFLICT DO UPDATE on the PK columns so the auto-inserted
    seed principal row (from local/001_init.sql) is overwritten on restore.
    """
    if not row:
        return
    cols = list(row.keys())
    placeholders = [f"${i + 1}" for i in range(len(cols))]
    values = [row[c] for c in cols]

    non_pk = [c for c in cols if c not in table.pk_cols]
    if non_pk:
        update_clause = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in non_pk)
        sql = (
            f'INSERT INTO "{table.name}" '
            f'({", ".join(f"\"{c}\"" for c in cols)}) '
            f'VALUES ({", ".join(placeholders)}) '
            f'ON CONFLICT ({", ".join(f"\"{c}\"" for c in table.pk_cols)}) '
            f'DO UPDATE SET {update_clause}'
        )
    else:
        sql = (
            f'INSERT INTO "{table.name}" '
            f'({", ".join(f"\"{c}\"" for c in cols)}) '
            f'VALUES ({", ".join(placeholders)}) '
            f'ON CONFLICT DO NOTHING'
        )

    await conn.execute(sql, *values)
