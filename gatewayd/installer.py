"""Install flow — the script a user runs after pasting their anchor code.

End-to-end:
  1. Reads the local hardware fingerprint
  2. Redeems the anchor code at the edge → cert + key + CA + upstream URL
  3. Writes cert/key/CA into ~/.config/skema/certs/
  4. Asks the user for a passphrase; generates a recovery code
  5. Generates a DEK and wraps it twice (passphrase + recovery)
  6. Applies the local-PG migration
  7. Connects to parallax (via mTLS through the new cert) and applies the
     parallax-side backup migration, then inserts the two envelope rows
  8. Generates an operator secret + audit HMAC key and writes gatewayd.toml
  9. Prints the recovery code to the user with the standard warning

Usage:
    python -m gatewayd.installer \\
        --edge-url http://127.0.0.1:8443 \\
        --anchor-code <code> \\
        --parallax-dsn postgresql://... \\
        --local-dsn postgresql://... \\
        --passphrase-from-env SKEMA_PASSPHRASE  # dev only; real install prompts
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from dataclasses import asdict
from pathlib import Path

import asyncpg

from gatewayd.crypto import KdfParams, new_dek, wrap_dek
from gatewayd.db import init_conn
from gatewayd.transport.anchor import RedemptionError, redeem


def _default_config_dir() -> Path:
    return Path(os.environ.get(
        "SKEMA_GATEWAY_HOME",
        str(Path.home() / ".config" / "skema"),
    ))


def _make_recovery_code() -> str:
    """24-character grouped recovery code, easy to write on paper."""
    raw = secrets.token_hex(12).upper()
    return "-".join(raw[i:i + 4] for i in range(0, 24, 4))


async def _provision_parallax(dsn: str,
                              env_passphrase: bytes,
                              env_recovery:  bytes,
                              dek: bytes,
                              parallax_migrations: list[Path],
                              parallax_seed_sql: Path | None) -> None:
    """Apply backup-side migrations to parallax and insert the two envelope rows."""
    conn = await asyncpg.connect(dsn)
    await init_conn(conn)
    try:
        if parallax_seed_sql and parallax_seed_sql.exists():
            await conn.execute(parallax_seed_sql.read_text())
        for path in parallax_migrations:
            await conn.execute(path.read_text())

        # In case of re-runs, retire any prior active envelopes
        await conn.execute(
            "UPDATE local_backup_envelope SET is_active=FALSE, superseded_at=NOW() "
            "WHERE is_active=TRUE"
        )

        for source, secret in (("passphrase", env_passphrase),
                                 ("recovery_code", env_recovery)):
            env = wrap_dek(dek, secret, source, KdfParams())
            await conn.execute(
                """
                INSERT INTO local_backup_envelope
                  (kdf_source, wrapped_dek, wrap_nonce, wrap_auth_tag,
                   kdf_salt, kdf_params, is_active)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, TRUE)
                """,
                env.kdf_source, env.wrapped_dek, env.wrap_nonce, env.wrap_auth_tag,
                env.kdf_salt, json.dumps(env.kdf_params.to_jsonb()),
            )
    finally:
        await conn.close()


async def _provision_local(dsn: str, local_migration: Path) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        # Idempotent: if schema already exists this no-ops on CREATE TABLE IF NOT EXISTS;
        # otherwise applies fresh.
        await conn.execute(local_migration.read_text())
    finally:
        await conn.close()


def _write_config(home: Path, cfg: dict) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "gatewayd.toml"
    # Minimal hand-written TOML; we control the schema. Keeps dependency surface small.
    lines = []
    for section, values in cfg.items():
        lines.append(f"[{section}]")
        for k, v in values.items():
            if isinstance(v, bool):
                lines.append(f'{k} = {"true" if v else "false"}')
            elif isinstance(v, (int, float)):
                lines.append(f"{k} = {v}")
            else:
                escaped = str(v).replace('"', '\\"')
                lines.append(f'{k} = "{escaped}"')
        lines.append("")
    path.write_text("\n".join(lines))
    return path


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    os.chmod(path, 0o600)


async def install(args) -> int:
    home = Path(args.home) if args.home else _default_config_dir()
    certs = home / "certs"
    certs.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[1]
    mig = repo_root / "db" / "migrations"
    local_mig    = mig / "local" / "001_init.sql"
    parallax_mig = [
        mig / "parallax" / "001_mcp_client_tokens_operator_columns.sql",
        mig / "parallax" / "002_local_backup.sql",
    ]
    parallax_seed = repo_root / "tests" / "migrations" / "fixtures" / "parallax-seed.sql"

    # ─── 1. Redeem anchor
    print(f"[install] redeeming anchor at {args.edge_url} ...")
    try:
        result = await redeem(args.edge_url, args.anchor_code)
    except RedemptionError as e:
        print(f"[install] anchor redemption failed: {e}", file=sys.stderr)
        return 2
    print("[install] redemption ok")

    # ─── 2. Persist cert / key / CA + upstream bearer
    (certs / "client.cert.pem").write_text(result.cert_pem)
    (certs / "client.key.pem").write_text(result.key_pem)
    os.chmod(certs / "client.key.pem", 0o600)
    (certs / "ca.cert.pem").write_text(result.ca_pem)
    _write_secret(home / "secrets" / "upstream.bearer", result.upstream_bearer)
    print(f"[install] wrote cert material to {certs}/")

    # ─── 3. Secrets
    if args.passphrase_from_env:
        passphrase = os.environ.get(args.passphrase_from_env, "").encode()
    elif args.passphrase:
        passphrase = args.passphrase.encode()
    else:
        import getpass
        passphrase = getpass.getpass("Choose a passphrase for encrypted backup: ").encode()
    if not passphrase:
        print("[install] passphrase empty; aborting", file=sys.stderr)
        return 3

    recovery_code = _make_recovery_code()
    dek = new_dek()

    # ─── 4. Provision parallax + local
    print("[install] applying local-PG migration ...")
    await _provision_local(args.local_dsn, local_mig)

    if args.parallax_dsn:
        print("[install] applying parallax migrations and inserting envelopes ...")
        await _provision_parallax(args.parallax_dsn,
                                   passphrase, recovery_code.encode(),
                                   dek, parallax_mig, parallax_seed)
    else:
        print("[install] skipping parallax envelope provisioning "
               "(--parallax-dsn not provided; backup envelopes will be set "
               "up via the daemon on first encrypted backup push).")

    # ─── 5. Write gatewayd.toml
    operator_secret = secrets.token_urlsafe(32)
    audit_key_hex   = secrets.token_bytes(32).hex()
    _write_secret(home / "secrets" / "operator.secret", operator_secret)
    _write_secret(home / "secrets" / "audit.key.hex", audit_key_hex)

    cfg_path = _write_config(home, {
        "mcp": {
            "listen_host":         "127.0.0.1",
            "listen_port":         7878,
            "operator_secret_env": "SKEMA_OPERATOR_SECRET",
        },
        "upstream": {
            "url":          result.upstream_url,
            "ca_path":      str(certs / "ca.cert.pem"),
            "cert_path":    str(certs / "client.cert.pem"),
            "key_path":     str(certs / "client.key.pem"),
            "bearer_token": result.upstream_bearer,
            "timeout_s":    30,
        },
        "backup": {
            "local_dsn": args.local_dsn,
            "enabled":   True,
        },
        "audit": {
            "audit_key_env": "SKEMA_AUDIT_HMAC_KEY",
        },
    })

    # ─── 6. Recovery code printout
    print()
    print("═" * 64)
    print("RECOVERY CODE — STORE OFFLINE, NOT WITH YOUR PASSPHRASE")
    print(f"  {recovery_code}")
    print()
    print("This code is the ONLY way to unlock your backup if you lose your")
    print("passphrase. We do not store it. We CANNOT recover it for you.")
    print("═" * 64)
    print()
    print(f"Config:           {cfg_path}")
    print(f"Operator secret:  {home / 'secrets' / 'operator.secret'}")
    print(f"Audit HMAC key:   {home / 'secrets' / 'audit.key.hex'}")
    print()
    print("To start the gateway:")
    print(f"  SKEMA_OPERATOR_SECRET=$(cat {home / 'secrets' / 'operator.secret'}) \\")
    print(f"  SKEMA_AUDIT_HMAC_KEY=$(cat {home / 'secrets' / 'audit.key.hex'}) \\")
    print(f"  SKEMA_GATEWAY_CONFIG={cfg_path} \\")
    print(f"  python -m gatewayd")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="gatewayd.installer")
    p.add_argument("--edge-url",     required=True)
    p.add_argument("--anchor-code",  required=True)
    p.add_argument("--local-dsn",    required=True)
    p.add_argument("--parallax-dsn", default="",
                    help="optional; only needed when bootstrapping backup envelopes "
                         "from this installer rather than via the daemon's first push")
    p.add_argument("--home",         help="config home (default: $SKEMA_GATEWAY_HOME or ~/.config/skema)")
    p.add_argument("--passphrase",   help="dev only; prefer --passphrase-from-env or interactive prompt")
    p.add_argument("--passphrase-from-env",
                    help="read passphrase from this env var (dev/automation)")
    return p.parse_args(argv)


def main() -> int:
    args = parse_args(sys.argv[1:])
    return asyncio.run(install(args))


if __name__ == "__main__":
    sys.exit(main())
