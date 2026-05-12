"""Configuration loader for the gateway daemon.

v1 config is a single TOML file at the path given by SKEMA_GATEWAY_CONFIG
(default: ~/.config/skema/gatewayd.toml). All values can be overridden by
environment variables prefixed with SKEMA_.

Secrets (passphrase, operator shared secret, HMAC audit key) are NOT in the
config file. They live in the OS keychain (delegated to `keyring` on a real
install) or in env vars for development. The config file points at handles.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MCPConfig:
    listen_host:        str = "127.0.0.1"
    listen_port:        int = 7878
    operator_secret_env: str = "SKEMA_OPERATOR_SECRET"
    # ^ env var name; the secret value itself is NOT stored in the config.


@dataclass
class UpstreamConfig:
    """How to reach the user's hosted skema container."""
    url:        str = "https://skema.example.invalid"
    ca_path:    str = ""                     # trust anchor for upstream's cert
    cert_path:  str = ""                     # our client cert
    key_path:   str = ""                     # our client key
    timeout_s:  float = 30.0


@dataclass
class BackupConfig:
    local_dsn:    str = "postgresql://postgres@127.0.0.1:5432/skema_local"
    enabled:      bool = True
    # parallax DSN comes from the upstream connection / endpoint discovery.


@dataclass
class AuditConfig:
    audit_key_env: str = "SKEMA_AUDIT_HMAC_KEY"


@dataclass
class GatewayConfig:
    mcp:       MCPConfig      = field(default_factory=MCPConfig)
    upstream:  UpstreamConfig = field(default_factory=UpstreamConfig)
    backup:    BackupConfig   = field(default_factory=BackupConfig)
    audit:     AuditConfig    = field(default_factory=AuditConfig)


def _default_config_path() -> Path:
    return Path(os.environ.get("SKEMA_GATEWAY_CONFIG",
                                str(Path.home() / ".config" / "skema" / "gatewayd.toml")))


def load(path: Path | None = None) -> GatewayConfig:
    """Load configuration. Falls back to defaults if the file is missing."""
    path = path or _default_config_path()
    data: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
    return GatewayConfig(
        mcp      = MCPConfig(**data.get("mcp", {})),
        upstream = UpstreamConfig(**data.get("upstream", {})),
        backup   = BackupConfig(**data.get("backup", {})),
        audit    = AuditConfig(**data.get("audit", {})),
    )
