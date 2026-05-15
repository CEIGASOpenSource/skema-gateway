"""Configuration loader for the gateway daemon.

v1 config is a single TOML file at the path given by SKEMA_GATEWAY_CONFIG
(default: ~/.config/skema/gatewayd.toml). All values can be overridden by
environment variables prefixed with SKEMA_.

Secrets (passphrase, operator shared secret, HMAC audit key) are NOT in
the config file. They live in the OS keychain (delegated to `keyring` on
a real install) or in env vars for development. The config file points
at handles.

Multi-container shape (v0.2+):

  [upstreams.maddie]
  kind = "user_entity"
  display_name = "Maddie"
  url = "https://maddie.skema.privatae.ai:8443/mcp"
  ca_path = "..."
  cert_path = "..."
  key_path = "..."
  bearer_token_env = "SKEMA_MADDIE_BEARER"
  wallpaper_url = "https://maddie.skema.privatae.ai:8443/wallpaper/static.jpg"

  [upstreams.skema-security]
  kind = "service_container"
  display_name = "Security"
  url = "https://10.0.0.14:9090/admin"
  ...

Legacy single `[upstream]` block is auto-migrated to `upstreams.default`
so existing installs keep working.
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
    """How to reach one specific upstream container's MCP endpoint.

    Per-container identity bundle. The gateway holds many of these (one
    per registered container in the tile grid) and picks the right one
    based on which tile the user has selected.
    """
    url:           str = "https://skema.example.invalid/mcp"
    ca_path:       str = ""        # trust anchor for upstream's cert
    cert_path:     str = ""        # our client cert
    key_path:      str = ""        # our client key
    bearer_token:  str = ""        # mcp_<...> token; matches mcp_client_tokens
    timeout_s:     float = 30.0

    # Multi-container metadata:
    kind:          str = "user_entity"     # 'user_entity' | 'service_container'
    display_name:  str = ""                # human-coherent tile label
    wallpaper_url: str = ""                # absolute URL to fetch static wallpaper
    icon_slug:     str = ""                # icon hint (used when no wallpaper)


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
    mcp:       MCPConfig                 = field(default_factory=MCPConfig)
    # Multi-upstream registry. Keys are short names used in /api/gateway/select
    # and in audit log rows.
    upstreams: dict[str, UpstreamConfig] = field(default_factory=dict)
    # Default upstream tile — which one's active at boot. If empty, the
    # first key in `upstreams` is used.
    default_upstream: str                = ""
    backup:    BackupConfig              = field(default_factory=BackupConfig)
    audit:     AuditConfig               = field(default_factory=AuditConfig)

    # ── Back-compat shim ───────────────────────────────────────────
    @property
    def upstream(self) -> UpstreamConfig:
        """Legacy single-upstream accessor. Returns the active default;
        used by code that hasn't been migrated to the registry yet."""
        if not self.upstreams:
            return UpstreamConfig()
        name = self.default_upstream or next(iter(self.upstreams))
        return self.upstreams[name]

    def default_name(self) -> str:
        if self.default_upstream:
            return self.default_upstream
        if self.upstreams:
            return next(iter(self.upstreams))
        return ""


def _default_config_path() -> Path:
    return Path(os.environ.get("SKEMA_GATEWAY_CONFIG",
                                str(Path.home() / ".config" / "skema" / "gatewayd.toml")))


def _build_upstream(d: dict) -> UpstreamConfig:
    """Build an UpstreamConfig, resolving bearer_token_env if present.

    Keeps tokens out of the config file: the file references the env var
    name; the value is read at load time.
    """
    d = dict(d)
    bt_env = d.pop("bearer_token_env", None)
    if bt_env and not d.get("bearer_token"):
        d["bearer_token"] = os.environ.get(bt_env, "")
    return UpstreamConfig(**d)


def load(path: Path | None = None) -> GatewayConfig:
    """Load configuration. Falls back to defaults if the file is missing.

    Accepts both:
      - new: `[upstreams.NAME]` TOML tables → dict of UpstreamConfig
      - legacy: single `[upstream]` block → auto-migrated to `upstreams.default`
    """
    path = path or _default_config_path()
    data: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)

    # Multi-upstream: walk [upstreams.NAME] tables.
    upstreams_section = data.get("upstreams", {})
    upstreams: dict[str, UpstreamConfig] = {}
    for name, entry in upstreams_section.items():
        if not isinstance(entry, dict):
            continue
        upstreams[name] = _build_upstream(entry)

    # Back-compat: legacy single [upstream] block.
    if not upstreams and "upstream" in data:
        upstreams["default"] = _build_upstream(data["upstream"])

    return GatewayConfig(
        mcp              = MCPConfig(**data.get("mcp", {})),
        upstreams        = upstreams,
        default_upstream = data.get("default_upstream", ""),
        backup           = BackupConfig(**data.get("backup", {})),
        audit            = AuditConfig(**data.get("audit", {})),
    )
