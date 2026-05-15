"""Unit tests for UpstreamRegistry — pure-Python, no network or DB."""
from __future__ import annotations

import pytest

from gatewayd.config import GatewayConfig, UpstreamConfig, load
from gatewayd.transport.mtls import UpstreamRegistry


# ── Config loader: multi-upstream + back-compat ──────────────────────


def test_loads_multi_upstream_toml(tmp_path):
    cfg_path = tmp_path / "gatewayd.toml"
    cfg_path.write_text("""
        default_upstream = "maddie"

        [upstreams.maddie]
        kind = "user_entity"
        display_name = "Maddie"
        url = "https://maddie.skema.privatae.ai:8443/mcp"

        [upstreams.skema-security]
        kind = "service_container"
        display_name = "Security"
        url = "https://10.0.0.14:9090/admin"
    """)
    cfg = load(cfg_path)
    assert set(cfg.upstreams.keys()) == {"maddie", "skema-security"}
    assert cfg.upstreams["maddie"].kind == "user_entity"
    assert cfg.upstreams["maddie"].display_name == "Maddie"
    assert cfg.upstreams["skema-security"].kind == "service_container"
    assert cfg.default_upstream == "maddie"


def test_legacy_single_upstream_block_migrates_to_default(tmp_path):
    cfg_path = tmp_path / "gatewayd.toml"
    cfg_path.write_text("""
        [upstream]
        url = "https://legacy.example/mcp"
        bearer_token = "mcp_legacy"
    """)
    cfg = load(cfg_path)
    assert "default" in cfg.upstreams
    assert cfg.upstreams["default"].url == "https://legacy.example/mcp"
    assert cfg.upstreams["default"].bearer_token == "mcp_legacy"


def test_bearer_token_env_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET_BEARER", "mcp_from_env")
    cfg_path = tmp_path / "gatewayd.toml"
    cfg_path.write_text("""
        [upstreams.x]
        url = "https://x.example/mcp"
        bearer_token_env = "MY_SECRET_BEARER"
    """)
    cfg = load(cfg_path)
    assert cfg.upstreams["x"].bearer_token == "mcp_from_env"


def test_back_compat_upstream_property_returns_default():
    cfg = GatewayConfig(
        upstreams={
            "primary": UpstreamConfig(url="https://primary"),
            "secondary": UpstreamConfig(url="https://secondary"),
        },
        default_upstream="primary",
    )
    # cfg.upstream is the property that returns the active default
    assert cfg.upstream.url == "https://primary"


def test_back_compat_upstream_property_empty():
    cfg = GatewayConfig()
    # No upstreams configured → returns a default UpstreamConfig (legacy behavior)
    assert cfg.upstream.url == "https://skema.example.invalid/mcp"


def test_default_name_picks_first_when_unset():
    cfg = GatewayConfig(upstreams={
        "alpha": UpstreamConfig(),
        "beta": UpstreamConfig(),
    })
    assert cfg.default_name() == "alpha"


# ── Registry selection logic ─────────────────────────────────────────


def test_registry_active_defaults_to_first():
    upstreams = {
        "alpha": UpstreamConfig(url="https://alpha"),
        "beta":  UpstreamConfig(url="https://beta"),
    }
    reg = UpstreamRegistry(upstreams)
    assert reg.active == "alpha"
    assert reg.names() == ["alpha", "beta"]


def test_registry_active_honors_default_name():
    upstreams = {
        "alpha": UpstreamConfig(url="https://alpha"),
        "beta":  UpstreamConfig(url="https://beta"),
    }
    reg = UpstreamRegistry(upstreams, default_name="beta")
    assert reg.active == "beta"


def test_registry_select_known_name():
    upstreams = {
        "alpha": UpstreamConfig(url="https://alpha"),
        "beta":  UpstreamConfig(url="https://beta"),
    }
    reg = UpstreamRegistry(upstreams)
    reg.select("beta")
    assert reg.active == "beta"


def test_registry_select_unknown_raises():
    reg = UpstreamRegistry({"alpha": UpstreamConfig()})
    with pytest.raises(KeyError):
        reg.select("nonexistent")


def test_registry_empty_active_is_empty():
    reg = UpstreamRegistry({})
    assert reg.active == ""
    assert reg.names() == []


def test_registry_active_client_before_aenter_raises():
    """active_client() needs the async context to have populated _clients."""
    reg = UpstreamRegistry({"alpha": UpstreamConfig()})
    with pytest.raises(KeyError):
        reg.active_client()  # _clients dict is empty until __aenter__
