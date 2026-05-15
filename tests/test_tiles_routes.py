"""Unit tests for tile-grid dashboard routes — no DB, no aiohttp app boot.

Exercises the three new handlers directly via make_mocked_request:
  GET  /api/gateway/tiles/containers
  GET  /api/gateway/tiles/wallpaper/<name>
  POST /api/gateway/select
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from gatewayd.config import UpstreamConfig
from gatewayd.transport.mtls import UpstreamRegistry
from gatewayd.dashboard.routes import (
    tiles_containers_handler,
    tiles_wallpaper_handler,
    tiles_select_handler,
)


def _state(registry: UpstreamRegistry) -> MagicMock:
    s = MagicMock()
    s.registry = registry
    return s


def _request(method: str, path: str, body: bytes = b"", state=None, match_info=None) -> web.Request:
    app = web.Application()
    if state is not None:
        app["state"] = state
    req = make_mocked_request(method, path, app=app, match_info=match_info or {})
    async def _json():
        return json.loads(body.decode("utf-8")) if body else {}
    req.json = _json  # type: ignore[attr-defined]
    return req


# ── tiles/containers ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_containers_lists_registered_tiles():
    upstreams = {
        "maddie": UpstreamConfig(kind="user_entity", display_name="Maddie",
                                   url="https://maddie.example/mcp"),
        "skema-security": UpstreamConfig(kind="service_container", display_name="Security",
                                           url="https://10.0.0.14:9090/admin"),
    }
    reg = UpstreamRegistry(upstreams)
    req = _request("GET", "/api/gateway/tiles/containers", state=_state(reg))

    resp = await tiles_containers_handler(req)
    body = json.loads(resp.body)
    assert body["active"] == "maddie"
    names = {t["name"] for t in body["tiles"]}
    assert names == {"maddie", "skema-security"}
    by_name = {t["name"]: t for t in body["tiles"]}
    assert by_name["maddie"]["active"] is True
    assert by_name["skema-security"]["active"] is False
    assert by_name["maddie"]["display_name"] == "Maddie"
    assert by_name["skema-security"]["kind"] == "service_container"


@pytest.mark.asyncio
async def test_containers_empty_when_no_upstreams():
    reg = UpstreamRegistry({})
    req = _request("GET", "/api/gateway/tiles/containers", state=_state(reg))
    resp = await tiles_containers_handler(req)
    body = json.loads(resp.body)
    assert body["tiles"] == []
    assert body["active"] == ""


# ── tiles/wallpaper/<name> ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_wallpaper_serves_cached_file(tmp_path, monkeypatch):
    """find_cached returns a real file → 200 with right Content-Type."""
    from gatewayd import wallpaper as wp_mod
    real = tmp_path / "maddie.jpg"
    real.write_bytes(b"\xff\xd8\xff\xe0FAKEJPEG")  # JPEG magic

    monkeypatch.setattr(wp_mod, "DEFAULT_CACHE_DIR", tmp_path)

    req = _request("GET", "/api/gateway/tiles/wallpaper/maddie", match_info={"name": "maddie"})
    resp = await tiles_wallpaper_handler(req)
    assert resp.status == 200
    assert resp.headers["Content-Type"] == "image/jpeg"


@pytest.mark.asyncio
async def test_wallpaper_404_when_no_cache(tmp_path, monkeypatch):
    from gatewayd import wallpaper as wp_mod
    monkeypatch.setattr(wp_mod, "DEFAULT_CACHE_DIR", tmp_path)
    req = _request("GET", "/api/gateway/tiles/wallpaper/nope", match_info={"name": "nope"})
    resp = await tiles_wallpaper_handler(req)
    assert resp.status == 404


@pytest.mark.asyncio
async def test_wallpaper_blocks_path_traversal():
    for evil in ["..", "../etc/passwd", "x/y", "foo;bar"]:
        req = _request("GET", f"/api/gateway/tiles/wallpaper/{evil}", match_info={"name": evil})
        resp = await tiles_wallpaper_handler(req)
        assert resp.status == 400, f"expected 400 for {evil!r}, got {resp.status}"


# ── select ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_select_flips_active():
    upstreams = {
        "alpha": UpstreamConfig(url="https://alpha"),
        "beta":  UpstreamConfig(url="https://beta"),
    }
    reg = UpstreamRegistry(upstreams)
    assert reg.active == "alpha"

    req = _request("POST", "/api/gateway/select", body=json.dumps({"name": "beta"}).encode(),
                   state=_state(reg))
    resp = await tiles_select_handler(req)
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["active"] == "beta"
    assert reg.active == "beta"


@pytest.mark.asyncio
async def test_select_unknown_returns_404():
    reg = UpstreamRegistry({"alpha": UpstreamConfig()})
    req = _request("POST", "/api/gateway/select", body=json.dumps({"name": "nope"}).encode(),
                   state=_state(reg))
    resp = await tiles_select_handler(req)
    assert resp.status == 404


@pytest.mark.asyncio
async def test_select_bad_body_returns_400():
    reg = UpstreamRegistry({"alpha": UpstreamConfig()})
    req = _request("POST", "/api/gateway/select", body=b"not-json", state=_state(reg))
    resp = await tiles_select_handler(req)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_select_missing_name_returns_400():
    reg = UpstreamRegistry({"alpha": UpstreamConfig()})
    req = _request("POST", "/api/gateway/select", body=b"{}", state=_state(reg))
    resp = await tiles_select_handler(req)
    assert resp.status == 400
