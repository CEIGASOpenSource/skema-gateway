"""Unit tests for operator_rename_handler — input validation only.

DB-touching paths are exercised by the integration test stack; here we
verify the request-shape rejections that gate the SQL.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from gatewayd.dashboard.routes import operator_rename_handler


VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"


def _make_request(op_id: str, body: bytes) -> web.Request:
    app = web.Application()
    # _state(request) just looks at request.app["state"]; rename only touches
    # state.local if validation passes, so a MagicMock pool that swallows
    # acquire() works for the negative cases.
    state = MagicMock()
    pool = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=MagicMock(execute=AsyncMock()))
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    state.local = pool
    app["state"] = state
    req = make_mocked_request("PATCH", f"/api/gateway/operators/{op_id}",
                              app=app, match_info={"operator_id": op_id})
    async def _json():
        return json.loads(body.decode("utf-8")) if body else {}
    req.json = _json  # type: ignore[attr-defined]
    return req


@pytest.mark.asyncio
async def test_rename_rejects_bad_uuid():
    req = _make_request("not-a-uuid", b'{"display_name": "x"}')
    resp = await operator_rename_handler(req)
    assert resp.status == 400
    assert b"operator_id" in resp.body


@pytest.mark.asyncio
async def test_rename_rejects_bad_json():
    req = _make_request(VALID_UUID, b"not-json")
    resp = await operator_rename_handler(req)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_rename_rejects_no_fields():
    req = _make_request(VALID_UUID, b"{}")
    resp = await operator_rename_handler(req)
    assert resp.status == 400
    assert b"no_fields" in resp.body


@pytest.mark.asyncio
async def test_rename_rejects_bad_icon_slug():
    """icon_slug must match [a-z][a-z0-9_-]{0,31} or be null/empty."""
    for bad in ["UPPER", "1starts-numeric", "x" * 50, "x;y", "x.y"]:
        body = json.dumps({"icon_slug": bad}).encode()
        req = _make_request(VALID_UUID, body)
        resp = await operator_rename_handler(req)
        assert resp.status == 400, f"expected 400 for {bad!r}"


@pytest.mark.asyncio
async def test_rename_accepts_valid_payload():
    body = json.dumps({"display_name": "Claude Code @ home", "icon_slug": "claude-code"}).encode()
    req = _make_request(VALID_UUID, body)
    resp = await operator_rename_handler(req)
    assert resp.status == 200
    body = json.loads(resp.body)
    assert "display_name" in body["updated"]
    assert "icon_slug" in body["updated"]


@pytest.mark.asyncio
async def test_rename_accepts_clearing_icon_slug():
    """Sending icon_slug=null clears the icon."""
    body = json.dumps({"icon_slug": None}).encode()
    req = _make_request(VALID_UUID, body)
    resp = await operator_rename_handler(req)
    assert resp.status == 200


@pytest.mark.asyncio
async def test_rename_accepts_display_name_only():
    body = json.dumps({"display_name": "Codex @ work"}).encode()
    req = _make_request(VALID_UUID, body)
    resp = await operator_rename_handler(req)
    assert resp.status == 200
    body = json.loads(resp.body)
    assert body["updated"] == ["display_name"]
