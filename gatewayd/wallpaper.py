"""Wallpaper fetcher + cache for the tile-grid dashboard.

Each registered upstream may publish a wallpaper URL (e.g. a service
container's /admin/wallpaper/static.jpg). The gateway fetches it once at
startup, caches it locally on disk, and serves it back to the dashboard
over same-origin so the browser's <img> tag works without CORS.

Caches at ~/.cache/skema-gateway/wallpapers/<upstream_name>.<ext> by
default; overridable via SKEMA_WALLPAPER_CACHE.

Fetch uses each upstream's mTLS cert bundle — same identity the MCP
relay would present.
"""
from __future__ import annotations

import asyncio
import logging
import os
import ssl
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from gatewayd.config import UpstreamConfig


log = logging.getLogger("gatewayd.wallpaper")

DEFAULT_CACHE_DIR = Path(os.environ.get(
    "SKEMA_WALLPAPER_CACHE",
    str(Path.home() / ".cache" / "skema-gateway" / "wallpapers"),
))


def _ext_from_url(url: str) -> str:
    p = urlparse(url).path
    for e in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
        if p.lower().endswith(e):
            return e
    return ".jpg"  # default


def cache_path_for(upstream_name: str, ext: str, cache_dir: Path | None = None) -> Path:
    d = cache_dir or DEFAULT_CACHE_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{upstream_name}{ext}"


def _ssl_context(cfg: UpstreamConfig) -> ssl.SSLContext | bool:
    if cfg.cert_path and cfg.key_path:
        ctx = ssl.create_default_context(cafile=cfg.ca_path or None)
        ctx.load_cert_chain(certfile=cfg.cert_path, keyfile=cfg.key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        return ctx
    return False  # dev / no cert


async def fetch_one(
    name: str,
    cfg: UpstreamConfig,
    cache_dir: Path | None = None,
    timeout_s: float = 10.0,
) -> Path | None:
    """Fetch one upstream's wallpaper into the local cache. Returns the
    cached file path, or None if the upstream has no wallpaper_url or
    the fetch failed.
    """
    if not cfg.wallpaper_url:
        return None
    ext = _ext_from_url(cfg.wallpaper_url)
    path = cache_path_for(name, ext, cache_dir)
    ssl_ctx = _ssl_context(cfg)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    headers = {}
    if cfg.bearer_token:
        headers["Authorization"] = f"Bearer {cfg.bearer_token}"

    try:
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(cfg.wallpaper_url, headers=headers) as resp:
                if resp.status != 200:
                    log.warning("wallpaper fetch %s → HTTP %d", name, resp.status)
                    return None
                body = await resp.read()
                if len(body) > 20 * 1024 * 1024:  # cap at 20 MB
                    log.warning("wallpaper %s exceeds 20 MB, ignoring", name)
                    return None
                path.write_bytes(body)
                log.info("cached wallpaper for %s → %s (%d bytes)", name, path, len(body))
                return path
    except Exception as e:
        log.warning("wallpaper fetch %s failed: %s", name, e)
        return None


async def prefetch_all(
    upstreams: dict[str, UpstreamConfig],
    cache_dir: Path | None = None,
) -> dict[str, Path]:
    """Fetch all upstreams concurrently. Returns {name: cached_path} for
    successes only."""
    tasks = [fetch_one(name, cfg, cache_dir) for name, cfg in upstreams.items()]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return {
        name: path
        for name, path in zip(upstreams.keys(), results)
        if path is not None
    }


def find_cached(upstream_name: str, cache_dir: Path | None = None) -> Path | None:
    """Look up the cached wallpaper for an upstream. Tries common
    extensions in order."""
    d = cache_dir or DEFAULT_CACHE_DIR
    for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
        p = d / f"{upstream_name}{ext}"
        if p.is_file():
            return p
    return None
