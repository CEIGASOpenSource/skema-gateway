"""gatewayd entry point.

  python -m gatewayd            # run the daemon
"""

from __future__ import annotations

import asyncio
import logging
import sys

import asyncpg
from aiohttp import web

from gatewayd.config import load
from gatewayd.db import init_conn
from gatewayd.mcp import build_app
from gatewayd.transport.mtls import UpstreamClient


async def _run() -> None:
    cfg = load()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("gatewayd")

    log.info("connecting to local PG at %s", cfg.backup.local_dsn)
    pool = await asyncpg.create_pool(cfg.backup.local_dsn, init=init_conn,
                                     min_size=1, max_size=4)

    async with UpstreamClient(cfg.upstream) as upstream:
        app = build_app(cfg, pool, upstream)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, cfg.mcp.listen_host, cfg.mcp.listen_port)
        await site.start()
        log.info("gatewayd listening on %s:%d", cfg.mcp.listen_host, cfg.mcp.listen_port)
        log.info("upstream skema at %s", cfg.upstream.url)
        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            log.info("shutting down")
        finally:
            await runner.cleanup()
            await pool.close()


def main() -> int:
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
