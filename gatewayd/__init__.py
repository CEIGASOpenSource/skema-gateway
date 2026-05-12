"""Skema Gateway daemon.

A local-machine daemon that:
  - Hosts an MCP server on 127.0.0.1 for local operator clients
    (Claude Code, Claude Desktop, LM Studio, ...)
  - Talks outbound mTLS to the user's hosted Skema container
  - Maintains an encrypted backup of the user's local PG to the hosted side
  - Writes a tamper-evident local audit log of every authorized action

See db/migrations/ for the schemas this daemon manages.
"""

__version__ = "0.1.0"
