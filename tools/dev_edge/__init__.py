"""Development-only mock of the Privatae-FW anchor redemption edge.

NOT for production use. This module:

  - Mints a self-signed CA on first start (or loads one from disk)
  - Accepts POST /v1/anchors/redeem with any anchor code (dev mode skips the
    machine_anchors lookup; in production, the edge validates the code+TTL
    against privatae.machine_anchors before signing)
  - Returns a CA-signed client cert + key + the CA cert + a configurable
    upstream URL pointing at a real or mock skema container

The cert lifetimes and key types match what the production CA should produce.
"""
