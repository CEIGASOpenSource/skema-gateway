"""Hardware fingerprint — a stable per-machine identifier.

Used by:
  - the installer at anchor redemption (sent to edge)
  - the gateway on every outbound call (sent to the skema container; the
    container's parallax DB verifies it matches what was recorded at bind
    time, refuses on mismatch)

v1 derives from `/etc/machine-id` on Linux. Cross-platform support (Windows
machine GUID, macOS IOPlatformUUID) is a downstream task.

The fingerprint is SHA-256 of the raw machine id, hex-encoded. Hashing
gives a uniform 32-byte output and keeps the raw machine-id off the wire.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def _read_linux_machine_id() -> bytes:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        p = Path(path)
        if p.exists():
            content = p.read_text(encoding="ascii").strip()
            if content:
                return content.encode("ascii")
    raise RuntimeError("no machine-id found on this system")


def fingerprint() -> str:
    """Return a stable per-machine identifier as a 64-char hex string."""
    if sys.platform.startswith("linux"):
        raw = _read_linux_machine_id()
    else:
        # Placeholder. Real cross-platform support is a future task.
        raise NotImplementedError(
            f"fingerprint() not yet implemented for platform {sys.platform!r}"
        )
    return hashlib.sha256(raw).hexdigest()
