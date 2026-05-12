#!/usr/bin/env bash
# Skema Gateway · Layer 3 backup/restore integration test.
#
# Brings up the test docker-compose, runs the Python E2E test, tears down.
# Requires the crypto venv from ../crypto/.venv with argon2-cffi installed.

set -euo pipefail
cd "$(dirname "$0")"

VENV=../crypto/.venv
if [ ! -d "$VENV" ]; then
    echo "Creating venv at $VENV..."
    python3 -m venv "$VENV"
fi

# Install daemon deps + test deps into the same venv
"$VENV/bin/pip" install -q \
    "argon2-cffi>=23.1.0" \
    "cryptography>=41.0.0" \
    "asyncpg>=0.29.0"

exec "$VENV/bin/python" test_backup_restore.py
