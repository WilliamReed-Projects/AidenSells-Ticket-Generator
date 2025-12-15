#!/usr/bin/env sh
set -euo pipefail

# Allow overriding the port externally (Railway injects PORT automatically)
PORT="${PORT:-3000}"
export PORT

python server.py
