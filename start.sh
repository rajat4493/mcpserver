#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8080}"
export PORT

exec python server.py
