#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-3333}"
export PORT

exec python server.py
