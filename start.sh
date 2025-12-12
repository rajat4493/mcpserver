#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8080}"
export PORT

exec uvicorn server:app --host 0.0.0.0 --port "$PORT"
