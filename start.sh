#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8000}"

exec uvicorn server:app --host 0.0.0.0 --port "$PORT"
