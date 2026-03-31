#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -z "${WARP_FRONT_PORT:-}" ]; then
  export WARP_FRONT_PORT=10899
fi

python scripts/generate_microwarp_compose.py

docker compose -f docker-compose.yml -f docker-compose.microwarp.generated.yml up -d
