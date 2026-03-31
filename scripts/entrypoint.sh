#!/usr/bin/env sh
set -eu

DEFAULT_APP_DIR="/app"
WORK_ROOT="${SELF_UPDATE_WORK_DIR:-/app/data/self_update}"
CURRENT_DIR="$WORK_ROOT/current"
EXECUTABLE_NAME="${SELF_UPDATE_EXECUTABLE_NAME:-codex-register}"

mkdir -p /app/data /app/logs "$WORK_ROOT"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

if [ -x "$CURRENT_DIR/$EXECUTABLE_NAME" ]; then
  cd "$CURRENT_DIR"
  exec "./$EXECUTABLE_NAME"
fi

cd "$DEFAULT_APP_DIR"
exec python /app/webui.py
