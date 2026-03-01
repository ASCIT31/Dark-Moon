#!/usr/bin/env bash
set -euo pipefail

SERVICE="opencode"

# Détection docker compose (plugin vs legacy)
if command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  DC="docker compose"
fi

# ------------------------------------------------------------
# TTY detection (pipe-safe)
# ------------------------------------------------------------
if [[ -t 0 ]]; then
  TTY_FLAGS="-it"
else
  TTY_FLAGS="-T"
fi

# ------------------------------------------------------------
# --log mode (darkmoon-cli)
# ------------------------------------------------------------
if [[ "${1:-}" == "--log" ]]; then
  if [[ $# -lt 2 ]]; then
    echo "Usage: $0 --log <session_id>"
    exit 1
  fi

  SESSION_ID="$2"

  exec $DC exec $TTY_FLAGS "$SERVICE" bash -lc "darkmoon-cli \"$SESSION_ID\""
fi

# ------------------------------------------------------------
# Default behaviour
# ------------------------------------------------------------

if [[ $# -eq 0 ]]; then
  # Mode TUI pur
  exec $DC exec $TTY_FLAGS "$SERVICE" bash -lc "darkmoon"
else
  # Mode CLI / agents / scripts
  exec $DC exec $TTY_FLAGS "$SERVICE" bash -lc "darkmoon \"$@\""
fi