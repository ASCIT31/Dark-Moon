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
# Command execution
# ------------------------------------------------------------

if [[ $# -eq 0 ]]; then
  # Mode TUI pur
  exec $DC exec $TTY_FLAGS "$SERVICE" bash -lc "darkmoon"
else
  # Mode CLI / agents / scripts
  exec $DC exec $TTY_FLAGS "$SERVICE" bash -lc "darkmoon \"$@\""
fi