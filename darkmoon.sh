#!/usr/bin/env bash
set -euo pipefail

SERVICE="opencode"
APP_BIN="opencode"

# ------------------------------------------------------------
# Détection docker compose (plugin vs legacy)
# ------------------------------------------------------------
if command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  DC=(docker compose)
fi

# ------------------------------------------------------------
# TTY detection (pipe-safe)
# ------------------------------------------------------------
if [[ -t 0 ]]; then
  TTY_FLAGS=(-it)
else
  TTY_FLAGS=(-T)
fi

# ------------------------------------------------------------
# --log mode
# ------------------------------------------------------------
if [[ "${1:-}" == "--log" ]]; then
  if [[ $# -lt 2 ]]; then
    echo "Usage: $0 --log <session_id>"
    exit 1
  fi

  SESSION_ID="$2"

  exec "${DC[@]}" exec "${TTY_FLAGS[@]}" "$SERVICE" \
    bash -lc 'exec "$1" "$2"' bash "darkmoon-cli" "$SESSION_ID"
fi

# ------------------------------------------------------------
# Default behaviour
# ------------------------------------------------------------
if [[ $# -eq 0 ]]; then
  # Mode interactif → TUI
  exec "${DC[@]}" exec "${TTY_FLAGS[@]}" "$SERVICE" \
    bash -lc 'exec "$1"' bash "$APP_BIN"
elif [[ "${1:0:1}" == "-" ]]; then
  # Le 1er argument est un flag (court ou long : -s, -c, -m,
  # --help, --version, --session, …). On passe la main directement
  # à `opencode` SANS la sous-commande `run`. C'est indispensable
  # pour -s/--session (continuer une session) et -c/--continue :
  # `opencode run` exigerait en plus un message positionnel et
  # échouerait avec "You must provide a message or a command".
  # Pour relancer une session en mode one-shot, mettre le message
  # en 1er : ./darkmoon.sh "mon prompt" -s <session_id>
  exec "${DC[@]}" exec "${TTY_FLAGS[@]}" "$SERVICE" \
    bash -lc 'app="$1"; shift; exec "$app" "$@"' bash "$APP_BIN" "$@"
else
  # Arguments positionnels = prompt one-shot. opencode exige la
  # sous-commande `run`, sinon il interprète la chaîne comme un cwd
  # et échoue avec "Failed to change directory to /<prompt>".
  exec "${DC[@]}" exec "${TTY_FLAGS[@]}" "$SERVICE" \
    bash -lc 'app="$1"; shift; exec "$app" run "$@"' bash "$APP_BIN" "$@"
fi