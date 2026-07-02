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
# Preflight: fail fast with a clear message if the configured
# on-prem LLM endpoint is unreachable from INSIDE the container.
# Without this, `opencode run` hangs silently — no output, no
# error, no logs — when ANTHROPIC_BASE_URL / OPENCODE_LOCAL_BASE_URL
# cannot be reached (see issue #28).
# ------------------------------------------------------------
preflight_provider_check() {
  local res
  res="$("${DC[@]}" exec -T "$SERVICE" bash -c '
    url="${ANTHROPIC_BASE_URL:-}"; mode="Anthropic (install.sh option 3)"
    if [ -z "$url" ]; then url="${OPENCODE_LOCAL_BASE_URL:-}"; mode="Local (install.sh option 2)"; fi
    [ -z "$url" ] && exit 0                         # cloud provider or none -> nothing to probe
    proto="${url%%://*}"; rest="${url#*://}"; hostport="${rest%%/*}"
    host="${hostport%%:*}"; port="${hostport##*:}"
    [ "$host" = "$port" ] && port=""                # no explicit port in URL
    [ -z "$port" ] && { [ "$proto" = https ] && port=443 || port=80; }
    # Pure-bash TCP connect (no curl in the image); detects the silent-hang case.
    if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then exit 0; fi
    printf "UNREACHABLE|%s|%s" "$mode" "$url"
    exit 3
  ' 2>/dev/null)" || true

  case "${res:-}" in
    UNREACHABLE\|*)
      local rest="${res#UNREACHABLE|}"
      local url="${rest#*|}"
      local mode="${rest%%|*}"
      {
        echo ""
        echo "❌ LLM endpoint not reachable from inside the Darkmoon container:"
        echo "      ${url}"
        echo "      (provider: ${mode})"
        echo ""
        echo "   The agent cannot run and would otherwise produce no output. Check:"
        echo "   • Network: the URL must be reachable FROM THE CONTAINER, not just your host."
        echo "     'localhost' / '127.0.0.1' point to the container itself — use the host LAN IP"
        echo "     or 'host.docker.internal', and confirm the server is actually running."
        echo "   • Protocol: option [3] expects an Anthropic Messages API endpoint (/v1/messages)."
        echo "     If your endpoint is OpenAI-compatible (e.g. blackbox, LiteLLM, Ollama), re-run"
        echo "     install.sh and choose [2] Local instead."
        echo ""
      } >&2
      exit 3
      ;;
  esac
}
preflight_provider_check

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