#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# DarkMoon Web UI — one command installer & launcher.
#
#   ./webui.sh            install (if needed) + start the stack and the Web UI
#   ./webui.sh up        start everything
#   ./webui.sh down      stop the Web UI + engine
#   ./webui.sh logs      tail the engine logs
#   ./webui.sh status    show what is running
#   ./webui.sh rebuild   rebuild the Web UI image
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

WEBUI_PORT="${DARKMOON_WEBUI_PORT:-8080}"
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.webui.yml)

DC=()
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "❌ Docker Compose v2 is required." >&2
  exit 1
fi

compose() { "${DC[@]}" "${COMPOSE_FILES[@]}" "$@"; }

ensure_env() {
  if [[ -f .opencode.env ]]; then
    return
  fi
  echo "⚠  No .opencode.env found — writing a starter local-model config."
  echo "   Open http://localhost:${WEBUI_PORT}/#/settings to paste your provider key."
  cat > .opencode.env <<'EOF'
# Darkmoon — LLM provider configuration
# Starter config: local model (Ollama). Replace from the Web UI settings panel.
OPENCODE_LOCAL_MODE=true
OPENCODE_LOCAL_PROVIDER_ID=ollama
OPENCODE_LOCAL_PROVIDER_NAME=Ollama
OPENCODE_LOCAL_BASE_URL=http://host.docker.internal:11434/v1
OPENCODE_LOCAL_MODEL=llama3.1
EOF
  chmod 600 .opencode.env
}

wait_for_webui() {
  echo "⏳ Waiting for the Web UI…"
  for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:${WEBUI_PORT}/api/health" >/dev/null 2>&1; then
      echo "✅ Web UI is up:  http://localhost:${WEBUI_PORT}"
      return 0
    fi
    sleep 2
  done
  echo "⚠  The Web UI did not answer in time. Check: docker compose logs webui" >&2
  return 1
}

case "${1:-install}" in
  install)
    ensure_env
    echo "▸ Pulling the DarkMoon engine images…"
    compose pull || echo "⚠  pull failed (building from source instead)"
    echo "▸ Starting the engine…"
    compose up -d opencode darkmoon
    echo "▸ Building the Web UI image…"
    compose build webui
    echo "▸ Starting the Web UI…"
    compose up -d webui
    wait_for_webui
    ;;
  up)
    ensure_env
    compose up -d
    wait_for_webui
    ;;
  down)
    compose down
    ;;
  logs)
    compose logs --tail=200 -f webui
    ;;
  status)
    compose ps
    ;;
  rebuild)
    compose build --no-cache webui
    compose up -d webui
    wait_for_webui
    ;;
  *)
    sed -n '2,12p' "$0"
    exit 1
    ;;
esac
