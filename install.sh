#!/usr/bin/env bash
set -euo pipefail

BIND_PATHS=(
  "./data"
  "./darkmoon-settings"
  "./workflows"
)

OPENCODE_ENV_FILE=".opencode.env"

# Colors
CYAN="\033[1;36m"
BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
MAGENTA="\033[1;35m"
BOLD="\033[1m"
RESET="\033[0m"

# ─────────────────────────────────────────────────────────────────
# Parse args
# ─────────────────────────────────────────────────────────────────
FORCE_RESET=false
for ARG in "$@"; do
  case "${ARG}" in
    --help|-h)
      echo "Usage: ./install.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --init    Force LLM provider reconfiguration (ignores existing .opencode.env)"
      echo "  --help    Show this help"
      echo ""
      echo "Examples:"
      echo "  ./install.sh           # rebuild, skip provider form if already configured"
      echo "  ./install.sh --init    # rebuild and reconfigure LLM provider"
      exit 0 ;;
    --reset|--init) FORCE_RESET=true ;;
  esac
done

SCRIPT_DIR="$(pwd)"

echo -e "${CYAN}"
cat << "EOF"

  ____             _                                
 |  _ \  __ _ _ __| | ___ __ ___   ___   ___  _ __  
 | | | |/ _` | '__| |/ / '_ ` _ \ / _ \ / _ \| '_ \ 
 | |_| | (_| | |  |   <| | | | | | (_) | (_) | | | |
 |____/ \__,_|_|  |_|\_\_| |_| |_|\___/ \___/|_| |_|

EOF
echo -e "${RESET}"

echo -e "${BLUE}🔎 Checking prerequisites...${RESET}"

if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker is not installed.${RESET}"
  echo -e "${YELLOW}Please install Docker before running this script.${RESET}"
  echo ""
  echo "Install guide: https://docs.docker.com/engine/install/"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker daemon is not running.${RESET}"
  echo -e "${YELLOW}Please start Docker and retry.${RESET}"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker Compose (v2) is not available.${RESET}"
  echo -e "${YELLOW}Install Docker Compose plugin:${RESET}"
  echo "https://docs.docker.com/compose/install/"
  exit 1
fi

echo -e "${GREEN}✔ Docker and Docker Compose detected${RESET}"

# ─────────────────────────────────────────────────────────────────
# Save .opencode.env BEFORE purge (unless --init)
# ─────────────────────────────────────────────────────────────────
SAVED_OPENCODE_ENV=""
if [ "${FORCE_RESET}" = false ] && [ -f "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}" ]; then
  SAVED_OPENCODE_ENV="$(cat "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}")"
fi

# ─────────────────────────────────────────────────────────────────
# Detect if provider already configured
# ─────────────────────────────────────────────────────────────────
SKIP_PROVIDER_FORM=false
if [ -n "${SAVED_OPENCODE_ENV}" ]; then
  set +u
  eval "$(echo "${SAVED_OPENCODE_ENV}" | sed 's/:[[:space:]]\+/=/g' | sed 's/\r//' | grep -E '^[A-Z_]+=.+')" 2>/dev/null || true
  set -u

  if [ -n "${OPENROUTER_PROVIDER:-}" ] && \
     [ -n "${OPENROUTER_API_KEY:-}" ] && \
     [ -n "${OPENCODE_MODEL:-}" ]; then
    SKIP_PROVIDER_FORM=true
  elif [ "${OPENCODE_LOCAL_MODE:-}" = "true" ] && \
       [ -n "${OPENCODE_LOCAL_PROVIDER_ID:-}" ] && \
       [ -n "${OPENCODE_LOCAL_BASE_URL:-}" ] && \
       [ -n "${OPENCODE_LOCAL_MODEL:-}" ]; then
    SKIP_PROVIDER_FORM=true
  fi
fi

# ─────────────────────────────────────────────────────────────────
# LLM Provider configuration
# ─────────────────────────────────────────────────────────────────
if [ "${SKIP_PROVIDER_FORM}" = true ]; then
  echo -e "${GREEN}✔ LLM provider already configured — skipping${RESET}"
  printf '%s\n' "${SAVED_OPENCODE_ENV}" > "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}"
else
  echo ""
  echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e "  🤖  LLM PROVIDER CONFIGURATION"
  echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  echo -e "  ${CYAN}[1]${RESET} ${BOLD}Cloud provider${RESET}  (Anthropic, OpenRouter, OpenAI, etc.)"
  echo -e "  ${CYAN}[2]${RESET} ${BOLD}Local model${RESET}     (Ollama, llama.cpp / llama-server)"
  echo ""

  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [1/2]: ${RESET}")" PROVIDER_TYPE
    case "${PROVIDER_TYPE}" in
      1|cloud|Cloud) PROVIDER_TYPE="cloud"; break ;;
      2|local|Local) PROVIDER_TYPE="local"; break ;;
      *) echo -e "${RED}  Please enter 1 (cloud) or 2 (local).${RESET}" ;;
    esac
  done

  # ── Cloud ────────────────────────────────────────────────────────
  if [ "${PROVIDER_TYPE}" = "cloud" ]; then
    echo ""
    echo -e "${CYAN}Available cloud providers (examples):${RESET}"
    echo -e "  ${YELLOW}anthropic${RESET}   → claude-opus-4-6, claude-sonnet-4-5"
    echo -e "  ${YELLOW}openai${RESET}      → gpt-4o, o3"
    echo -e "  ${YELLOW}openrouter${RESET}  → any model via openrouter.ai"
    echo ""

    read -r -p "$(echo -e "${YELLOW}Provider name (e.g. anthropic): ${RESET}")" CLOUD_PROVIDER
    while [ -z "${CLOUD_PROVIDER}" ]; do
      echo -e "${RED}  Provider name cannot be empty.${RESET}"
      read -r -p "$(echo -e "${YELLOW}Provider name: ${RESET}")" CLOUD_PROVIDER
    done

    read -r -p "$(echo -e "${YELLOW}Model name    (e.g. claude-opus-4-6): ${RESET}")" CLOUD_MODEL
    while [ -z "${CLOUD_MODEL}" ]; do
      echo -e "${RED}  Model name cannot be empty.${RESET}"
      read -r -p "$(echo -e "${YELLOW}Model name: ${RESET}")" CLOUD_MODEL
    done

    read -r -s -p "$(echo -e "${YELLOW}API key: ${RESET}")" CLOUD_API_KEY
    echo ""
    while [ -z "${CLOUD_API_KEY}" ]; do
      echo -e "${RED}  API key cannot be empty.${RESET}"
      read -r -s -p "$(echo -e "${YELLOW}API key: ${RESET}")" CLOUD_API_KEY
      echo ""
    done

    cat > "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}" <<EOF
# Darkmoon — LLM cloud provider config
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
OPENROUTER_PROVIDER=${CLOUD_PROVIDER}
OPENCODE_MODEL=${CLOUD_MODEL}
OPENROUTER_API_KEY=${CLOUD_API_KEY}
EOF

  # ── Local ─────────────────────────────────────────────────────────
  else
    echo ""
    echo -e "${CYAN}Local provider options:${RESET}"
    echo -e "  ${YELLOW}[1]${RESET} Ollama       (default: http://localhost:11434/v1)"
    echo -e "  ${YELLOW}[2]${RESET} llama.cpp    (llama-server, default: http://localhost:8080/v1)"
    echo -e "  ${YELLOW}[3]${RESET} Custom URL   (any OpenAI-compatible endpoint)"
    echo ""

    while true; do
      read -r -p "$(echo -e "${YELLOW}Local engine [1/2/3]: ${RESET}")" LOCAL_ENGINE
      case "${LOCAL_ENGINE}" in
        1|ollama|Ollama)
          LOCAL_PROVIDER_ID="ollama"
          LOCAL_PROVIDER_NAME="Ollama (local)"
          DEFAULT_BASE_URL="http://localhost:11434/v1"
          break ;;
        2|llama*|llamacpp)
          LOCAL_PROVIDER_ID="llama.cpp"
          LOCAL_PROVIDER_NAME="llama-server (local)"
          DEFAULT_BASE_URL="http://localhost:8080/v1"
          break ;;
        3|custom|Custom)
          LOCAL_PROVIDER_ID="local"
          LOCAL_PROVIDER_NAME="Local model"
          DEFAULT_BASE_URL=""
          break ;;
        *) echo -e "${RED}  Please enter 1, 2 or 3.${RESET}" ;;
      esac
    done

    read -r -p "$(echo -e "${YELLOW}Base URL [${DEFAULT_BASE_URL}]: ${RESET}")" LOCAL_BASE_URL
    LOCAL_BASE_URL="${LOCAL_BASE_URL:-${DEFAULT_BASE_URL}}"
    while [ -z "${LOCAL_BASE_URL}" ]; do
      echo -e "${RED}  Base URL cannot be empty.${RESET}"
      read -r -p "$(echo -e "${YELLOW}Base URL: ${RESET}")" LOCAL_BASE_URL
    done

    read -r -p "$(echo -e "${YELLOW}Model name (e.g. qwen2.5-coder:7b): ${RESET}")" LOCAL_MODEL
    while [ -z "${LOCAL_MODEL}" ]; do
      echo -e "${RED}  Model name cannot be empty.${RESET}"
      read -r -p "$(echo -e "${YELLOW}Model name: ${RESET}")" LOCAL_MODEL
    done

    cat > "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}" <<EOF
# Darkmoon — LLM local provider config
# Generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
OPENCODE_LOCAL_MODE=true
OPENCODE_LOCAL_PROVIDER_ID=${LOCAL_PROVIDER_ID}
OPENCODE_LOCAL_PROVIDER_NAME=${LOCAL_PROVIDER_NAME}
OPENCODE_LOCAL_BASE_URL=${LOCAL_BASE_URL}
OPENCODE_LOCAL_MODEL=${LOCAL_MODEL}
EOF

  fi # end PROVIDER_TYPE
fi # end SKIP_PROVIDER_FORM

chmod 600 "${SCRIPT_DIR}/${OPENCODE_ENV_FILE}"
echo -e "${GREEN}✔ ${OPENCODE_ENV_FILE} written${RESET}"

# ─────────────────────────────────────────────────────────────────
# Stop stack + purge + rebuild
# ─────────────────────────────────────────────────────────────────
echo -e "${BLUE}🛑 Stopping stack (containers + networks + volumes + images)...${RESET}"
docker compose down --remove-orphans --volumes --rmi all

echo -e "${BLUE}🧹 Purging bind mounts...${RESET}"
for path in "${BIND_PATHS[@]}"; do
  if [ -d "$path" ]; then
    echo -e "${YELLOW}  - removing ${path}${RESET}"
    rm -rf "$path"
  else
    echo -e "${YELLOW}  - ${path} (absent)${RESET}"
  fi
done

echo -e "${BLUE}🧽 Purging docker build cache...${RESET}"
docker builder prune -f

echo -e "${BLUE}🔨 Rebuilding images (no cache)...${RESET}"
docker compose build --no-cache

echo -e "${BLUE}🚀 Recreating containers...${RESET}"
docker compose up -d --force-recreate

echo -e "${GREEN}✅ Darkmoon stack rebuilt CLEAN${RESET}"
