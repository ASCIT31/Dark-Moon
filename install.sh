#!/usr/bin/env bash
set -euo pipefail

BIND_PATHS=(
  "./data"
  "./darkmoon-settings"
  "./workflows"
)

# Colors
CYAN="\033[1;36m"
BLUE="\033[1;34m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

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

# Check Docker
if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker is not installed.${RESET}"
  echo -e "${YELLOW}Please install Docker before running this script.${RESET}"
  echo ""
  echo "Install guide:"
  echo "https://docs.docker.com/engine/install/"
  exit 1
fi

# Check Docker daemon
if ! docker info >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker daemon is not running.${RESET}"
  echo -e "${YELLOW}Please start Docker and retry.${RESET}"
  exit 1
fi

# Check Docker Compose v2
if ! docker compose version >/dev/null 2>&1; then
  echo -e "${RED}❌ Docker Compose (v2) is not available.${RESET}"
  echo -e "${YELLOW}Install Docker Compose plugin:${RESET}"
  echo "https://docs.docker.com/compose/install/"
  exit 1
fi

echo -e "${GREEN}✔ Docker and Docker Compose detected${RESET}"

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