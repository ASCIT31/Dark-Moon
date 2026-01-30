#!/usr/bin/env bash
set -euo pipefail

BIND_PATHS=(
  "./data"
  "./darkmoon-settings"
  "./workflows"
)

echo "🛑 Stopping stack (containers + networks + volumes + images of this compose)..."
docker compose down --remove-orphans --volumes --rmi all

echo "🧹 Purging bind mounts..."
for path in "${BIND_PATHS[@]}"; do
  if [ -d "$path" ]; then
    echo "  - rm -rf $path"
    rm -rf "$path"
  else
    echo "  - $path (absent)"
  fi
done

echo "🧽 Purging build cache (optional but often useful)..."
docker builder prune -f

echo "🔨 Rebuild & recreate..."
docker compose build --no-cache
docker compose up -d --force-recreate

echo "✅ Stack recreated CLEAN"