#!/usr/bin/env bash
# Copy every generated agent .md into the three repos' conf/agents/.
# New agent files are byte-identical across all three repos (only ad.md,
# kubernetes.md and pentest.md legitimately differ between editions).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
REPOS=(
  "/home/mehdi/Dark-Moon-community"
  "/home/mehdi/Dark-Moon-prod"
  "/home/mehdi/Dark-Moon-Front-API"
)
[ -d "$OUT" ] || { echo "no out/ dir — run generate.py first"; exit 1; }
n=$(ls "$OUT"/*.md 2>/dev/null | wc -l)
echo "mirroring $n generated agent(s) into ${#REPOS[@]} repos"
for repo in "${REPOS[@]}"; do
  dest="$repo/conf/agents"
  [ -d "$dest" ] || { echo "  SKIP (no conf/agents): $repo"; continue; }
  for f in "$OUT"/*.md; do
    cp "$f" "$dest/$(basename "$f")"
  done
  echo "  -> $repo/conf/agents ($(ls "$OUT"/*.md | wc -l) files)"
done
echo "done."
