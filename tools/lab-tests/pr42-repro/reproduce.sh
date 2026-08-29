#!/usr/bin/env bash
#
# reproduce.sh - reproduce the PR #42 regression from REAL tool output, then
# show the same session against the current code.
#
# Widening the default protection boundary to URL/DOMAIN/PATH (issue #40, merged
# as PR #41) meant essentially every pentest command carries a placeholder, so
# every exfiltration rule started firing on legitimate work. PR #42 reported it
# from a VulnHub-style box: the agent could not inspect a discovered value, and
# lost the ability to spot a `~myfiles` directory it had found.
#
# This script rebuilds that shape as a real web service, runs real httpx / ffuf /
# curl against it inside the toolbox, and feeds the captured output through the
# privacy gateway. Nothing is hand-written: the strings the gateway sees are the
# ones the scanners actually produced.
#
#   Before: 4 of 9 natural follow-up commands refused, filenames unreadable.
#   After:  0 of 9 refused, filenames readable.
#
# Usage:
#   tools/lab-tests/pr42-repro/reproduce.sh                 # this checkout only
#   BASELINE_IMAGE=ascit/opencode-darkmoon:latest \
#     tools/lab-tests/pr42-repro/reproduce.sh               # also show "before"
#
# Env:
#   TOOLBOX_CONTAINER   toolbox container to scan from   (default: darkmoon)
#   BASELINE_IMAGE      image whose MCP carries the pre-fix code, for the A/B
#   KEEP_LAB=1          leave the lab container running afterwards
set -uo pipefail


HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
TOOLBOX="${TOOLBOX_CONTAINER:-darkmoon}"
LAB_NAME="pr42-repro-lab"
OUT="$HERE/captured"
PY_IMAGE="${PY_IMAGE:-python:3.12-slim}"

cleanup() {
  [ "${KEEP_LAB:-0}" = "1" ] || docker rm -f "$LAB_NAME" >/dev/null 2>&1
  [ "${KEEP_CAPTURES:-0}" = "1" ] || rm -rf "$OUT"
}
trap cleanup EXIT

mkdir -p "$OUT"

docker inspect "$TOOLBOX" >/dev/null 2>&1 || {
  echo "Toolbox container '$TOOLBOX' is not running. Start the stack first, or set TOOLBOX_CONTAINER." >&2
  exit 2
}
NET="$(docker inspect "$TOOLBOX" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | awk '{print $1}')"

echo "== building the lab =="
docker build -q -t pr42-repro-lab "$HERE" >/dev/null || { echo "build failed" >&2; exit 1; }
docker rm -f "$LAB_NAME" >/dev/null 2>&1
docker run -d --name "$LAB_NAME" --network "$NET" pr42-repro-lab >/dev/null || { echo "lab failed to start" >&2; exit 1; }
LAB_IP="$(docker inspect "$LAB_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
until docker exec "$TOOLBOX" curl -s -o /dev/null "http://$LAB_IP/" 2>/dev/null; do sleep 1; done
echo "   lab up at http://$LAB_IP"

echo
echo "== capturing REAL tool output from the toolbox =="
dex() { docker exec "$TOOLBOX" bash -c "$1" 2>&1; }
dex "httpx -u http://$LAB_IP -json -silent"                                  > "$OUT/httpx.txt"
dex "httpx -u 'http://$LAB_IP/index.php?page=home&lang=en' -json -silent"    > "$OUT/httpx_query.txt"
dex "curl -s 'http://$LAB_IP/index.php?page=debug'"                          > "$OUT/debug.txt"
dex "curl -s http://$LAB_IP/~myfiles/"                                       > "$OUT/myfiles.txt"
dex "ffuf -u http://$LAB_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -t 40 -s -maxtime 40" > "$OUT/ffuf.txt"
for f in "$OUT"/*.txt; do printf "   %-18s %s bytes\n" "$(basename "$f")" "$(wc -c < "$f")"; done

run_against() {
  local label="$1" mcp_mount="$2" image="$3" workdir="$4"
  echo
  echo "== $label =="
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$mcp_mount" \
    -v "$HERE/compare.py:/compare.py:ro" \
    -v "$OUT:/realout:ro" \
    -w "$workdir" --entrypoint "" "$image" \
    sh -c 'if [ -x .venv/bin/python ]; then .venv/bin/python /compare.py; else pip install --quiet cryptography >/dev/null 2>&1; python3 /compare.py; fi'
}

if [ -n "${BASELINE_IMAGE:-}" ]; then
  run_against "BEFORE - $BASELINE_IMAGE" \
    "$HERE/compare.py:/compare.py:ro" "$BASELINE_IMAGE" /opt/darkmoon/mcp/server
fi

run_against "AFTER - this checkout" "$REPO/mcp:/mcp:ro" "$PY_IMAGE" /mcp

echo
echo "Done. Re-run with BASELINE_IMAGE=ascit/opencode-darkmoon:latest for the A/B."
