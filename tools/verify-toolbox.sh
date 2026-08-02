#!/usr/bin/env bash
#
# verify-toolbox.sh — post-build regression gate for the Darkmoon toolbox.
#
# The toolbox has not been rebuilt in a long time and some install methods can go
# stale (moved URLs, renamed packages, go-install breakage). This script proves,
# after a build, that EVERY tool the MCP allow-list exposes is actually present
# AND responds — so agents never dispatch a command the toolbox silently lacks,
# and so our new tools (aws/az/gcloud/gsutil/bq/psql/mysql/redis-cli) did not
# regress the existing ones.
#
# It runs live probes inside the toolbox container (default: darkmoon) and cross-
# checks them against the allow-list in mcp/src/tools/core/executor.py.
#
# Usage:
#   tools/verify-toolbox.sh [container_name]     # probe a running container
#   TOOLBOX_LOCAL=1 tools/verify-toolbox.sh      # probe the host PATH instead
#
# Exit code: 0 = all allow-listed tools alive; 1 = at least one missing/broken.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
EXECUTOR="$REPO/mcp/src/tools/core/executor.py"
CONTAINER="${1:-darkmoon}"

# Tools that are shell builtins / not expected as standalone binaries — skip probe.
SKIP_REGEX='^(bash|cat|chmod|grep|awk|sed)$'

# How to run a command in the chosen environment.
run() {
  if [ "${TOOLBOX_LOCAL:-0}" = "1" ]; then
    timeout 25 bash -c "$1" 2>&1
  else
    timeout 25 docker exec "$CONTAINER" bash -c "$1" 2>&1
  fi
}

# Liveness probe for one tool: present on PATH, and at least one help/version
# form yields output or a clean exit. Returns 0 alive, 2 present-but-mute, 1 absent.
probe() {
  local t="$1" out rc
  # presence
  if ! run "command -v '$t' >/dev/null 2>&1"; then
    return 1
  fi
  # try a series of liveness forms; success = exit 0 OR non-empty output
  local forms=(
    "$t --version" "$t version" "$t -version" "$t --help" "$t -h" "$t help"
  )
  # per-tool overrides where the generic forms misbehave
  case "$t" in
    kubectl)   forms=("kubectl version --client=true -o yaml") ;;
    az)        forms=("az version") ;;
    gsutil)    forms=("gsutil version") ;;
    bq)        forms=("bq version") ;;
    lightpanda)forms=("lightpanda --help" "lightpanda version") ;;
    ping)      forms=("ping -V" "ping -c1 127.0.0.1") ;;
    ping.py)   forms=("ping.py -h") ;;
    redis-cli) forms=("redis-cli --version") ;;
    psql)      forms=("psql --version") ;;
    mysql)     forms=("mysql --version") ;;
    hydra)     forms=("hydra -h") ;;
    snmpwalk)  forms=("snmpwalk -V" "snmpwalk -h") ;;
  esac
  for f in "${forms[@]}"; do
    out="$(run "$f")"; rc=$?
    if [ $rc -eq 0 ] || [ -n "$out" ]; then
      return 0
    fi
  done
  return 2
}

echo "== Darkmoon toolbox verification =="
if [ "${TOOLBOX_LOCAL:-0}" = "1" ]; then
  echo "target: local host PATH"
else
  if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "ERROR: container '$CONTAINER' is not running."; exit 1
  fi
  echo "target: container '$CONTAINER'"
fi
[ -f "$EXECUTOR" ] || { echo "ERROR: executor.py not found at $EXECUTOR"; exit 1; }

# Extract the allow-list.
mapfile -t TOOLS < <(python3 - "$EXECUTOR" <<'PY'
import re,sys
s=open(sys.argv[1]).read()
m=re.search(r'self\.allowed_tools\s*=\s*\{(.*?)\}', s, re.S)
for t in re.findall(r'"([^"]+)"', m.group(1)):
    print(t)
PY
)
echo "allow-list size: ${#TOOLS[@]}"
echo

alive=0; mute=0; absent=0
declare -a ABSENT_LIST MUTE_LIST
for t in "${TOOLS[@]}"; do
  if [[ "$t" =~ $SKIP_REGEX ]]; then
    printf "  %-26s %s\n" "$t" "SKIP (shell builtin)"; continue
  fi
  probe "$t"; r=$?
  case $r in
    0) printf "  %-26s %s\n" "$t" "OK";    alive=$((alive+1)) ;;
    2) printf "  %-26s %s\n" "$t" "PRESENT-BUT-MUTE"; mute=$((mute+1)); MUTE_LIST+=("$t") ;;
    1) printf "  %-26s %s\n" "$t" "MISSING <== REGRESSION"; absent=$((absent+1)); ABSENT_LIST+=("$t") ;;
  esac
done

echo
echo "== summary =="
echo "  alive:            $alive"
echo "  present-but-mute: $mute   ${MUTE_LIST[*]:-}"
echo "  MISSING:          $absent  ${ABSENT_LIST[*]:-}"
echo
if [ "$absent" -gt 0 ]; then
  echo "RESULT: FAIL — $absent allow-listed tool(s) missing from the toolbox."
  echo "        A missing tool means an agent will hit 'Tool not in allowed list' or"
  echo "        'command not found' at runtime. Fix the install (Dockerfile/setup_*.sh)."
  exit 1
fi
echo "RESULT: PASS — every allow-listed tool is present and responsive."
[ "$mute" -gt 0 ] && echo "NOTE: present-but-mute tools exist but produced no help/version output; verify manually."
exit 0
