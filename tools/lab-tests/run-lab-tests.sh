#!/usr/bin/env bash
#
# run-lab-tests.sh — end-to-end validation of the new credential-gated agents.
#
# SAFETY: this is meant to run against a FRESH / ISOLATED darkmoon+opencode pair
# (a CI build or a dedicated test stack), NEVER against a shared production
# opencode container — restarting or re-configuring a shared opencode kills live
# client campaigns (INC-011). It refuses to run unless DARKMOON_TEST_STACK=1.
#
# It brings up local labs, proves each new agent's core commands execute in the
# toolbox against a real service, then (optionally) drives one broad campaign to
# validate dispatch + finding-push + report generation.
#
#   Part A  toolbox command validation (cheap, no LLM)   -> always runs
#   Part B  dispatch regression + one campaign (LLM)     -> RUN_CAMPAIGN=1
#
# Usage:
#   DARKMOON_TEST_STACK=1 tools/lab-tests/run-lab-tests.sh
#   DARKMOON_TEST_STACK=1 RUN_CAMPAIGN=1 tools/lab-tests/run-lab-tests.sh
set -uo pipefail

TOOLBOX="${TOOLBOX_CONTAINER:-darkmoon}"
NET="$(docker inspect "$TOOLBOX" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null || echo host)"
pass=0; failc=0
ok(){ printf "  [OK]   %s\n" "$1"; pass=$((pass+1)); }
ko(){ printf "  [FAIL] %s\n" "$1"; failc=$((failc+1)); }
dex(){ docker exec "$TOOLBOX" bash -c "$1" 2>&1; }
# chk DESC PATTERN COMMAND — capture output first (avoids pipefail+grep -q SIGPIPE)
chk(){ local out; out="$(dex "$3")"; if printf '%s' "$out" | grep -qi -- "$2"; then ok "$1"; else ko "$1"; fi; }

[ "${DARKMOON_TEST_STACK:-0}" = "1" ] || { echo "Refusing to run: set DARKMOON_TEST_STACK=1 (never run against a shared prod opencode)."; exit 2; }

echo "== lab setup =="
# Redis lab (unauthenticated — messaging-cache)
docker rm -f dm-redis-lab >/dev/null 2>&1
docker run -d --name dm-redis-lab --network "$NET" redis:7 redis-server --protected-mode no >/dev/null 2>&1 \
  && echo "  redis-lab up (127.0.0.1:6379)" || echo "  redis-lab FAILED"
sleep 2

echo
echo "== Part A — toolbox command validation (no LLM) =="

MYSQL_HOST="${MYSQL_HOST:-172.22.0.2}"; MYSQL_CRED="${MYSQL_CRED:--uroot -prootwolf}"

echo "[messaging-cache / Redis]"
chk "redis PING (unauth positive artifact)"       "PONG"  "redis-cli -h 127.0.0.1 -p 6379 PING"
chk "redis CONFIG GET dir (RDB-write RCE primitive)" "/data" "redis-cli -h 127.0.0.1 CONFIG GET dir"
chk "redis unauth write CONFIRMED"                "ok"    "redis-cli -h 127.0.0.1 SET dm_probe ok >/dev/null; redis-cli -h 127.0.0.1 GET dm_probe"
dex "redis-cli -h 127.0.0.1 DEL dm_probe" >/dev/null

echo "[sql-databases / MySQL @ vulnapp-mysql]"
chk "mysql connect + version"                 "^[0-9]"        "mysql -h $MYSQL_HOST $MYSQL_CRED -N -e 'select version();'"
chk "mysql grants (ALL PRIVILEGES)"           "ALL PRIVILEGES" "mysql -h $MYSQL_HOST $MYSQL_CRED -N -e 'show grants;'"
chk "mysql secure_file_priv (OUTFILE feasibility)" "secure_file_priv" "mysql -h $MYSQL_HOST $MYSQL_CRED -N -e 'show variables like \"secure_file_priv\";'"

echo "[docker / socket API]"
chk "docker socket API responds" "ApiVersion" '[ -S /var/run/docker.sock ] && curl -s --unix-socket /var/run/docker.sock http://localhost/version'

echo "[cloud preflight gating — must STOP cleanly without creds, not hallucinate]"
chk "aws preflight STOPs cleanly (credential-gated)" "Unable to locate credentials" "aws sts get-caller-identity"
chk "az preflight STOPs cleanly"                     "az login"                      "az account show"
chk "gcloud preflight STOPs cleanly"                 "No credentialed"               "gcloud auth list"

echo
echo "== Part A summary: $pass ok, $failc fail =="

if [ "${RUN_CAMPAIGN:-0}" = "1" ]; then
  echo
  echo "== Part B — dispatch + campaign (LLM; costs tokens) =="
  echo "  Regression check: a plain web target must NOT dispatch any credential-gated agent."
  echo "  Positive check:   a target with a supplied DB credential must dispatch sql-databases."
  echo "  Launch from ~/test-setup, e.g.:"
  echo "    nohup ./darkmoon.sh 'TARGET: http://127.0.0.1:3000' >> /tmp/camp_web.log 2>&1 &   # juiceshop: expect web agents only"
  echo "    nohup ./darkmoon.sh 'TARGET: 172.22.0.2 MySQL in scope creds root:rootwolf' >> /tmp/camp_db.log 2>&1 &"
  echo "  Then verify no new-agent false-dispatch on the web run, and sql-databases findings + a full report on the db run:"
  echo "    curl -s 'http://127.0.0.1:8000/api/v1/vulnerabilities?campaign_id=<id>' | jq '.total'"
  echo "  (Run this ONLY on an isolated test stack, never the shared prod opencode — INC-011.)"
fi
exit $([ "$failc" -eq 0 ] && echo 0 || echo 1)
