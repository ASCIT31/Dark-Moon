#!/usr/bin/env bash
#
# check-no-regression.sh — invariant gate for the Darkmoon agents-expansion work.
#
# Run BEFORE and AFTER any change touching agents / pentest.md / apply-settings.sh /
# the MCP allow-list / live_push.py. It locks the regressions we already paid for
# last week and proves the new credential-gated agents are wired the way the
# working agents are (the INC-010a lesson: a SIGNAL block alone is not enough).
#
# Usage: tools/check-no-regression.sh [repo_dir]     (default: the repo this lives in)
# Exit 0 = all invariants hold; 1 = at least one regression.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:-$(cd "$HERE/.." && pwd)}"
PENTEST="$REPO/conf/agents/pentest.md"
APPLY="$REPO/conf/apply-settings.sh"
LIVEPUSH="$REPO/mcp/api/live_push.py"
AGENTS_DIR="$REPO/conf/agents"

fail=0
ok()   { printf "  [OK]   %s\n" "$1"; }
bad()  { printf "  [FAIL] %s\n" "$1"; fail=$((fail+1)); }

NEW_AGENTS="aws azure entra-id gcp github gitlab jenkins terraform ansible docker container-registry hashicorp-vault sql-databases messaging-cache"

echo "== no-regression gate for: $REPO =="

# ---- INC-010: golang dispatch requires POSITIVE evidence, never absence-of-markers
if [ -f "$PENTEST" ]; then
  echo "[INC-010] golang false-positive dispatch"
  if [ "$(grep -c 'most often Go' "$PENTEST")" -eq 0 ]; then ok "no 'most often Go' fallback text"; else bad "'most often Go' fallback text is BACK — golang will false-dispatch"; fi
  if [ "$(grep -c 'POSITIVE Go' "$PENTEST")" -ge 1 ]; then ok "'POSITIVE Go' requirement present"; else bad "'POSITIVE Go' requirement missing"; fi
  # our new planes must carry the same doctrine
  if grep -q 'POSITIVE ARTIFACT' "$PENTEST"; then ok "credential-gated planes use POSITIVE ARTIFACT doctrine"; else bad "new planes missing POSITIVE ARTIFACT doctrine"; fi
else
  bad "pentest.md not found"
fi

# ---- INC-009: report body is regenerated server-side, deterministically
if [ -f "$LIVEPUSH" ]; then
  echo "[INC-009] deterministic report generation"
  if [ "$(grep -c '_is_reference = True' "$LIVEPUSH")" -ge 1 ]; then ok "finalize regenerates report from DB (_is_reference = True)"; else bad "_is_reference no longer forced True — report can be non-deterministic"; fi
fi

# ---- INC-010a: every new agent wired at BOTH load-bearing places (roster + signal)
if [ -f "$PENTEST" ]; then
  echo "[wiring] roster + signal-matrix presence"
  roster_block="$(awk '/SUBAGENT PROMPT = RAW AGENT FILE/{f=1} f&&/1\) PROMPT CONSTRUCTION/{f=0} f' "$PENTEST")"
  for a in $NEW_AGENTS; do
    in_roster=0; echo "$roster_block" | grep -qE "^[[:space:]]*$a[[:space:]]*$" && in_roster=1
    in_signal=0; grep -qE "^SIGNAL: $a plane present" "$PENTEST" && in_signal=1
    if [ "$in_roster" -eq 1 ] && [ "$in_signal" -eq 1 ]; then ok "$a: roster + signal"; else bad "$a: roster=$in_roster signal=$in_signal (need both)"; fi
  done
  # new planes must NOT be added to the headless-browser web-agent list
  if grep -A4 'Web agents that ALWAYS trigger headless-browser' "$PENTEST" | grep -qE '\baws\b|\bazure\b|\bterraform\b'; then
    bad "a cloud/infra agent leaked into the headless-browser trigger list (they are NOT web agents)"
  else ok "no cloud/infra agent in the headless-browser trigger list"; fi
fi

# ---- registration in apply-settings.sh + the .md file exists + is LF
echo "[files] agent .md present, LF, registered"
for a in $NEW_AGENTS; do
  md="$AGENTS_DIR/$a.md"
  [ -f "$md" ] && ok "$a.md present" || bad "$a.md MISSING"
  [ -f "$md" ] && { [ "$(grep -c $'\r' "$md")" -eq 0 ] && ok "$a.md is LF" || bad "$a.md has CRLF"; }
  grep -q "\"$a\":" "$APPLY" && ok "$a registered in apply-settings.sh" || bad "$a NOT in apply-settings.sh"
done

# ---- pentest.md newline style unchanged for this edition
if [ -f "$PENTEST" ]; then
  cr="$(grep -c $'\r' "$PENTEST")"
  case "$REPO" in
    *Front-API*) [ "$cr" -gt 100 ] && ok "Front-API pentest.md kept CRLF ($cr)" || bad "Front-API pentest.md lost CRLF ($cr)";;
    *)           [ "$cr" -eq 0 ]   && ok "pentest.md kept LF" || bad "pentest.md gained CRLF ($cr)";;
  esac
fi

# ---- apply-settings.sh renders valid JSON with all agents
if [ -f "$APPLY" ]; then
  echo "[config] apply-settings.sh renders valid opencode.json"
  sb="$(mktemp -d)"
  sed "s#/root/.config/opencode#$sb/config#g; s#/root/.local/share/opencode#$sb/share#g" "$APPLY" > "$sb/a.sh"
  mkdir -p "$sb/config" "$sb/share"
  if OPENROUTER_PROVIDER=anthropic OPENROUTER_API_KEY=x OPENCODE_MODEL=anthropic/x bash "$sb/a.sh" >/dev/null 2>&1; then
    if python3 - "$sb/config/opencode.json" "$NEW_AGENTS" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); agents=d.get("agent",{})
missing=[a for a in sys.argv[2].split() if a not in agents]
print("MISSING:"+",".join(missing) if missing else "ALLPRESENT:%d"%len(agents))
sys.exit(1 if missing else 0)
PY
    then ok "opencode.json valid, all new agents present"; else bad "opencode.json missing new agents"; fi
  else bad "apply-settings.sh failed to render opencode.json"; fi
  rm -rf "$sb"
fi

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: PASS — no regression in $(basename "$REPO")."; exit 0
else echo "RESULT: FAIL — $fail invariant(s) broken in $(basename "$REPO")."; exit 1; fi
