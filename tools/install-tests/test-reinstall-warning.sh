#!/usr/bin/env bash
# Re-running install.sh over an existing install must ask before deleting
# ./darkmoon-settings (custom agents included) and back it up on "yes".
#
# Runs install.sh in a throwaway copy with a stub `docker` on PATH (no daemon,
# nothing built). A terminal is simulated with `script` (util-linux); "no
# terminal" with `setsid`, which leaves the process without a controlling tty.
#
#   bash tools/install-tests/test-reinstall-warning.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK:?}"' EXIT

command -v script >/dev/null || { echo "SKIP: util-linux 'script' not found"; exit 0; }
command -v setsid >/dev/null || { echo "SKIP: 'setsid' not found"; exit 0; }

mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "${DOCKER_LOG:-/dev/null}"
case "$1" in run) exit 1 ;; esac   # no GPU runtime
exit 0
EOF
chmod +x "$WORK/bin/docker"

PASS=0
FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
nok()  { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else nok "$1"; echo "----- output -----"; cat "$D/out"; echo "------------------"; fi; }

# A fresh install directory: installer + shipped agents + an already configured provider.
new_dir() {
  D="$WORK/$1"
  mkdir -p "$D/conf"
  cp "$REPO/install.sh" "$D/"
  cp -a "$REPO/conf/agents" "$D/conf/agents"
  printf 'ANTHROPIC_BASE_URL=http://127.0.0.1:1/v1\nANTHROPIC_MODEL=test-model\n' > "$D/.opencode.env"
  export DOCKER_LOG="$D/docker.log"
}

# An existing install: populated darkmoon-settings with the shipped agents plus one custom agent.
seed_existing() {
  mkdir -p "$D/darkmoon-settings/agents" "$D/workflows"
  cp "$REPO"/conf/agents/*.md "$D/darkmoon-settings/agents/"
  echo "my private agent" > "$D/darkmoon-settings/agents/my-custom-agent.md"
  echo "edited" >> "$D/darkmoon-settings/agents/$(ls "$REPO/conf/agents" | grep '\.md$' | head -n1)"
  echo '{}' > "$D/darkmoon-settings/opencode.json"
  echo 'wf' > "$D/workflows/custom.yml"
}

# Run install.sh with a terminal, typing $1 at the prompt.
run_tty()   { ( cd "$D" && printf '%s\n' "$1" | PATH="$WORK/bin:$PATH" script -qec "bash ./install.sh ${2:-}" /dev/null ) > "$D/out" 2>&1; echo $? > "$D/rc"; }
# Run install.sh with no controlling terminal and stdin closed.
run_notty() { ( cd "$D" && env PATH="$WORK/bin:$PATH" ${2:-} setsid -w bash ./install.sh ${1:-} </dev/null ) > "$D/out" 2>&1; echo $? > "$D/rc"; }
backups()   { ls -d "$D"/darkmoon-settings.backup-* 2>/dev/null | wc -l | tr -d ' '; }

echo "1. fresh install: no prompt, install proceeds"
new_dir fresh
run_notty
check "exit 0"                    '[ "$(cat "$D/rc")" = 0 ]'
check "no warning"                '! grep -q "EXISTING DARKMOON INSTALL" "$D/out"'
check "stack rebuilt"             'grep -q "rebuilt CLEAN" "$D/out" && grep -q "compose .*up -d" "$D/docker.log"'
check "no backup dir"             '[ "$(backups)" = 0 ]'

echo "2. existing install + answer n: nothing deleted"
new_dir answer_n; seed_existing
run_tty n
check "exit non-zero"             '[ "$(cat "$D/rc")" != 0 ]'
check "warning shown"             'grep -q "EXISTING DARKMOON INSTALL DETECTED" "$D/out"'
check "lists darkmoon-settings"   'grep -q "darkmoon-settings.*(.* files)" "$D/out"'
check "names the custom agent"    'grep -q "my-custom-agent.md (custom)" "$D/out"'
check "names the edited agent"    'grep -q "(modified)" "$D/out"'
check "asks Continue? [y/N]"      'grep -qF "Continue? [y/N]" "$D/out"'
check "says nothing deleted"      'grep -q "nothing was deleted" "$D/out"'
check "custom agent intact"       '[ "$(cat "$D/darkmoon-settings/agents/my-custom-agent.md")" = "my private agent" ]'
check "workflows intact"          '[ -f "$D/workflows/custom.yml" ]'
check "stack never touched"       '! grep -qE "compose .*(down|up|build)" "$D/docker.log"'
check "no backup dir"             '[ "$(backups)" = 0 ]'

echo "3. existing install + empty answer (default No): nothing deleted"
new_dir answer_empty; seed_existing
run_tty ""
check "exit non-zero"             '[ "$(cat "$D/rc")" != 0 ]'
check "custom agent intact"       '[ -f "$D/darkmoon-settings/agents/my-custom-agent.md" ]'
check "stack never touched"       '! grep -qE "compose .*(down|up|build)" "$D/docker.log"'

echo "4. existing install + answer y: backup then reinstall"
new_dir answer_y; seed_existing
run_tty y
check "exit 0"                    '[ "$(cat "$D/rc")" = 0 ]'
check "one backup dir"            '[ "$(backups)" = 1 ]'
check "backup holds custom agent" '[ "$(cat "$D"/darkmoon-settings.backup-*/agents/my-custom-agent.md)" = "my private agent" ]'
check "backup holds config"       '[ -f "$(ls -d "$D"/darkmoon-settings.backup-*)/opencode.json" ]'
check "workflows backed up"       'ls "$D"/workflows.backup-*/custom.yml >/dev/null 2>&1'
check "settings purged"           '[ ! -e "$D/darkmoon-settings" ]'
check "backup path announced"     'grep -q "Backup: .*darkmoon-settings.backup-" "$D/out"'
check "backup path printed"       'grep -q "backed up to .*darkmoon-settings.backup-" "$D/out"'
check "stack rebuilt"             'grep -q "rebuilt CLEAN" "$D/out"'
check ".opencode.env kept"        'grep -q "ANTHROPIC_MODEL=test-model" "$D/.opencode.env"'

echo "5. existing install, no terminal, no flag: abort, nothing deleted"
new_dir notty; seed_existing
run_notty
check "exit non-zero"             '[ "$(cat "$D/rc")" != 0 ]'
check "warning shown"             'grep -q "EXISTING DARKMOON INSTALL DETECTED" "$D/out"'
check "explains --yes"            'grep -q "DARKMOON_ASSUME_YES=1" "$D/out"'
check "custom agent intact"       '[ -f "$D/darkmoon-settings/agents/my-custom-agent.md" ]'
check "stack never touched"       '! grep -qE "compose .*(down|up|build)" "$D/docker.log"'
check "no backup dir"             '[ "$(backups)" = 0 ]'

echo "6. existing install, no terminal, --yes: backup + proceed"
new_dir notty_flag; seed_existing
run_notty --yes
check "exit 0"                    '[ "$(cat "$D/rc")" = 0 ]'
check "backup holds custom agent" '[ -f "$(ls -d "$D"/darkmoon-settings.backup-*)/agents/my-custom-agent.md" ]'
check "stack rebuilt"             'grep -q "rebuilt CLEAN" "$D/out"'

echo "7. existing install, no terminal, DARKMOON_ASSUME_YES=1: backup + proceed"
new_dir notty_env; seed_existing
run_notty "" DARKMOON_ASSUME_YES=1
check "exit 0"                    '[ "$(cat "$D/rc")" = 0 ]'
check "backup holds custom agent" '[ -f "$(ls -d "$D"/darkmoon-settings.backup-*)/agents/my-custom-agent.md" ]'
check "stack rebuilt"             'grep -q "rebuilt CLEAN" "$D/out"'

echo ""
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
