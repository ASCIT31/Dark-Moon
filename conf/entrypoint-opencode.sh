#!/usr/bin/env bash
set -u
# ⚠️ PAS de set -e global (contrôlé manuellement)

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fatal() {
  log "FATAL: $*"
  exit 1
}

#######################################
# Paths
#######################################
AGENTS_DIR="/root/.opencode/agents"
DEFAULT_AGENTS="/opt/darkmoon/default-agents"
DEFAULT_WORKFLOWS="/opt/darkmoon/default-workflows"
WORKFLOWS_DIR="/opt/darkmoon/mcp/server/src/tools/workflows/"
OPENCODE_CONFIG_FILE="/root/.config/opencode/opencode.json"
OPENCODE_AUTH_FILE="/root/.local/share/opencode/auth.json"
APPLY_SCRIPT="/root/conf/apply-settings.sh"

#######################################
# Sanity checks
#######################################
[ -d "$DEFAULT_AGENTS" ] || fatal "Default agents dir missing: $DEFAULT_AGENTS"

#######################################
# Prepare directories (bind-mount safe)
#######################################
log "Preparing directories"
mkdir -p \
  "$AGENTS_DIR" \
  "$(dirname "$OPENCODE_CONFIG_FILE")" \
  "$(dirname "$OPENCODE_AUTH_FILE")"

#######################################
# Apply OpenCode config (ALWAYS)
#######################################
log "Applying OpenCode configuration (forced)"

log "Runtime environment variables available:"
# Redact secret values (anything whose name contains KEY/TOKEN/SECRET/PASSWORD)
env | grep -E 'OPENROUTER_|OPENCODE_' | sed -E 's/^([^=]*(KEY|TOKEN|SECRET|PASSWORD)[^=]*)=.*/\1=REDACTED/I' || true

[ -x "$APPLY_SCRIPT" ] || fatal "Apply script not executable: $APPLY_SCRIPT"

if ! "$APPLY_SCRIPT"; then
  fatal "apply-settings failed"
fi

#######################################
# Seed agents (VOLUME-SAFE)
#######################################
log "Checking agents directory"

mkdir -p "$AGENTS_DIR"

if [ -z "$(ls -A "$AGENTS_DIR" 2>/dev/null)" ]; then
  log "Agents dir empty → seeding from image"

  if ! cp -a "$DEFAULT_AGENTS/." "$AGENTS_DIR/"; then
    fatal "Failed to seed agents"
  fi

  log "Agents seeded successfully"
else
  log "Agents dir already populated → skip"
fi

#######################################
# Seed workflows (VOLUME-SAFE)
#######################################
log "Checking workflows directory"

mkdir -p "$WORKFLOWS_DIR"

if [ -z "$(ls -A "$WORKFLOWS_DIR" 2>/dev/null)" ]; then
  log "Workflows dir empty → seeding from image"

  if ! cp -a "$DEFAULT_WORKFLOWS/." "$WORKFLOWS_DIR/"; then
    fatal "Failed to seed workflows"
  fi

  log "Workflows seeded successfully"
else
  log "Workflows dir already populated → skip"
fi

#######################################
# Final state summary (debug friendly)
#######################################
log "Final agent directory content:"
ls -la "$AGENTS_DIR"


#######################################
# OpenCode Markdown export watcher
#######################################
#######################################
# Real-time Markdown watcher (inotify)
#######################################

SESSIONS_DIR="/root/.local/share/opencode/sessions"

log "Preparing OpenCode sessions directory"
mkdir -p "$SESSIONS_DIR"

log "Starting real-time Markdown watcher (inotify on /)"

inotifywait -m / \
  -e create -e moved_to -e close_write \
  --format '%w%f' |
while read -r path; do
  file="$(basename "$path")"

  case "$file" in
    *.md) ;;
    *) continue ;;
  esac

  case "$path" in
    /*.md) ;;
    *) continue ;;
  esac

  src="$path"
  dst="$SESSIONS_DIR/$file"

  [ -f "$src" ] || continue

  if [ -f "$dst" ]; then
    ts=$(date '+%Y%m%d-%H%M%S')
    dst="$SESSIONS_DIR/${file%.md}-$ts.md"
  fi

  log "Markdown detected → moving $src → $dst"
  mv -f "$src" "$dst"
done &

#######################################
# Persistent Darkmoon MCP (issue #40, section 3)
#######################################
# Start the darkmoon MCP as a persistent streamable-http server BEFORE opencode,
# so its per-process vault AND the pre-model tokenization socket are up before any
# session. opencode connects to it as a remote MCP (apply-settings.sh writes the
# matching config), which lets the privacy plugin tokenize the launch prompt — and
# the session-title call that precedes the first model turn — with no wait. Set
# DARKMOON_MCP_TRANSPORT=stdio to fall back to per-session stdio spawning.
if [ "${DARKMOON_MCP_TRANSPORT:-http}" != "stdio" ]; then
  export DARKMOON_MCP_TRANSPORT="${DARKMOON_MCP_TRANSPORT:-http}"
  export DARKMOON_MCP_HOST="${DARKMOON_MCP_HOST:-127.0.0.1}"
  export DARKMOON_MCP_PORT="${DARKMOON_MCP_PORT:-8181}"
  export DARKMOON_MCP_PATH="${DARKMOON_MCP_PATH:-/mcp}"
  # Persistent MCP = one long-lived vault shared by every session; give it a long
  # TTL so placeholders minted for a launch prompt still rehydrate into a report
  # generated much later in a long campaign (the vault is in-memory and local-only,
  # and resets on container restart).
  export DARKMOON_PRIVACY_TTL="${DARKMOON_PRIVACY_TTL:-604800}"
  log "Starting persistent Darkmoon MCP (http) on ${DARKMOON_MCP_HOST}:${DARKMOON_MCP_PORT}${DARKMOON_MCP_PATH}"
  /usr/local/bin/darkmoon-mcp >/tmp/darkmoon-mcp-boot.log 2>&1 &
fi

#######################################
# Start main process
#######################################
log "Starting main process: $*"
exec "$@"