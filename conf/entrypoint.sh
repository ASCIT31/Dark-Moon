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
ENV_FILE="/root/.env"
OPENCODE_CONFIG_FILE="/root/.config/opencode/opencode.json"
OPENCODE_AUTH_FILE="/root/.local/share/opencode/auth.json"
APPLY_SCRIPT="/root/conf/apply-settings.sh"

#######################################
# Sanity checks
#######################################
[ -d "$DEFAULT_AGENTS" ] || fatal "Default agents dir missing: $DEFAULT_AGENTS"
[ -f "$ENV_FILE" ] || fatal ".env not found at $ENV_FILE"

#######################################
# Prepare directories (bind-mount safe)
#######################################
log "Preparing directories"
mkdir -p \
  "$AGENTS_DIR" \
  "$(dirname "$OPENCODE_CONFIG_FILE")" \
  "$(dirname "$OPENCODE_AUTH_FILE")"

#######################################
# Apply OpenCode config ONCE
#######################################
if [ ! -f "$OPENCODE_CONFIG_FILE" ]; then
  log "Applying OpenCode configuration"

  set -a
  source "$ENV_FILE"
  set +a

  [ -x "$APPLY_SCRIPT" ] || fatal "Apply script not executable: $APPLY_SCRIPT"

  "$APPLY_SCRIPT" || log "WARN: apply-settings failed (continuing)"
else
  log "OpenCode configuration already present"
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
# Start main process
#######################################
log "Starting main process: $*"
exec "$@"