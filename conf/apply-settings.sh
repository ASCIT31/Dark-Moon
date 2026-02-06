#!/usr/bin/env bash
set -euo pipefail

OPENCODE_CONFIG_DIR="/root/.config/opencode"
OPENCODE_CONFIG_FILE="$OPENCODE_CONFIG_DIR/opencode.json"

OPENCODE_AUTH_DIR="/root/.local/share/opencode"
OPENCODE_AUTH_FILE="$OPENCODE_AUTH_DIR/auth.json"

fail() { echo "❌ $*" >&2; exit 1; }
log()  { echo "[INIT] $*" >&2; }

#######################################
# Environment (injected by runtime)
#######################################
OPENROUTER_PROVIDER="${OPENROUTER_PROVIDER:-}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
OPENCODE_MODEL="${OPENCODE_MODEL:-}"


#######################################
# Decide model strategy (OpenRouter vs fallback)
#######################################
USE_OPENROUTER=true

if [ -z "${OPENROUTER_PROVIDER:-}" ] || \
   [ -z "${OPENROUTER_API_KEY:-}" ] || \
   [ -z "${OPENCODE_MODEL:-}" ]; then
  USE_OPENROUTER=false
fi

if [ "$USE_OPENROUTER" = true ]; then
  FINAL_MODEL="$OPENROUTER_PROVIDER/$OPENCODE_MODEL"
  log "Using OpenRouter model: $FINAL_MODEL"
else
  FINAL_MODEL="opencode/big-pickle"
  log "OpenRouter vars missing → fallback to $FINAL_MODEL"
fi

#######################################
# Create directories
#######################################
mkdir -p "$OPENCODE_CONFIG_DIR" "$OPENCODE_AUTH_DIR"

#######################################
# Write opencode.json (ALWAYS)
#######################################
cat > "$OPENCODE_CONFIG_FILE" <<EOF
{
  "\$schema": "https://opencode.ai/config.json",

  "mcp": {
    "darkmoon": {
      "type": "local",
      "command": ["/usr/local/bin/darkmoon-mcp"],
      "timeout": 36000000,
      "enabled": true
    }
  },

  "permission": { "*": "allow" },

  "agent": {
    "pentest-web": {
      "mode": "primary",
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "prompt_file": "/root/.opencode/agents/pentest-web.md"
    }
  }
}
EOF

echo "✅ OpenCode config written to $OPENCODE_CONFIG_FILE"

#######################################
# Write auth.json ONLY if OpenRouter is used
#######################################
if [ "$USE_OPENROUTER" = true ]; then
  cat > "$OPENCODE_AUTH_FILE" <<EOF
{
  "$OPENROUTER_PROVIDER": {
    "type": "api",
    "key": "$OPENROUTER_API_KEY"
  }
}
EOF
  echo "✅ OpenCode auth written to $OPENCODE_AUTH_FILE"
else
  rm -f "$OPENCODE_AUTH_FILE"
  log "No auth.json written (fallback model does not require API key)"
fi

#######################################
# Optional warmup (SAFE, NON BLOCKING)
#######################################

#######################################
# Optional opencode TUI bootstrap (TEST — NO KILL)
#######################################

log "Optional opencode TUI bootstrap (test mode, no kill)"

if command -v /usr/local/bin/opencode >/dev/null 2>&1; then
  (
    # Lancer opencode dans un vrai pseudo-TTY
    script -q -c "/usr/local/bin/opencode --model \"$FINAL_MODEL\"" /dev/null &
    OPENCODE_PID=$!

    log "opencode TUI started in background (pid=$OPENCODE_PID)"
    log "NOT killing it — test mode"
  ) &
fi

log "Warmup finished (script continues)"
