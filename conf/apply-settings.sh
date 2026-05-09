#!/usr/bin/env bash
set -euo pipefail

OPENCODE_CONFIG_DIR="/root/.config/opencode"
OPENCODE_CONFIG_FILE="$OPENCODE_CONFIG_DIR/opencode.json"

OPENCODE_AUTH_DIR="/root/.local/share/opencode"
OPENCODE_AUTH_FILE="$OPENCODE_AUTH_DIR/auth.json"

fail() { echo "❌ $*" >&2; exit 1; }
log()  { echo "[INIT] $*" >&2; }

#######################################
# Environment (injected by runtime via .opencode.env)
#######################################

# Cloud provider vars
OPENROUTER_PROVIDER="${OPENROUTER_PROVIDER:-}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
OPENCODE_MODEL="${OPENCODE_MODEL:-}"

# Local provider vars
OPENCODE_LOCAL_MODE="${OPENCODE_LOCAL_MODE:-false}"
OPENCODE_LOCAL_PROVIDER_ID="${OPENCODE_LOCAL_PROVIDER_ID:-}"
OPENCODE_LOCAL_PROVIDER_NAME="${OPENCODE_LOCAL_PROVIDER_NAME:-Local model}"
OPENCODE_LOCAL_BASE_URL="${OPENCODE_LOCAL_BASE_URL:-}"
OPENCODE_LOCAL_MODEL="${OPENCODE_LOCAL_MODEL:-}"

#######################################
# Decide model strategy
# Priority: local > cloud > fallback
#######################################
USE_LOCAL=false
USE_OPENROUTER=false

if [ "${OPENCODE_LOCAL_MODE}" = "true" ] && \
   [ -n "${OPENCODE_LOCAL_PROVIDER_ID:-}" ] && \
   [ -n "${OPENCODE_LOCAL_BASE_URL:-}" ] && \
   [ -n "${OPENCODE_LOCAL_MODEL:-}" ]; then
  USE_LOCAL=true
elif [ -n "${OPENROUTER_PROVIDER:-}" ] && \
     [ -n "${OPENROUTER_API_KEY:-}" ] && \
     [ -n "${OPENCODE_MODEL:-}" ]; then
  USE_OPENROUTER=true
fi

if [ "$USE_LOCAL" = true ]; then
  # Local provider: model string is just the model name (no provider/ prefix)
  FINAL_MODEL="${OPENCODE_LOCAL_PROVIDER_ID}/${OPENCODE_LOCAL_MODEL}"
  log "Using local provider: ${OPENCODE_LOCAL_PROVIDER_NAME} → model: ${FINAL_MODEL}"
  log "Base URL: ${OPENCODE_LOCAL_BASE_URL}"
elif [ "$USE_OPENROUTER" = true ]; then
  FINAL_MODEL="$OPENROUTER_PROVIDER/$OPENCODE_MODEL"
  log "Using cloud provider: $FINAL_MODEL"
else
  FINAL_MODEL="opencode/big-pickle"
  log "No provider configured → fallback to $FINAL_MODEL"
fi

#######################################
# Create directories
#######################################
mkdir -p "$OPENCODE_CONFIG_DIR" "$OPENCODE_AUTH_DIR"

#######################################
# Write opencode.json (ALWAYS)
#######################################

# Build optional provider block for local mode
LOCAL_PROVIDER_BLOCK=""
if [ "$USE_LOCAL" = true ]; then
  LOCAL_PROVIDER_BLOCK=$(cat <<PROVEOF
,

  "provider": {
    "${OPENCODE_LOCAL_PROVIDER_ID}": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "${OPENCODE_LOCAL_PROVIDER_NAME}",
      "options": {
        "baseURL": "${OPENCODE_LOCAL_BASE_URL}"
      },
      "models": {
        "${OPENCODE_LOCAL_MODEL}": {
          "name": "${OPENCODE_LOCAL_MODEL}"
        }
      }
    }
  }
PROVEOF
)
fi

cat > "$OPENCODE_CONFIG_FILE" <<EOF
{
  "\$schema": "https://opencode.ai/config.json"${LOCAL_PROVIDER_BLOCK},

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
    "pentest": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "primary": true,
      "prompt_file": "/root/.opencode/agents/pentest.md"
    },

    "active-directory": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/ad.md"
    },

    "aspnet": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/aspnet.md"
    },

    "python-flask": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/flask.md"
    },

    "graphql": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/graphql.md"
    },

    "headless-browser": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/headless-browser.md"
    },

    "kubernetes": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/kubernetes.md"
    },

    "nest": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/nest.md"
    },

    "php": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/php.md"
    },

    "ruby-on-rails": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/ruby.md"
    },

    "springboot": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/springboot.md"
    },

    "nodejs": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/nodejs-express-angular.md"
    },

    "wordpress": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/wordpress.md"
    },

    "prestashop": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/prestashop.md"
    },

    "moodle": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/moodle.md"
    },

    "magento": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/magento.md"
    },

    "joomla": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/joomla.md"
    },

    "drupal": {
      "model": "$FINAL_MODEL",
      "mcp": ["darkmoon"],
      "secondary": true,
      "prompt_file": "/root/.opencode/agents/drupal.md"
    }
  }
}
EOF

echo "✅ OpenCode config written to $OPENCODE_CONFIG_FILE"

#######################################
# Write auth.json ONLY for cloud providers
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
elif [ "$USE_LOCAL" = true ]; then
  rm -f "$OPENCODE_AUTH_FILE"
  log "Local provider — no auth.json needed"
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
