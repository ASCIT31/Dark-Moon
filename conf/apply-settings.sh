#!/usr/bin/env bash
set -euo pipefail

OPENCODE_CONFIG_DIR="/root/.config/opencode"
OPENCODE_CONFIG_FILE="$OPENCODE_CONFIG_DIR/opencode.json"
# Darkmoon agent registry (agent id -> agent file), read by the orchestrator; written below
DARKMOON_AGENTS_FILE="$OPENCODE_CONFIG_DIR/darkmoon-agents.json"

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
OPENCODE_LOCAL_API_KEY="${OPENCODE_LOCAL_API_KEY:-}"
# AI SDK adapter of the local / custom provider. Default: the generic OpenAI-compatible adapter (chat/completions with
# max_tokens), right for Ollama, llama.cpp, vLLM, LiteLLM... OpenAI reasoning models reject max_tokens and need the
# OpenAI adapter (Responses API, max_output_tokens). Azure endpoints get the native Azure mode below without this
# setting; OPENCODE_LOCAL_NPM=@ai-sdk/openai remains for OpenAI's own API or an OpenAI-native proxy serving reasoning
# models through the custom-URL provider. Only adapters bundled in the opencode binary are accepted (nothing is fetched).
OPENCODE_LOCAL_NPM="${OPENCODE_LOCAL_NPM:-}"
# A local / custom URL on Azure (*.openai.azure.com, *.services.ai.azure.com, *.cognitiveservices.azure.com) is turned
# into the native Azure mode; OPENCODE_LOCAL_AZURE_NATIVE=false keeps it on the generic adapter.
OPENCODE_LOCAL_AZURE_NATIVE="${OPENCODE_LOCAL_AZURE_NATIVE:-true}"

# Azure AI Foundry / Azure OpenAI, native mode: opencode's built-in "azure" provider (@ai-sdk/azure, Responses API).
# AZURE_RESOURCE_NAME and AZURE_API_KEY are opencode's own variables; AZURE_MODEL is the deployment name.
# AZURE_USE_COMPLETION_URLS=true sends chat/completions instead, for a deployment that does not serve the Responses API.
AZURE_RESOURCE_NAME="${AZURE_RESOURCE_NAME:-}"
AZURE_API_KEY="${AZURE_API_KEY:-}"
AZURE_MODEL="${AZURE_MODEL:-}"
AZURE_USE_COMPLETION_URLS="${AZURE_USE_COMPLETION_URLS:-false}"
AZURE_KEY_ENV="AZURE_API_KEY"

# On-prem Anthropic-compatible vars (opencode reads ANTHROPIC_BASE_URL / ANTHROPIC_API_KEY from env)
ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-}"
ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-}"

#######################################
# Decide model strategy
# Priority: local > anthropic > cloud > fallback
#######################################
USE_AZURE=false
USE_LOCAL=false
USE_ANTHROPIC=false
USE_OPENROUTER=false

# Native Azure mode, explicit (AZURE_*) or from a local / custom URL that is an Azure resource endpoint. The generic
# OpenAI-compatible adapter fails there: it sends max_tokens, which OpenAI reasoning deployments reject.
_azure_resource_of(){  # <url> -> resource name when the host is an Azure resource endpoint, else nothing
  local h="${1#*://}"; h="${h%%/*}"; h="${h%%:*}"; h="$(printf '%s' "$h" | tr 'A-Z' 'a-z')"
  case "$h" in
    *.openai.azure.com|*.services.ai.azure.com|*.cognitiveservices.azure.com)
      local r="${h%%.*}"; [[ "$r" =~ ^[a-z0-9][a-z0-9-]*$ ]] && printf '%s' "$r" ;;
  esac
}
if [ -n "${AZURE_RESOURCE_NAME}" ] && [ -n "${AZURE_MODEL}" ]; then
  # both are written into opencode.json: plain names only (no quote, backslash or space can reach the JSON)
  if [[ "${AZURE_RESOURCE_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] && [[ "${AZURE_MODEL}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]; then
    USE_AZURE=true
  else
    log "WARNING: AZURE_RESOURCE_NAME / AZURE_MODEL must be plain names (letters, digits, - . _ :) -- Azure mode not applied"
  fi
elif [ "${OPENCODE_LOCAL_MODE}" = "true" ] && [ "${OPENCODE_LOCAL_AZURE_NATIVE}" != "false" ] && \
     [[ "${OPENCODE_LOCAL_MODEL:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] && [ -n "$(_azure_resource_of "${OPENCODE_LOCAL_BASE_URL:-}")" ]; then
  USE_AZURE=true
  AZURE_RESOURCE_NAME="$(_azure_resource_of "${OPENCODE_LOCAL_BASE_URL}")"
  AZURE_MODEL="${OPENCODE_LOCAL_MODEL}"
  [ -n "${AZURE_API_KEY}" ] || AZURE_KEY_ENV="OPENCODE_LOCAL_API_KEY"
  log "Local provider URL is an Azure resource endpoint: using the native Azure provider (OPENCODE_LOCAL_AZURE_NATIVE=false to keep the generic adapter)"
fi

if [ "$USE_AZURE" = true ]; then
  :
elif [ "${OPENCODE_LOCAL_MODE}" = "true" ] && \
   [ -n "${OPENCODE_LOCAL_PROVIDER_ID:-}" ] && \
   [ -n "${OPENCODE_LOCAL_BASE_URL:-}" ] && \
   [ -n "${OPENCODE_LOCAL_MODEL:-}" ]; then
  USE_LOCAL=true
elif [ -n "${ANTHROPIC_BASE_URL:-}" ] && [ -n "${ANTHROPIC_MODEL:-}" ]; then
  USE_ANTHROPIC=true
elif [ -n "${OPENROUTER_PROVIDER:-}" ] && \
     [ -n "${OPENROUTER_API_KEY:-}" ] && \
     [ -n "${OPENCODE_MODEL:-}" ]; then
  USE_OPENROUTER=true
fi

if [ "$USE_AZURE" = true ]; then
  FINAL_MODEL="azure/${AZURE_MODEL}"
  log "Using Azure provider (native): resource ${AZURE_RESOURCE_NAME} → model: ${FINAL_MODEL}"
  [ "${AZURE_USE_COMPLETION_URLS}" = "true" ] && log "Azure: chat/completions API (AZURE_USE_COMPLETION_URLS=true)"
elif [ "$USE_LOCAL" = true ]; then
  # Local provider: model string is just the model name (no provider/ prefix)
  FINAL_MODEL="${OPENCODE_LOCAL_PROVIDER_ID}/${OPENCODE_LOCAL_MODEL}"
  log "Using local provider: ${OPENCODE_LOCAL_PROVIDER_NAME} → model: ${FINAL_MODEL}"
  log "Base URL: ${OPENCODE_LOCAL_BASE_URL}"
  case "${OPENCODE_LOCAL_NPM}" in
    ""|@ai-sdk/openai-compatible) OPENCODE_LOCAL_NPM="@ai-sdk/openai-compatible" ;;
    @ai-sdk/openai) log "Local provider adapter: ${OPENCODE_LOCAL_NPM}" ;;
    *) log "WARNING: OPENCODE_LOCAL_NPM='${OPENCODE_LOCAL_NPM}' is not supported (use @ai-sdk/openai-compatible or @ai-sdk/openai; for Azure, use the native Azure mode: AZURE_RESOURCE_NAME + AZURE_API_KEY + AZURE_MODEL) -- falling back to @ai-sdk/openai-compatible"
       OPENCODE_LOCAL_NPM="@ai-sdk/openai-compatible" ;;
  esac
  # Cache-health guard: an openai-compatible local provider pointed at an Anthropic
  # endpoint silently disables prompt caching (the cache_control marker is sent in
  # OpenAI form, which Anthropic's OpenAI-compat endpoint ignores -> up to 50-90%
  # higher input cost). Warn and point at the native-provider fix.
  case "${OPENCODE_LOCAL_BASE_URL}" in
    *anthropic*)
      log "WARNING: local provider targets an Anthropic endpoint via the OpenAI-compatible SDK -- Anthropic prompt caching is DISABLED. For caching, use the native anthropic provider: set OPENCODE_LOCAL_MODE=false + ANTHROPIC_BASE_URL + ANTHROPIC_MODEL." ;;
  esac
elif [ "$USE_ANTHROPIC" = true ]; then
  # On-prem Anthropic-compatible: opencode routes via ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY (env)
  FINAL_MODEL="anthropic/${ANTHROPIC_MODEL}"
  log "Using on-prem Anthropic-compatible endpoint → model: ${FINAL_MODEL}"
  log "Base URL: ${ANTHROPIC_BASE_URL}"
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

# Build optional provider block.
# - azure mode  : configures opencode's built-in "azure" provider (no npm to resolve).
# - local mode  : declares a full OpenAI-compatible provider.
# - anthropic   : registers the custom model id under the built-in "anthropic"
#                 provider, otherwise opencode validates the configured model
#                 against its hard-coded catalogue and rejects it with
#                 ProviderModelNotFoundError.
PROVIDER_BLOCK=""
if [ "$USE_AZURE" = true ]; then
  # The key is referenced, never written: opencode resolves {env:…} at load time from its own environment
  # (.opencode.env), so opencode.json never holds it.
  AZURE_MODEL_OPTIONS=""
  [ "${AZURE_USE_COMPLETION_URLS}" = "true" ] && AZURE_MODEL_OPTIONS=$(printf ',\n          "options": { "useCompletionUrls": true }')
  PROVIDER_BLOCK=$(cat <<PROVEOF
,

  "provider": {
    "azure": {
      "options": {
        "resourceName": "${AZURE_RESOURCE_NAME}",
        "apiKey": "{env:${AZURE_KEY_ENV}}"
      },
      "models": {
        "${AZURE_MODEL}": {
          "name": "${AZURE_MODEL}"${AZURE_MODEL_OPTIONS}
        }
      }
    }
  }
PROVEOF
)
elif [ "$USE_LOCAL" = true ]; then
  # Optional API key for authenticated OpenAI-compatible endpoints (Bearer auth).
  # JSON-escaped via python3 so keys containing quotes/backslashes can't break the config.
  LOCAL_API_KEY_OPTION=""
  if [ -n "${OPENCODE_LOCAL_API_KEY:-}" ]; then
    LOCAL_API_KEY_OPTION=$(OPENCODE_LOCAL_API_KEY="$OPENCODE_LOCAL_API_KEY" python3 -c 'import json,os; print(",\n        \"apiKey\": " + json.dumps(os.environ["OPENCODE_LOCAL_API_KEY"]))')
  fi
  PROVIDER_BLOCK=$(cat <<PROVEOF
,

  "provider": {
    "${OPENCODE_LOCAL_PROVIDER_ID}": {
      "npm": "${OPENCODE_LOCAL_NPM}",
      "name": "${OPENCODE_LOCAL_PROVIDER_NAME}",
      "options": {
        "baseURL": "${OPENCODE_LOCAL_BASE_URL}"${LOCAL_API_KEY_OPTION}
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
elif [ "$USE_ANTHROPIC" = true ]; then
  PROVIDER_BLOCK=$(cat <<PROVEOF
,

  "provider": {
    "anthropic": {
      "models": {
        "${ANTHROPIC_MODEL}": {
          "name": "${ANTHROPIC_MODEL}"
        }
      }
    }
  }
PROVEOF
)
fi

# Darkmoon MCP wiring (issue #40, section 3). By default the MCP runs as a
# PERSISTENT streamable-http server started at boot (entrypoint), so opencode
# connects to it as a remote MCP and the privacy plugin can reach its vault
# before the first prompt. DARKMOON_MCP_TRANSPORT=stdio keeps the old per-session
# local spawn.
if [ "${DARKMOON_MCP_TRANSPORT:-http}" = "stdio" ]; then
  MCP_DARKMOON='"darkmoon": { "type": "local", "command": ["/usr/local/bin/darkmoon-mcp"], "timeout": 36000000, "enabled": true }'
else
  _DM_MCP_URL="http://${DARKMOON_MCP_HOST:-127.0.0.1}:${DARKMOON_MCP_PORT:-8181}${DARKMOON_MCP_PATH:-/mcp}"
  MCP_DARKMOON="\"darkmoon\": { \"type\": \"remote\", \"url\": \"${_DM_MCP_URL}\", \"enabled\": true }"
fi

cat > "$OPENCODE_CONFIG_FILE" <<EOF
{
  "\$schema": "https://opencode.ai/config.json"${PROVIDER_BLOCK},

  "model": "$FINAL_MODEL",
  "small_model": "$FINAL_MODEL",

  "mcp": {
    ${MCP_DARKMOON}
  },

  "plugin": ["file:///opt/darkmoon/plugins/darkmoon-privacy.ts", "file:///opt/darkmoon/plugins/darkmoon-growth-cta.ts"],

  "permission": { "*": "allow" },

  "agent": {
    "pentest": {
      "model": "$FINAL_MODEL",
      "mode": "primary"
    },

    "aws": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "azure": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "entra-id": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "gcp": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "github": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "gitlab": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "jenkins": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "terraform": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "ansible": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "docker": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "container-registry": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "hashicorp-vault": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "sql-databases": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "messaging-cache": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },
    "firmware": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "sso-idp": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "gitops": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "observability": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "storage": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "edge-proxy": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "vpn-remote-access": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "firewall-network": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "email-infrastructure": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "backup": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "pki-adcs": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "nosql-databases": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "container-platform": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "hypervisor": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "business-platforms": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "mobile": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "mdm": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "active-directory": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "aspnet": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "python-flask": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "graphql": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "llm": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "golang": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "headless-browser": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "kubernetes": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "nest": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "php": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "ruby-on-rails": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "springboot": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "nodejs": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "wordpress": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "prestashop": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "moodle": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "magento": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "joomla": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    },

    "drupal": {
      "model": "$FINAL_MODEL",
      "mode": "subagent"
    }
  }
}
EOF

echo "✅ OpenCode config written to $OPENCODE_CONFIG_FILE"

# Darkmoon agent registry: which file holds each agent's playbook. The orchestrator (pentest.md, PHASES 1 and 6) reads
# it to enumerate the agents and to inline the right file when it dispatches one; the agent id and the file name differ
# for some agents (active-directory -> ad.md, nodejs -> nodejs-express-angular.md, ...). It is Darkmoon's own data, so it
# lives here and never in opencode.json: opencode keeps every unknown key of an agent block as a model call option, and
# strict OpenAI-compatible endpoints (Azure AI Foundry) reject the request ("Unrecognized request argument supplied").
# opencode itself loads the same files natively from /root/.opencode/agents. Same agent set as the "agent" map above
# (mcp/tests/test_agent_native_keys.py).
cat > "$DARKMOON_AGENTS_FILE" <<'REGEOF'
{
  "agents": {
    "pentest": { "prompt_file": "/root/.opencode/agents/pentest.md" },
    "aws": { "prompt_file": "/root/.opencode/agents/aws.md" },
    "azure": { "prompt_file": "/root/.opencode/agents/azure.md" },
    "entra-id": { "prompt_file": "/root/.opencode/agents/entra-id.md" },
    "gcp": { "prompt_file": "/root/.opencode/agents/gcp.md" },
    "github": { "prompt_file": "/root/.opencode/agents/github.md" },
    "gitlab": { "prompt_file": "/root/.opencode/agents/gitlab.md" },
    "jenkins": { "prompt_file": "/root/.opencode/agents/jenkins.md" },
    "terraform": { "prompt_file": "/root/.opencode/agents/terraform.md" },
    "ansible": { "prompt_file": "/root/.opencode/agents/ansible.md" },
    "docker": { "prompt_file": "/root/.opencode/agents/docker.md" },
    "container-registry": { "prompt_file": "/root/.opencode/agents/container-registry.md" },
    "hashicorp-vault": { "prompt_file": "/root/.opencode/agents/hashicorp-vault.md" },
    "sql-databases": { "prompt_file": "/root/.opencode/agents/sql-databases.md" },
    "messaging-cache": { "prompt_file": "/root/.opencode/agents/messaging-cache.md" },
    "firmware": { "prompt_file": "/root/.opencode/agents/firmware.md" },
    "sso-idp": { "prompt_file": "/root/.opencode/agents/sso-idp.md" },
    "gitops": { "prompt_file": "/root/.opencode/agents/gitops.md" },
    "observability": { "prompt_file": "/root/.opencode/agents/observability.md" },
    "storage": { "prompt_file": "/root/.opencode/agents/storage.md" },
    "edge-proxy": { "prompt_file": "/root/.opencode/agents/edge-proxy.md" },
    "vpn-remote-access": { "prompt_file": "/root/.opencode/agents/vpn-remote-access.md" },
    "firewall-network": { "prompt_file": "/root/.opencode/agents/firewall-network.md" },
    "email-infrastructure": { "prompt_file": "/root/.opencode/agents/email-infrastructure.md" },
    "backup": { "prompt_file": "/root/.opencode/agents/backup.md" },
    "pki-adcs": { "prompt_file": "/root/.opencode/agents/pki-adcs.md" },
    "nosql-databases": { "prompt_file": "/root/.opencode/agents/nosql-databases.md" },
    "container-platform": { "prompt_file": "/root/.opencode/agents/container-platform.md" },
    "hypervisor": { "prompt_file": "/root/.opencode/agents/hypervisor.md" },
    "business-platforms": { "prompt_file": "/root/.opencode/agents/business-platforms.md" },
    "mobile": { "prompt_file": "/root/.opencode/agents/mobile.md" },
    "mdm": { "prompt_file": "/root/.opencode/agents/mdm.md" },
    "active-directory": { "prompt_file": "/root/.opencode/agents/ad.md" },
    "aspnet": { "prompt_file": "/root/.opencode/agents/aspnet.md" },
    "python-flask": { "prompt_file": "/root/.opencode/agents/flask.md" },
    "graphql": { "prompt_file": "/root/.opencode/agents/graphql.md" },
    "llm": { "prompt_file": "/root/.opencode/agents/llm.md" },
    "golang": { "prompt_file": "/root/.opencode/agents/golang.md" },
    "headless-browser": { "prompt_file": "/root/.opencode/agents/headless-browser.md" },
    "kubernetes": { "prompt_file": "/root/.opencode/agents/kubernetes.md" },
    "nest": { "prompt_file": "/root/.opencode/agents/nest.md" },
    "php": { "prompt_file": "/root/.opencode/agents/php.md" },
    "ruby-on-rails": { "prompt_file": "/root/.opencode/agents/ruby.md" },
    "springboot": { "prompt_file": "/root/.opencode/agents/springboot.md" },
    "nodejs": { "prompt_file": "/root/.opencode/agents/nodejs-express-angular.md" },
    "wordpress": { "prompt_file": "/root/.opencode/agents/wordpress.md" },
    "prestashop": { "prompt_file": "/root/.opencode/agents/prestashop.md" },
    "moodle": { "prompt_file": "/root/.opencode/agents/moodle.md" },
    "magento": { "prompt_file": "/root/.opencode/agents/magento.md" },
    "joomla": { "prompt_file": "/root/.opencode/agents/joomla.md" },
    "drupal": { "prompt_file": "/root/.opencode/agents/drupal.md" }
  }
}
REGEOF

# TUI config (opencode >= 1.19): the Darkmoon Terminal Explorer, a read-only TUI plugin that browses the local
# projects, campaigns, findings, reports and attack paths (/explore; no model call). Community reads the local
# store through darkmoon_explore.py; evidence is masked before display, or withheld if it cannot be masked.
cat > "$OPENCODE_CONFIG_DIR/tui.json" <<'TUIEOF'
{
  "$schema": "https://opencode.ai/tui.json",
  "plugin": [["file:///opt/darkmoon/plugins/darkmoon-explorer/index.tsx",
              {"source": "files", "data": "/root/.local/share/opencode", "reports": "/root/.local/share/opencode/reports"}]]
}
TUIEOF

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
elif [ "$USE_AZURE" = true ]; then
  rm -f "$OPENCODE_AUTH_FILE"
  log "Azure provider — key read from the environment, no auth.json needed"
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
