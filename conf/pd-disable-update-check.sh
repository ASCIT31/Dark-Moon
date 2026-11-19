#!/bin/bash
# =============================================================================
# ProjectDiscovery tools: no update check (pentest O2, 03/11/2026)
# =============================================================================
# naabu, httpx, nuclei, subfinder, katana... call https://api.pdtm.sh at every run
# to compare their version (nuclei also checks its templates). From a pentest
# toolbox that is a call to a third party the operator did not ask for, which
# also tells it when and from where a scan runs. The agents' prompts pass -duc
# in some places only; this turns the check off for EVERY invocation, whatever
# the flags: each tool reads ~/.config/<tool>/config.yaml (goflags) where a long
# flag name is a key. Only tools that do have the flag get the key, an existing
# config (nuclei ships one) is appended to, never replaced. Idempotent: run at
# build time (Dockerfile) and again at container start (entrypoint), so a /root
# volume or a newer tool keeps it.
# =============================================================================
set -u
CONF_HOME="${XDG_CONFIG_HOME:-${HOME:-/root}/.config}"
TOOLS="${PD_TOOLS:-naabu httpx nuclei subfinder katana dnsx tlsx uncover cdncheck asnmap alterx shuffledns mapcidr interactsh-client notify cvemap vulnx chaos}"
for t in $TOOLS; do
    bin="/usr/local/bin/$t"            # never the python httpx CLI that shadows it on PATH
    [ -x "$bin" ] || bin="$(command -v "$t" 2>/dev/null)" || continue
    [ -n "$bin" ] || continue
    timeout 15 "$bin" -h 2>&1 | grep -q -- '-disable-update-check' || continue
    cfg="$CONF_HOME/$t/config.yaml"
    mkdir -p "$(dirname "$cfg")" 2>/dev/null || continue
    if ! grep -qE '^[[:space:]]*disable-update-check:' "$cfg" 2>/dev/null; then
        [ -s "$cfg" ] && [ -n "$(tail -c1 "$cfg")" ] && echo >> "$cfg"
        echo "disable-update-check: true" >> "$cfg" 2>/dev/null || continue
    fi
    echo "[PD] $t: update check disabled ($cfg)"
done
exit 0
