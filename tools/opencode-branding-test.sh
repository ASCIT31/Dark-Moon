#!/usr/bin/env bash
#
# opencode-branding-test.sh — assert the Darkmoon branding we require in the TUI
# and the head-less CLI of a built opencode binary.
#
# WHY THIS EXISTS: Darkmoon ships a thin fork of opencode whose ONLY source
# patch is branding — the logo art in packages/opencode/src/cli/logo.ts (the
# single module imported by BOTH the head-less banner `cli/ui.ts` and the TUI
# component `cli/cmd/tui/component/logo.tsx`) and the OPENCODE_VERSION env.
# Every time we re-sync the fork with upstream, those surfaces can silently
# regress to stock "opencode" branding. This test is the contract: run it after
# each sync/build (locally or in CI) and it fails loudly if the binary does not
# show what we want. It is written so another engineer or AI agent can see,
# from the assertions alone, exactly what the TUI/CLI must display.
#
# The "what we want" art is read FROM conf/tui/logo.ts (the source of truth we
# inject), so changing the logo there updates the test automatically — no magic
# strings to keep in sync.
#
# Usage:
#   tools/opencode-branding-test.sh <path-to-opencode-binary>
#   tools/opencode-branding-test.sh --image <docker-image>     # extracts /usr/local/bin/opencode (or /opencode-bin)
#   tools/opencode-branding-test.sh                            # defaults to the opencode in the running stack
#
# Exit 0 = branding correct; 1 = a branding assertion failed.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LOGO_TS="$REPO/conf/tui/logo.ts"

fail=0
ok()   { printf '  [OK]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail+1)); }
strip_ansi() { sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g'; }

# ---- resolve the binary to test -------------------------------------------
BIN=""
TMPBIN=""
cleanup() { [ -n "$TMPBIN" ] && rm -f "$TMPBIN"; }
trap cleanup EXIT

if [ "${1:-}" = "--image" ]; then
  IMG="${2:?--image needs an image name}"
  TMPBIN="$(mktemp)"
  cid="$(docker create "$IMG")"
  docker cp "$cid:/opencode-bin" "$TMPBIN" 2>/dev/null \
    || docker cp "$cid:/usr/local/bin/opencode" "$TMPBIN" 2>/dev/null
  docker rm -f "$cid" >/dev/null 2>&1 || true
  chmod +x "$TMPBIN"; BIN="$TMPBIN"
elif [ -n "${1:-}" ]; then
  BIN="$1"
else
  # default: the opencode binary inside the running stack
  if docker exec opencode test -x /usr/local/bin/opencode 2>/dev/null; then
    TMPBIN="$(mktemp)"
    docker cp opencode:/usr/local/bin/opencode "$TMPBIN" >/dev/null 2>&1
    chmod +x "$TMPBIN"; BIN="$TMPBIN"
  fi
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "no runnable opencode binary found (arg / --image / running stack)"; exit 1; }
[ -f "$LOGO_TS" ] || { echo "logo source of truth not found: $LOGO_TS"; exit 1; }

echo "== opencode branding contract =="
echo "   binary: $BIN"
echo "   logo  : $LOGO_TS"

# ---- derive the REQUIRED art from the injected logo.ts (source of truth) ---
# The art rows are the backtick-delimited strings that contain the block glyph █
# (this skips backtick tokens in the header comment such as `logo`/`go`/`marks`).
# logo.left[] renders first, logo.right[] second; row 1 of each is distinctive.
_art_rows="$(grep -oP '(?<=`)[^`]*█[^`]*(?=`)' "$LOGO_TS")"
want_left="$(printf '%s\n' "$_art_rows" | sed -n '1p')"
n_left="$(printf '%s\n' "$_art_rows" | grep -c '█')"
# right-side art begins after the left block; assume equal halves, else fall back to the last row.
want_right="$(printf '%s\n' "$_art_rows" | sed -n "$(( n_left/2 + 1 ))p")"
# stock opencode art line that MUST NOT survive branding
STOCK_ART='█▀▀█ █▀▀█ █▀▀█ █▀▀▄'

# ---- 1) version must be the Darkmoon version -------------------------------
ver="$("$BIN" --version 2>/dev/null | strip_ansi | tr -d '[:space:]')"
case "$ver" in
  opencode-darkmoon-*) ok "CLI --version is Darkmoon-branded ($ver)" ;;
  *) bad "CLI --version is NOT Darkmoon-branded (got '${ver:-<empty>}', want opencode-darkmoon-*)" ;;
esac

# ---- 2) the head-less banner (shown via `--help` usage) must be our logo ----
help_out="$("$BIN" --help 2>&1 | strip_ansi)"
if [ -n "$want_left" ] && printf '%s' "$help_out" | grep -qF "$want_left"; then
  ok "CLI --help shows the Darkmoon logo (left art present)"
else
  bad "CLI --help is missing the Darkmoon logo (left art absent)"
fi
if [ -n "$want_right" ] && printf '%s' "$help_out" | grep -qF "$want_right"; then
  ok "CLI --help shows the Darkmoon logo (right art present)"
else
  bad "CLI --help is missing the Darkmoon logo (right art absent)"
fi
if printf '%s' "$help_out" | grep -qF "$STOCK_ART"; then
  bad "CLI --help still shows the STOCK opencode logo — branding did not apply"
else
  ok "CLI --help does not show the stock opencode logo"
fi

# ---- 3) TUI path -----------------------------------------------------------
# NOTE: we do NOT grep the binary. `bun build --compile` embeds the JS graph in
# a compressed form, so neither the DarkMoon nor the stock art appears as raw
# bytes — a binary grep gives false negatives (and false "absent" positives).
# The `--help` banner above is rendered by cli/ui.ts from the compiled
# packages/opencode/src/cli/logo.ts, which is the SAME module the TUI component
# (cli/cmd/tui/component/logo.tsx) imports. So a correct `--help` banner proves
# the TUI logo is DarkMoon too; there is no separate TUI assertion to make.

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: PASS — TUI & CLI branding is Darkmoon."; exit 0
else echo "RESULT: FAIL — $fail branding assertion(s) broken (re-check Dockerfile.opencode logo injection after the fork sync)."; exit 1; fi
