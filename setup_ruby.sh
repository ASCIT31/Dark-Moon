#!/usr/bin/env bash
set -euo pipefail

msg(){ echo "[*] $*"; }
ok(){ echo "[OK] $*"; }

RUBY_PREFIX="/opt/darkmoon/ruby"
RUBY_BIN="$RUBY_PREFIX/bin/ruby"
GEM_BIN="$RUBY_PREFIX/bin/gem"
BUNDLE_BIN="$RUBY_PREFIX/bin/bundle"
BIN_OUT="/out/bin"


# whatweb
msg "Installing WhatWeb (Ruby)…"

WHATWEB_DIR="/opt/darkmoon/whatweb"
git clone --depth=1 https://github.com/urbanadventurer/WhatWeb "$WHATWEB_DIR"

# Validation que le fichier principal existe
test -f "$WHATWEB_DIR/whatweb" || { echo "ERROR: whatweb script not found in $WHATWEB_DIR"; exit 1; }

# Bundler
"$GEM_BIN" install bundler --no-document

cd "$WHATWEB_DIR"
"$BUNDLE_BIN" install

# wrapper
cat >"$BIN_OUT/whatweb" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/ruby/bin/ruby /opt/darkmoon/whatweb/whatweb "$@"
EOF
chmod +x "$BIN_OUT/whatweb"

# Vérification finale
test -x "$BIN_OUT/whatweb" || { echo "ERROR: whatweb wrapper not created"; exit 1; }

ok "WhatWeb installed"

# ------------------------------------------------------------
# WPScan — DOC OFFICIELLE: gem install
# ------------------------------------------------------------
msg "Installing WPScan (Ruby)…"

"$GEM_BIN" install wpscan --no-document

# wrapper
cat >"$BIN_OUT/wpscan" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/ruby/bin/wpscan "$@"
EOF
chmod +x "$BIN_OUT/wpscan"

test -x "$BIN_OUT/wpscan" || { echo "ERROR: wpscan wrapper not created"; exit 1; }

ok "WPScan installed"