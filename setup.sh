#!/usr/bin/env bash
# --- PROLOGUE OBLIGATOIRE ---
export GOPROXY=direct
export GOSUMDB=off
set -euo pipefail
# Empêche le téléchargement auto d'un toolchain Go différent
export GOTOOLCHAIN=local
# Evite les warnings/erreurs "buildvcs"
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

# Où déposer les binaires buildés
export BIN_OUT="${BIN_OUT:-/out/bin}"
mkdir -p "$BIN_OUT"

# Helpers utilisés plus bas
msg(){ echo "[*] $*"; }
ok(){  echo "[OK] $*"; }
warn(){ echo "[WARN] $*" >&2; }

# Installe les deps build C/libpcap si nécessaire
ensure_build_deps() {
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcap; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    msg "Installation des deps build (libpcap-dev, gcc, pkg-config)…"
    apt-get update -y
    apt-get install -y --no-install-recommends libpcap-dev pkg-config gcc
    rm -rf /var/lib/apt/lists/*
  else
    warn "libpcap headers introuvables et pas d'apt-get. Installe libpcap-dev/gcc/pkg-config dans l'image."
  fi
}

ensure_build_deps

# 1) ---- kubeletctl — DOC OFFICIELLE: binary release ---- 
msg "kubeletctl …"

KUBELETCTL_VERSION="v1.13"
KUBELETCTL_URL="https://github.com/cyberark/kubeletctl/releases/download/${KUBELETCTL_VERSION}/kubeletctl_linux_amd64"
TMP_KUBELETCTL="/tmp/kubeletctl"

curl -fsSL "$KUBELETCTL_URL" -o "$TMP_KUBELETCTL"
chmod +x "$TMP_KUBELETCTL"

if "$TMP_KUBELETCTL" version >/dev/null 2>&1 || "$TMP_KUBELETCTL" help >/dev/null 2>&1; then
  install -D -m0755 "$TMP_KUBELETCTL" "$BIN_OUT/kubeletctl"
  ok "kubeletctl install (${KUBELETCTL_VERSION})"
else
  warn "kubeletctl KO (binaire invalide)"
fi

rm -f "$TMP_KUBELETCTL"


# 2) ---- kubescape — DOC OFFICIELLE: install.sh ----
msg "kubescape …"

KUBESCAPE_VERSION="v3.0.9"
curl -fsSL \
  "https://github.com/kubescape/kubescape/releases/download/${KUBESCAPE_VERSION}/kubescape-ubuntu-latest" \
  -o /tmp/kubescape

chmod +x /tmp/kubescape
install -D -m0755 /tmp/kubescape "$BIN_OUT/kubescape"

ok "kubescape ${KUBESCAPE_VERSION}"

# kubectl-who-can

msg "kubectl-who-can …"

go install github.com/aquasecurity/kubectl-who-can/cmd/kubectl-who-can@latest

WHOCAN_BIN="$(go env GOPATH)/bin/kubectl-who-can"
if [ -x "$WHOCAN_BIN" ]; then
  install -D -m0755 "$WHOCAN_BIN" "$BIN_OUT/kubectl-who-can"
  ok "kubectl-who-can install"
else
  warn "kubectl-who-can KO"
fi

# 3) ---- rbac-police — DOC OFFICIELLE: go install ----
msg "rbac-police …"

GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/PaloAltoNetworks/rbac-police@latest

RBAC_POLICE_BIN="$(go env GOPATH)/bin/rbac-police"
if [ -x "$RBAC_POLICE_BIN" ]; then
  install -D -m0755 "$RBAC_POLICE_BIN" "$BIN_OUT/rbac-police"
  ok "rbac-police install (go install)"
else
  warn "rbac-police KO (binaire introuvable)"
fi

# 4) ---- naabu — DOC OFFICIELLE: go install (v2) ----
msg "naabu …"

GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

NAABU_BIN="$(go env GOPATH)/bin/naabu"
if [ -x "$NAABU_BIN" ]; then
  install -D -m0755 "$NAABU_BIN" "$BIN_OUT/naabu"
  ok "naabu install (go install)"
else
  warn "naabu KO (binaire introuvable)"
fi

# 5) ---- httpx — DOC OFFICIELLE: go install ----
msg "httpx …"

GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest

HTTPX_BIN="$(go env GOPATH)/bin/httpx"
if [ -x "$HTTPX_BIN" ]; then
  install -D -m0755 "$HTTPX_BIN" "$BIN_OUT/httpx"
  ok "httpx install (go install)"
else
  warn "httpx KO (binaire introuvable)"
fi

# 6) katana — DOC OFFICIELLE: go install
msg "katana …"
CGO_ENABLED=1 GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/projectdiscovery/katana/cmd/katana@latest
KATANA_BIN="$(go env GOPATH)/bin/katana"
if [ -x "$KATANA_BIN" ]; then
  install -D -m0755 "$KATANA_BIN" "$BIN_OUT/katana"
  ok "katana install (go install)"
else
  warn "katana KO (binaire introuvable)"
fi


# 8) nuclei — DOC OFFICIELLE: go install (module v3)
msg "nuclei …"
GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
NUCLEI_BIN="$(go env GOPATH)/bin/nuclei"
if [ -x "$NUCLEI_BIN" ]; then
  install -D -m0755 "$NUCLEI_BIN" "$BIN_OUT/nuclei"
  ok "nuclei install (go install)"
else
  warn "nuclei KO (binaire introuvable)"
fi

# 9) zgrab2 — DOC OFFICIELLE: go install (binaire cmd/zgrab2)
msg "zgrab2 …"
GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/zmap/zgrab2/cmd/zgrab2@latest
ZGRAB2_BIN="$(go env GOPATH)/bin/zgrab2"
if [ -x "$ZGRAB2_BIN" ]; then
  install -D -m0755 "$ZGRAB2_BIN" "$BIN_OUT/zgrab2"
  ok "zgrab2 install (go install)"
else
  warn "zgrab2 KO (binaire introuvable)"
fi

# 10) ffuf — fuzzer / directory & parameter discovery
msg "ffuf …"
GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/ffuf/ffuf/v2@latest

FFUF_BIN="$(go env GOPATH)/bin/ffuf"
if [ -x "$FFUF_BIN" ]; then
  install -D -m0755 "$FFUF_BIN" "$BIN_OUT/ffuf"
  ok "ffuf install (go install)"
else
  warn "ffuf KO (binaire introuvable)"
  exit 1
fi

# 11) subfinder — DOC OFFICIELLE: go install (module v2)
msg "subfinder …"

GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

SUBFINDER_BIN="$(go env GOPATH)/bin/subfinder"

if [ -x "$SUBFINDER_BIN" ]; then
  install -D -m0755 "$SUBFINDER_BIN" "$BIN_OUT/subfinder"
  ok "subfinder install (go install)"
else
  warn "subfinder KO (binaire introuvable)"
fi

# 12) kube-bench — DOC OFFICIELLE: go install
msg "kube-bench …"
GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/aquasecurity/kube-bench@latest

KUBE_BENCH_BIN="$(go env GOPATH)/bin/kube-bench"
if [ -x "$KUBE_BENCH_BIN" ]; then
  install -D -m0755 "$KUBE_BENCH_BIN" "$BIN_OUT/kube-bench"
  ok "kube-bench install (go install)"
else
  warn "kube-bench KO (binaire introuvable)"
fi

# 13) grpcurl — DOC OFFICIELLE: go install
msg "grpcurl …"
GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

GRPCURL_BIN="$(go env GOPATH)/bin/grpcurl"
if [ -x "$GRPCURL_BIN" ]; then
  install -D -m0755 "$GRPCURL_BIN" "$BIN_OUT/grpcurl"
  ok "grpcurl install (go install)"
else
  warn "grpcurl KO (binaire introuvable)"
fi

# 14) ---- DIRB (autotools + libcurl custom) ----
msg "dirb …"

DIRB_REPO="https://github.com/v0re/dirb"
DIRB_SRC="/tmp/dirb"
OUT="/out"
CURL_PREFIX="/out/curl"

rm -rf "$DIRB_SRC"
git clone --depth=1 "$DIRB_REPO" "$DIRB_SRC"
cd "$DIRB_SRC"

# rendre visible la libcurl custom
export PATH="${CURL_PREFIX}/bin:${PATH}"
export PKG_CONFIG_PATH="${CURL_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CPPFLAGS="-I${CURL_PREFIX}/include"
export LDFLAGS="-L${CURL_PREFIX}/lib -Wl,-rpath,${CURL_PREFIX}/lib"
export CFLAGS="-O2 -pipe -fPIC -fcommon"

# sanity check libcurl
if [ ! -x "${CURL_PREFIX}/bin/curl-config" ]; then
  echo "[FATAL] curl-config introuvable dans ${CURL_PREFIX}/bin"
  exit 1
fi

# configure (DIRB ignore --with-curl, mais garde les flags)
./configure --prefix="$OUT"

make clean || true
make -j"$(nproc)"

# installation manuelle
install -d "$OUT/bin" "$OUT/wordlists/dirb"
install -m 0755 "src/dirb" "$OUT/bin/dirb"
cp -a "wordlists/." "$OUT/wordlists/dirb/"

# vérification safe (dirb -h retourne 255 → ne pas casser set -e)
"$OUT/bin/dirb" -h >/dev/null 2>&1 || true

ok "dirb install (libcurl custom)"

# 15) ---- kubectl — DOC OFFICIELLE: binary release ----
msg "kubectl …"

KUBECTL_URL="https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
TMP_KUBECTL="/tmp/kubectl"

curl -fsSL "$KUBECTL_URL" -o "$TMP_KUBECTL"
chmod +x "$TMP_KUBECTL"

if "$TMP_KUBECTL" version --client >/dev/null 2>&1; then
  install -D -m0755 "$TMP_KUBECTL" "$BIN_OUT/kubectl"
  ok "kubectl install (official binary)"
else
  warn "kubectl KO (binaire invalide)"
fi

rm -f "$TMP_KUBECTL"

# 16) ---- waybackurls — DOC OFFICIELLE: go install ----
msg "waybackurls …"

GO111MODULE=on GOTOOLCHAIN=local \
  go install github.com/tomnomnom/waybackurls@latest

WAYBACKURLS_BIN="$(go env GOPATH)/bin/waybackurls"
if [ -x "$WAYBACKURLS_BIN" ]; then
  install -D -m0755 "$WAYBACKURLS_BIN" "$BIN_OUT/waybackurls"
  ok "waybackurls install (go install)"
else
  warn "waybackurls KO (binaire introuvable)"
fi

# Récapitulatif et validation
msg "Binaires installés dans $BIN_OUT :"
ls -lh "$BIN_OUT" || true

# Validation stricte : vérifier qu'au moins 10 binaires ont été installés
BINARY_COUNT=$(find "$BIN_OUT" -type f -executable | wc -l)
MIN_EXPECTED=10

if [ "$BINARY_COUNT" -lt "$MIN_EXPECTED" ]; then
  warn "ERREUR: Seulement $BINARY_COUNT binaires trouvés dans $BIN_OUT (minimum attendu: $MIN_EXPECTED)"
  exit 1
fi

ok "Validation réussie: $BINARY_COUNT binaires installés"
