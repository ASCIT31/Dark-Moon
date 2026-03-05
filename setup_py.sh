#!/usr/bin/env bash
set -euo pipefail

# Helpers (définis seulement s'ils n'existent pas déjà)
if ! command -v msg >/dev/null 2>&1; then
  msg() {
    echo "[*] $*"
  }
fi

if ! command -v ok >/dev/null 2>&1; then
  ok() {
    echo "[OK] $*"
  }
fi

if ! command -v warn >/dev/null 2>&1; then
  warn() {
    echo "[WARN] $*" >&2
  }
fi

# Chemins de sortie standardisés
PY_PREFIX="/opt/darkmoon/python"
PY_BIN="$PY_PREFIX/bin/python3"
PIP_BIN="$PY_PREFIX/bin/pip3"
BIN_OUT="/out/bin"

# Créer le répertoire de sortie pour les wrappers
mkdir -p "$BIN_OUT"

msg "Vérification runtime Python embarqué…"
if [ ! -x "$PY_BIN" ]; then
  warn "Python non trouvé à $PY_BIN. Construis d'abord Python dans le Dockerfile (bloc builder) puis recopie /opt/darkmoon/python dans l'image runtime."
  exit 1
fi

# Pas de cache, wheels manylinux quand dispo
msg "Upgrade pip…"
"$PIP_BIN" install --no-cache-dir --upgrade pip setuptools wheel

msg "Installation impacket (latest)…"

"$PIP_BIN" install --no-cache-dir --prefer-binary \
    impacket \
    "ldap3<3" \
    "pyasn1<0.6"

"$PY_BIN" -c "import impacket"
"$PIP_BIN" check

for bin in /opt/darkmoon/python/bin/impacket-*; do
    [ -f "$bin" ] && ln -sf "$bin" "$BIN_OUT/"
done

ok "impacket latest installed"


# netexec (ex-CrackMapExec) – utilise les binaires installés par pip (nxc / netexec)

PYTHON_BIN="/opt/darkmoon/python/bin"

# Mise à jour pip avant installation
msg "Mise à jour de pip..."
"$PIP_BIN" install --no-cache-dir --upgrade pip setuptools wheel

# Pré-installation d'aardwolf (dépendance problématique de NetExec)
# Utilisation de binary wheel si disponible, sinon skip
msg "Pré-installation d'aardwolf (peut échouer, non bloquant)..."
"$PIP_BIN" install --no-cache-dir --prefer-binary aardwolf || {
  warn "aardwolf n'a pas pu être installé depuis PyPI, tentative via NetExec..."
}

# Installation de NetExec avec --no-build-isolation pour mieux gérer les dépendances
msg "Installation de NetExec..."
"$PIP_BIN" install --no-cache-dir \
  "git+https://github.com/Pennyw0rth/NetExec.git@v1.4.0" || {
  warn "Échec installation NetExec@v1.4.0, tentative avec latest stable..."
  "$PIP_BIN" install --no-cache-dir netexec
}

# Wrappers pour NetExec et BloodHound
cat >"$BIN_OUT/netexec" <<'EOF'
#!/bin/sh
if [ -x /opt/darkmoon/python/bin/nxc ]; then
  exec /opt/darkmoon/python/bin/nxc "$@"
elif [ -x /opt/darkmoon/python/bin/netexec ]; then
  exec /opt/darkmoon/python/bin/netexec "$@"
else
  echo "[-] NetExec (nxc) not installed in /opt/darkmoon/python/bin" >&2
  exit 127
fi
EOF
chmod +x "$BIN_OUT/netexec"

# Alias CrackMapExec pour compatibilité
cat >"$BIN_OUT/crackmapexec" <<'EOF'
#!/bin/sh
exec /usr/local/bin/netexec "$@"
EOF
chmod +x "$BIN_OUT/crackmapexec"

cat >"$BIN_OUT/bloodhound-python" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/bloodhound "$@"
EOF
chmod +x "$BIN_OUT/bloodhound-python"

# ------------------------------------------------------------
# NetExec OpenSSL 3 compatibility patch (disable PKINIT/PFX)
# ------------------------------------------------------------
msg "Patching NetExec for OpenSSL 3 (disable PKINIT/PFX)..."

PY_SITE="$("$PY_BIN" - <<'PY'
import site
print(site.getsitepackages()[0])
PY
)"

# ============================================================
# Patch nxc/helpers/pfx.py
# ============================================================
PFX="$PY_SITE/nxc/helpers/pfx.py"

if [ -f "$PFX" ]; then
  export PFX_PATH="$PFX"

  python3 - <<'PY'
import pathlib, re, os

p = pathlib.Path(os.environ["PFX_PATH"])
s = p.read_text()

# 1) Neutralise oscrypto imports
s = re.sub(
    r"from oscrypto\.keys import .*",
    "parse_pkcs12 = parse_certificate = parse_private = None",
    s
)
s = re.sub(
    r"from oscrypto\.asymmetric import .*",
    "rsa_pkcs1v15_sign = load_private_key = None",
    s
)

# 2) Supprime import PKINIT direct et remplace par stub sûr
s = re.sub(
    r"from minikerberos\.pkinit import PKINIT, DirtyDH",
    "class _PKINIT_DISABLED:\n"
    "    def __init__(self, *a, **kw):\n"
    "        raise RuntimeError('PKINIT disabled (OpenSSL 3)')\n\n"
    "PKINIT = _PKINIT_DISABLED\n"
    "DirtyDH = None",
    s
)

p.write_text(s)
print("[OK] Patched nxc/helpers/pfx.py")
PY
else
  warn "pfx.py not found, skipping patch"
fi

# ============================================================
# Patch minikerberos/pkinit.py
# ============================================================
PKINIT="$PY_SITE/minikerberos/pkinit.py"

if [ -f "$PKINIT" ]; then
  export PKINIT_PATH="$PKINIT"

  python3 - <<'PY'
import pathlib, re, os

p = pathlib.Path(os.environ["PKINIT_PATH"])
s = p.read_text()

# Neutralise oscrypto imports
s = re.sub(
    r"from oscrypto\.keys import .*",
    "parse_pkcs12 = None",
    s
)
s = re.sub(
    r"from oscrypto\.asymmetric import .*",
    "rsa_pkcs1v15_sign = load_private_key = None",
    s
)

# Supprime toute exception levée au chargement
s = re.sub(
    r"raise RuntimeError\\(.*PKINIT.*\\)",
    "",
    s
)

p.write_text(s)
print("[OK] Patched minikerberos/pkinit.py")
PY
else
  warn "pkinit.py not found, skipping patch"
fi

# ============================================================
# Nettoyage défensif (optionnel mais recommandé)
# ============================================================
"$PIP_BIN" uninstall -y oscrypto || true

ok "NetExec OpenSSL 3 patch applied (PKINIT/PFX disabled)"


# ------------------------------------------------------------
# Outils supplémentaires
# ------------------------------------------------------------
msg "Installation wafw00f …"
"$PIP_BIN" install --no-cache-dir wafw00f && ok "wafw00f"

msg "Installation sqlmap …"
"$PIP_BIN" install --no-cache-dir sqlmap && ok "sqlmap"

msg "Installation arjun …"
"$PIP_BIN" install --no-cache-dir arjun && ok "arjun"

msg "Installation awscli …"
"$PIP_BIN" install --no-cache-dir awscli && ok "awscli"

# ------------------------------------------------------------
# FinalRecon (reconnaissance web) - Version pinnée
# ------------------------------------------------------------
msg "Installation FinalRecon (depuis GitHub)…"
FR_DIR="/opt/darkmoon/finalrecon"
FINALRECON_VERSION="v1.1.6"

git clone --depth=1 --branch "$FINALRECON_VERSION" https://github.com/thewhiteh4t/FinalRecon.git "$FR_DIR"
"$PIP_BIN" install --no-cache-dir -r "$FR_DIR/requirements.txt"

# Validation que finalrecon.py existe
test -f "$FR_DIR/finalrecon.py" || { warn "finalrecon.py not found in $FR_DIR"; exit 1; }
ok "FinalRecon $FINALRECON_VERSION"

# ------------------------------------------------------------
# CMSeeK — DOC OFFICIELLE: git clone + requirements
# ------------------------------------------------------------
msg "Installation CMSeeK …"

CMSEEK_DIR="/opt/darkmoon/cmseek"

git clone --depth=1 https://github.com/Tuhinshubhra/CMSeeK "$CMSEEK_DIR"

"$PIP_BIN" install --no-cache-dir -r "$CMSEEK_DIR/requirements.txt"

# wrapper
cat >"$BIN_OUT/cmseek" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/python3 /opt/darkmoon/cmseek/cmseek.py "$@"
EOF
chmod +x "$BIN_OUT/cmseek"

test -x "$BIN_OUT/cmseek" || { warn "cmseek wrapper not created"; exit 1; }

ok "CMSeeK installed"

# ------------------------------------------------------------
# Création des wrappers dans /out/bin (copiés dans runtime)
# ------------------------------------------------------------
msg "Création des wrappers Python…"

cat >"$BIN_OUT/wafw00f" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/wafw00f "$@"
EOF
chmod +x "$BIN_OUT/wafw00f"

cat >"$BIN_OUT/sqlmap" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/sqlmap "$@"
EOF
chmod +x "$BIN_OUT/sqlmap"

cat >"$BIN_OUT/arjun" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/arjun "$@"
EOF
chmod +x "$BIN_OUT/arjun"

cat >"$BIN_OUT/aws" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/aws "$@"
EOF
chmod +x "$BIN_OUT/aws"

cat >"$BIN_OUT/finalrecon" <<'EOF'
#!/bin/sh
exec /opt/darkmoon/python/bin/python3 /opt/darkmoon/finalrecon/finalrecon.py "$@"
EOF
chmod +x "$BIN_OUT/finalrecon"

ok "Wrappers créés dans $BIN_OUT: impacket-smbclient, netexec, crackmapexec, bloodhound-python, rpcdump.py, wafw00f, sqlmap, arjun, aws, finalrecon"

