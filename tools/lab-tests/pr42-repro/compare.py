#!/usr/bin/env python3
"""Feed REAL captured tool output through the privacy gateway and see what the
agent can still do with what it was handed.

Driven by reproduce.sh, which captures /realout from live httpx / ffuf / curl
runs against the lab. Import path is whichever MCP tree the container carries,
so the same script measures the pre-fix image and the current checkout.
"""
import glob
import os
import sys

for candidate in ("/opt/darkmoon/mcp/server", "/mcp", os.getcwd()):
    if os.path.isdir(os.path.join(candidate, "src", "privacy")):
        sys.path.insert(0, candidate)
        break

from src.privacy import CommandGateway, PrivacyVault, resolve_categories  # noqa: E402

try:
    from src.privacy import GatewayPolicy  # noqa: F401
    BUILD = "degrade policy present (fixed)"
except ImportError:
    BUILD = "no GatewayPolicy (pre-fix code)"

gw = CommandGateway()
vault = PrivacyVault(session_id="pr42", enabled_categories=resolve_categories(None))

print("build under test: %s" % BUILD)

# --- 1. the agent reads its own tool output, tokenized on the way in ---------
views = {}
for path in sorted(glob.glob("/realout/*.txt")):
    raw = open(path, encoding="utf-8", errors="replace").read()
    views[os.path.basename(path)] = gw.sanitize_output(raw, vault)

# --- 2. what it does next, using only the references it was handed ----------
url_phs = sorted(p for p in vault.known_placeholders() if p.startswith("URL_"))
path_phs = sorted(p for p in vault.known_placeholders() if p.startswith("PATH_"))

steps = []
for i, ph in enumerate(url_phs[:3]):
    steps.append(("fetch a discovered URL", "curl -s %s" % ph))
    if i == 0:
        steps.append(("probe it", "httpx -u %s -json" % ph))
        steps.append(("scan it", "nuclei -u %s -severity high" % ph))
for i, ph in enumerate(path_phs[:3]):
    steps.append(("read a discovered file", "cat %s" % ph))
    if i == 0:
        steps.append(("grep it for a password", "grep -i password %s" % ph))

refused = 0
for label, cmd in steps:
    res = gw.process_command(cmd, vault)
    if res.blocked:
        refused += 1
        print("  [REFUSED] %-24s %s" % (label, cmd))
        print("            %s" % res.reason)
    else:
        print("  [   ok   ] %-24s %s" % (label, cmd))

# --- 3. can it still pattern-match on what it found? ------------------------
haystack = "".join(views.values())
tilde = "~myfiles" in haystack
names = [n for n in ("index.php", "robots.txt", "db_connect.php", ".htaccess")
         if n in haystack]

print()
print("  refused                : %d/%d" % (refused, len(steps)))
print("  '~myfiles' visible     : %s" % ("yes" if tilde else "NO"))
print("  filenames readable     : %s" % (", ".join(names) if names else "NONE"))
sys.exit(0)
