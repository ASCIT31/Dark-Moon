#!/usr/bin/env python3
"""
Wire the new credential-gated sub-agents into a repo's pentest.md and
apply-settings.sh. Newline-safe (preserves CRLF where the file uses it),
idempotent (re-running does nothing if the agents are already wired).

Every functional agent must be wired at the SAME places the working agents are,
per the INC-010a lesson: adding a SIGNAL block alone is NOT enough — the agent
MUST appear in the SPAWN-PROTOCOL roster ("SUBAGENT PROMPT = RAW AGENT FILE"),
or the orchestrator has no dispatchable name for it.

These new planes are CREDENTIAL-GATED / POSITIVE-ARTIFACT ONLY (like kubernetes
and active-directory): never auto-dispatched on inference, only on a concrete
artifact (a leaked key, an exposed API/port, an operator-provided credential).
They are NOT web agents, so they are deliberately NOT added to the
headless-browser trigger list.

Usage: python3 wire.py <path-to-repo> [<path-to-repo> ...]
"""
import os
import sys

# (agent id, one-line positive-artifact trigger for the signal matrix)
NEW_AGENTS = [
    ("aws", "a leaked AKIA/ASIA key, an ~/.aws/credentials, an EC2/ECS IMDS (169.254.169.254) response, or operator-provided AWS credentials"),
    ("azure", "an az session, a service-principal id+secret, an Azure IMDS (169.254.169.254/metadata/identity) response, or an azureProfile.json"),
    ("entra-id", "a Microsoft Graph token, an app clientId+clientSecret, or a device-code session for the tenant"),
    ("gcp", "a service_account.json, a ya29./AIza token, a GCE metadata (metadata.google.internal) response, or a gcloud auth session"),
    ("github", "a ghp_/ghs_/github_pat_ token, an exposed .git/config with credentials, or a GitHub App installation token"),
    ("gitlab", "a glpat- token, a leaked CI/CD variable, or a runner registration token"),
    ("jenkins", "a reachable Jenkins URL (X-Jenkins header, /api/json, or a Jenkins login/Whitelabel banner) or provided Jenkins credentials"),
    ("terraform", "an exposed .tfstate / remote-state http backend, or an operator-provided Terraform/IaC repository"),
    ("ansible", "inventory/playbook/vault files, or an AWX/Automation-Controller URL plus a token"),
    ("docker", "an exposed Docker daemon socket (/var/run/docker.sock) or an unauthenticated Docker TCP API on 2375/2376"),
    ("container-registry", "a reachable OCI registry v2 API (/v2/ on Harbor/Quay/GHCR/GitLab/Artifactory/Nexus/ECR/ACR/GAR)"),
    ("hashicorp-vault", "a reachable $VAULT_ADDR/v1/sys/health, or a Vault token / AppRole / Kubernetes-auth material"),
    ("sql-databases", "a reachable database port (5432/3306/1433/1521) together with operator-provided or leaked credentials"),
    ("messaging-cache", "a reachable broker/cache port (Redis 6379, RabbitMQ 5672/15672, Kafka 9092, MQTT 1883, ActiveMQ 8161, ZooKeeper 2181)"),
]

ROSTER_ANCHOR = "    nest\n    any future agent"
SIGNAL_ANCHOR = "PHASE 3 — REACTIVE FEEDBACK LOOP (CORE MECHANISM)"
APPLY_ANCHOR = '"prompt_file": "/root/.opencode/agents/pentest.md"'


def detect_nl(raw_bytes):
    return "\r\n" if raw_bytes.count(b"\r\n") > 20 else "\n"


def read(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    nl = detect_nl(raw)
    text = raw.decode("utf-8").replace("\r\n", "\n")
    return text, nl


def write(path, text, nl):
    data = text.replace("\n", nl).encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(data)


def roster_block():
    return "\n".join(f"    {aid}" for aid, _ in NEW_AGENTS)


def signal_section():
    lines = []
    add = lines.append
    add("=" * 80)
    add("PHASE 2b — CREDENTIAL-GATED PLANES (MANUAL / POSITIVE-ARTIFACT DISPATCH)")
    add("=" * 80)
    add("")
    add("The following planes are CLOUD / IDENTITY / CI-CD / IaC / SECRETS / DATA")
    add("planes. They are NEVER dispatched by inference and NEVER on the mere absence")
    add("of other-language markers. Each dispatches ONLY when a concrete POSITIVE")
    add("ARTIFACT names it — a leaked credential, an exposed API/port, or a scope")
    add("value the operator supplied. This mirrors the kubernetes / active-directory")
    add("manual-only doctrine and prevents false-positive dispatch (INC-010).")
    add("")
    add("Dispatch rule for every entry below:")
    add("  - If the operator supplied credentials/scope for the plane -> dispatch it.")
    add("  - Else if a parent agent surfaced the positive artifact listed -> dispatch it.")
    add("  - Else -> do NOT dispatch. Log 'Detected — Manual Authorization Required'")
    add("    in the report and continue. Never guess the plane from absence of signal.")
    add("These agents are NOT web agents: they do NOT trigger headless-browser.")
    add("")
    for aid, trigger in NEW_AGENTS:
        add("-" * 80)
        add(f"SIGNAL: {aid} plane present")
        add("-" * 80)
        add("POSITIVE ARTIFACT (any one; required — inference is NOT a signal):")
        add(f"    - {trigger}")
        add(f"DISPATCH: {aid}")
        add("DISPATCH MODE: CREDENTIAL-GATED / POSITIVE-ARTIFACT ONLY — flag but do not")
        add("    auto-dispatch unless the operator provided scope or the artifact fired.")
        add("CONTEXT PASS: target/endpoint, the credential or artifact source, discovered")
        add("    resource identifiers, and any downstream secrets to hand off.")
        add("")
    return "\n".join(lines)


def wire_pentest(path):
    text, nl = read(path)
    changed = False
    # 1) roster
    if "\n    aws\n" not in text and ROSTER_ANCHOR in text:
        text = text.replace(ROSTER_ANCHOR, roster_block() + "\n" + ROSTER_ANCHOR, 1)
        changed = True
    # 2) signal section — insert before the ==== fence that precedes PHASE 3
    if "PHASE 2b — CREDENTIAL-GATED PLANES" not in text and SIGNAL_ANCHOR in text:
        idx = text.index(SIGNAL_ANCHOR)
        # back up to the start of the ==== fence line just above PHASE 3
        pre = text.rindex("\n" + "=" * 80, 0, idx)
        # pre points at the newline before the opening fence of PHASE 3's banner
        insert_at = pre + 1  # start of the fence line
        block = signal_section() + "\n\n"
        text = text[:insert_at] + block + text[insert_at:]
        changed = True
    if changed:
        write(path, text, nl)
    return changed


def apply_block(aid):
    return (
        f'    "{aid}": {{\n'
        f'      "model": "$FINAL_MODEL",\n'
        f'      "mcp": ["darkmoon"],\n'
        f'      "secondary": true,\n'
        f'      "prompt_file": "/root/.opencode/agents/{aid}.md"\n'
        f'    }},\n'
    )


def wire_apply(path):
    text, nl = read(path)
    if '"aws": {' in text:
        return False
    if APPLY_ANCHOR not in text:
        return False
    idx = text.index(APPLY_ANCHOR)
    # find the closing "    },\n" of the pentest block right after the anchor
    close = text.index("\n    },\n", idx) + len("\n    },\n")
    blocks = "\n" + "".join(apply_block(aid) for aid, _ in NEW_AGENTS)
    text = text[:close] + blocks + text[close:]
    write(path, text, nl)
    return True


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    for repo in sys.argv[1:]:
        pm = os.path.join(repo, "conf", "agents", "pentest.md")
        ap = os.path.join(repo, "conf", "apply-settings.sh")
        c1 = wire_pentest(pm) if os.path.exists(pm) else None
        c2 = wire_apply(ap) if os.path.exists(ap) else None
        print(f"{os.path.basename(repo):24} pentest.md wired={c1}  apply-settings wired={c2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
