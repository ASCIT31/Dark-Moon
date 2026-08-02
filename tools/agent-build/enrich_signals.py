#!/usr/bin/env python3
"""
Enrich the PHASE 2b credential-gated signal-matrix entries in pentest.md with a
rich, AD-style list of CONCRETE positive-artifact indicators for each new agent —
so the orchestrator recognizes a real artifact reliably (few misses) without ever
firing on a name / header / inference (no false positive, same discipline as golang).

Replaces, per agent, the single-line POSITIVE ARTIFACT block with a multi-indicator
block. Newline-safe (preserves the Front-API CRLF). Idempotent.

Usage: python3 enrich_signals.py <repo> [<repo> ...]
"""
import os, re, sys

GUARD = ("POSITIVE ARTIFACT — INDICATORS (any ONE fires the plane; each must be CONCRETE "
         "and, where cheap, VERIFIED — a bare name, a hostname without creds, a header, or "
         "an inference from what is ABSENT is NOT an artifact; apply the STATUS QUALIFICATION "
         "demo/example/placeholder test before trusting a secret; same discipline as golang):")

# Per-agent concrete indicators (AD-style). Each string is one bullet.
IND = {
 "aws": [
   "an AWS access key in AKIA…/ASIA… format (long-term or STS temporary), ideally with its secret and/or session token",
   "an ~/.aws/credentials or ~/.aws/config file, or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in an env/.env/CI-CD variable/leaked config",
   "the EC2/ECS/EKS metadata service reachable or reflected via SSRF (169.254.169.254/latest/meta-data/iam/…, 169.254.170.2, or an IRSA token file) returning role credentials",
   "an assumed-role ARN plus a usable session, or a Cognito identity-pool that mints credentials",
   "verify where possible: the key authenticates (aws sts get-caller-identity). A Stripe pk_/NEXT_PUBLIC_/public-by-design value is NOT an artifact",
 ],
 "azure": [
   "an az CLI login session, or a service-principal appId + clientSecret + tenantId (or a certificate credential)",
   "Azure IMDS reachable/reflected (169.254.169.254/metadata/identity/oauth2/token, header Metadata:true) returning a management token",
   "an azureProfile.json / ~/.azure content, a storage-account key or SAS token, or an ARM management bearer token",
   "an App Service IDENTITY_ENDPOINT + IDENTITY_HEADER, or a managed-identity token for management.azure.com",
 ],
 "entra-id": [
   "a Microsoft Graph bearer token (aud=graph.microsoft.com), or an access/refresh token for login.microsoftonline.com",
   "an application clientId + clientSecret (+ tenantId), or a certificate credential bound to a service principal",
   "a device-code session, or an FOCI refresh token usable across first-party apps",
 ],
 "gcp": [
   "a service_account.json (type=service_account, contains private_key), or GOOGLE_APPLICATION_CREDENTIALS pointing at one",
   "a ya29.… OAuth token or an AIza… API key, or a gcloud auth session",
   "the GCE/GKE metadata server reachable/reflected (metadata.google.internal, header Metadata-Flavor: Google) returning a token",
   "a GKE kubeconfig from get-credentials -> record and hand to kubernetes (manual-only), do not attack the cluster here",
 ],
 "github": [
   "a token in ghp_/ghs_/gho_/github_pat_ format, or GITHUB_TOKEN in a workflow/env",
   "an exposed .git/config, .git-credentials, or a remote URL embedding a token",
   "a GitHub App JWT / installation access token (verify scopes via /user where possible)",
 ],
 "gitlab": [
   "a token in glpat-… format, a project/group access token, a CI_JOB_TOKEN, a deploy token, or a runner registration token",
   "a leaked .gitlab-ci CI/CD variable, or a remote URL embedding oauth2:<token> (verify via /api/v4/personal_access_tokens/self)",
 ],
 "jenkins": [
   "a reachable Jenkins controller (X-Jenkins response header, a readable /api/json, or the Whitelabel/login page)",
   "a user:apiToken pair, an exposed credentials.xml + secrets/master.key, or an anonymously-reachable /script or /scriptText",
 ],
 "terraform": [
   "an exposed remote state readable (an http backend without auth, a public S3/GCS/azurerm state object, a Consul-KV state) returning a .tfstate with secrets",
   "a .tfstate / .terraform/terraform.tfstate / backend config with credentials, or TF_VAR_* secrets in env",
 ],
 "ansible": [
   "an inventory (hosts/inventory.ini) or group_vars/host_vars with ansible_ssh_pass / ansible_become_pass / passwords",
   "an Ansible Vault file plus a vault-password-file in clear (or crackable), an ansible.cfg with credentials, or an AWX/Automation-Controller URL + a usable token",
 ],
 "docker": [
   "the Docker Engine socket reachable (/var/run/docker.sock, or a docker.sock mounted into a container)",
   "an unauthenticated Docker TCP API on 2375/2376, a DOCKER_HOST pointing at a remote daemon, or a docker config.json with registry credentials",
 ],
 "container-registry": [
   "a reachable OCI Registry v2 API (a /v2/ endpoint returning 200 or 401 WWW-Authenticate: Bearer) — Docker Registry, Harbor (/api/v2.0), Quay, GHCR, GitLab Registry, JFrog Artifactory (/artifactory/api), Nexus (/service/rest), ECR/ACR/GAR",
   "registry credentials in a docker config.json/.dockercfg, or an image reference pointing at a private registry",
 ],
 "hashicorp-vault": [
   "a reachable $VAULT_ADDR/v1/sys/health or /sys/seal-status (unsealed), plus a usable token (hvs.…/s.…), an AppRole role_id+secret_id, or a Kubernetes-auth SA token bound to a Vault mount",
   "VAULT_TOKEN / VAULT_ADDR in an env or config file",
 ],
 "sql-databases": [
   "a reachable database port (PostgreSQL 5432, MySQL/MariaDB 3306, MSSQL 1433, Oracle 1521, MongoDB 27017) TOGETHER WITH working credentials",
   "a connection string/DSN, a leaked password, a .pgpass/.my.cnf, an ORM/app config with the creds, or default/weak creds that actually authenticate",
 ],
 "messaging-cache": [
   "a reachable broker/cache endpoint that accepts a connection — Redis 6379 (PING->PONG, anon or leaked AUTH), RabbitMQ 5672 / mgmt 15672, Kafka 9092, MQTT 1883, ActiveMQ 8161/61616, ZooKeeper 2181, NATS 4222/8222",
   "anonymously, or with a leaked broker URI / credentials",
 ],
}


def detect_nl(raw):
    return "\r\n" if raw.count(b"\r\n") > 20 else "\n"


def enrich(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    nl = detect_nl(raw)
    text = raw.decode("utf-8").replace("\r\n", "\n")
    if "POSITIVE ARTIFACT — INDICATORS" in text:
        return False  # already enriched
    changed = 0
    for aid, bullets in IND.items():
        block = GUARD + "\n" + "\n".join(f"    - {b}" for b in bullets) + f"\nDISPATCH: {aid}\n"
        pat = re.compile(
            r"POSITIVE ARTIFACT \(any one; required — inference is NOT a signal\):\n"
            r"(?:.*\n)*?DISPATCH: " + re.escape(aid) + r"\n"
        )
        new_text, n = pat.subn(block, text, count=1)
        if n:
            text = new_text
            changed += 1
    if changed:
        with open(path, "wb") as fh:
            fh.write(text.replace("\n", nl).encode("utf-8"))
    return changed


def main():
    for repo in sys.argv[1:]:
        p = os.path.join(repo, "conf", "agents", "pentest.md")
        if not os.path.exists(p):
            print(f"{repo}: no pentest.md"); continue
        c = enrich(p)
        print(f"{os.path.basename(repo):24} enriched {c} agent signal blocks")


if __name__ == "__main__":
    main()
