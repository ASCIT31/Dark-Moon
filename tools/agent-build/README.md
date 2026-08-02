# Darkmoon agent-build

Tooling that generates spine-compliant Darkmoon sub-agents, wires them into every
repo, and gates them against regression. Built for the 2026-08 credential-gated
agent expansion; use it for every new agent from now on.

## Why a generator

Every secondary agent shares a **byte-identical spine** (STATUS QUALIFICATION
banner, SUB-AGENT rule, ANTI-BRUTEFORCE, SCANNER, BLACKBOX, DASHBOARD push). Typing
it by hand drifts. `generate.py` extracts those blocks **verbatim from `graphql.md`**
and assembles each agent from a small JSON profile, so the spine can never drift and
every agent is the same shape/length as the reference fleet.

## Files

| File | Role |
|---|---|
| `generate.py` | build `.md` agents from `profiles/*.json` into `out/` (LF-only). `--selfcheck` verifies the spine round-trips. |
| `validate.py` | conformance gate: banner byte-identity, front-matter, `{{TARGET}}`, do-not-finalize, END marker, no orchestrator-only leakage. |
| `wire.py <repo>…` | insert each agent into `pentest.md` (roster **and** signal matrix — newline-safe, preserves Front-API CRLF) and `apply-settings.sh`. Idempotent. |
| `mirror.sh` | copy `out/*.md` into all three repos' `conf/agents/`. |
| `profiles/*.json` | one per agent: id, description, objective (`{{TARGET}}`), strict_constraints, preflight, offensive, priorities, stop_note. |

## Add a new agent (Wave 2/3)

```bash
cd tools/agent-build
# 1. write profiles/<id>.json   (copy aws.json as the template)
python3 generate.py <id>          # -> out/<id>.md
python3 validate.py out/<id>.md   # must PASS
bash mirror.sh                    # -> conf/agents in all 3 repos
python3 wire.py ../.. ../../../Dark-Moon-prod ../../../Dark-Moon-Front-API
# 2. rebuild the image (CI), then:
../verify-toolbox.sh              # every allow-listed tool alive
../check-no-regression.sh         # INC-009/INC-010 + wiring intact
```

If the agent needs a new toolbox binary, add it to the Dockerfile / `setup_py.sh`
**and** to the MCP allow-list (`mcp/src/tools/core/executor.py`) — `verify-toolbox.sh`
will fail until the two agree.

## Doctrine for these agents (do not break)

- **Credential-gated / positive-artifact dispatch.** Cloud/identity/CI/IaC/secrets/
  data agents dispatch only on a concrete artifact (leaked key, exposed API/port,
  operator credential), never on inference. This is what prevents the golang-style
  false dispatch (INC-010). Each carries a `PHASE 0 — CREDENTIAL PREFLIGHT` with a
  STOP LOGIC; the orchestrator entry is in `pentest.md` → `PHASE 2b`.
- **Not web agents.** They are never added to the headless-browser trigger list.
- **Push complete evidence.** The final report is generated server-side from pushed
  findings (INC-009). A finding with thin evidence yields a thin report — fill every
  evidence field.

## Delivered in Wave 1 (2026-08)

`aws`, `azure`, `entra-id`, `gcp`, `github`, `gitlab`, `jenkins`, `terraform`,
`ansible`, `docker`, `container-registry`, `hashicorp-vault`, `sql-databases`
(PostgreSQL/MySQL/MSSQL/Oracle), `messaging-cache` (Redis/RabbitMQ/Kafka/NATS/MQTT/
ActiveMQ/ZooKeeper). Toolbox gained `az`, `gcloud`/`gsutil`/`bq`,
`postgresql-client`, `default-mysql-client`, `redis-tools` (aws was already present).
