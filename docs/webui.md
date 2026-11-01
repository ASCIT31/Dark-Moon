# DarkMoon Web UI

A browser front-end for the open-source DarkMoon engine. The engine is untouched:
the Web UI drives the same containers, the same MCP server and the same 51 agents —
it only adds a dashboard, a live console, a findings explorer and a settings panel.

```
┌────────────┐   HTTP/SSE    ┌──────────────┐   docker.sock   ┌────────────────┐
│  Browser   │ ────────────► │  darkmoon-   │ ─────────────► │  opencode      │
│            │ ◄──────────── │  webui       │                │  + MCP server  │
└────────────┘               │  (FastAPI)   │ ─────────────► │  darkmoon      │
                             └──────────────┘   exec          │  (toolbox)     │
                                     │                       └────────────────┘
                                     │ reads
                                     ▼
                    darkmoon-settings/  campaigns · findings · infrastructure
                    reports/            markdown reports
                    sessions/           opencode session logs
                    conf/agents/        the 51 agent prompts
                    mcp/                allowlist + workflows
```

## Install & run

```bash
git clone https://github.com/ASCIT31/Dark-Moon.git
cd Dark-Moon
./webui.sh            # pull the engine, build the Web UI, start everything
```

Then open **http://localhost:8080**.

`./webui.sh` is idempotent and safe to re-run. Other subcommands:

| Command | Effect |
|---|---|
| `./webui.sh install` | full install: pull engine images → start engine → build & start Web UI |
| `./webui.sh up` / `down` | start / stop the whole stack |
| `./webui.sh status` | `docker compose ps` |
| `./webui.sh logs` | follow the Web UI logs |
| `./webui.sh rebuild` | rebuild the Web UI image |

The port is configurable with `DARKMOON_WEBUI_PORT=9000 ./webui.sh`.

The classic CLI workflow still works unchanged:

```bash
./darkmoon.sh "TARGET: example.com"
./darkmoon.sh --log <session_id>
```

## Configuring the LLM provider

The engine needs a model before it can run an assessment. Open the **Settings**
tab in the Web UI and pick one of:

* **Cloud provider** — provider id (e.g. `anthropic`), model id, API key. Written as
  `OPENROUTER_PROVIDER` / `OPENCODE_MODEL` / `OPENROUTER_API_KEY`.
* **Local model** — Ollama or llama.cpp base URL + model. Use
  `http://host.docker.internal:11434/v1` so the container can reach your host.
  Written as `OPENCODE_LOCAL_MODE` / `OPENCODE_LOCAL_BASE_URL` / `OPENCODE_LOCAL_MODEL`.
* **On-prem Anthropic-compatible endpoint** — base URL + model, optional key.

The provider is written to `.opencode.env` (mode `600`). **Restart the engine**
(Settings → *Restart*, or `./darkmoon.sh`/`docker compose restart opencode`) for it
to take effect — the settings page says so too.

## What the Web UI gives you

| Tab | Content |
|---|---|
| **Overview** | Campaign/finding counters, severity breakdown, recent campaigns and reports, engine health. |
| **New assessment** | Launches a pentest against a target with program, focus, noise, scope, credentials and format. The prompt is assembled exactly like the CLI (`TARGET: … PROGRAM="…" FOCUS=… NOISE=… FORMAT=…`). |
| **Live console** | SSE stream of the running assessment, a classified event feed (findings / commands / errors / recon) and a *start MCP stream* button that tails the raw MCP output (`darkmoon-cli`). |
| **Campaigns** | Every campaign the MCP recorded, with target, status, duration, finding and node counts. |
| **Findings** | All vulnerabilities with severity, CVSS, endpoint, discovering agent, CVE, MITRE ATT&CK id, status and remediation. Filter by severity, campaign and free text. |
| **Infrastructure** | The attack-surface map the orchestrator built: nodes, parents, technologies, ports, risk levels — drawn as a graph. |
| **Reports** | The generated markdown reports (`reports/pentest_report_<host>_<ts>.md`), viewable inline and downloadable. |
| **Sessions** | The opencode session logs on disk plus the session index read from the opencode SQLite DB. |
| **Agents** | The 1 orchestrator + 50 specialist agents, with their full prompt methodology. |
| **MCP tools** | The 140+ offensive tools the MCP allowlist exposes, and the workflow modules. |
| **Settings** | LLM provider, engine start/stop/restart/logs. |

### AI scope generator

In the **New assessment** view, next to the *Scope* field, click **✨ AI scope
generator**. Paste a bug-bounty program brief (HackerOne, Bugcrowd, Intigriti or
any platform text) and the configured LLM extracts a structured JSON scope:

```json
{
  "name": "1win",
  "in_scope": ["1win.com", "1wintoken.com"],
  "out_of_scope": ["social engineering", "DoS"],
  "rewards": { "critical": 3000, "high": 1500, "medium": 150, "low": 50 },
  "rate_limit": "5 req/sec, 5 concurrent",
  "safe_harbor": true,
  "exclusions": ["self-XSS", "open redirect"]
}
```

Click **✓ Use this scope** and the assets land in the launch form's *Scope* field
and the exclusions in *Notes*, ready to run. The modal ships with a worked
1win/HackerOne example.

It talks to whatever you configured in Settings — cloud, local (Ollama / LM Studio)
or on-prem Anthropic-compatible — over the OpenAI-compatible API, so it works with
any provider. If the model is unavailable it reports the error instead of hanging.

## API

Everything the UI does is available over HTTP, so it can be scripted:

```bash
# launch an assessment
curl -X POST localhost:8080/api/launch -H 'content-type: application/json' \
     -d '{"target":"example.com","focus":"sqli,xss","noise":"low","format":"h1"}'

# follow it live
curl -N localhost:8080/api/jobs/<job_id>/stream

# findings
curl 'localhost:8080/api/findings?severity=critical'

# reports / campaigns / infra
curl localhost:8080/api/reports
curl localhost:8080/api/campaigns
curl localhost:8080/api/infra/<campaign_id>
```

Interactive API docs: <http://localhost:8080/api/docs>.

## Security notes

* The Web UI binds to `0.0.0.0:8080` inside the container and is published on the
  host. It has **no authentication** — put it behind a reverse proxy / VPN, or bind
  it to `127.0.0.1` (`ports: - "127.0.0.1:8080:8080"` in `docker-compose.webui.yml`).
* It mounts the Docker socket, so anyone who can reach it can run commands in the
  engine containers. Treat it as a privileged local service.
* Only run assessments against infrastructure you are explicitly authorised to test.
