# ⚙️ Darkmoon — Installation & Setup

This document explains **how to install, configure, and run Darkmoon**, step by step.

No internal knowledge of the project is required.

---

## 1. Prerequisites

Before starting, you must have:

- Docker
- Docker Compose
- Access to an LLM provider (OpenRouter, Anthropic, OpenAI…)

---

## 2. General project structure

Darkmoon relies on **Docker** and **Docker Compose**.

The important components are :

- an **OpenCode** container (AI + agents),
- a **Darkmoon Toolbox** container (pentest tools),
- **shared volumes** for configuration.

---

## 3. Configuration of environment variables in docker compose

Docker Compose is **the entry point for the entire AI configuration**.

### Example environment variable

```env
environment:
   # 🔽 TEST runtime variables LLM conf
   - OPENROUTER_PROVIDER=openai
   - OPENCODE_MODEL=gpt-4o
   - OPENROUTER_API_KEY=sk-svcacct-xxx
```

### Role of the variables

| Variable              | Role               |
| --------------------- | ------------------ |
| `OPENROUTER_PROVIDER` | LLM model provider |
| `OPENCODE_MODEL`      | Exact model used   |
| `OPENROUTER_API_KEY`  | Provider API key   |

👉 No secret is stored in the Docker image.

---

## 4. Automatic generation of OpenCode files

On first launch, Darkmoon :

1. reads the variables,
2. automatically generates :
   - `opencode.json`,
   - `auth.json`,

3. configures the main agent,
4. initializes OpenCode.

All of this is done by the script :

```
conf/apply-settings.sh
```

👉 You **do not need to generate anything manually**.

You can choose not to fill in the variables, in which case the default opencode model `opencode/big-pickle` will be executed

---

## 5. Volumes and persistence

Configuration files are persisted via Docker volumes.

### Important volumes

```yaml
- ./darkmoon-settings:/root/.config/opencode/:rw
- ./darkmoon-settings:/root/.local/share/opencode/:rw
- ./darkmoon-settings/agents:/root/.opencode/agents/:rw
```

### What this allows

- Modify the configuration **without rebuild**
- Add or modify AI agents
- Keep logs and OpenCode state

---

## 6. Build and launch Darkmoon

### Building the images

```bash
docker compose build
```

### Launching the stack

```bash
docker compose up -d
```

👉 The first launch may take some time (image build).

---

## 7. Launch Darkmoon (User CLI)

A wrapper is provided : `darkmoon.sh`.

### Make the wrapper executable

```bash
chmod +x darkmoon.sh
```

### Install globally (optional)

```bash
sudo cp darkmoon.sh /usr/local/bin/darkmoon
```

### Launch Darkmoon with TUI Console

```bash
darkmoon
```

Or with a direct command :

```bash
darkmoon "TARGET: mondomaine.com"
```

### View logs

When executing the darkmoon TUI, the session initializes, to view the logs in real time, you must open a new additional bash console and type the command described in the chat of Darkmmon `./darkmoon.sh --log {{session_id}}`.

```bash
Let me start with that.
I'll begin by initializing the session as required by the protocol.
⚙ darkmoon_get_session
Thinking: Good, I have the session ID: c0d67d10. Now I need to display the monitoring command to the user as required.
Session Initialized
Monitoring Command:
./darkmoon.sh --log c0d67d10
Now I'll proceed with the vulnerability assessment. Let me first identify the target's technological landscape.
```

you will be able to view the logs in bash session in real time:

```bash
└─$ ./darkmoon.sh --log c0d67d10

darkmoon(live)> streaming MCP output…
[11:37:59] darkmoon> httpx -mc 200,302 -u https://dark-moon.org


    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/

                projectdiscovery.io


[11:37:59] darkmoon> katana -aff -fx -jc -jsl -xhr -kf all -depth 5 -u https://dark-moon.org


   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

                projectdiscovery.io

[INF] Current httpx version v1.8.1 (latest)
[WRN] UI Dashboard is disabled, Use -dashboard option to enable
[INF] Current katana version v1.4.0 (latest)

^C
darkmoon(live)> stopped.
```

---

## 8. Direct access to the container (debug)

It is possible to enter the OpenCode container directly :

```bash
docker exec -ti opencode bash
```

This allows :

- to inspect files,
- to modify agents,
- to test OpenCode directly.

---

## 9. Where to modify what (summary)

| Action                    | Where                             |
| ------------------------- | --------------------------------- |
| Change the LLM model      | `.env`                            |
| Modify `opencode.json`    | `darkmoon-settings/opencode.json` |
| Modify `auth.json`        | `darkmoon-settings/auth.json`     |
| Add an agent              | `darkmoon-settings/agents/`       |
| Add an agent before build | `conf/agents/`                    |

---

## 10. Quick summary

- `.env` → AI configuration
- `docker compose up -d` → launch
- `darkmoon` → usage
- Volumes → persistence & live modification

---

➡️ For build or rebuild issues :
see `docs/rebuild-and-troubleshooting.md`
