<center>

![DarkMoon Logo](docs/pics/DARKMOON%20LOGOTYPE%20PRINCIPAL%20CHRYSLER%20RVB%20900PX%20W%2072PPI.png)

A platform that allows you to conduct a complete penetration testing campaign

</center>

# Summary

- [I. Preview](#i-preview)
- [II. Installation](#ii-installation)
  - [II.1. Prerequisites](#ii1-prerequisites)
  - [II.2. General project structure](#ii2-general-project-structure)
  - [II.3. Configuration of environment variables in docker compose](#ii3-configuration-of-environment-variables-in-docker-compose)
    - [II.3.a Example environment variable](#ii3a-example-environment-variable)
    - [II.3.b Role of the variables](#ii3b-role-of-the-variables)
  - [II.4. Automatic generation of OpenCode files](#ii4-automatic-generation-of-opencode-files)
  - [II.5. Volumes and persistence](#ii5-volumes-and-persistence)
    - [II.5.a Important volumes](#ii5a-important-volumes)
    - [II.5.b What this allows](#ii5b-what-this-allows)
  - [II.6. Build and launch Darkmoon](#ii6-build-and-launch-darkmoon)
    - [II.6.a Building the images](#ii6a-building-the-images)
    - [II.6.b Launching the stack](#ii6b-launching-the-stack)
  - [II.7. Launch Darkmoon (User CLI)](#ii7-launch-darkmoon-user-cli)
    - [II.7.a Make the wrapper executable](#ii7a-make-the-wrapper-executable)
    - [II.7.b Install globally (optional)](#ii7b-install-globally-optional)
    - [II.7.c Launch Darkmoon with TUI Console](#ii7c-launch-darkmoon-with-tui-console)
    - [II.7.d View logs](#ii7d-view-logs)
  - [II.8. Direct access to the container (debug)](#ii8-direct-access-to-the-container-debug)
  - [II.9. Where to modify what (summary)](#ii9-where-to-modify-what-summary)
  - [II.10. Quick summary](#ii10-quick-summary)
- [III. Uses](#iii-uses)
  - [III.1. Prompt Examples](#iii1-prompt-examples)
- [IV. Architecture](#iv-architecture)
  - [IV.1. Core Idea](#iv1-core-idea)
  - [IV.2. Main Components (Who Does What)](#iv2-main-components-who-does-what)
    - [IV.2.a. OpenCode — The Brain](#iv2a-opencode--the-brain)
    - [IV.2.b. AI Agents — The Strategy Layer](#iv2b-ai-agents--the-strategy-layer)
    - [IV.2.c. MCP Darkmoon — The Security Gatekeeper](#iv2c-mcp-darkmoon--the-security-gatekeeper)
    - [IV.2.d. Darkmoon Toolbox — The Real Tools](#iv2d-darkmoon-toolbox--the-real-tools)
    - [IV.2.e. Docker \& Volumes — Isolation and Persistence](#iv2e-docker--volumes--isolation-and-persistence)
  - [IV.3. Execution Flow (Simple Overview)](#iv3-execution-flow-simple-overview)
    - [IV.3.a Deployment diagram](#iv3a-deployment-diagram)
    - [IV.3.b Network flow diagram](#iv3b-network-flow-diagram)
    - [IV.3.c Activity diagram — End-to-end penetration testing](#iv3c-activity-diagram--end-to-end-penetration-testing)
  - [IV.4. Security by Design](#iv4-security-by-design)
  - [IV.5. Why This Architecture Is Robust](#iv5-why-this-architecture-is-robust)
- [V. AI Agents](#v-ai-agents)
  - [V.1. What is a Darkmoon Agent?](#v1-what-is-a-darkmoon-agent)
  - [V.2. Agent Philosophy](#v2-agent-philosophy)
  - [V.3. Structure of a Darkmoon Agent](#v3-structure-of-a-darkmoon-agent)
    - [V.3.a Simplified Example](#v3a-simplified-example)
    - [V.3.b List of Agents](#v3b-list-of-agents)
    - [V.3.c Common Sections](#v3c-common-sections)
  - [V.4. Real Example: pentest-web](#v4-real-example-pentest-web)
  - [V.5. Critical Rules for Agents](#v5-critical-rules-for-agents)
    - [V.5.a Autonomy](#v5a-autonomy)
    - [V.5.b MCP-only](#v5b-mcp-only)
    - [V.5.c Communication](#v5c-communication)
  - [V.6. Where Agents Live](#v6-where-agents-live)
    - [V.6.a Before Build](#v6a-before-build)
    - [V.6.b After Build (Recommended)](#v6b-after-build-recommended)
  - [V.7. Agent Lifecycle](#v7-agent-lifecycle)
  - [V.8. Adding a New Agent](#v8-adding-a-new-agent)
    - [V.8.a. Method 1 — After Build (Recommended)](#v8a-method-1--after-build-recommended)
    - [V.8.b. Method 2 — Before Build](#v8b-method-2--before-build)
  - [V.9. Best Practices](#v9-best-practices)
  - [V.10. Summary](#v10-summary)
- [VI. Contributing](#vi-contributing)
- [VII. License](#vii-license)

# I. Preview

![darkmoon-preview.gif](docs/pics/darkmoon-preview.gif)

Here's an example of penetration testing of a [GOAD Active Directory Lab](https://github.com/Orange-Cyberdefense/GOAD)

[Back to Summary](#summary)

# II. Installation

## II.1. Prerequisites

Before starting, you must have:

- Docker
- Docker Compose
- Access to an LLM provider (OpenRouter, Anthropic, OpenAI…)

[Back to Summary](#summary)

## II.2. General project structure

Darkmoon relies on **Docker** and **Docker Compose**.

The important components are :

- an **OpenCode** container (AI + agents),
- a **Darkmoon Toolbox** container (pentest tools),
- **shared volumes** for configuration.

[Back to Summary](#summary)

## II.3. Configuration of environment variables in docker compose

Docker Compose is **the entry point for the entire AI configuration**.

[Back to Summary](#summary)

### II.3.a Example environment variable

```env
environment:
   # 🔽 TEST runtime variables LLM conf
   - OPENROUTER_PROVIDER=openai
   - OPENCODE_MODEL=gpt-4o
   - OPENROUTER_API_KEY=sk-svcacct-xxx
```

[Back to Summary](#summary)

### II.3.b Role of the variables

| Variable              | Role               |
| --------------------- | ------------------ |
| `OPENROUTER_PROVIDER` | LLM model provider |
| `OPENCODE_MODEL`      | Exact model used   |
| `OPENROUTER_API_KEY`  | Provider API key   |

👉 No secret is stored in the Docker image.

[Back to Summary](#summary)

## II.4. Automatic generation of OpenCode files

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

[Back to Summary](#summary)

## II.5. Volumes and persistence

Configuration files are persisted via Docker volumes.

[Back to Summary](#summary)

### II.5.a Important volumes

```yaml
- ./darkmoon-settings:/root/.config/opencode/:rw
- ./darkmoon-settings:/root/.local/share/opencode/:rw
- ./darkmoon-settings/agents:/root/.opencode/agents/:rw
```

[Back to Summary](#summary)

### II.5.b What this allows

- Modify the configuration **without rebuild**
- Add or modify AI agents
- Keep logs and OpenCode state

## II.6. Build and launch Darkmoon

### II.6.a Building the images

```bash
docker compose build
```

[Back to Summary](#summary)

### II.6.b Launching the stack

```bash
docker compose up -d
```

👉 The first launch may take some time (image build).

[Back to Summary](#summary)

## II.7. Launch Darkmoon (User CLI)

A wrapper is provided : `darkmoon.sh`.

[Back to Summary](#summary)

### II.7.a Make the wrapper executable

```bash
chmod +x darkmoon.sh
```

[Back to Summary](#summary)

### II.7.b Install globally (optional)

```bash
sudo cp darkmoon.sh /usr/local/bin/darkmoon
```

[Back to Summary](#summary)

### II.7.c Launch Darkmoon with TUI Console

```bash
darkmoon
```

Or with a direct command :

```bash
darkmoon "TARGET: mondomaine.com"
```

[Back to Summary](#summary)

### II.7.d View logs

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

[Back to Summary](#summary)

## II.8. Direct access to the container (debug)

It is possible to enter the OpenCode container directly :

```bash
docker exec -ti opencode bash
```

This allows :

- to inspect files,
- to modify agents,
- to test OpenCode directly.

[Back to Summary](#summary)

## II.9. Where to modify what (summary)

| Action                    | Where                             |
| ------------------------- | --------------------------------- |
| Change the LLM model      | `.env`                            |
| Modify `opencode.json`    | `darkmoon-settings/opencode.json` |
| Modify `auth.json`        | `darkmoon-settings/auth.json`     |
| Add an agent              | `darkmoon-settings/agents/`       |
| Add an agent before build | `conf/agents/`                    |

[Back to Summary](#summary)

## II.10. Quick summary

- `.env` → AI configuration
- `docker compose up -d` → launch
- `darkmoon` → usage
- Volumes → persistence & live modification

[Back to Summary](#summary)

# III. Uses

## III.1. Prompt Examples

Here's a list of prompt you can do with Darkmoon GPT

[Back to Summary](#summary)

# IV. Architecture

This document explains how Darkmoon is built, who is responsible for what, and why the architecture is robust. It avoids unnecessary low-level details while remaining technically clear.

**Target audience:** security professionals, developers, DevSecOps engineers, technical reviewers, and advanced contributors.

[Back to Summary](#summary)

## IV.1. Core Idea

Darkmoon is built around a strict and deliberate principle:

> The AI never interacts directly with pentesting tools.

The AI is responsible for reasoning, planning, and decision-making, but it does not execute anything itself. Every concrete action goes through a controlled intermediary layer. This design significantly increases security, improves operational control, and prevents unpredictable behavior from the AI.

[Back to Summary](#summary)

## IV.2. Main Components (Who Does What)

### IV.2.a. OpenCode — The Brain

OpenCode acts as the central orchestrator of the system. It communicates with the LLM, manages AI agents, determines the next actions to perform, and calls the MCP whenever a real-world action is required. Importantly, OpenCode never executes any pentesting tool directly. It strictly remains at the orchestration and reasoning level.

[Back to Summary](#summary)

### IV.2.b. AI Agents — The Strategy Layer

AI agents are defined in Markdown files. Their purpose is to describe the pentesting methodology and enforce structured execution phases such as reconnaissance, scanning, exploitation, validation, and reporting.

Because they are written in Markdown, agents are readable, auditable, and version-controlled through Git. They can be modified without rebuilding the entire project. This design ensures transparency and flexibility while maintaining strict behavioral constraints such as autonomy and non-interactivity.

[Back to Summary](#summary)

### IV.2.c. MCP Darkmoon — The Security Gatekeeper

The MCP is the central security boundary of Darkmoon. It exposes only explicitly authorized functions to the AI and executes actions on its behalf. All inputs and outputs are strictly controlled and structured.

This means the AI can only perform operations that the MCP explicitly allows. The MCP effectively acts as an internal controlled API layer, ensuring that the AI never gains direct access to the system or execution environment.

[Back to Summary](#summary)

### IV.2.d. Darkmoon Toolbox — The Real Tools

The Toolbox contains the actual pentesting tools and runs inside a dedicated Docker container. Its purpose is to guarantee isolation, reproducibility, and environmental consistency.

Tools are compiled once and executed within a minimal runtime environment. This reduces dependencies, minimizes the attack surface, and ensures stable behavior across deployments.

[Back to Summary](#summary)

### IV.2.e. Docker & Volumes — Isolation and Persistence

Docker is used to isolate system components from each other and from the host system. This reduces risk exposure and enforces strict runtime boundaries. Volumes allow configuration and data to persist while still enabling dynamic modifications without requiring full redeployment.

[Back to Summary](#summary)

## IV.3. Execution Flow (Simple Overview)

When a user submits a prompt, OpenCode analyzes the request and delegates the mission to an AI agent. The agent determines the appropriate strategy and, when an action is needed, calls a function exposed by the MCP. The MCP then executes the corresponding tool inside the Docker-based Toolbox. Results are returned to the MCP, passed back to the agent in structured form, and used to determine the next step or produce a final report. The entire flow remains controlled and traceable.

[Back to Summary](#summary)

### IV.3.a Deployment diagram

This diagram illustrates the overall architecture and data flow of the system. The User interacts with the platform through a command-line interface or prompt sent to DarkmoonCLI. This interface forwards the request to OpenCode, which acts as the orchestration layer responsible for managing AI-driven tasks.

OpenCode communicates with MCP (Model Context Protocol) to access external capabilities.

MCP then interacts with the Toolbox, a collection of tools executed through the Docker API, allowing isolated and reproducible execution environments. This layered architecture separates the user interface, AI orchestration, tool abstraction, and actual execution of security tools.

```mermaid
flowchart LR
  User -->|CLI / Prompt| DarkmoonCLI
  DarkmoonCLI --> OpenCode
  OpenCode --> MCP
  MCP -->|Docker API| Toolbox
```

[Back to Summary](#summary)

### IV.3.b Network flow diagram

This sequence diagram describes the step-by-step interaction between the user, the AI system, and the execution environment. The process begins when the User submits a prompt to OpenCode. OpenCode delegates the task to an AI Agent, which determines the appropriate actions to perform. The agent calls a function exposed through MCP Darkmoon, which serves as a standardized interface to external tools.

MCP then triggers the execution of a real tool inside the Docker Toolbox. Once the tool finishes its execution, the results are returned to MCP, which formats them into a structured output.

The AI agent analyzes these results to decide the next action or produce a conclusion. Finally, OpenCode delivers a summarized result back to the user.

```mermaid
sequenceDiagram
  participant U as User
  participant O as OpenCode
  participant A as AI Agent
  participant M as MCP Darkmoon
  participant T as Docker Toolbox

  U->>O: User prompt
  O->>A: Delegate task
  A->>M: MCP function call
  M->>T: Execute real tool
  T-->>M: Results
  M-->>A: Structured output
  A-->>O: Next decision
  O-->>U: Summary / result
```

[Back to Summary](#summary)

### IV.3.c Activity diagram — End-to-end penetration testing

This diagram represents the logical workflow followed by the AI agent during an automated security testing process. The workflow starts when a user prompt triggers the AI Agent, which initiates a reconnaissance phase to gather information about the target system. The process then moves to automated scanning, where vulnerabilities are searched using automated tools.

If potential weaknesses are discovered, the agent attempts targeted exploitation to verify their existence. The impact validation phase confirms whether the exploitation leads to a meaningful security impact. If further exploration is required, the workflow loops back to the scanning phase for deeper analysis.

Once sufficient findings are collected, the system performs correlation and reporting, producing a structured report before reaching the final step of the process.

```mermaid
flowchart TD
  Start([User Prompt])
  Agent[AI Agent]
  Recon[Reconnaissance]
  Scan[Automated Scanning]
  Exploit[Targeted Exploitation]
  Validate[Impact Validation]
  Report[Correlation & Reporting]
  End([End])

  Start --> Agent
  Agent --> Recon
  Recon --> Scan
  Scan --> Exploit
  Exploit --> Validate
  Validate --> Scan
  Validate --> Report
  Report --> End
```

[Back to Summary](#summary)

## IV.4. Security by Design

Darkmoon enforces clear boundaries:

| From    | To      | Role             |
| ------- | ------- | ---------------- |
| Agent   | MCP     | Action control   |
| MCP     | Toolbox | Secure execution |
| Toolbox | Host    | Docker isolation |

The AI does:

- Never executes system commands
- Never controls Docker
- Never leaves its designated scope

[Back to Summary](#summary)

## IV.5. Why This Architecture Is Robust

The architecture is robust because responsibilities are clearly separated and there is no hidden or implicit logic. Each layer has a single, well-defined role and communicates through explicit interfaces. Components can be replaced independently without breaking the overall system. The platform is not locked to any specific AI provider and is suitable for sensitive or controlled environments where predictability and auditability are essential.

> [!note]
> For a deeper understanding of how agents operate, see [🤖 AI Agents](#v--ai-agents).

[Back to Summary](#summary)

# V. AI Agents

This document describes **how AI agents work in Darkmoon**:

- their role,
- their structure,
- their rules,
- and how to create or modify them.

Target audience:

- advanced pentesters
- agent creators
- security researchers
- contributors

[Back to Summary](#summary)

## V.1. What is a Darkmoon Agent?

A Darkmoon agent is:

- a **Markdown file**,
- loaded by OpenCode,
- that defines **autonomous behavior**,
- and controls the MCP to perform real actions.

👉 It is **not** a standard prompt.
👉 It is a **complete operational strategy**.

[Back to Summary](#summary)

## V.2. Agent Philosophy

Darkmoon agents are designed to:

- act **without asking questions**,
- assume explicit authorization,
- automatically chain actions,
- favor depth over speed,
- correlate results.

An agent **does not ask**:

- “Do you want to continue?”
- “What is the scope?”

👉 The scope is **already defined by the user**.

[Back to Summary](#summary)

## V.3. Structure of a Darkmoon Agent

An agent is a structured Markdown file.

### V.3.a Simplified Example

```markdown
---
id: pentest-web
name: pentest-web
description: Fully autonomous pentest agent
---

You are an autonomous AI cybersecurity agent.
```

### V.3.b List of Agents

Currently, there are 4 agents:

- `pentest-web` — the agent dedicated to web application pentesting, attempts attacks like XSS, SQLi, SSRF, XXE, etc.
- `pentest-ad` — the agent for Windows infrastructure and Active Directory pentesting (ADDS, SMB, Windows, etc.).
- `pentest-kubernetes` — the agent for surface attack pentesting of a Kubernetes cluster.
- `pentest-network` — the agent for network infrastructure attacks (FTP, FTPS, SFTP, SSH, TELNET, SMTP, SNMP, etc.).

### V.3.c Common Sections

- metadata (`id`, `name`, `description`)
- execution rules
- capabilities
- communication rules
- MCP call rules
- security constraints

[Back to Summary](#summary)

## V.4. Real Example: pentest-web

The `pentest-web` agent is:

- fully autonomous,
- focused on real pentesting,
- aggressive but non-destructive,
- based **exclusively on MCP**.

It:

- chooses its own workflows,
- can directly execute tools via MCP,
- correlates results between steps,
- iterates until attack vectors are exhausted.

👉 It is an **AI pentester**, not an assistant.

[Back to Summary](#summary)

## V.5. Critical Rules for Agents

### V.5.a Autonomy

An agent:

- never asks for confirmation,
- never asks for user input,
- acts immediately.

### V.5.b MCP-only

An agent:

- **never touches Docker**,
- **never launches tools directly**,
- always goes through MCP.

This ensures:

- auditability,
- control,
- security.

### V.5.c Communication

Agents:

- minimize user messages,
- prioritize tool calls,
- never expose internal reasoning.

[Back to Summary](#summary)

## V.6. Where Agents Live

### V.6.a Before Build

```
conf/agents/
```

These agents are:

- integrated into the image,
- automatically copied at first launch.

### V.6.b After Build (Recommended)

```
darkmoon-settings/agents/
```

Advantages:

- modify without rebuild,
- persistence,
- external versioning.

[Back to Summary](#summary)

## V.7. Agent Lifecycle

1. OpenCode starts
2. Checks if agents already exist
3. Initial seed if needed
4. Dynamic loading
5. On-demand execution

👉 The seed only happens **once**.

[Back to Summary](#summary)

## V.8. Adding a New Agent

### V.8.a. Method 1 — After Build (Recommended)

1. Create a `.md` file in:

```
darkmoon-settings/agents/
```

2. Restart Darkmoon
3. The agent is immediately available

### V.8.b. Method 2 — Before Build

1. Add the agent in:

```
conf/agents/
```

2. Rebuild the stack
3. The agent will be automatically seeded

[Back to Summary](#summary)

## V.9. Best Practices

- One agent = one clear role
- Do not mix scanning, reporting, and remediation
- Prefer multiple specialized agents
- Keep rules strict
- Test progressively

[Back to Summary](#summary)

## V.10. Summary

Darkmoon agents:

- are autonomous,
- auditable,
- extensible,
- and secure by design.

They form **the strategic brain** of the platform.

➡️ To understand how agents execute actions:
see `docs/workflows.md`

[Back to Summary](#summary)

# VI. Contributing

If you to contribute to the project, you access to the coding guideline at [CONTRIBUTING.md](CONTRIBUTING.md)

[Back to Summary](#summary)

# VII. License

Code licensed under [GNU GPL v3](LICENSE)

[Back to Summary](#summary)
