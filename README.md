<center>

![DarkMoon Logo](docs/pics/DARKMOON%20LOGOTYPE%20PRINCIPAL%20CHRYSLER%20RVB%20900PX%20W%2072PPI.png)

A platform that allows you to conduct a complete penetration testing campaign

</center>

## Summary

- [Summary](#summary)
- [I. Preview](#i-preview)
- [II. Prerequisites](#ii-prerequisites)
  - [II.1. Dependencies](#ii1-dependencies)
- [III. Architecture](#iii-architecture)
  - [III.1. 🧠 Core Idea](#iii1--core-idea)
  - [III.2. 🧩 Main Components (Who Does What)](#iii2--main-components-who-does-what)
    - [III.2.a. 🧠 OpenCode — The Brain](#iii2a--opencode--the-brain)
    - [III.2.b. 🤖 AI Agents — The Strategy Layer](#iii2b--ai-agents--the-strategy-layer)
    - [III.2.c. 🔐 MCP Darkmoon — The Security Gatekeeper](#iii2c--mcp-darkmoon--the-security-gatekeeper)
    - [III.2.d. 🧰 Darkmoon Toolbox — The Real Tools](#iii2d--darkmoon-toolbox--the-real-tools)
    - [III.2.e. 🐳 Docker \& Volumes — Isolation and Persistence](#iii2e--docker--volumes--isolation-and-persistence)
  - [III.3. 🔄 Execution Flow (Simple Overview)](#iii3--execution-flow-simple-overview)
  - [III.4. 🔐 Security by Design](#iii4--security-by-design)
  - [III.5. 🧱 Why This Architecture Is Robust](#iii5--why-this-architecture-is-robust)
- [IV. Uses](#iv-uses)
- [X. License](#x-license)

## I. Preview

[Back to Summary](#summary)

## II. Prerequisites

### II.1. Dependencies

[Back to Summary](#summary)

## III. Architecture

This document explains how Darkmoon is built, who is responsible for what, and why the architecture is robust. It avoids unnecessary low-level details while remaining technically clear.

**Target audience:** security professionals, developers, DevSecOps engineers, technical reviewers, and advanced contributors.

[Back to Summary](#summary)

### III.1. 🧠 Core Idea

Darkmoon is built around a strict and deliberate principle:

> The AI never interacts directly with pentesting tools.

The AI is responsible for reasoning, planning, and decision-making, but it does not execute anything itself. Every concrete action goes through a controlled intermediary layer. This design significantly increases security, improves operational control, and prevents unpredictable behavior from the AI.

[Back to Summary](#summary)

### III.2. 🧩 Main Components (Who Does What)

#### III.2.a. 🧠 OpenCode — The Brain

OpenCode acts as the central orchestrator of the system. It communicates with the LLM, manages AI agents, determines the next actions to perform, and calls the MCP whenever a real-world action is required. Importantly, OpenCode never executes any pentesting tool directly. It strictly remains at the orchestration and reasoning level.

[Back to Summary](#summary)

#### III.2.b. 🤖 AI Agents — The Strategy Layer

AI agents are defined in Markdown files. Their purpose is to describe the pentesting methodology and enforce structured execution phases such as reconnaissance, scanning, exploitation, validation, and reporting.

Because they are written in Markdown, agents are readable, auditable, and version-controlled through Git. They can be modified without rebuilding the entire project. This design ensures transparency and flexibility while maintaining strict behavioral constraints such as autonomy and non-interactivity.

[Back to Summary](#summary)

#### III.2.c. 🔐 MCP Darkmoon — The Security Gatekeeper

The MCP is the central security boundary of Darkmoon. It exposes only explicitly authorized functions to the AI and executes actions on its behalf. All inputs and outputs are strictly controlled and structured.

This means the AI can only perform operations that the MCP explicitly allows. The MCP effectively acts as an internal controlled API layer, ensuring that the AI never gains direct access to the system or execution environment.

[Back to Summary](#summary)

#### III.2.d. 🧰 Darkmoon Toolbox — The Real Tools

The Toolbox contains the actual pentesting tools and runs inside a dedicated Docker container. Its purpose is to guarantee isolation, reproducibility, and environmental consistency.

Tools are compiled once and executed within a minimal runtime environment. This reduces dependencies, minimizes the attack surface, and ensures stable behavior across deployments.

[Back to Summary](#summary)

#### III.2.e. 🐳 Docker & Volumes — Isolation and Persistence

Docker is used to isolate system components from each other and from the host system. This reduces risk exposure and enforces strict runtime boundaries. Volumes allow configuration and data to persist while still enabling dynamic modifications without requiring full redeployment.

[Back to Summary](#summary)

### III.3. 🔄 Execution Flow (Simple Overview)

When a user submits a prompt, OpenCode analyzes the request and delegates the mission to an AI agent. The agent determines the appropriate strategy and, when an action is needed, calls a function exposed by the MCP. The MCP then executes the corresponding tool inside the Docker-based Toolbox. Results are returned to the MCP, passed back to the agent in structured form, and used to determine the next step or produce a final report. The entire flow remains controlled and traceable.

[Back to Summary](#summary)

### III.4. 🔐 Security by Design

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

### III.5. 🧱 Why This Architecture Is Robust

The architecture is robust because responsibilities are clearly separated and there is no hidden or implicit logic. Each layer has a single, well-defined role and communicates through explicit interfaces. Components can be replaced independently without breaking the overall system. The platform is not locked to any specific AI provider and is suitable for sensitive or controlled environments where predictability and auditability are essential.

For a deeper understanding of how agents operate, see `docs/agents.md`.

[Back to Summary](#summary)

## IV. Uses

[Back to Summary](#summary)

## X. License

[Back to Summary](#summary)
