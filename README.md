<div align="center">

![DarkMoon Logo](docs/pics/logo_blue.png)

# DarkMoon

### The open-source AI penetration testing platform that runs a full pentest on its own, and never leaks your data

**Point DarkMoon at an authorized target. 50 specialist AI agents reason, chain real exploits across web, cloud, Active Directory and Kubernetes, and return proof for every finding. Self-hosted, and the model only ever sees `IP_PRIVATE_001`, never your real IPs, hosts or credentials.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub stars](https://img.shields.io/github/stars/ASCIT31/Dark-Moon?style=social&label=Star)](https://github.com/ASCIT31/Dark-Moon)
[![Benchmark: 57 vulns on OWASP Juice Shop](https://img.shields.io/badge/benchmark-57%20real%20vulns%20on%20Juice%20Shop-critical)](https://github.com/ASCIT31/Darkmoon-Benchmarks)

[**⭐ Star DarkMoon**](https://github.com/ASCIT31/Dark-Moon) · [**▶️ Watch the 60s demo**](https://youtu.be/1bFRVuMkZzY?si=peKxwuxzbXBnb2zO) · [**🚀 Quickstart**](#quick-start) · [**📊 57-vuln benchmark**](https://github.com/ASCIT31/Darkmoon-Benchmarks)

**As featured in** [Help Net Security](https://www.helpnetsecurity.com/2026/06/29/darkmoon-open-source-ai-pentesting-platform/) · [Cyber Security News](https://cybersecuritynews.com/darkmoon-penetration-testing-platform/) · [DevOps.com](https://devops.com/why-ci-cd-security-testing-is-going-autonomous-and-why-it-should-stay-local/) · [SecurityBrief](https://securitybrief.co.uk/story/asc-it-launches-darkmoon-for-private-ai-pentesting) · [LinuxLinks](https://www.linuxlinks.com/darkmoon-ai-powered-autonomous-penetration-testing-platform/) · [IT Brief](https://itbrief.co.uk/story/asc-it-launches-darkmoon-for-private-ai-pentesting) · [ChannelLife](https://channellife.co.uk/story/asc-it-launches-darkmoon-for-private-ai-pentesting)

<a href="https://youtu.be/1bFRVuMkZzY?si=peKxwuxzbXBnb2zO">
  <img src="docs/pics/darkmoon-youtube.png" alt="Watch DarkMoon run a full autonomous penetration test" />
</a>

**▶️ Watch DarkMoon run a full autonomous penetration test**

</div>

---

## What is DarkMoon?

DarkMoon is an **open-source AI penetration testing** platform. Point it at a target you are authorized to test, and it runs the whole assessment on its own: it reasons, plans, and dispatches **50 specialist agents** that execute real offensive operations through a controlled MCP layer, then reports every vulnerability with the exact command, the raw output and the proof behind it.

It does not replace the pentester. It clears the repetitive part of an assessment with evidence, so your experts spend their time on judgment, not toil.

---

## Why DarkMoon?

- 🌐 **Beyond the web** — one agentic system across web, APIs, Active Directory, Kubernetes, cloud (AWS, Azure, GCP), CI/CD, databases and IoT firmware, chained end to end
- 🕶️ **Your data never reaches the LLM** — reversible local tokenization turns real IPs, hostnames, URLs, credentials and paths into deterministic placeholders (`IP_PRIVATE_001`, ...), rehydrated locally only at the moment a tool runs and masked back out of every result. Runs fully on a local model. And it never costs you a command: when a value is headed somewhere it must not go, the command still runs and the far end receives the placeholder instead. This is the part no cloud competitor has.
- 🧾 **Proof, not scores** — every finding ships with the exact command and raw output, reproducible, so there is nothing to trust blindly and almost nothing to triage
- 🔧 **50 specialist agents, 50+ offensive tools** — Nuclei, NetExec, BloodHound, sqlmap, Impacket, Naabu, httpx, ffuf and more, orchestrated over MCP
- 🛡️ **Security by design** — the AI never runs a command directly; every action flows through a controlled, logged MCP interface
- ♾️ **CI/CD native** — trigger a pentest in the pipeline and get findings as artifacts
- 📖 **Nothing hidden** — GPLv3, self-hosted, each agent's methodology is plain Markdown you can read, diff and fork

Built for **security teams**, **DevSecOps engineers**, **red teamers** and **ethical hacking** professionals.

---

## 📊 Benchmark: 57 real vulnerabilities on OWASP Juice Shop

Real, reproducible **black-box** run against OWASP Juice Shop on a **local LLM** (nothing leaves your infrastructure):

| Metric | Result |
|---|---|
| Vulnerabilities found | **57** (8 critical / 24 high / 21 medium / 4 low) |
| Wall-clock time | **28.5 min** |
| Proof-of-exploitation | per finding |
| LLM | local (Ollama / llama.cpp) |

Reproduce it and compare tools yourself: **[ASCIT31/Darkmoon-Benchmarks](https://github.com/ASCIT31/Darkmoon-Benchmarks)**.

## 🆚 How DarkMoon compares

| | **DarkMoon** | strix | shannon | PentAGI |
|---|:--:|:--:|:--:|:--:|
| Runs on **local LLM** (data never leaves) | ✅ | ❌ cloud | ❌ cloud | partial |
| Privacy Gateway (local tokenization) | ✅ | ❌ | ❌ | ❌ |
| Active Directory + Kubernetes | ✅ | ❌ | ❌ | partial |
| Proof-of-exploitation | ✅ | ✅ | ✅ | ✅ |
| Open source | ✅ GPL-3.0 | ✅ | ✅ | ✅ |

*Compiled from public repos/docs (2026-08); corrections welcome via PR.*

## Quick Start

### Prerequisites

- Docker & Docker Compose
- An LLM API key (OpenRouter, Anthropic, OpenAI, or local models)

> **Note:** GPU configuration, NVIDIA driver troubleshooting, and advanced environment setup are covered in the [Full Documentation, GPU Troubleshooting](docs/full.md#ii2--darkmoon--gpu-troubleshooting-guide-official).

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/ASCIT31/Dark-Moon.git
cd Dark-Moon
```

**2. Configure your LLM provider**

`install.sh` handles provider configuration interactively, no need to edit `docker-compose.yml`:

```bash
./install.sh           # skip form if .opencode.env already configured
./install.sh --init    # force reconfiguration (cloud or local model)
./install.sh --help    # show usage
```

Supports **cloud providers** (Anthropic, OpenAI, OpenRouter…) and **local models** (Ollama, llama.cpp).

> **Note:** For full details on environment variables and local model setup, see the [Full Documentation, Environment Variables](docs/full.md#ii3-configuration-of-environment-variables).

**3. Build and launch**

```bash
./install.sh  # Clean install with full stack reset
```

**4. Run your first assessment**

```bash
./darkmoon.sh "TARGET: example.com"
```

**5. Monitor in real-time**

```bash
./darkmoon.sh --log <session_id>
```

> **Note:** Real-time session logs display every command executed by the MCP server. See [Full Documentation, Session Logs](docs/full.md#ii7e-step-1--start-an-assessment) for details.

---

## How It Works

DarkMoon operates as a strategic **AI security agent** orchestrator aligned with ISO 27001, NIST SP 800-115, and MITRE ATT&CK methodologies.

When you provide a target, the platform automatically:

1. 🔍 **Discovers** the target environment (ports, services, protocols)
2. 🧠 **Fingerprints** the technology stack (frameworks, CMS, APIs)
3. 🎯 **Models** the attack surface
4. 🚀 **Deploys** specialized sub-agents based on detected technologies
5. 🔬 **Executes** an **intelligent vulnerability scanning** loop with reactive adaptation
6. ✅ **Validates** findings with evidence (requests, payloads, responses)
7. 📝 **Generates** a structured audit report

### Sub-Agent Orchestration

DarkMoon dynamically selects and dispatches specialized agents depending on the technologies discovered:

| Detected Technology | Agent Triggered |
|---|---|
| WordPress, Drupal, Joomla, Magento, PrestaShop, Moodle | CMS-specific agent |
| PHP, Node.js, Flask, ASP.NET, Spring Boot, Ruby on Rails, Go | Stack-specific agent |
| GraphQL | GraphQL agent |
| Active Directory | AD agent |
| Kubernetes | Kubernetes agent |
| AWS, Azure, GCP | Cloud-provider agent |
| Entra ID (Microsoft identity) | Identity agent |
| GitHub, GitLab, Jenkins | SCM & CI/CD agent |
| Terraform, Ansible | Infrastructure-as-Code agent |
| Docker, container registries | Container agent |
| HashiCorp Vault | Secrets agent |
| PostgreSQL, MySQL, MSSQL, Oracle | Database agent |
| Redis, RabbitMQ, Kafka, MQTT | Messaging & cache agent |
| Firmware / IoT images | Firmware agent |
| Headless browser required | Headless browser agent |

Multiple agents can execute **in parallel** across hybrid architectures.

Planes that require credentials to be meaningful (cloud accounts, CI/CD, secret stores, databases, Active Directory, Kubernetes) are **never dispatched on inference**. They fire only when a concrete artifact is found (a key, a token, a reachable metadata endpoint) or when you authorize them explicitly, and are otherwise flagged in the report.

> **Note:** For the complete list of agents, their structure, lifecycle, and how to create custom agents, see [Full Documentation, AI Agents](docs/full.md#v-ai-agents).

### Architecture Overview

```
User ──> DarkmoonCLI ──> OpenCode (AI Brain) ──> MCP (Security Gatekeeper) ──> Docker Toolbox (Real Tools)
```

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

The AI reasons and plans. The MCP controls what can be executed. The Toolbox runs isolated tools inside Docker. **The AI never directly touches the system**, this is **security by design**.

> **Note:** For the full architecture breakdown (deployment diagrams, network flows, security boundaries), see [Full Documentation, Architecture](docs/full.md#iv-architecture).

---

## Scope Definition

DarkMoon supports flexible scope definition directly from the command line.

**Quick pentest (zero config):**

```bash
./darkmoon.sh "TARGET: http://172.19.0.3:3000"
```

**Bug bounty mode (flags activate automatically):**

```bash
./darkmoon.sh "TARGET: http://172.19.0.3:3000 PROGRAM=\"Juice Shop\" FOCUS=sqli,xss,idor NOISE=moderate FORMAT=h1"
```

Key flags include `FOCUS`, `EXCLUDE`, `CREDS`, `TOKEN`, `NOISE`, `SEVERITY`, `FORMAT`, and more, all interpreted naturally by the AI.

> **Note:** For the complete flags reference, asset types, EXCLUDE/FOCUS free-form syntax, and advanced multi-target scoping, see [Full Documentation, Scope Definition](docs/full.md#ii7c-launch-darkmoon-with-tui-console).

---

## Integrated Toolbox

DarkMoon ships with a purpose-built Docker image containing **50+ security tools** compiled and optimized in a multi-stage build:

| Category | Tools (examples) |
|---|---|
| Port scanning | Naabu (discovery), nmap (targeted service probes) |
| Web scanning | Nuclei, ffuf, dirb, sqlmap, Arjun, wafw00f |
| Recon & crawling | Subfinder, Katana, Waybackurls, httpx |
| CMS | WPScan, CMSeeK, WhatWeb |
| Active Directory | NetExec, BloodHound, Impacket (30+ scripts) |
| Kubernetes | kubectl, Kubescape, Kubeletctl, kube-bench, rbac-police |
| Cloud CLIs | aws, az, gcloud, gsutil, bq |
| Databases & cache | psql, mysql, redis-cli, sqlite3 |
| Firmware / IoT | binwalk, unsquashfs, sasquatch, firmwalker |
| Cracking | hashcat, john, 7z2john |
| Network | Hydra, curl, dig, SNMP tools |
| Browser | Lightpanda (headless) |

All tools are directly accessible, no path configuration needed.

> **Note:** For the complete tools list with installation details and how to add new tools, see [Full Documentation, Toolbox](docs/full.md#vi-toolbox).

---

## 📖 Documentation Guide

DarkMoon's [Full Documentation](docs/full.md) covers everything you need to operate the platform. Here is a quick reference to the most important sections:

| Topic | What You'll Find | Link |
|---|---|---|
| **GPU & Driver Setup** | NVIDIA troubleshooting for Docker, WSL, and native Linux | [GPU Guide](docs/full.md#ii2--darkmoon--gpu-troubleshooting-guide-official) |
| **Environment Variables** | LLM provider configuration, API keys, model selection | [Environment Config](docs/full.md#ii3-configuration-of-environment-variables-in-docker-compose) |
| **Startup & Build** | install.sh behavior, docker compose build, stack management | [Build & Launch](docs/full.md#ii6-build-and-launch-darkmoon) |
| **Scope & Flags** | TARGET syntax, bug bounty mode, FOCUS/EXCLUDE, credentials | [Scope Definition](docs/full.md#ii7c-launch-darkmoon-with-tui-console) |
| **Assessment Workflow** | Step-by-step: discovery, fingerprinting, agents, reporting | [Assessment Engine](docs/full.md#ii7d-how-to-use-the-darkmoon-assessment-engine) |
| **Real-Time Session Logs** | Monitor commands executed by the MCP server live | [Session Logs](docs/full.md#ii7e-step-1--start-an-assessment) |
| **AI Agents** | Agent structure, lifecycle, how to create or modify agents | [AI Agents](docs/full.md#v-ai-agents) |
| **Architecture** | Deployment diagrams, security boundaries, execution flow | [Architecture](docs/full.md#iv-architecture) |
| **Toolbox** | Complete tool list, adding tools, Docker image internals | [Toolbox](docs/full.md#vi-toolbox) |
| **MCP Workflows** | Workflow structure, creating custom workflows, best practices | [MCP Workflows](docs/full.md#vii-mcp-workflows) |
| **Available Tools List** | Full table of 50+ tools with paths and sources | [Tools List](docs/full.md#vi10-toolbox-list) |
| **Training Labs** | Recommended vulnerable labs to train DarkMoon | [Pentester Labs](docs/full.md#vi11-bonus-pentester-lab-to-train-darkmoon) |

---

## Use Cases

DarkMoon is designed as a versatile **security testing platform** for:

- 🔒 **Security teams**, run continuous **automated penetration testing** across your infrastructure
- ⚙️ **DevSecOps pipelines**, integrate **AI-driven security research** into CI/CD workflows
- 🎯 **Bug bounty hunters**, accelerate **ethical hacking** with autonomous target analysis
- 🔬 **Security researchers**, explore attack surfaces with an **AI cybersecurity platform** that adapts in real time
- 🎓 **Training & education**, learn offensive security with guided, reproducible assessments

---

## Example Prompts

```bash
# Web application pentest
./darkmoon.sh "TARGET: http://172.19.0.3:3000"

# Active Directory assessment
./darkmoon.sh "TARGET: 192.168.1.10"

# Bug bounty with specific focus
./darkmoon.sh "TARGET: https://app.example.com PROGRAM=\"Example BB\" FOCUS=sqli,rce,ssrf EXCLUDE=H1 FORMAT=h1"
```

> **Note:** For more prompt examples including DVGA, Juice Shop, and headless browser scenarios, see [Full Documentation, Prompt Examples](docs/full.md#iii-uses).

---

## Contributing

DarkMoon is open source and welcomes contributions. Whether you want to add new agents, integrate tools, create workflows, or improve documentation, see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by ASC-IT with 💚 for the global security community**

🔒 Open Source · 🤖 AI-Powered · 🇫🇷 Made in France

[⭐ Star us on GitHub](https://github.com/ASCIT31/Dark-Moon) · [📖 Full Documentation](docs/full.md) · [▶️ Watch the Demo](https://youtu.be/1bFRVuMkZzY?si=peKxwuxzbXBnb2zO)

</div>
