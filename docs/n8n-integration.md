# n8n community node — `n8n-nodes-darkmoon`

> Wire DarkMoon into your automations. The **`n8n-nodes-darkmoon`** community node
> lets an [n8n](https://n8n.io) workflow **trigger a DarkMoon pentest against a
> target you are authorised to assess, pull back the findings, and review the fix
> pull requests DarkMoon prepares** — so security testing and remediation review
> can be wired into CI/CD, ticketing, chat and reporting automations like any
> other step.

- **Package:** `n8n-nodes-darkmoon` (v0.3.0) — **live on npm**, installable via n8n Community Nodes: `n8n-nodes-darkmoon`
- **npm:** <https://www.npmjs.com/package/n8n-nodes-darkmoon>
- **Repository:** <https://github.com/ASCIT31/darkmoon-n8n>
- **License:** MIT

> DarkMoon **runs and validates** security tests; it does not, and this node does
> not, guarantee that a system is secure. Findings can include false positives and
> must be reviewed by a qualified human. Only run assessments against systems you
> own or have explicit written authorisation to test. **This node never merges a
> pull request** — every fix is left for a person to review and merge.

## Installation

Follow the [n8n community nodes installation guide](https://docs.n8n.io/integrations/community-nodes/installation/).
In a self-hosted n8n: **Settings → Community Nodes → Install**, then enter
`n8n-nodes-darkmoon`.

## Credentials

The node talks to the **DarkMoon Dashboard API** (the FastAPI service shipped with
DarkMoon, typically on port `8000`). Create a **DarkMoon API** credential with a
Base URL (e.g. `http://darkmoon.internal:8000`), a dashboard username and password;
the node logs in at run time (`POST /api/v1/auth/login`) to obtain a short-lived
JWT. Use the credential's **Test** button to verify.

> **Requires DarkMoon Pro.** The REST **Dashboard API** (`/api/v1/*`), its
> authentication, the remediation → pull-request engine and the PDF export are
> **Pro** components — they are not part of the open-source engine. The community
> (open source) edition runs as **CLI + MCP + local JSON + Markdown report** and
> has no REST API for this node to connect to.

## Operations

| Operation | What it does |
|---|---|
| **Run Pentest** | Starts a pentest against a target (URL or host). With *Wait for Completion* on (default) it polls to completion and returns the campaign, findings and severity stats; off, it returns the `run_id` for a later *Get Findings*. Options include additional/out-of-scope targets, focus areas, minimum severity, and **Enable Remediation** (see below). |
| **Get Findings** | Returns the vulnerabilities for a campaign, with aggregated stats (`by_severity`, `by_category`, `by_status`). |
| **Get Report** | Returns the markdown report for a campaign. |
| **List Campaigns** | Lists past and running campaigns. |
| **List Pull Requests** | Lists the fix pull requests DarkMoon prepared. Server-side filter: `campaign_id`; state / provider / repository filters are applied client-side. States: `proposed`, `draft`, `open`, `merged`, `closed`, `error`. |
| **Get Pull Request** | Returns one PR record (diff summary, validation, linked findings). |
| **Get Pull Requests by Finding** | Returns the PRs that address a specific finding. |

## Remediation from the node

DarkMoon can, after confirming an issue, generate a fix and open a **pull request**
for a human to review. This is a Pro capability that runs **during** the pentest —
not a separate API call. In the node it is turned on with **Enable Remediation**
on the *Run Pentest* operation (default **off**; with it off, behaviour is
unchanged and only findings are returned).

When enabled, provide under *Remediation Settings* a **Credential Reference**
(required) — the **opaque id** of an SCM credential stored in DarkMoon's vault,
**not a token** — and optionally the repository URL, whether DarkMoon may create
the repo, and a bounded wait for the PRs to appear.

```
confirmed finding → generate fix → validate in sandbox → retest → open pull request → human review → manual merge
```

**Pull requests are read-only through the API and this node.** PR records are
created by DarkMoon's remediation agent during the run; there is no endpoint to
open, update or merge a PR, and this node deliberately provides none. Merging is
always a manual human step in your SCM.

## Example workflow

The repo ships **"DarkMoon Pentest and Remediation Review"**
(`examples/darkmoon-pentest-and-remediation-review.json`): it triggers a pentest
on an authorised demo-lab target, enables remediation with a credential reference,
waits for completion, lists the reviewable pull requests (`proposed` / `draft` /
`open`), and summarises everything into a message ready for a Slack / Microsoft
Teams / Jira / Linear / GitHub / email node. It **merges nothing**. Replace the
target, the DarkMoon credential and the opaque credential reference before running.

## Security notes

- **No SCM tokens in workflow parameters** — remediation takes an opaque vault
  reference, never a raw token or key. The SCM secret stays in DarkMoon's encrypted
  vault; the dashboard password stays in the n8n credential store.
- **No secrets in logs** — the node never logs requests or credentials; errors
  surface only the API's own `detail` message.
- **No automatic merges** — the API exposes pull requests read-only; the node has
  no write/merge operation.
- **Authorised targets only** — run assessments only against systems you own or are
  explicitly authorised to test.
