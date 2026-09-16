# Remediation agent — findings to sandbox-validated fix pull requests

> **Edition:** Pro. **One line:** after a pentest, a defensive agent turns each
> confirmed finding into a minimal code fix, proves it in an ephemeral sandbox,
> and opens a **pull request for human review — never a merge.**

DarkMoon's specialists prove impact. The remediation agent is their defensive
counterpart: it reads the campaign's confirmed findings, locates the root cause
in the target's **own source**, writes the smallest correct fix, **reproduces
the exploit before the patch and re-runs it (plus payload variants and the repo's
tests) after** to prove the fix works without regressing, and opens a pull
request carrying that evidence. A human reviews and merges.

DarkMoon **runs and validates** security tests and their fixes. It does **not**
guarantee that a system is secure. Findings and fixes can include false
positives and must be reviewed by a qualified human. **No pull request is ever
merged automatically.**

## The loop

```
confirmed finding → locate root cause → validate in ephemeral sandbox
      → generate minimal fix → retest (exploit + variants + repo tests)
      → open pull request → HUMAN review → manual merge
```

The pull requests are produced **alongside** the server-rendered report — a
campaign ends with both a report and a set of reviewable fixes. The report is
still generated deterministically by the server from the pushed findings; the
remediation agent never touches it and never finalizes the campaign.

## For each confirmed finding

1. **Locate the root cause** in the operator-supplied repository (category-specific
   vulnerable-sink patterns plus tokens from the finding), not the symptom. Several
   candidates are ranked per file so a decoy line cannot hide the real sink.
2. **Reproduce the exploit** in an ephemeral, self-destructing Docker sandbox built
   from the target's own Dockerfile, published only on `127.0.0.1` and removed on
   exit — proof the finding is real in this build.
3. **Write the smallest fix** through an injected LLM that returns structured
   search/replace edits (applied deterministically, then a unified diff is
   synthesised). A second **over-reach judge** pass reviews the diff for scope creep.
4. **Rebuild and run the adversarial gates** — the exploit **and its variants** must
   now fail, and known-good behaviour plus the repo's tests must still pass —
   iterating until confident or giving up honestly.
5. **Open a pull request** (never a merge) carrying the finding reference, the
   root-cause explanation, the diff and the before/after validation evidence, and
   **link it to the finding(s)** it resolves.

DarkMoon's edge over generic auto-fixers: it starts from a **real, already-proven
exploit**, so it gives the reviewer hard before/after proof rather than a static
claim.

## Dispositions (never a fabricated fix)

| Disposition | Meaning |
|---|---|
| **patched** | gates passed, judge approved, confidence above threshold → PR opened. |
| **proposed** | no push target/credential, or a dry-run → branch and commit prepared locally, recorded for the operator, no external push. |
| **draft** | a fix was produced but not fully validated (e.g. no buildable sandbox) → draft PR at lower confidence, evidence attached. |
| **failed / skipped** | no usable patch, or no code location mapped. Never a fabricated or unproven fix. |

## Enabling it

- **Dashboard (Pro UI)** — save a Git push credential once from the sidebar user
  block; in *New Campaign* or *Scheduler* tick **Remediation**, pick the saved
  credential and give the source repo (or ask DarkMoon to create a fresh one for
  no-repo engagements). The vulnerabilities table gains a **PR** column linking
  each finding to a pull-request detail page (forge URL, state, linked findings,
  diff stat, before/after validation).
- **CLI / TUI** — add `REMEDIATE=1 REPO=… CREDENTIAL_REF=…` to the prompt, or run
  the pipeline directly:
  `python -m src.remediation --campaign-id <id> --repo <url> --credential-ref <cred_id>`.
- **CI/CD** — an opt-in stage runs the pipeline after the pentest, taking the push
  token from a CI secret.

## Credentials (the token never travels with the run)

To open a pull request the agent needs a Git push credential (a forge token or an
SSH key). The secret is protected end to end:

- **Encrypted at rest** — sealed with Fernet (a persistent key from
  `DARKMOON_SECRET_KEY` or a `0600` key file); the JSON store never holds a
  cleartext token.
- **Never returned** — the credentials API is JWT-gated on every route and returns
  a secret only as `{ set, hint }` (last 4 characters, masked), never its value.
- **Opaque reference** — the campaign launch line carries an opaque id such as
  `cred_ab12cd`, **never the token**. The pipeline resolves the real secret
  locally at push time; it is never exposed to the model, a command, a log or the
  API.

```bash
# the token is saved once in the UI; the run only carries its opaque id
./darkmoon.sh "TARGET: … REMEDIATE=1 REPO=https://github.com/acme/app CREDENTIAL_REF=cred_ab12cd"
```

Providers grouped by capability: **Git / pull requests** — `github`, `gitlab`
(merge requests), `gitea`, `gogs`, `bitbucket`, `azure_devops`, `generic_git`,
`ssh`; **Cloud** — `aws`, `azure`, `gcp`; **SIEM / observability** — `splunk`,
`elastic`, `microsoft_sentinel`, `ibm_qradar`, `wazuh`, `google_chronicle`,
`sumo_logic`, `graylog`, `datadog`, `arcsight`.

## Reproducing a repo's own exploits — `.darkmoon/repro.json`

Full sandbox validation needs to know how to build the target and how to tell
"exploited" from "safe". A repo can ship a `.darkmoon/repro.json` keyed by finding
`id` or `category`, describing the sandbox spec plus `exploit` / `variants` /
`normal` probes. A probe is "exploited" when its marker appears in the response
body or the status is in `exploit_status`; a `normal` (regression) probe passes
when the good path still works. Absent a repro plan, the pipeline still generates
and judges a fix but marks it unreproduced (draft PR, lower confidence).

## OWASP Juice Shop — remediation demonstration

To show the engine end to end on a well-known target, we ran it against a
standalone fork of the OWASP Juice Shop and published the resulting fixes as pull
requests for human review:

- Repository (standalone, MIT): **[ASCIT31/juice-shop](https://github.com/ASCIT31/juice-shop)**
- Pull requests: **[57 remediation PRs](https://github.com/ASCIT31/juice-shop/pulls)** —
  each maps one or more findings to a tested fix, with the diff and validation
  evidence.

This is an **internal demonstration of DarkMoon's remediation engine**, not a set
of external contributions to the upstream OWASP Juice Shop project. Every PR is
left **open for human review** — consistent with the rule that DarkMoon never
merges automatically.

## Honest limitations

- Full sandbox validation needs a **buildable Dockerfile** and, ideally, a
  `.darkmoon/repro.json`. Without them the agent still proposes a fix but opens a
  **draft** PR at lower confidence and says so.
- **GitLab** exposes merge requests, not "pull requests" — these are the PR
  equivalent and are treated the same (proposals for review, never auto-merged).
- Bitbucket / Azure DevOps PR creation is implemented but exercised less than the
  GitHub / GitLab / Gitea paths.
- Human-in-the-loop is **absolute**: the agent opens PRs; it never merges,
  force-pushes over a default branch, or closes review.
