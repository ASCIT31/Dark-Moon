# DarkMoon workflow — error register (ALSCO / Secure Gateway campaign, 2026-11-02 → 03)

Post-campaign audit of the workflow the engine actually followed during the
three-phase ALSCO / Secure Gateway assessment (`sandbox.securegateway.com` +
`sandbox-royal.securegateway.com`, origin `188.34.187.32`). Every entry below was
observed live during the campaign; each fix is committed with this register.

The campaign's own bottom line, for context: the engine raised 1 CRITICAL and 2
HIGH findings across the phases, then **refuted all three of them itself** with
reproducible evidence. The final store carries 0 critical / 0 high / 2 low /
26 informational records, and the final report
(`reports/pentest_report_sandbox.securegateway.com_20261103-0427.md`) says so.
The errors below are the ones that produced the false positives and the ones
that made cleaning them up harder than it should have been.

---

## E1 — Evidence oracle used without a stability control (produced the false CRITICAL)

**Observed.** The first run compared response **md5** between `?article=9` and
`?article=9-1`, found them equal, and concluded "the server evaluates the
arithmetic in the SQL WHERE clause" → CRITICAL 9.8, `T1190`, status confirmed.

**Root cause.** The page embeds a per-request read counter
(`<img src="img/home-read.svg">1126121`), so the md5 of the body changes on
every view. Two back-to-back requests for `?article=9` produced different md5s
with identical length. The "byte-identical md5" evidence was an artefact of
comparing a small, slowly-changing page — the md5s quoted in the finding were
not reproducible at all.

**Fix.** GATE 1 in `conf/agents/pentest.md`: an oracle (md5/length/status) may
only be used as evidence after the same input is requested twice and proven
stable. Valid oracles: status + length + a semantic marker (rendered title, row
count).

## E2 — Severity escalated before the decisive discriminator (produced both false HIGHs)

**Observed.** `homeLang` values ending in `"` returned an origin-side HTTP 500
with an empty body. The engine filed `homeLang` and `complaint-insert` as HIGH
7.5 "spliced raw into a double-quoted SQL literal" on that basis.

**Root cause.** The 500 was taken as a SQL syntax error without testing whether
the interior is ever parsed as SQL. When the decisive tests ran — interior
parity (`ar",NO_SUCH_COL,"B`, unbalanced paren, bogus subquery all
byte-identical), timing (`SL/**/EEP(8)` returns in ~1.0 s), arity (1..20 extra
values change nothing), operators (`O/**/R 1=1` returns the same 0-row page) —
every one showed the interior never reaches the database. The real defect is an
application-level PHP fatal on an odd number of *trailing* double quotes.

**Fix.** GATE 2: `sql_injection` may not be CONFIRMED without an interior-parity
probe, a timing probe with ≥3 repetitions of SLEEP and a control, and a semantic
TRUE/FALSE that changes the row count.

## E3 — Rule identifier cited from memory, never observed in any response

**Observed.** The Phase-2 report attributed the whole `/**/` section to
`G.S.942190`. Across every response of the campaign that rule never appeared
once; the rule that actually fires is **`G.S.942100`** (with `G.S.942190`
appearing only in payloads the engine itself typed).

**Root cause.** Attribution by assumption instead of by observation.

**Fix.** GATE 3: rule ids, error codes and header names must be copied verbatim
from an observed response, with the response line shown.

## E4 — `push_finding` had no de-duplication (39 records for 38 findings)

**Observed.** The store ended the campaign with 39 records for 38 distinct
titles — plus several near-duplicates with different wording (the `/auth/`
case-sensitivity finding, the `/**/` bypass, the `PHPSESSID` flags and the
`?topic` disclosure each existed twice). The agent had to hand-mark
`WITHDRAWN / CONSOLIDATED` in titles and hand-edit store files to reconcile.

**Root cause.** `mcp/api/live_push.py:push_finding()` appended blindly and
`dashboard_push_finding()` minted a fresh `vuln_` id on every call.

**Fix (code).** `push_finding()` now upserts by normalized title. A re-push
UPDATES the existing record in place: keeps its id and `discovered_at`, merges
the textual evidence, increments a `revision` counter, and returns
`updated: true`. A correction record titled `"WITHDRAWN / FALSE POSITIVE -
<original>"` resolves to the same key as the original (withdrawal markers are
stripped before comparison) so pushing a correction withdraws the original
rather than leaving a live duplicate. Regression tests in
`mcp/tests/test_live_push_fixes.py`.

## E5 — Report regenerated while the store still carried the withdrawn findings

**Observed.** The 23:26 report shipped *after* the withdrawal corrections still
listed both HIGH SQLi records as "Confirmed HIGH 7.5", and the management
summary opened with "2 high severity vulnerabilities were identified requiring
urgent attention."

**Root cause.** The management summary and the posture counted every record on
disk, including withdrawn ones; nothing recomputed the severity view after a
withdrawal.

**Fix (code).** `_generate_report_from_db()` now computes the posture, the
plain-language top-3 and the summary table from **validated records only**.
Withdrawn records stay in the findings table (tagged
`~~title~~ *(withdrawn / false positive)*`) and in the details as the audit
trail, with an explicit exclusion note under the summary. Campaign stats gain
`total_records` / `withdrawn`, and `total_findings` counts validated records.

## E6 — Rate limit lived only in prompt text (naabu at 500 pps → 6-minute IP ban)

**Observed.** The first run launched `naabu -p top-1000 -rate 500` against a
program whose policy caps automated scanning at 5 req/s / 5 concurrent. The
Secure Gateway firewall banned the source IP for ~6 minutes and the run lost its
target.

**Root cause.** The engine has no rate-limit enforcement of its own; the cap
existed only as prompt advice, which the agent overrode when picking tool flags.

**Fix.** GATE 4: ≤5 req/s and ≤5 concurrent per host is an engine constraint,
not a suggestion; wide+fast port scans are forbidden by default.

## E7 — Stateful flows probed without a session (CSRF "broken" was an artefact)

**Observed.** Independent verification (hunting round 2) showed the sandbox
egress IP rotates between requests (`47.253.4.207`, `47.253.152.120`, … in one
session), so every response carries a **new** `PHPSESSID` and the
session↔IP binding breaks. Any stateful test (CSRF forms, captcha) done with
one connection per request fails with a misleading `CSRF comparison failed`
that looks like an application bug. With a single persistent connection the
complaint form works end-to-end: CSRF validates, the arithmetic captcha passes,
the row is written.

**Root cause.** The engine's probes were one-shot connections with no cookie
jar, so stateful behaviour could not be observed at all.

**Fix.** GATE 5: stateful endpoints must be driven on one connection reusing
the Cookie header, with a session-validity control (GET then POST on that
connection) before any "broken" conclusion.

## E8 — Blocked route declared dead without an egress caveat

**Observed.** `/auth/*` returned `403 [AS]` from our egress, and the engine
filed "2FA login flow is unreachable — WAF access-control rule". Verification
suggests the `[AS]` block is IP/session-based, not proof the route is dead;
the programme's own guideline is to **request a test account from ALSCO**.

**Fix.** GATE 7: unreachable ≠ dead; an unreachability conclusion must state
the egress caveat and whether a session/another egress could unlock it.

## E9 — Operator premise encoded as fact (the "Total record: 2" hunt)

**Observed.** The Phase-2.5 directive asserted "`subPage=2` does not return a
second page even though the response says `Total record: 2`". The response
actually says `Total record: 6`, and page 1 already returns all six rows —
there is no second page. The engine burned several turns refuting its own
brief.

**Fix.** GATE 6: every premise handed to the agent is a lead until re-verified
with one control request.

---

## Status of the fixes

| Error | Fix | Where |
|---|---|---|
| E1 oracle stability | GATE 1 | `conf/agents/pentest.md` |
| E2 SQLi discriminator | GATE 2 | `conf/agents/pentest.md` |
| E3 rule-id attribution | GATE 3 | `conf/agents/pentest.md` |
| E4 store de-duplication | upsert by title + marker-insensitive key | `mcp/api/live_push.py`, tests in `mcp/tests/test_live_push_fixes.py` |
| E5 stale report summary | validated-only counts + withdrawn tagging | `mcp/api/live_push.py`, tests in `mcp/tests/test_live_push_fixes.py` |
| E6 rate limit | GATE 4 | `conf/agents/pentest.md` |
| E7 sessionless stateful tests | GATE 5 | `conf/agents/pentest.md` |
| E8 egress caveat | GATE 7 | `conf/agents/pentest.md` |
| E9 premise verification | GATE 6 | `conf/agents/pentest.md` |

**Known follow-ups (not fixed here).** The Web UI recomputes its counters from
the raw store records, so withdrawn records still appear in its Overview counts
until the store is reconciled; the report is the vendor-facing artifact and is
correct. `dashboard_push_finding()` could also expose the `withdrawn` flag as
an explicit tool argument rather than relying on title markers.
---

# Web UI error register (2026-11-03 UI audit)

Same campaign, Web UI side. Verified live against the real store (28 records,
26 of them withdrawn) before/after each fix.

## W1 — Overview counted withdrawn records as live findings

**Observed.** `/api/overview` reported `findings.total: 28 / open: 28` while
only 2 records were actually valid — the 26 withdrawn/refuted corrections
(which the MCP had just learned to exclude) were counted as if they were
payable findings, and the severity chart showed 26 info + 2 low.

**Fix.** The withdrawal rule (`_is_withdrawn` / `_validated`, mirroring
`mcp/api/live_push.py`) now drives `overview`: `total`/`open`/`by_severity`
count validated records only, and a new `findings.withdrawn` field exposes the
audit-trail size. The Overview grid gained an explicit **Withdrawn** stat and
the "Open" stat is now labelled **Open (valid)** with its own accent colour
(it previously borrowed the "low" green underline, which read as a severity).

## W2 — Findings view listed withdrawn records as ordinary findings

**Observed.** `/api/findings` (and the table) returned every store record, so
a vendor-looking reviewer saw 28 rows where 26 were refuted corrections with
no visual distinction.

**Fix.** `/api/findings` excludes withdrawn records by default (same rule as
the report); `?include_withdrawn=1` re-includes them **flagged** with
`withdrawn: true`. The table renders flagged rows muted + struck-through with
an inline "(withdrawn / false positive)" tag, behind a new
*include withdrawn / false positives* checkbox. Same for
`/api/campaigns/{id}`: `findings` is validated-only, `withdrawn` is returned
separately for the drawer, and `/api/campaigns` exposes
`findings_count` (validated) alongside `records_count`.

## W3 — "Save MiniMax MCP" failed whenever the provider form was empty

**Observed.** The MiniMax panel re-sent `mode/provider/model/api_key/base_url`
from the provider form; with an empty form the request hit the cloud branch,
which raises 400 "model and api_key are required" **before** the MiniMax block
ever runs. Saving only the MCP key was impossible.

**Fix.** The panel now sends **only** the MiniMax fields, and `set_env`
detects the MiniMax-only save (no provider keys in the body) and preserves the
provider config already on disk instead of routing through a provider branch.

## W4 — Stale assets after a redeploy (browser served the old app.js)

**Observed.** After rebuilding the image, a fresh navigation still executed
the previous `app.js` from browser cache — the new stat labels did not appear
until a hard reload, which makes every UI fix look "not applied" in
verification.

**Fix.** HTTP middleware sets `Cache-Control: no-cache` on `/`,
`/static/*` and `/api/*`, so the browser revalidates against the StaticFiles
ETag and picks up new builds. (StaticFiles already emits the ETag, so unchanged
assets still answer 304.)

## W5 — Cosmetic: campaign status badges were all grey

**Observed.** Campaign status badges hardcoded the `neutral` class, so a
`running` campaign and a `completed` one were visually identical in the
Campaigns table and in the campaign drawer.

**Fix.** `statusBadge()` colour-codes the status (`running` → accent,
`completed`/`finished` → green) across the campaigns table, the campaign
drawer and the Overview recent list.

## W6 — Cosmetic: CVSS "0.0" noise on withdrawn/informational records

**Observed.** `findingCard` rendered "CVSS 0.0" for every record whose score
was 0 or N/A, adding noise to the drawer.

**Fix.** The CVSS chip is only rendered when the score parses to a number > 0.

---

# Discovery-workflow error register (2026-11-03, D-series)

Audit of the discovery workflow itself: workflows, tool invocation, MCP
exposure, prompts. Verified against the real campaign traces.

## D1 — `naabu` ran uncapped in the port_scan workflow (the actual IP-ban incident)

**Observed.** `port_scan.py` launched `naabu -list … -top-ports N` with no
`-rate`; the campaign's free-form invocation added `-rate 500` and the target
firewall banned the source for ~6 minutes. The prompt's "≤5 req/s" was advice
the agent overrode when it picked flags.

**Fix (code).** `mcp/src/rate_limiter.py` — a mechanical rate floor applied in
`DarkmoonDockerClient.execute_command`, the single choke point every command
passes through: if a network tool is invoked without its vendor rate flag, the
flag is injected with the cap (naabu/masscan/nmap/ffuf/feroxbuster 25, nuclei
15, katana 10, httpx 15, wpscan 5); an explicit higher value is *floored*, an
explicit lower value is kept. Capping is applied per shell-segment so a flag
belonging to one command cannot leak into another (`naabu … && cat out` caps
only the naabu part). `port_scan.scan_ports` also gained an explicit
`rate_limit=25` parameter and its command carries `-rate` natively. The caps
are also exposed via `list_allowed_tools()` as `engine_rate_limits` so an
agent can discover them.

## D2 — No automated CVE discovery existed at all

**Observed.** The engine had no step from "product+version identified" to
"applicable CVEs": a version banner was either dropped or, worse, turned into
CVE numbers from the model's memory — the same failure family as E3 (the rule
id cited from memory that never appeared in any response).

**Fix (code + prompt).** New `cve_lookup` workflow
(`mcp/src/tools/workflows/cve_lookup.py`), auto-discovered by the registry:
- `search_cves(product, version, max_results, recent_years, min_severity)` —
  one public NVD 2.0 request (no API key; tolerant of its 5 req/30s polite
  limit), `recent_years: 5` window by default and `0` for an all-time sweep,
  returns a CVSS-descending shortlist with description, references, mapped
  CPEs and a `version_hint_match` flag.
- `get_cve(cve_id)` — full single record.
- GATE 9 in `conf/agents/pentest.md` wires it into the doctrine: fingerprint →
  `cve_lookup` → targeted nuclei validation, and an explicit "never cite CVE
  identifiers from memory" rule.

## D3 — Workflows composed commands without rate flags of their own

**Observed.** `subdomain_discovery` (httpx), `web_crawler` (katana) and
`vulnerability_scan` (nuclei) all launched their tools unbounded; only
`port_scan` got a native flag in this fix, because for the others the
mechanical choke-point injection (D1) now covers every invocation including
composed `&&` scripts — the engine-side guarantee is the point, not per-file
patches.

## Status

| Error | Fix | Where |
|---|---|---|
| D1 naabu uncapped → IP ban | mechanical rate floor at the choke point + native `-rate` in port_scan | `mcp/src/rate_limiter.py`, `mcp/src/docker_client.py`, `mcp/src/tools/workflows/port_scan.py` |
| D2 no CVE discovery | `cve_lookup` workflow (NVD 2.0) + GATE 9 in the prompt | `mcp/src/tools/workflows/cve_lookup.py`, `conf/agents/pentest.md` |
| D3 unbounded workflow tools | covered by the D1 choke-point guarantee | `mcp/src/rate_limiter.py` |

**Tests:** `mcp/tests/test_discovery_workflow.py` — 13 tests (flag injection,
floor-not-raise, per-segment capping, argv-list capping, registry discovery,
NVD parsing/ranking/filtering offline against fixtures). Full suite: 137 passed.

---

# Scope-driven rate policy + deployment errors (2026-11-03, P-series, PornBox)

Directive that surfaced these: run the PornBox programme, where the rate budget
is qualitatively different — PornBox PROHIBITS automated tools and any "tool
that generates a significant volume of traffic", while ALSCO allowed automated
scanning within 5 req/s. A single global cap cannot serve both.

## P1 — The rate cap was a global constant instead of a scope property

**Observed.** The first mechanical limiter (D1) floored every network tool to a
hard-wired 25 pps. For PornBox that is a compliance violation (automation is
prohibited outright); for a programme that states its own tighter number (ALSCO:
5 req/s), the stated number was ignored.

**Fix (code).** `mcp/src/scope_policy.py` — the rate budget is parsed from the
programme's OWN wording: stated rates ("5 requests per second", "300 requests
per minute"), concurrency ("5 concurrent"), courtesy phrases ("keep scanning to
a minimum" → limited mode), and outright prohibitions ("automated tools … not
allowed", "significant volume of traffic" → manual mode). Enforcement:
- `tool_cap()` = MIN(tool default, scope allowance) — the engine never RAISES a
  rate, the scope's tighter number wins.
- Manual mode (automation prohibited) floors everything to a 2 req/s trickle
  AND refuses high-volume scanners pre-flight (nuclei/ffuf/katana/naabu/
  sqlmap/nikto/…), execution-guard style, with a manual-testing alternative.
- `enforce_rate_limits(command, policy)` threads the policy through the
  choke point; `rate_limiter` without a policy keeps the engine default.
- `dashboard_init_campaign(rate_policy=…)` accepts the programme's verbatim
  text or a parsed dict, stores it on the campaign (visible in the report)
  and registers it on the docker client per session.
- `list_allowed_tools()` exposes the effective `engine_rate_limits`.

**Verified.** ALSCO text → `mode: automated, rps: 5, concurrency: 5` and naabu
capped at `-rate 5`. PornBox text → `mode: manual, rps: 2, prohibit: true`,
naabu floored to `-rate 2`, and nuclei/ffuf/katana/sqlmap/naabu/nikto refused
pre-flight while `curl` (manual testing) stays allowed.

## P2 — The policy could not reach the engine without agent cooperation

**Observed.** The first PornBox run created its campaign with
`rate_policy: null` — the policy lived in the prompt text, and the agent called
`dashboard_init_campaign` without the (optional) argument, so nothing was
enforced.

**Fix (code).** The Web UI launch endpoint now writes the programme's verbatim
policy to the SHARED data store (`darkmoon-settings/rate_policy.json`, mounted
into the engine container at `/root/.local/share/opencode/rate_policy.json`),
and `scope_policy.resolve_policy()` reads it as a fallback in its chain:
session policy > campaign scope file > env override > engine default. The
enforcement no longer depends on the agent remembering to pass the argument.
(The campaign record may still show the default when the agent skips the
argument — the file is the enforcement source of truth.)

## P3 — A broken MCP deploy silently killed the whole campaign (and the launch went out unredacted)

**Observed.** Mounting the live MCP code (`src/`, `api/`) into the engine
container made the persistent MCP daemon crash at boot on a mid-copy import
error (`NameError: Optional` in rate_limiter.py). The entrypoint fired and
forgot: no port check, no retry. The campaign then started against a dead MCP —
the privacy tokenization failed, the launch prompt went out unredacted, and the
agent (correctly) refused to work and ended the run after ~12 lines.

**Fix (code).** `conf/entrypoint-opencode.sh` now verifies the MCP port is
actually listening and retries (6 attempts, restart + log tail), exiting FATAL
with the boot log if the MCP never comes up — the campaign must not start
against a dead engine. Also added the missing `docker-compose.yml` mounts for
`mcp/src` and `mcp/api` so engine fixes deploy without a full image rebuild
(the pattern `workflows/` already used; the `.venv` stays from the image).

## P4 — Agent routed curl to the wrong container (self-corrected)

**Observed.** The PornBox agent tried `curl` via `bash` inside the opencode
container (no curl there) instead of `darkmoon_execute_command` (the toolbox,
which has it). It self-corrected via the `which` ladder — but wasted turns.

**Fix.** Noted for the prompt backlog: the discovery doctrine should say
explicitly that network probes run through `darkmoon_execute_command` (the
toolbox), not the engine's own shell.

## Status

| Error | Fix | Where |
|---|---|---|
| P1 global cap instead of scope policy | parse the programme's own wording; manual mode + pre-flight refusal | `mcp/src/scope_policy.py`, `mcp/src/rate_limiter.py`, `mcp/src/docker_client.py`, `dashboard_init_campaign`, `list_allowed_tools` |
| P2 policy unreachable without agent cooperation | launch writes `rate_policy.json` into the shared store; MCP reads it as fallback | `webui/server.py`, `mcp/src/scope_policy.py` |
| P3 dead-MCP deploy killed the campaign | entrypoint verifies the port and retries, FATAL otherwise | `conf/entrypoint-opencode.sh`, `docker-compose.yml` (live mounts) |
| P4 curl routed to the wrong container | documented for the prompt backlog | this register |

**Tests:** `mcp/tests/test_scope_policy.py` — 13 tests (ALSCO/PornBox parsing,
min-of-caps, floor-not-raise, manual-mode refusal of scanners while curl stays
allowed, scope-JSON field consumption, courtesy-phrase limited mode). Full
suite: 150 passed. Live-verified inside the engine container against the real
PornBox policy file.
