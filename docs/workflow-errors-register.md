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
