# Cyber Score — methodology (`darkmoon-cyber-score/1`)

The Cyber Score is an **exposure rating of what one campaign found in its tested scope**, from 0 to 100 (higher means
less exposure found), with a grade from A to E. It is not a measure of the overall security level, not a compliance
statement and not a probability of breach. The same code computes it in Darkmoon Community and Darkmoon Pro
(`mcp/api/exec_core/score.py`, shipped byte-identically in both editions).

> **Not scientifically validated.** The weights, caps and coverage floors below are set by experts to meet explicit
> product rules. They have not been validated against breach outcomes or an external benchmark, and the variance
> between two runs on the same target has not been measured.

The values in this document are checked against the code by an automated test
(`mcp/tests/test_cyber_score_methodology_doc.py`): if the code changes, this page must change with it.

## 1. Status before any number

Every rating first gets a status:

| Status | When | Number |
|---|---|---|
| **Not rated** | the campaign did not complete (running, stopped, aborted, error); a retest campaign; coverage signals absent (campaign recorded before they existed) or without measured duration, or with neither a dispatched agent nor a toolbox command observed; a **severity filter applied at launch**; coverage signals **modified after the campaign was finalised** | none |
| **Limited test** | completed, but under at least one coverage floor (section 2), or launched with **attack exclusions** or a **reduced (stealth) mode**, or declared short (a focus list) | capped at `LIMITED_CAP` |
| **Rated** | otherwise | 0 to 100 |

100 is reachable only for a rated campaign and always comes with « no weakness was found in the tested scope; it is
not a proof of absence ».

## 2. Coverage floor (recorded by the server, never declared by the agents)

The Darkmoon server records, for every campaign: its kind (full, retest, short), the measured activity (server clock,
from the campaign start to its finalisation), the specialised agents dispatched (from the agent session log), the
assets registered in the infrastructure map, the toolbox commands executed through the MCP server, and the launch
restrictions given at launch (counts only: severity filter, attack exclusions, noise level, out-of-scope assets,
custom rules, focus list).

A rated campaign must reach every floor:

| Floor | Value |
|---|---|
| Measured activity | `MIN_DURATION_SECONDS` seconds |
| Specialised agents observed in the session log | `MIN_AGENTS` |
| Assets registered | `MIN_ASSETS` |
| Toolbox commands executed | `MIN_COMMANDS` |

Launch restrictions: a severity filter (any value below `critical`) means **Not rated**; attack exclusions or the
stealth noise level mean **Limited test**; out-of-scope assets and custom rules are listed with the rating.

Once a campaign is finalised (completed, aborted, stopped, failed), a later finalisation never changes its status nor
its measured activity, and an aborted or stopped campaign never becomes completed. At the first close the server
stores a digest of the coverage signals; if the signals no longer match it, the campaign is **Not rated** (« signals
modified after finalisation »). This detects naive edits of the record only; it is not a security boundary.

## 3. Formula

1. **Penalty unit = one asset and one weakness class.** The asset is the campaign target. The weakness class is a
   coarse family of the finding category (for example `xss_stored`, `xss_dom` and `html_injection` are all *XSS*).
   The same unit is the action of the Prioritized Treatment Plan: one action per weakness class and asset.
2. **Unit penalty** = the highest *severity weight × proof factor* among its open findings, plus a bounded increment
   per additional distinct weakness in the unit.
3. **Class penalty** = the largest unit of the class plus a bounded share of the other units of the class (other
   assets).
4. **Rating** = 100 minus the sum of the class penalties, rounded half up, bounded to 0..100.
5. **Caps by worst evidence**, applied after step 4, then the cap of a limited test.
6. **Grade** from the rating.

Findings held for privacy review and findings marked false positive are counted nowhere. Informational findings are
counted but weigh nothing. A finding declared closed during the campaign is still scored (as confirmed): a closure is
not verified until a completed retest. Attack paths, treatment statuses and retest verdicts are **not** part of the
v1 rating; they are shown beside it.

### Reference values

| Constant | Value | Meaning |
|---|---|---|
| `SEVERITY_WEIGHT.critical` | 30 | weight of a critical finding |
| `SEVERITY_WEIGHT.high` | 15 | weight of a high finding |
| `SEVERITY_WEIGHT.medium` | 5 | weight of a medium finding |
| `SEVERITY_WEIGHT.low` | 2 | weight of a low finding |
| `SEVERITY_WEIGHT.info` | 0 | weight of an informational finding |
| `PROOF_FACTOR.exploited` | 1.0 | proof factor: reported as exploited |
| `PROOF_FACTOR.confirmed` | 0.8 | proof factor: reported as confirmed |
| `PROOF_FACTOR.unconfirmed` | 0.5 | proof factor: to confirm |
| `UNIT_INCREMENT` | 0.1 | +10 % per additional distinct weakness in a unit |
| `UNIT_INCREMENT_CAP` | 0.3 | at most +30 % per unit |
| `CLASS_SPREAD` | 0.25 | share of each further unit of a class (other assets) |
| `CLASS_SPREAD_CAP` | 0.5 | at most +50 % of the class's largest unit |
| `CAPS.exploited_critical` | 39 | maximum rating while an exploited critical finding is open |
| `CAPS.confirmed_critical` | 49 | maximum rating while a confirmed critical finding is open |
| `CAPS.exploited_high` | 59 | maximum rating while an exploited high finding is open |
| `LIMITED_CAP` | 69 | maximum rating of a limited test |
| `MIN_DURATION_SECONDS` | 1800 | coverage floor: 30 minutes of measured activity |
| `MIN_AGENTS` | 2 | coverage floor: specialised agents |
| `MIN_ASSETS` | 1 | coverage floor: registered assets |
| `MIN_COMMANDS` | 10 | coverage floor: toolbox commands |
| `GRADES.A` | 90 | grade A from this rating |
| `GRADES.B` | 75 | grade B from this rating |
| `GRADES.C` | 60 | grade C from this rating |
| `GRADES.D` | 40 | grade D from this rating |
| `GRADES.E` | 0 | grade E below 40 |

Unconfirmed (« to confirm ») findings never set a cap. An exploited critical finding always gives grade E; a limited
test is at best C.

## 4. What moves the rating

The rating document explains what holds it where it is (`next_cap_level`):

- when a cap binds, which findings hold it (for example « capped at 39 while 10 exploited critical findings remain
  open; then capped at 59 while 18 exploited high findings remain open ») and the rating the same rules would give if a
  new campaign no longer reported them;
- when the penalty sum alone sets the rating (often at 0), that sum and the caps behind it.

It also lists the weakness classes that weigh most with their share of the penalty sum (`top_classes`) and the
penalty sum relative to the scale (`penalty_over_scale`), so two campaigns both rated 0 can be told apart.

Recording a treatment never changes the rating: only a new campaign (or, for a treatment status, a completed retest)
shows its effect.

## 5. Verification by retest

A retest is not rated. A treatment action declared applied becomes « Not reproduced at retest » only from a
**completed retest that met its coverage gate**: at least one asset registered, at least one toolbox command executed,
a measured duration, and among the dispatched agents one of the agents that reported the action's findings. A retest
without that coverage verifies nothing: the action stays « Applied — not verified » and the retest is shown as
« Retest without coverage — not verified ». « Not reproduced at retest » is not a proof of resolution; a new full
campaign confirms it.

## 6. Trend

A trend (« improved », « degraded ») is given only between two rated full campaigns of the same target, with the
scope differences listed (agents not run, assets, measured activity). The dashboard « vs previous scan » delta follows
the same rule; otherwise the previous campaign is named and no delta is shown.

## 7. Limitations

1. Exposure of the tested scope only; not a security level, a compliance statement or a probability.
2. Not scientifically validated: weights and caps are expert-set.
3. **Severity and proof level are reported by the testing agent**, with evidence on file; the server normalises them
   but does not re-verify them, and the caps by worst evidence follow the agent's report. CVSS scores shown in the
   report are recomputed by the server from the vectors; the rating uses the displayed severity.
4. **Run-to-run variance has not been measured**: two campaigns on the same target may find different weaknesses; a
   severity chosen differently by an agent can move a grade.
5. **Saturation at 0**: very exposed applications all read 0; use the breakdown (penalty sum, top classes, caps) to
   compare them.
6. Coverage floors are presence and volume signals, not proof that every test of a class was run. Commands run by the
   agent's own shell are not counted.
7. Weakness classes come from a curated mapping of agent categories; a mislabelled category lands in another class.
8. The asset is the campaign target; multi-asset scopes are supported by the formula but not yet tested on real data.
9. Darkmoon Community: no MCP tool writes the declarations, the treatment statuses or the coverage signals, but the
   local agent has shell access in the same container; Community declarations and coverage signals are therefore
   not tamper-evident (the digest above detects naive edits only).
