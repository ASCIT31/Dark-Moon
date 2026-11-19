import { describe, expect, test } from "bun:test"
import {
  clean,
  declaredLinks,
  evidenceSections,
  ExplorerApi,
  filterFindings,
  page,
  pathChain,
  pathFindingIds,
  pathProof,
  searchSections,
  splitSections,
  windowAround,
  type Finding,
} from "./core"

const F = (o: Partial<Finding>): Finding => ({ id: "v", title: "t", ...o })

describe("clean", () => {
  test("strips ANSI, OSC and control characters from API strings", () => {
    expect(clean("a\x1b[31mred\x1b[0m\x1b]0;title\x07b\x00\x07c")).toBe("aredbc")
  })
  test("truncates long values", () => {
    expect(clean("x".repeat(10), 4)).toBe("xxxx…")
    expect(clean("a\x9d8;;http://x\x9cb\x9b2Jc\u202ed\x90q\x9ce")).toBe("ab2Jcde")
  })
})

describe("findings", () => {
  const list = [
    F({ id: "a", title: "Low thing", severity: "low", status: "unconfirmed", endpoint: "http://h1:8080/x" }),
    F({ id: "b", title: "SQL injection", severity: "critical", status: "exploited", endpoint: "http://h2:443/" }),
    F({ id: "c", title: "Info", severity: "info", status: "confirmed", endpoint: "http://h1:8080/y", cve: "CVE-2024-1" }),
  ]
  test("sorted by severity", () => {
    expect(filterFindings(list, {}).map((v) => v.id)).toEqual(["b", "a", "c"])
  })
  test("filters by severity, proof status, target and query", () => {
    expect(filterFindings(list, { severity: "critical" }).map((v) => v.id)).toEqual(["b"])
    expect(filterFindings(list, { status: "confirmed" }).map((v) => v.id)).toEqual(["c"])
    expect(filterFindings(list, { target: "h1:8080" }).map((v) => v.id)).toEqual(["a", "c"])
    expect(filterFindings(list, { query: "cve-2024" }).map((v) => v.id)).toEqual(["c"])
  })
  test("pagination clamps and windowing keeps the cursor visible", () => {
    const big = Array.from({ length: 1200 }, (_, i) => i)
    expect(page(big, 99, 50)).toMatchObject({ page: 23, pages: 24 })
    expect(page([], 0, 50)).toMatchObject({ items: [], page: 0, pages: 1 })
    const w = windowAround(1200, 600, 20)
    expect(600 >= w.start && 600 < w.end && w.end - w.start === 20).toBe(true)
    expect(windowAround(5, 4, 20)).toEqual({ start: 0, end: 5 })
  })
})

describe("evidence and links", () => {
  test("evidence keeps only present fields, cleaned", () => {
    const s = evidenceSections({ explanation: "why\x1b[2J", commands: ["curl x"], logs: [], raw_request: "" })
    expect(s).toEqual([
      { label: "Explanation", text: "why" },
      { label: "Commands", text: "curl x" },
    ])
  })
  test("enabled_by accepts ids or objects", () => {
    expect(declaredLinks(F({ enabled_by: ["vuln_1", { id: "vuln_2" }] }))).toEqual(["vuln_1", "vuln_2"])
    expect(declaredLinks(F({}))).toEqual([])
  })
})

describe("attack paths keep the proof contract", () => {
  const steps = [
    { n: 1, node_label: "Web", finding_id: null },
    { n: 2, node_label: "DB", finding_id: "vuln_9" },
  ]
  const checked = { status: "corroborated", unverified: [], checked: true }
  test("inferred and declared are never proven", () => {
    expect(pathProof({ id: "p", title: "", provenance: "inferred", hypothesis: true })).toEqual({
      label: "Possible Attack Path",
      short: "POSSIBLE",
      proven: false,
      why: "inferred by the server, a hypothesis",
    })
    expect(pathProof({ id: "p", title: "", provenance: "agent-declared", hypothesis: true }).proven).toBe(false)
    // a derived path is evidence-backed only when the engine checked its claims (exec_core legend.path_kind_of)
    expect(pathProof({ id: "p", title: "", provenance: "derived", hypothesis: false, corroboration: checked }).proven).toBe(true)
    expect(pathProof({ id: "p", title: "", provenance: "derived", hypothesis: false }).proven).toBe(false)
    expect(pathProof({ id: "p", title: "", provenance: "derived", hypothesis: false, corroboration: { ...checked, checked: false } }).proven).toBe(false)
  })
  test("dashed arrows for hypotheses, solid for proven", () => {
    expect(pathChain({ id: "p", title: "", hypothesis: true, steps })[1]).toContain("╌▶ DB  [vuln_9]")
    expect(pathChain({ id: "p", title: "", provenance: "observed", hypothesis: false, steps })[1]).toContain("─▶ DB")
    expect(pathFindingIds({ id: "p", title: "", finding_ids: ["vuln_1"], steps })).toEqual(["vuln_1", "vuln_9"])
    const objSteps = [{ n: 1, node_label: "X", findings: [{ id: "vuln_7", title: "t" }] }]
    expect(pathFindingIds({ id: "p", title: "", steps: objSteps })).toEqual(["vuln_7"])
    expect(pathChain({ id: "p", title: "", hypothesis: true, steps: objSteps })[0]).toContain("[vuln_7]")
  })
})

describe("markdown report", () => {
  test("splits on headings outside code fences", () => {
    const s = splitSections("intro\n# A\ntext\n```\n# not a heading\n```\n## B\nmore")
    expect(s.map((x) => x.title)).toEqual(["", "A", "B"])
    expect(s[1].body).toContain("# not a heading")
  })
  test("malformed markdown (unclosed fence, broken table) does not throw", () => {
    const s = splitSections("# T\n| a | b\n|---\n```js\nconst x = 1\n# inside\n")
    expect(s.map((x) => x.title)).toEqual(["T"])
  })
  test("report model metadata lines (section marker, link anchors) are never shown", () => {
    const md = "# R\n\n<!-- dm-section: cyber-score -->\n## 1. Cyber Score\n<a id=\"cyber_score\"></a>\n\ntext\n```\n<a id=\"kept\"></a>\n```\n"
    const s = splitSections(md)
    expect(s.map((x) => x.title)).toEqual(["R", "1. Cyber Score"])
    expect(s[1].body).not.toContain("<a id=\"cyber_score\">")
    expect(s[1].body).not.toContain("dm-section")
    expect(s[1].body).toContain("<a id=\"kept\"></a>")
  })

  test("search returns matching sections", () => {
    const s = splitSections("# A\nfoo\n# B\nbar foo\n# C\nbaz")
    expect(searchSections(s, "FOO")).toEqual([0, 1])
    expect(searchSections(s, " ")).toEqual([])
  })
})

describe("api client", () => {
  const ok = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
  test("token stays in memory and is sent as bearer; 401 drops it", async () => {
    const seen: string[] = []
    const fetcher = (async (url: string, init: RequestInit) => {
      seen.push(new Headers(init.headers).get("Authorization") ?? "-")
      if (String(url).endsWith("/auth/login")) return ok({ token: "T1", must_change_password: false })
      if (String(url).endsWith("/projects")) return seen.length > 2 ? ok({}, 401) : ok({ data: [{ id: "p", name: "P" }] })
      return ok({})
    }) as unknown as typeof fetch
    const api = new ExplorerApi("http://x/api/v1", fetcher)
    await api.login("u", "pw")
    expect(await api.projects()).toEqual([{ id: "p", name: "P" }])
    expect(seen).toEqual(["-", "Bearer T1"])
    await expect(api.projects()).rejects.toMatchObject({ kind: "auth" })
    expect(api.authenticated).toBe(false)
  })
  test("network errors are typed", async () => {
    const api = new ExplorerApi("http://x", (async () => {
      throw new Error("ECONNREFUSED")
    }) as unknown as typeof fetch)
    await expect(api.projects()).rejects.toMatchObject({ kind: "network" })
  })
  test("campaigns hide sub-agent runs and sort newest first", async () => {
    const api = new ExplorerApi("http://x", (async () =>
      ok({
        data: [
          { id: "a", project_id: "p", date: "2026-01-01" },
          { id: "b", project_id: "p", date: "2026-02-01" },
          { id: "s", project_id: "p", date: "2026-03-01", is_subagent: true },
          { id: "o", project_id: "q", date: "2026-04-01" },
        ],
      })) as unknown as typeof fetch)
    expect((await api.campaigns("p")).map((c) => c.id)).toEqual(["b", "a"])
  })
})

describe("v2: data sources, cache and helpers", () => {
  const { CachedSource, FileSource, sortFindings, proofMark, tocOf, citedFindings, palette, splitSections: split } = require("./core")

  test("cache: back-navigation does not refetch, invalidate does, failures are not cached", async () => {
    let calls = 0
    let fail = true
    const inner: any = {
      kind: "api", needsLogin: true, authenticated: true,
      projects: async () => { calls++; if (fail) { fail = false; throw { kind: "network", message: "x" } } return [{ id: "p", name: "P" }] },
      logout() {}, login: async () => ({ mustChange: false }),
    }
    let t = 0
    const c = new CachedSource(inner, 1000, () => t)
    await expect(c.projects()).rejects.toMatchObject({ kind: "network" })
    await Promise.resolve()
    expect(await c.projects()).toEqual([{ id: "p", name: "P" }])
    expect(await c.projects()).toEqual([{ id: "p", name: "P" }])
    expect(calls).toBe(2)
    t = 2000
    await c.projects()
    expect(calls).toBe(3)
    c.invalidate()
    await c.projects()
    expect(calls).toBe(4)
  })

  test("file source: same shapes as the API, typed errors, no login", async () => {
    const seen: string[][] = []
    const fs = new FileSource(async (args: string[]) => {
      seen.push(args)
      if (args[0] === "finding") return { code: 2, stdout: "", stderr: "not found: x" }
      if (args[0] === "report") return { code: 0, stdout: '{"content":"# R"}', stderr: "" }
      if (args[0] === "campaigns") return { code: 0, stdout: JSON.stringify({ data: [{ id: "a", project_id: "p", date: "1" }, { id: "s", is_subagent: true }] }), stderr: "" }
      return { code: 1, stdout: "", stderr: "adapter error: KeyError" }
    })
    expect(fs.needsLogin).toBe(false)
    expect((await fs.campaigns("p")).map((c: any) => c.id)).toEqual(["a"])
    expect(await fs.report("c1")).toBe("# R")
    await expect(fs.finding("x")).rejects.toMatchObject({ kind: "http", status: 404 })
    await expect(fs.projects()).rejects.toMatchObject({ kind: "parse" })
    await expect(fs.vulnerabilities({ project_id: "p" })).rejects.toBeTruthy()
    expect(seen.find((a) => a[0] === "vulnerabilities")).toEqual(["vulnerabilities", "--project", "p"])
  })

  test("file source: adapter error text is cleaned before display", async () => {
    const fs = new FileSource(async () => ({ code: 1, stdout: "", stderr: "boom \x1b]0;pwn\x07\x1b[2J" }))
    await expect(fs.projects()).rejects.toMatchObject({ message: "boom " })
  })

  test("sorting keeps severity as the tie-breaker", () => {
    const l = [
      { id: "1", title: "b", severity: "low", status: "exploited" },
      { id: "2", title: "a", severity: "critical", status: "unconfirmed" },
      { id: "3", title: "c", severity: "high", status: "exploited" },
    ]
    expect(sortFindings(l, "severity").map((f: any) => f.id)).toEqual(["2", "3", "1"])
    expect(sortFindings(l, "proof").map((f: any) => f.id)).toEqual(["3", "1", "2"])
    expect(sortFindings(l, "title").map((f: any) => f.id)).toEqual(["2", "1", "3"])
  })

  test("proof is never colour alone", () => {
    expect([proofMark("exploited"), proofMark("confirmed"), proofMark("nope")]).toEqual(["●", "◐", "○"])
  })

  test("report contents and cited findings", () => {
    const s = split("# A\nsee vuln_a52c3f and vuln_a52c3f\n## B\n### C\nvuln_zz not an id\n#### D")
    expect(tocOf(s).map((t: any) => [t.title, t.level])).toEqual([["A", 1], ["B", 2], ["C", 3]])
    expect(citedFindings(s[0].body)).toEqual(["vuln_a52c3f"])
    expect(citedFindings("vuln_zz")).toEqual([])
  })

  test("palette follows the dashboard tokens", () => {
    const d = palette("dark")
    expect([d.canvas, d.surface, d.raised, d.hover]).toEqual(["#000000", "#0f0f0f", "#1a1a1a", "#242424"])
    expect([d.critical, d.high, d.medium, d.low]).toEqual(["#ff453a", "#ff8a1f", "#ffd426", "#2ec5d3"])
    expect([d.alice, d.jordy, d.neon, d.chrysler, d.royal, d.uranian]).toEqual(["#dceaf4", "#87bfff", "#2667ff", "#3b26cc", "#0a2472", "#add7f6"])
    expect(palette("light").canvas).toBe("#f4f4f4")
    expect([palette("dark").code, palette("light").code]).toEqual(["#add7f6", "#2f6fb8"])
  })

  test("proof labels are the legend vocabulary (exec_core.legend)", () => {
    const { pathProof } = require("./core")
    expect(pathProof({ id: "p", title: "", provenance: "observed", hypothesis: false }).label).toBe("Evidence-Backed Attack Path")
    expect(pathProof({ id: "p", title: "", provenance: "agent-declared", hypothesis: true }).label).toBe("Possible Attack Path")
    expect(pathProof({ id: "p", title: "", provenance: "agent-declared", hypothesis: true }).why).toBe("declared by the agent, not verified")
    expect(pathProof({ id: "p", title: "", provenance: "inferred", hypothesis: true }).why).toBe("inferred by the server, a hypothesis")
    // a declared path that a client marks hypothesis:false is never promoted: only the server's evidence makes a path proven
    expect(pathProof({ id: "p", title: "", provenance: "agent-declared" }).proven).toBe(false)
    expect(pathProof({ id: "p", title: "", provenance: "declared", hypothesis: false }).proven).toBe(false)
    expect(pathProof({ id: "p", title: "", hypothesis: false }).proven).toBe(false)
  })
})

describe("visual primitives use real data only", () => {
  const { buckets, sparkline, hbar, activityOf, glyphs, unicodeTerminal, durationText } = require("./core")
  test("buckets count timestamps, ignore unparseable ones", () => {
    const t = ["2026-11-18T10:00:00Z", "2026-11-18T10:00:30Z", "2026-11-18T10:09:59Z", "nope", undefined]
    expect(buckets(t, 10, "2026-11-18T10:00:00Z", "2026-11-18T10:10:00Z")).toEqual([2, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    expect(buckets([], 4)).toEqual([0, 0, 0, 0])
  })
  test("sparkline never invents a value", () => {
    expect(sparkline([0, 0, 0], "▁▂▃▄▅▆▇█")).toBe("▁▁▁")
    expect(sparkline([0, 1, 4], "▁▂▃▄▅▆▇█")).toBe("▁▃█")
  })
  test("bars keep one cell for a non-zero value and none for zero", () => {
    expect(hbar(1, 100, 10)).toEqual({ fill: 1, rest: 9 })
    expect(hbar(0, 5, 10)).toEqual({ fill: 0, rest: 10 })
    expect(hbar(5, 5, 10)).toEqual({ fill: 10, rest: 0 })
  })
  test("activity comes from campaign dates and discovery times, newest first", () => {
    const a = activityOf([{ id: "c1", date: "2026-11-18T10:00:00Z", status: "stopped" }], [{ id: "v1", title: "X", severity: "high", discovered_at: "2026-11-18T10:05:00Z" }, { id: "v2", title: "no time" }])
    expect(a.map((x: any) => x.ref)).toEqual(["v1", "c1"])
  })
  test("ASCII fallback", () => {
    expect(unicodeTerminal({ LANG: "C" })).toBe(false)
    expect(unicodeTerminal({ LANG: "en_US.UTF-8" })).toBe(true)
    expect(unicodeTerminal({ LANG: "en_US.UTF-8", DARKMOON_ASCII: "1" })).toBe(false)
    expect(Object.values(glyphs(false)).join("")).toMatch(/^[\x20-\x7e]*\[object Object\]$|^[\x20-\x7e]*$/)
    expect(durationText(1730)).toBe("29 min")
    expect(durationText(undefined)).toBe("—")
  })
})

describe("splitSections: server section ids", () => {
  test("the id marker is never shown and keys the next heading", () => {
    const md = "# R\n\n<!-- dm-section: management-summary -->\n## MANAGEMENT SUMMARY\ntext\n\n<!-- dm-section: fix-first -->\n\n## PRIORITIZED TREATMENT PLAN\nrows\n"
    const s = splitSections(md)
    expect(s.map((x) => x.key ?? null)).toEqual([null, "management-summary", "fix-first"])
    expect(s.some((x) => x.body.includes("dm-section"))).toBe(false)
  })
  test("a marker followed by text, or inside a fence, keys nothing", () => {
    const s = splitSections("<!-- dm-section: a -->\ntext\n## H\n```\n<!-- dm-section: b -->\n## not a heading\n```\n")
    expect(s.find((x) => x.title === "H")?.key).toBeUndefined()
    expect(s.map((x) => x.body).join("")).toContain("<!-- dm-section: b -->")
  })
  test("old reports without markers split as before", () => {
    expect(splitSections("## FIX FIRST\nx\n").map((x) => [x.title, x.key])).toEqual([["FIX FIRST", undefined]])
  })
})

describe("executive views: display only, the words of exec_core", () => {
  const core = require("./core")

  test("path kinds: the same cases as exec_core legend.path_kind_of", () => {
    const P = (provenance: string, hypothesis: boolean, corroboration?: any) => ({ id: "p", title: "", provenance, hypothesis, corroboration })
    const ok = { status: "corroborated", unverified: [], checked: true }
    const cases: [any, string][] = [
      [P("observed", false), "evidence_backed"],
      [P("observed", true), "possible"],
      [P("derived", false, ok), "evidence_backed"],
      [P("derived", false, { ...ok, checked: false }), "possible"],
      [P("derived", false, { status: "corroborated", unverified: [] }), "possible"],
      [P("derived", true, { status: "claimed", unverified: ["x"], checked: true }), "possible"],
      [P("derived", false, { ...ok, unverified: ["x"] }), "possible"],
      [P("derived", false), "possible"],
      [P("declared", false), "possible"],
      [P("agent-declared", false), "possible"],
      [P("inferred", false), "possible"],
      [P("whatever", false), "possible"],
      [null, "possible"],
    ]
    for (const [p, k] of cases) expect(core.pathKind(p)).toBe(k)
    expect(core.pathKindCounts({ paths: cases.map((c) => c[0]).filter(Boolean) })).toEqual({ total: 12, evidence_backed: 2, possible: 10 })
  })

  test("score headline: a number only when rated or limited, never for « Not rated »", () => {
    expect(core.scoreHeadline({ score_status: "rated", score: 0, grade: "E", status_label: "Rated" })).toEqual({ big: "E  0/100", status: "Rated", rated: true, limited: false })
    expect(core.scoreHeadline({ score_status: "limited", score: 41, grade: "D", status_label: "Limited test" }).limited).toBe(true)
    const nr = core.scoreHeadline({ score_status: "not_rated", score: 55, grade: "C", status_label: "Not rated" })
    expect(nr.big).toBe("Not rated")
    expect(nr.big).not.toContain("55")
    expect(core.scoreHeadline(undefined).big).toBe("Not rated")
    expect(core.scoreWhy({ status_reasons: [{ code: "x", text: "Retest campaign" }] })).toBe("Retest campaign")
    expect(core.scoreWhy({ status_meaning: "No rating" })).toBe("No rating")
  })

  test("treatment: applied always reads not verified; a retest wording needs its completed retest", () => {
    expect(core.treatmentLabel({ action_id: "a", status: "applied", status_label: "Applied" })).toBe("Applied — not verified")
    expect(core.treatmentLabel({ action_id: "a", status: "applied", status_label: "Applied — not verified" })).toBe("Applied — not verified")
    expect(core.treatmentLabel({ action_id: "a", status: "verified_resolved", status_label: "Not reproduced at retest", last_retest: { retest_id: "r1" } })).toBe("Not reproduced at retest")
    expect(core.treatmentLabel({ action_id: "a", status: "verified_resolved", status_label: "Not reproduced at retest" })).toBe("Retest result not on file — not verified")
    expect(core.treatmentLabel({ action_id: "a", status: "proposed", status_label: "Proposed" })).toBe("Proposed")
    expect(core.treatmentLabel(undefined)).toBe("proposed")
    for (const s of ["proposed", "in_progress", "applied", "verified_resolved", "failed_verification", "risk_accepted", "deferred"]) {
      expect(core.treatmentMark(s, true).length).toBe(1)
      expect(core.treatmentMark(s, false)).toMatch(/^[ -~]$/)
    }
    expect(core.treatmentLabel({ action_id: "a", status: "applied", status_label: "Applied\x1b[2J" })).not.toContain("\x1b")
  })

  test("frameworks: four states in words, never a percentage, a grade or « compliant »", () => {
    const f = { framework: "gdpr", label: "GDPR", applicability: { status: "to_confirm", label: "To confirm" }, counts: { weakness_observed: 3, none_observed_in_tested_scope: 1, not_tested: 2, not_technically_assessable: 4 } }
    const line = core.frameworkLine(f)
    expect(line).toBe("3 weakness observed · 1 none observed in tested scope · 2 not tested · 4 not technically assessable")
    expect(line + core.frameworkLine(f, true)).not.toMatch(/%|compliant|grade/i)
    expect(core.applicabilityOf(f)).toEqual({ status: "to_confirm", label: "To confirm" })
    expect(core.applicabilityOf({ framework: "x", applicability: "declared_by_customer", applicability_label: "Applicable" })).toEqual({ status: "declared_by_customer", label: "Applicable" })
  })

  test("profile: provenance is a shape and a word; unknown values are never invented", () => {
    expect(core.provenanceBadge("verified").word).toBe("Verified")
    expect(core.provenanceBadge("declared_by_customer").word).toBe("Declared")
    expect(core.provenanceBadge("detected").word).toBe("Detected")
    expect(core.provenanceBadge("unknown").word).toBe("Not provided")
    expect(new Set(["verified", "declared_by_customer", "detected", "unknown"].map((p) => core.provenanceBadge(p).mark)).size).toBe(4)
    expect(core.provenanceBadge("verified", false).mark).toMatch(/^[ -~]$/)
    expect(core.profileValue(null)).toBe("—")
    expect(core.profileValue(["a", "b"])).toBe("a, b")
    expect(core.profileValue(true)).toBe("yes")
  })

  test("legend: shared words, evidence status kept apart from severity", () => {
    const l = {
      path_kind: { evidence_backed: { label: "Evidence-Backed Attack Path", meaning: "m1" }, possible: { label: "Possible Attack Path", meaning: "m2" } },
      evidence_status: { exploited: { label: "Exploited", meaning: "e" }, confirmed: { label: "Confirmed", meaning: "c" }, unconfirmed: { label: "To confirm", meaning: "u" } },
      treatment: { in_progress: { label: "Treatment in Progress", meaning: "t" }, not_reproduced: { label: "Not reproduced at retest", meaning: "n" }, risk_accepted: { label: "Risk accepted", meaning: "r" } },
      score_status: { rated: { label: "Rated", meaning: "a" }, limited: { label: "Limited test", meaning: "b" }, not_rated: { label: "Not rated", meaning: "c" } },
    }
    const text = core.legendLines(l).join("\n")
    for (const w of ["Evidence-Backed Attack Path", "Possible Attack Path", "To confirm", "Treatment in Progress", "Not reproduced at retest", "Not rated", "not severity"]) expect(text).toContain(w)
    expect(core.legendLines(l, false).join("\n")).toMatch(/^[\x20-\x7e\n—«»…·]*$/)
    expect(core.legendLines(undefined).join("\n")).toContain("Possible Attack Path")
    const compact = core.legendLines(l, true, true)
    expect(compact.length).toBeLessThanOrEqual(13)
    for (const w of ["Evidence-Backed Attack Path", "Possible Attack Path", "To confirm", "Not reproduced at retest", "Not rated"]) expect(compact.join("\n")).toContain(w)
  })

  test("wrapLines: bounded lines, cut text says so", () => {
    expect(core.wrapLines("aaa bbb ccc ddd", 7, 3)).toEqual(["aaa bbb", "ccc ddd"])
    expect(core.wrapLines("aaa bbb ccc ddd eee", 7, 2)).toEqual(["aaa bbb", "ccc dd…"])
    expect(core.wrapLines("x".repeat(20), 8, 2)).toEqual(["xxxxxxx…"])
    expect(core.wrapLines("", 8, 2)).toEqual([])
  })

  test("sources: the executive documents come from the server routes / the adapter commands", async () => {
    const urls: string[] = []
    const api = new core.ExplorerApi("http://x/api/v1", (async (u: string) => {
      urls.push(u)
      return new Response("{}", { status: 200 })
    }) as any)
    api.useToken("t")
    await api.executive("c1"); await api.projectExecutive("p1"); await api.plan("c1"); await api.frameworks("c1"); await api.profile("p1"); await api.legend()
    expect(urls.map((u) => u.replace("http://x/api/v1", ""))).toEqual([
      "/campaigns/c1/executive", "/projects/p1/executive", "/campaigns/c1/treatment-plan", "/campaigns/c1/framework-assessment", "/projects/p1/profile", "/executive/legend",
    ])
    const seen: string[][] = []
    const fs = new core.FileSource(async (a: string[]) => (seen.push(a), { code: 0, stdout: "{}", stderr: "" }))
    await fs.executive("c1"); await fs.projectExecutive("p1"); await fs.plan("c1"); await fs.frameworks("c1"); await fs.profile("p1"); await fs.legend()
    expect(seen).toEqual([["executive", "c1"], ["executive", "--project", "p1"], ["plan", "c1"], ["frameworks", "c1"], ["profile", "p1"], ["legend"]])
    const c = new core.CachedSource(fs)
    await c.plan("c1"); await c.plan("c1"); await c.projectExecutive("p1"); await c.executive("p1")
    expect(seen.length).toBe(6 + 3) // cached per key; a project block and a campaign block never share a key
  })
})
