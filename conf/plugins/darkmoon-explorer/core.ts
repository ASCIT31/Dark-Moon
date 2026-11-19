/**
 * Darkmoon Terminal Explorer — data access and pure view logic (no UI, no LLM).
 *
 * Read-only client of the existing Darkmoon API (/api/v1). Nothing here computes
 * findings, stats or attack-path causality: it only fetches what the server already
 * produced and shapes it for a terminal. The bearer token lives in memory only.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export type Project = {
  id: string
  name: string
  target?: string | { host?: string; ip?: string }
  campaigns_count?: number
  vulnerabilities_count?: number
  latest_risk?: string
}

export type Campaign = {
  id: string
  project_id?: string
  date?: string
  status?: string
  overall_risk?: string
  is_subagent?: boolean
  report_path?: string | null
  stats?: Record<string, unknown>
  vulnerabilities?: Finding[]
}

export type Finding = {
  id: string
  title: string
  severity?: string
  status?: string
  endpoint?: string
  category?: string
  cve?: string | null
  cvss_score?: number | null
  mitre_attack_id?: string | null
  discovered_by_agent?: string
  description?: string
  remediation?: unknown
  enabled_by?: unknown
  evidence?: Record<string, unknown>
  display?: { asset_host?: string; title_short?: string }
}

export type PathStep = {
  n: number
  node_label?: string
  plain?: string
  finding_id?: string | null
  findings?: (string | { id?: string })[]
  proof?: string
  kind?: string
}

export type AttackPath = {
  id: string
  title: string
  provenance?: string
  hypothesis?: boolean
  certainty?: string
  criticality?: string
  status?: string
  finding_ids?: string[]
  steps?: PathStep[]
  note?: string
}

export type AttackPaths = {
  summary?: Record<string, unknown>
  paths?: AttackPath[]
  fix_first?: unknown
}

export type VulnStats = {
  by_severity?: Record<string, number>
  by_status?: Record<string, number>
  by_category?: Record<string, number>
}

/** What the TUI needs, whatever the edition: Pro reads the API, Community reads its local store. */
export interface DataSource {
  readonly kind: "api" | "files"
  readonly needsLogin: boolean
  readonly authenticated: boolean
  login(username: string, password: string): Promise<{ mustChange: boolean }>
  logout(): void
  projects(): Promise<Project[]>
  campaigns(projectId?: string): Promise<Campaign[]>
  campaign(id: string): Promise<Campaign>
  finding(id: string): Promise<Finding>
  vulnerabilities(filter?: { project_id?: string; campaign_id?: string }): Promise<{ data: Finding[]; stats?: VulnStats }>
  report(campaignId: string): Promise<string>
  attackPaths(campaignId: string): Promise<AttackPaths>
}

export type ApiError = { kind: "auth" | "network" | "http" | "parse"; status?: number; message: string }

export class ExplorerApi implements DataSource {
  readonly kind = "api" as const
  readonly needsLogin = true
  private token: string | undefined
  constructor(
    readonly base: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  get authenticated() {
    return Boolean(this.token)
  }

  useToken(token: string | undefined) {
    this.token = token?.trim() || undefined
  }

  logout() {
    this.token = undefined
  }

  async login(username: string, password: string): Promise<{ mustChange: boolean }> {
    const body = await this.request<{ token?: string; must_change_password?: boolean }>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    })
    if (!body.token) throw { kind: "auth", message: "Login refused" } satisfies ApiError
    this.token = body.token
    return { mustChange: Boolean(body.must_change_password) }
  }

  async projects(): Promise<Project[]> {
    return (await this.request<{ data: Project[] }>("/projects")).data ?? []
  }

  async campaigns(projectId?: string): Promise<Campaign[]> {
    const all = (await this.request<{ data: Campaign[] }>("/campaigns")).data ?? []
    return all
      .filter((c) => !c.is_subagent && (!projectId || c.project_id === projectId))
      .sort((a, b) => String(b.date ?? "").localeCompare(String(a.date ?? "")))
  }

  async campaign(id: string): Promise<Campaign> {
    return (await this.request<{ data: Campaign }>(`/campaigns/${enc(id)}`)).data
  }

  async finding(id: string): Promise<Finding> {
    const body = await this.request<Finding | { data: Finding }>(`/vulnerabilities/${enc(id)}`)
    return "data" in body && body.data ? body.data : (body as Finding)
  }

  async vulnerabilities(filter: { project_id?: string; campaign_id?: string } = {}): Promise<{ data: Finding[]; stats?: VulnStats }> {
    const q = new URLSearchParams(Object.entries(filter).filter(([, v]) => v) as [string, string][]).toString()
    const body = await this.request<{ data?: Finding[]; stats?: VulnStats }>(`/vulnerabilities${q ? `?${q}` : ""}`)
    return { data: body.data ?? [], stats: body.stats }
  }

  async report(campaignId: string): Promise<string> {
    const body = await this.request<{ content?: string }>(`/campaigns/${enc(campaignId)}/report`)
    return typeof body.content === "string" ? body.content : ""
  }

  async attackPaths(campaignId: string): Promise<AttackPaths> {
    return await this.request<AttackPaths>(`/campaigns/${enc(campaignId)}/attack-paths?include=steps`)
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers)
    if (this.token) headers.set("Authorization", `Bearer ${this.token}`)
    let res: Response
    try {
      res = await this.fetcher(this.base + path, { ...init, headers, signal: AbortSignal.timeout(15000) })
    } catch (e) {
      throw { kind: "network", message: `Darkmoon API unreachable (${this.base})` } satisfies ApiError
    }
    if (res.status === 401 || res.status === 403) {
      if (path !== "/auth/login") this.token = undefined
      throw { kind: "auth", status: res.status, message: "Session expired or not allowed" } satisfies ApiError
    }
    if (!res.ok) throw { kind: "http", status: res.status, message: `API error ${res.status}` } satisfies ApiError
    try {
      return (await res.json()) as T
    } catch {
      throw { kind: "parse", message: "Unreadable API response" } satisfies ApiError
    }
  }
}

const enc = (s: string) => encodeURIComponent(s)

export function errorText(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) return clean(String((e as ApiError).message))
  return "Unexpected error"
}

/** Strip terminal control sequences: API strings (evidence, titles) must never drive the terminal. */
export function clean(value: unknown, max = 4000): string {
  const s = typeof value === "string" ? value : value == null ? "" : JSON.stringify(value)
  const out = s
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x9d\x90\x98\x9e\x9f][^\x07\x9c\x1b]*(\x07|\x9c|\x1b\\)?/g, "") // 8-bit OSC / DCS / SOS / PM / APC strings
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "") // C0, C1, bidi
  return out.length > max ? out.slice(0, max) + "…" : out
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"]

export function severityRank(s: string | undefined): number {
  const i = SEVERITIES.indexOf(String(s ?? "").toLowerCase() as Severity)
  return i < 0 ? SEVERITIES.length : i
}

/** Text label, never colour alone. */
export function severityTag(s: string | undefined): string {
  const v = String(s ?? "info").toLowerCase()
  return ({ critical: "CRIT", high: "HIGH", medium: "MED ", low: "LOW ", info: "INFO" } as Record<string, string>)[v] ?? "INFO"
}

export function proofTag(status: string | undefined): string {
  const v = String(status ?? "").toLowerCase()
  if (v === "exploited") return "exploited"
  if (v === "confirmed") return "confirmed"
  if (v === "false_positive" || v === "quarantined") return v.replace("_", " ")
  return "unconfirmed"
}

export type FindingFilter = { severity?: string; status?: string; target?: string; query?: string }

export function filterFindings(list: Finding[], f: FindingFilter): Finding[] {
  const q = f.query?.trim().toLowerCase()
  return list
    .filter((v) => !f.severity || String(v.severity).toLowerCase() === f.severity)
    .filter((v) => !f.status || proofTag(v.status) === f.status)
    .filter((v) => !f.target || targetOf(v) === f.target)
    .filter(
      (v) =>
        !q ||
        [v.id, v.title, v.endpoint, v.category, v.cve, v.mitre_attack_id]
          .filter(Boolean)
          .some((x) => String(x).toLowerCase().includes(q)),
    )
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title))
}

export function targetOf(v: Finding): string {
  if (v.display?.asset_host) return v.display.asset_host
  try {
    return new URL(String(v.endpoint)).host
  } catch {
    return String(v.endpoint ?? "")
  }
}

export function targetsOf(list: Finding[]): string[] {
  return [...new Set(list.map(targetOf).filter(Boolean))].sort()
}

export function page<T>(list: T[], index: number, size: number): { items: T[]; page: number; pages: number } {
  const pages = Math.max(1, Math.ceil(list.length / size))
  const p = Math.min(Math.max(0, index), pages - 1)
  return { items: list.slice(p * size, p * size + size), page: p, pages }
}

/** Keep the cursor visible in a window of `height` rows. */
export function windowAround(length: number, cursor: number, height: number): { start: number; end: number } {
  if (length <= height) return { start: 0, end: length }
  const start = Math.min(Math.max(0, cursor - Math.floor(height / 2)), length - height)
  return { start, end: start + height }
}

export function countsOf(list: Finding[]) {
  const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, exploited: 0 }
  for (const v of list) {
    const s = String(v.severity ?? "info").toLowerCase()
    c[s] = (c[s] ?? 0) + 1
    if (proofTag(v.status) === "exploited") c.exploited++
  }
  return c
}

// ---------------------------------------------------------------- evidence

const EVIDENCE_FIELDS: [string, string][] = [
  ["explanation", "Explanation"],
  ["commands", "Commands"],
  ["raw_request", "Request"],
  ["raw_response", "Response"],
  ["payloads", "Payloads"],
  ["extracted_data", "Extracted data"],
  ["logs", "Logs"],
]

/** Evidence as served by the API (already redacted server-side), flattened for display. */
export function evidenceSections(evidence: Record<string, unknown> | undefined): { label: string; text: string }[] {
  if (!evidence) return []
  const out: { label: string; text: string }[] = []
  for (const [key, label] of EVIDENCE_FIELDS) {
    const raw = evidence[key]
    if (raw == null || (Array.isArray(raw) && raw.length === 0) || raw === "") continue
    const unescape = (x: string) => x.replace(/\\r\\n|\\n/g, "\n").replace(/\\t/g, "  ")
    const text = unescape(Array.isArray(raw) ? raw.map((x) => clean(x, 1500)).join("\n") : clean(raw, 3000))
    if (text.trim()) out.push({ label, text })
  }
  return out
}

/** enabled_by as declared by the agent. Shown as a declaration, never as proof. */
export function declaredLinks(v: Finding): string[] {
  const raw = v.enabled_by
  const items = Array.isArray(raw) ? raw : raw ? [raw] : []
  return items
    .map((x) => (typeof x === "string" ? x : x && typeof x === "object" ? String((x as any).id ?? (x as any).finding_id ?? "") : ""))
    .filter(Boolean)
    .map((x) => clean(x, 120))
}

export function remediationText(r: unknown): string {
  if (!r) return ""
  if (typeof r === "string") return clean(r, 2000)
  if (typeof r === "object") {
    const o = r as Record<string, unknown>
    return clean(o.summary ?? o.text ?? o.description ?? o.steps ?? JSON.stringify(o), 2000)
  }
  return clean(r, 2000)
}

// ---------------------------------------------------------------- attack paths

/** The server's proof contract: only hypothesis:false is proven; agent-declared and inferred stay hypotheses. */
export function pathProof(p: AttackPath): { label: string; proven: boolean } {
  if (p.hypothesis === false) return { label: "PROVEN · corroborated", proven: true }
  const prov = String(p.provenance ?? "").toLowerCase()
  if (prov.includes("declared")) return { label: "DECLARED · not verified", proven: false }
  if (prov === "inferred") return { label: "INFERRED · hypothesis", proven: false }
  return { label: "HYPOTHESIS", proven: false }
}

/** Unicode chain; solid arrow only for proven paths, dashed otherwise. */
export function pathChain(p: AttackPath): string[] {
  const arrow = pathProof(p).proven ? "─▶" : "╌▶"
  return (p.steps ?? []).map((s, i) => {
    const node = clean(s.node_label ?? `step ${s.n}`, 80)
    const f = stepFinding(s)
    return `${i === 0 ? "  " : arrow} ${node}${f ? `  [${clean(f, 40)}]` : ""}`
  })
}

/** The finding behind a step: the API gives `finding_id` and/or `findings` as ids or objects. */
export function stepFinding(s: PathStep): string | undefined {
  if (s.finding_id) return s.finding_id
  const f = s.findings?.[0]
  return (typeof f === "string" ? f : f?.id) || undefined
}

export function pathFindingIds(p: AttackPath): string[] {
  const ids = new Set<string>(p.finding_ids ?? [])
  for (const s of p.steps ?? []) {
    if (s.finding_id) ids.add(s.finding_id)
    for (const f of s.findings ?? []) {
      const id = typeof f === "string" ? f : f?.id
      if (id) ids.add(id)
    }
  }
  return [...ids]
}

// ---------------------------------------------------------------- markdown report

export type Section = { title: string; level: number; body: string; key?: string }

/** Stable section id written by the server on the line before a heading (``<!-- dm-section: fix-first -->``). */
const SECTION_ID = /^\s*<!--\s*dm-section:\s*([a-z0-9][a-z0-9-]{0,63})\s*-->\s*$/

/** Split a report on headings outside fenced code; tolerant of malformed Markdown (unclosed fences). A section id
 *  marker is never shown: it gives its ``key`` to the heading that follows it (blank lines allowed in between). */
export function splitSections(md: string): Section[] {
  const lines = clean(md, 2_000_000).replace(/\r\n?/g, "\n").split("\n")
  const out: Section[] = []
  let cur: Section = { title: "", level: 0, body: "" }
  let fence: string | null = null
  let key: string | undefined
  for (const line of lines) {
    const f = line.match(/^\s{0,3}(`{3,}|~{3,})/)
    if (f) fence = fence ? (line.trim().startsWith(fence[0]) ? null : fence) : f[1]
    const id = !fence && !f ? line.match(SECTION_ID) : null
    if (id) {
      key = id[1]
      continue
    }
    const h = !fence && !f ? line.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/) : null
    if (h) {
      if (cur.body.trim() || cur.title) out.push(cur)
      cur = { title: h[2], level: h[1].length, body: line + "\n", ...(key ? { key } : {}) }
      key = undefined
    } else {
      if (line.trim()) key = undefined
      cur.body += line + "\n"
    }
  }
  if (cur.body.trim() || cur.title) out.push(cur)
  return out
}

export function searchSections(sections: Section[], query: string): number[] {
  const q = query.trim().toLowerCase()
  if (!q) return []
  return sections.flatMap((s, i) => (s.body.toLowerCase().includes(q) ? [i] : []))
}

// ---------------------------------------------------------------- Community: local store through the adapter

export type Runner = (args: string[]) => Promise<{ code: number; stdout: string; stderr: string }>

/**
 * Community edition: no API. A short-lived, read-only Python adapter (`darkmoon_explore.py`) reads the local
 * JSON store, applies the evidence redaction and prints the same JSON shapes as the Pro API. No daemon, no cache
 * file, no new store. If the redaction module cannot load, the adapter withholds evidence (fail closed).
 */
export class FileSource implements DataSource {
  readonly kind = "files" as const
  readonly needsLogin = false
  readonly authenticated = true
  constructor(private readonly run: Runner) {}
  async login() {
    return { mustChange: false }
  }
  logout() {}
  private async call<T>(...args: string[]): Promise<T> {
    let r: Awaited<ReturnType<Runner>>
    try {
      r = await this.run(args)
    } catch {
      throw { kind: "network", message: "Local Darkmoon data adapter could not start" } satisfies ApiError
    }
    if (r.code !== 0) {
      const msg = clean(r.stderr.trim().split("\n").pop() ?? "", 160) || `adapter exit ${r.code}`
      throw { kind: r.code === 2 ? "http" : "parse", status: r.code === 2 ? 404 : undefined, message: msg } satisfies ApiError
    }
    try {
      return JSON.parse(r.stdout) as T
    } catch {
      throw { kind: "parse", message: "Unreadable local data" } satisfies ApiError
    }
  }
  async projects() {
    return (await this.call<{ data: Project[] }>("projects")).data ?? []
  }
  async campaigns(projectId?: string) {
    const all = (await this.call<{ data: Campaign[] }>("campaigns")).data ?? []
    return all
      .filter((c) => !c.is_subagent && (!projectId || c.project_id === projectId))
      .sort((a, b) => String(b.date ?? "").localeCompare(String(a.date ?? "")))
  }
  async campaign(id: string) {
    return (await this.call<{ data: Campaign }>("campaign", id)).data
  }
  async finding(id: string) {
    return (await this.call<{ data: Finding }>("finding", id)).data
  }
  async vulnerabilities(filter: { project_id?: string; campaign_id?: string } = {}) {
    const args = ["vulnerabilities"]
    if (filter.project_id) args.push("--project", filter.project_id)
    if (filter.campaign_id) args.push("--campaign", filter.campaign_id)
    return await this.call<{ data: Finding[]; stats?: VulnStats }>(...args)
  }
  async report(campaignId: string) {
    return (await this.call<{ content?: string }>("report", campaignId)).content ?? ""
  }
  async attackPaths(campaignId: string) {
    return await this.call<AttackPaths>("paths", campaignId)
  }
}

/** In-memory read-through cache: back-navigation never refetches; `r` invalidates. Nothing is written to disk. */
export class CachedSource implements DataSource {
  private memo = new Map<string, { at: number; value: Promise<unknown> }>()
  constructor(
    readonly inner: DataSource,
    private readonly ttlMs = 60_000,
    private readonly now: () => number = Date.now,
  ) {}
  get kind() {
    return this.inner.kind
  }
  get needsLogin() {
    return this.inner.needsLogin
  }
  get authenticated() {
    return this.inner.authenticated
  }
  invalidate() {
    this.memo.clear()
  }
  login(u: string, p: string) {
    this.memo.clear()
    return this.inner.login(u, p)
  }
  logout() {
    this.memo.clear()
    this.inner.logout()
  }
  private get<T>(key: string, load: () => Promise<T>): Promise<T> {
    const hit = this.memo.get(key)
    if (hit && this.now() - hit.at < this.ttlMs) return hit.value as Promise<T>
    const value = load()
    this.memo.set(key, { at: this.now(), value })
    value.catch(() => this.memo.delete(key))
    return value
  }
  projects() {
    return this.get("projects", () => this.inner.projects())
  }
  campaigns(projectId?: string) {
    return this.get(`campaigns:${projectId ?? ""}`, () => this.inner.campaigns(projectId))
  }
  campaign(id: string) {
    return this.get(`campaign:${id}`, () => this.inner.campaign(id))
  }
  finding(id: string) {
    return this.get(`finding:${id}`, () => this.inner.finding(id))
  }
  vulnerabilities(f: { project_id?: string; campaign_id?: string } = {}) {
    return this.get(`vulns:${f.project_id ?? ""}:${f.campaign_id ?? ""}`, () => this.inner.vulnerabilities(f))
  }
  report(id: string) {
    return this.get(`report:${id}`, () => this.inner.report(id))
  }
  attackPaths(id: string) {
    return this.get(`paths:${id}`, () => this.inner.attackPaths(id))
  }
}

// ---------------------------------------------------------------- v2 view helpers

export type SortKey = "severity" | "proof" | "title" | "date" | "target"
export const SORT_KEYS: SortKey[] = ["severity", "proof", "title", "date", "target"]

const PROOF_RANK: Record<string, number> = { exploited: 0, confirmed: 1, unconfirmed: 2 }

export function sortFindings(list: Finding[], key: SortKey): Finding[] {
  const by: Record<SortKey, (a: Finding, b: Finding) => number> = {
    severity: (a, b) => severityRank(a.severity) - severityRank(b.severity),
    proof: (a, b) => (PROOF_RANK[proofTag(a.status)] ?? 3) - (PROOF_RANK[proofTag(b.status)] ?? 3),
    title: (a, b) => a.title.localeCompare(b.title),
    date: (a, b) => String((b as any).discovered_at ?? "").localeCompare(String((a as any).discovered_at ?? "")),
    target: (a, b) => targetOf(a).localeCompare(targetOf(b)),
  }
  return [...list].sort((a, b) => by[key](a, b) || severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title))
}

/** Proof as a glyph that is not colour alone: ● exploited, ◐ confirmed, ○ unconfirmed. */
export function proofMark(status: string | undefined): string {
  const p = proofTag(status)
  return p === "exploited" ? "●" : p === "confirmed" ? "◐" : "○"
}

export function shortDate(iso: string | undefined): string {
  const s = String(iso ?? "")
  return s.length >= 16 ? `${s.slice(0, 10)} ${s.slice(11, 16)}` : s.slice(0, 10)
}

export type TocEntry = { index: number; title: string; level: number }

/** Report contents: chapters (#, ##) and their sections (###), in reading order. */
export function tocOf(sections: Section[], maxLevel = 3): TocEntry[] {
  return sections.flatMap((s, index) =>
    s.title && s.level <= maxLevel ? [{ index, title: clean(s.title.replace(/[*_`]/g, "").replace(/\p{Extended_Pictographic}\uFE0F?/gu, "●"), 120), level: s.level }] : [],
  )
}

/** Finding ids cited by a block of report text (the report renders them verbatim, e.g. « vuln_a52c3f »). */
export function citedFindings(text: string): string[] {
  return [...new Set(text.match(/\bvuln_[0-9a-f]{4,}\b/g) ?? [])]
}

/** Darkmoon palette, from the Darkmoon dashboard tokens and the brand charter. */
export type Palette = Record<
  | "canvas" | "surface" | "raised" | "hover" | "ink" | "ink2" | "ink3" | "off" | "rule"
  | "alice" | "jordy" | "neon" | "chrysler" | "royal" | "uranian"
  | "critical" | "high" | "medium" | "low" | "info" | "criticalInk" | "code" | "edge",
  string
>

export function palette(mode: "dark" | "light"): Palette {
  const brand = { alice: "#dceaf4", jordy: "#87bfff", neon: "#2667ff", chrysler: "#3b26cc", royal: "#0a2472", uranian: "#add7f6" }
  return mode === "dark"
    ? { canvas: "#000000", surface: "#0f0f0f", raised: "#1a1a1a", hover: "#242424", ink: "#ffffff", ink2: "#d1d1d6",
        ink3: "#a1a1a6", off: "#808085", rule: "#242424", ...brand,
        critical: "#ff453a", high: "#ff8a1f", medium: "#ffd426", low: "#2ec5d3", info: "#a1a1a6", criticalInk: "#ff7a70", code: "#add7f6", edge: "#3a3a3e" }
    : { canvas: "#f4f4f4", surface: "#ffffff", raised: "#f4f4f4", hover: "#ededed", ink: "#000000", ink2: "#242424",
        ink3: "#4a515b", off: "#646b75", rule: "#ededed", ...brand, jordy: "#2f6fb8", uranian: "#3a7fae",
        critical: "#e0301e", high: "#d86400", medium: "#a88000", low: "#0a7f96", info: "#4a515b", criticalInk: "#e0301e", code: "#2f6fb8", edge: "#c7c7cc" }
}

// ---------------------------------------------------------------- visual primitives (real data only)

/** Unicode glyphs with an ASCII fallback for terminals without UTF-8 (no Nerd Font needed either way). */
export type Glyphs = Record<"mark" | "bar" | "track" | "sel" | "node" | "nodeOpen" | "proven" | "hyp" | "arrow" | "dot" | "spark", string> & {
  box: { tl: string; tr: string; bl: string; br: string; h: string; v: string; tee: string }
}
export function glyphs(unicode: boolean): Glyphs {
  return unicode
    ? { mark: "■", bar: "█", track: "─", sel: "▌", node: "●", nodeOpen: "○", proven: "│", hyp: "┆", arrow: "▼", dot: "·", spark: "▁▂▃▄▅▆▇█",
        box: { tl: "╭", tr: "╮", bl: "╰", br: "╯", h: "─", v: "│", tee: "┬" } }
    : { mark: "#", bar: "=", track: "-", sel: ">", node: "*", nodeOpen: "o", proven: "|", hyp: ":", arrow: "v", dot: ".", spark: " .:-=+*#",
        box: { tl: "+", tr: "+", bl: "+", br: "+", h: "-", v: "|", tee: "+" } }
}
export function unicodeTerminal(env: Record<string, string | undefined>): boolean {
  if (env["DARKMOON_ASCII"] === "1") return false
  const loc = `${env["LC_ALL"] ?? ""} ${env["LC_CTYPE"] ?? ""} ${env["LANG"] ?? ""}`.toUpperCase()
  return loc.trim() === "" || loc.includes("UTF-8") || loc.includes("UTF8")
}

/** Count timestamps into n equal buckets between start and end. Unparseable timestamps are ignored. */
export function buckets(times: (string | undefined)[], n: number, start?: string, end?: string): number[] {
  const ts = times.map((t) => Date.parse(String(t ?? ""))).filter((t) => Number.isFinite(t))
  const out = new Array(Math.max(1, n)).fill(0)
  if (!ts.length) return out
  const a = Number.isFinite(Date.parse(String(start))) ? Date.parse(String(start)) : Math.min(...ts)
  const b0 = Number.isFinite(Date.parse(String(end))) ? Date.parse(String(end)) : Math.max(...ts)
  const b = b0 > a ? b0 : a + 1
  for (const t of ts) {
    const i = Math.min(out.length - 1, Math.max(0, Math.floor(((t - a) / (b - a)) * out.length)))
    out[i]++
  }
  return out
}

/** One character per bucket; an empty bucket is the lowest step, never invented. */
export function sparkline(counts: number[], steps: string): string {
  const max = Math.max(0, ...counts)
  if (!max) return steps[0].repeat(counts.length)
  return counts.map((c) => (c === 0 ? steps[0] : steps[Math.max(1, Math.round((c / max) * (steps.length - 1)))])).join("")
}

/** Horizontal bar: filled part proportional to value/max, never below one cell for a non-zero value. */
export function hbar(value: number, max: number, width: number): { fill: number; rest: number } {
  const w = Math.max(0, width)
  if (!max || !value) return { fill: 0, rest: w }
  const fill = Math.min(w, Math.max(1, Math.round((value / max) * w)))
  return { fill, rest: w - fill }
}

export type Activity = { at: string; kind: "campaign" | "finding"; text: string; severity?: string; ref: string }

/** Recent activity from real records only: campaign starts and finding discoveries, newest first. */
export function activityOf(campaigns: Campaign[], findings: Finding[], limit = 8): Activity[] {
  const out: Activity[] = []
  for (const c of campaigns) if (c.date) out.push({ at: String(c.date), kind: "campaign", text: `${clean(c.id, 40)} ${clean(c.status ?? "", 12)}`.trim(), ref: c.id })
  for (const f of findings) {
    const at = (f as any).discovered_at ?? (f as any).first_seen
    if (at) out.push({ at: String(at), kind: "finding", text: clean((f as any).short_title || f.title, 120), severity: f.severity, ref: f.id })
  }
  return out.sort((a, b) => b.at.localeCompare(a.at)).slice(0, limit)
}

export function timeOf(iso: string | undefined): string {
  const s = String(iso ?? "")
  return s.length >= 16 ? s.slice(11, 16) : s
}

export function durationText(seconds: unknown): string {
  const s = Number(seconds)
  if (!Number.isFinite(s) || s <= 0) return "—"
  const m = Math.round(s / 60)
  return m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`
}
