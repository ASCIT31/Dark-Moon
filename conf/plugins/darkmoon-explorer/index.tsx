/** @jsxImportSource @opentui/solid */
/**
 * Darkmoon Terminal Explorer — OpenCode TUI plugin (opencode >= 1.19, official `tui` plugin API).
 *
 * A keyboard-first workspace for projects, campaigns, findings, Markdown reports and attack paths, inside the
 * OpenCode console. Read-only, zero model call: Pro reads the existing /api/v1 routes, Community reads its local
 * store through `darkmoon_explore.py`. Open with `/explore`, the palette (« Darkmoon explorer ») or <leader>d.
 */
import type { TuiPlugin, TuiPluginApi } from "@opencode-ai/plugin/tui"
import { RGBA, SyntaxStyle, type BoxRenderable, type ScrollBoxRenderable } from "@opentui/core"
import { useBindings } from "@opentui/keymap/solid"
import { useKeyboard, useTerminalDimensions } from "@opentui/solid"
import { createEffect, createMemo, createSignal, For, on, Show, type JSX } from "solid-js"
import { execFile } from "node:child_process"
import {
  activityOf,
  applicabilityMark,
  applicabilityOf,
  declaredByText,
  effortText,
  frameworkLine,
  gradeLever,
  maintenanceCheckLine,
  retestNote,
  riskAcceptanceText,
  legendLines,
  scrollKey,
  scrollWindow,
  topTabs,
  wrapDialogLines,
  maintenanceLines,
  pathKindCounts,
  profileValue,
  provenanceBadge,
  scoreHeadline,
  scoreWhy,
  treatmentLabel,
  treatmentMark,
  wrapLines,
  FRAMEWORK_STATES,
  PATH_KIND_LABEL,
  PROFILE_GROUPS,
  type ActionRow,
  type Executive,
  type FrameworkAssessment,
  type Legend,
  type ProfileDoc,
  type MaintenanceDoc,
  type TreatmentPlan,
  buckets,
  durationText,
  glyphs,
  hbar,
  sparkline,
  timeOf,
  unicodeTerminal,
  CachedSource,
  citedFindings,
  clean,
  countsOf,
  declaredLinks,
  errorText,
  evidenceSections,
  ExplorerApi,
  FileSource,
  filterFindings,
  page,
  palette,
  pathFindingIds,
  pathKind,
  pathProof,
  proofMark,
  proofTag,
  remediationText,
  searchSections,
  severityTag,
  shortDate,
  sortFindings,
  splitSections,
  stepFinding,
  targetOf,
  targetsOf,
  tocOf,
  windowAround,
  SEVERITIES,
  SORT_KEYS,
  type AttackPath,
  type AttackPaths,
  type Campaign,
  type Finding,
  type FindingFilter,
  type Palette,
  type PathStep,
  type Project,
  type Section,
  type SortKey,
  type VulnStats,
} from "./core"

const ROUTE = "darkmoon.explorer"
const PAGE = 50
const BOLD = 1

type Options = { source?: "api" | "files"; api?: string; data?: string; reports?: string; python?: string; mcp?: string }

function createSource(o: Options): CachedSource {
  if (o.source === "files") {
    const script = new URL("./darkmoon_explore.py", import.meta.url).pathname
    const pre = [...(o.data ? ["--data", o.data] : []), ...(o.reports ? ["--reports", o.reports] : []), ...(o.mcp ? ["--mcp", o.mcp] : [])]
    const run = (args: string[]) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((resolve, reject) => {
        execFile(o.python ?? "python3", ["-I", "-B", script, ...pre, ...args], { timeout: 20000, maxBuffer: 64 << 20 }, (err, stdout, stderr) => {
          if (err && typeof (err as any).code !== "number") return reject(err)
          resolve({ code: err ? Number((err as any).code) : 0, stdout: String(stdout), stderr: String(stderr) })
        })
      })
    return new CachedSource(new FileSource(run))
  }
  const base = (o.api ?? process.env["DARKMOON_API_URL"] ?? "http://127.0.0.1:8000/api/v1").replace(/\/+$/, "")
  const api = new ExplorerApi(base)
  api.useToken(process.env["DARKMOON_EXPLORER_TOKEN"])
  return new CachedSource(api)
}

// ------------------------------------------------------------------------------------------------ navigation model

type Tab = "workspace" | "projects" | "campaigns" | "findings" | "plan" | "paths" | "reports"
const TABS: { id: Tab; label: string; short: string }[] = [
  { id: "workspace", label: "Workspace", short: "Work" },
  { id: "projects", label: "Projects", short: "Proj" },
  { id: "campaigns", label: "Campaigns", short: "Camp" },
  { id: "findings", label: "Findings", short: "Find" },
  { id: "plan", label: "Plan", short: "Plan" },
  { id: "paths", label: "Attack paths", short: "Paths" },
  { id: "reports", label: "Reports", short: "Docs" },
]

type View =
  | { k: "login" }
  | { k: "workspace" }
  | { k: "projects" }
  | { k: "campaigns"; project?: Project; purpose?: "paths" | "reports" | "plan" }
  | { k: "campaign"; campaign: Campaign }
  | { k: "findings"; campaign?: Campaign }
  | { k: "finding"; id: string; title: string }
  | { k: "report"; campaign: Campaign }
  | { k: "paths"; campaign: Campaign }
  | { k: "path"; campaign: Campaign; path: AttackPath }
  | { k: "plan"; campaign: Campaign }
  | { k: "frameworks"; campaign: Campaign }
  | { k: "profile"; project: Project }

type Cell = { text: string; w?: number; fg?: string; bold?: boolean; right?: boolean }
type Row = { key: string; header?: boolean; mark?: { glyph: string; fg: string }; cells: Cell[] }

function rootView(tab: Tab): View {
  if (tab === "paths") return { k: "campaigns", purpose: "paths" }
  if (tab === "reports") return { k: "campaigns", purpose: "reports" }
  if (tab === "plan") return { k: "campaigns", purpose: "plan" }
  if (tab === "findings") return { k: "findings" }
  return { k: tab } as View
}

// ------------------------------------------------------------------------------------------------ the explorer

function Explorer(props: { api: TuiPluginApi; src: CachedSource; close: () => void }) {
  const api = props.api
  const src = props.src
  const dims = useTerminalDimensions()
  const P = createMemo<Palette>(() => palette(api.theme.mode() === "light" ? "light" : "dark"))
  const C = (hex: string) => RGBA.fromHex(hex)
  const W = () => dims().width
  const layout = createMemo(() => (W() >= 150 ? "wide" : W() >= 100 ? "split" : W() >= 80 ? "compact" : "single"))
  const bodyH = () => Math.max(4, dims().height - 5)
  const G = glyphs(unicodeTerminal(process.env as Record<string, string | undefined>))
  const pm = (status: string | undefined) => (G.mark === "■" ? proofMark(status) : ({ "●": "*", "◐": "+", "○": "o" } as Record<string, string>)[proofMark(status)])
  // which pane receives the keys: the list, or the detail on its right (inspector, path, document)
  const [focus, setFocus] = createSignal<"list" | "detail">("list")
  const [tocOpen, setTocOpen] = createSignal(true)
  const inline = () => layout() === "wide" || layout() === "split"

  const [tab, setTab] = createSignal<Tab>("workspace")
  const [stack, setStack] = createSignal<View[]>([src.needsLogin && !src.authenticated ? { k: "login" } : { k: "workspace" }])
  const view = () => stack()[stack().length - 1]
  const [cursors, setCursors] = createSignal<number[]>([0])
  const cur = () => cursors()[cursors().length - 1] ?? 0
  const setCur = (n: number) => setCursors((c) => [...c.slice(0, -1), n])
  // list pane width: the list keeps the room the title needs; content and inspector share the rest
  const listWidth = createMemo(() => {
    const v = view().k
    const l = layout()
    if (l === "single" || l === "compact") return W()
    if (v === "report") return tocOpen() ? Math.min(40, Math.floor(W() * 0.28)) : 0
    if (v === "finding" || v === "path") return Math.min(44, Math.floor(W() * 0.3))
    if (v === "paths") return Math.min(l === "wide" ? 48 : 40, Math.floor(W() * 0.32))
    if (v === "findings") return l === "wide" ? Math.floor(W() * 0.5) : Math.floor(W() * 0.52)
    if (v === "campaign") return Math.min(52, Math.floor(W() * 0.4))
    if (v === "plan") return l === "wide" ? Math.min(84, Math.floor(W() * 0.5)) : Math.floor(W() * 0.5)
    if (v === "frameworks") return Math.min(l === "wide" ? 72 : 58, Math.floor(W() * 0.48))
    if (v === "profile") return l === "wide" ? Math.min(96, Math.floor(W() * 0.6)) : Math.floor(W() * 0.58)
    return l === "wide" ? Math.min(84, Math.floor(W() * 0.5)) : Math.floor(W() * 0.5)
  })
  const [busy, setBusy] = createSignal(0)
  const [error, setError] = createSignal<string>()

  // data
  const [projects, setProjects] = createSignal<Project[]>([])
  const [campaigns, setCampaigns] = createSignal<Campaign[]>([])
  const [campaign, setCampaign] = createSignal<Campaign>()
  const [globalFindings, setGlobalFindings] = createSignal<Finding[]>([])
  const [globalStats, setGlobalStats] = createSignal<VulnStats>()
  const [detail, setDetail] = createSignal<Finding>()
  const [sections, setSections] = createSignal<Section[]>([])
  const [paths, setPaths] = createSignal<AttackPaths>()
  const [pathCounts, setPathCounts] = createSignal<Record<string, Record<string, unknown>>>({})
  const [filter, setFilter] = createSignal<FindingFilter>({})
  const [sort, setSort] = createSignal<SortKey>("severity")
  const [query, setQuery] = createSignal("")
  const [pageIndex, setPageIndex] = createSignal(0)
  const [matches, setMatches] = createSignal<number[]>([])
  const [section, setSection] = createSignal(0)
  const [step, setStep] = createSignal(0)
  // executive views (documents computed by exec_core: the TUI only displays them)
  type Loaded<T> = { doc?: T; error?: string }
  const [execDocs, setExecDocs] = createSignal<Record<string, Loaded<Executive>>>({})
  const [profiles, setProfiles] = createSignal<Record<string, Loaded<ProfileDoc>>>({})
  const [plan, setPlan] = createSignal<TreatmentPlan>()
  const [assessment, setAssessment] = createSignal<FrameworkAssessment>()
  const [legendDoc, setLegendDoc] = createSignal<Legend>()

  let scroll: ScrollBoxRenderable | undefined
  const sectionNodes = new Map<number, BoxRenderable>()

  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setBusy((n) => n + 1)
    setError(undefined)
    try {
      return await fn()
    } catch (e: any) {
      if (e?.kind === "auth" && src.needsLogin) {
        setStack([{ k: "login" }])
        setCursors([0])
      }
      setError(errorText(e))
      return undefined
    } finally {
      setBusy((n) => n - 1)
    }
  }

  const projectOf = (c: Campaign | undefined) => projects().find((p) => p.id === c?.project_id)
  const targetLabel = (p: Project | undefined) => {
    const t = p?.target as any
    return clean(typeof t === "string" ? t : (t?.host ?? t?.ip ?? ""), 60).replace(/^https?:\/\//, "")
  }
  const campaignTarget = (c: Campaign | undefined) => targetLabel(projectOf(c))

  async function load(v: View) {
    switch (v.k) {
      case "workspace":
      case "projects":
        await run(async () => {
          const [p, c, f] = await Promise.all([src.projects(), src.campaigns(), src.vulnerabilities()])
          setProjects(p)
          setCampaigns(c)
          setGlobalFindings(f.data)
          setGlobalStats(f.stats)
          void prefetchPaths(c.slice(0, 6))
        })
        break
      case "campaigns":
        await run(async () => {
          const [p, c] = await Promise.all([src.projects(), src.campaigns(v.project?.id)])
          setProjects(p)
          setCampaigns(c)
          void prefetchPaths(c.slice(0, 20))
        })
        break
      case "campaign":
        await run(async () => {
          setCampaign(await src.campaign(v.campaign.id))
          void prefetchPaths([v.campaign])
        })
        break
      case "findings":
        if (v.campaign) await run(async () => setCampaign(await src.campaign(v.campaign!.id)))
        else
          await run(async () => {
            const [p, f] = await Promise.all([src.projects(), src.vulnerabilities()])
            setProjects(p)
            setGlobalFindings(f.data)
            setGlobalStats(f.stats)
          })
        break
      case "finding":
        await run(async () => setDetail(await src.finding(v.id)))
        break
      case "report":
        setSections([])
        setSection(0)
        sectionNodes.clear()
        await run(async () => setSections(splitSections(await src.report(v.campaign.id))))
        break
      case "paths":
      case "path":
        await run(async () => setPaths(await src.attackPaths(v.campaign.id)))
        break
      case "plan":
        setPlan(undefined)
        await run(async () => {
          const [pl, pa] = await Promise.all([src.plan(v.campaign.id), src.attackPaths(v.campaign.id).catch(() => undefined)])
          setPlan(pl)
          if (pa) setPaths(pa)
        })
        break
      case "frameworks":
        setAssessment(undefined)
        await run(async () => setAssessment(await src.frameworks(v.campaign.id)))
        break
      case "profile":
        await run(async () => {
          const d = await src.profile(v.project.id)
          setProfiles((m) => ({ ...m, [v.project.id]: { doc: d } }))
        })
        break
    }
  }

  // executive block of the campaign / project in context (lazy, cached; an older server simply has none)
  async function loadExec(key: string) {
    if (!key || execDocs()[key]?.doc) return
    const [kind, id] = [key.slice(0, 1), key.slice(2)]
    try {
      const doc = kind === "p" ? await src.projectExecutive(id) : await src.executive(id)
      setExecDocs((m) => ({ ...m, [key]: { doc } }))
    } catch (e) {
      setExecDocs((m) => ({ ...m, [key]: { error: errorText(e) } }))
    }
  }
  async function loadProfile(id: string) {
    if (!id || profiles()[id]?.doc) return
    try {
      const doc = await src.profile(id)
      setProfiles((m) => ({ ...m, [id]: { doc } }))
    } catch (e) {
      setProfiles((m) => ({ ...m, [id]: { error: errorText(e) } }))
    }
  }

  async function prefetchPaths(list: Campaign[]) {
    for (const c of list) {
      if (pathCounts()[c.id]) continue
      try {
        const doc = await src.attackPaths(c.id)
        const k = pathKindCounts(doc)
        setPathCounts((m) => ({ ...m, [c.id]: { paths_total: k.total, evidence_backed: k.evidence_backed, possible: k.possible } }))
      } catch {
        /* the count stays unknown; the paths screen reports the error */
      }
    }
  }

  function push(v: View, cursor = 0) {
    setStack((s) => [...s, v])
    setCursors((c) => [...c, cursor])
    setMatches([])
    setStep(0)
    if (v.k === "findings") setPageIndex(0)
    void load(v)
  }

  function goTab(t: Tab) {
    if (view().k === "login") return
    setTab(t)
    setStack([rootView(t)])
    setCursors([0])
    setQuery("")
    setFilter({})
    void load(rootView(t))
  }

  function back() {
    if (api.ui.dialog.open) return api.ui.dialog.clear()
    if (focus() === "detail" && ["findings", "paths", "plan", "frameworks", "profile"].includes(view().k)) return setFocus("list")
    if (view().k === "login") return props.close()
    // at the root, esc does not leave: keys typed next would land in the chat prompt and reach the model
    if (stack().length <= 1) return api.ui.toast({ variant: "info", message: "Press q to return to the console." })
    const leaving = view().k
    setStack((s) => s.slice(0, -1))
    setCursors((c) => c.slice(0, -1))
    setError(undefined)
    if (leaving === "finding" && view().k === "findings") return // list state is still loaded
    void load(view())
  }

  // first screen: without a login step (Community, or a token from the environment) load it right away
  if (view().k !== "login") void load(view())

  // ---------------------------------------------------------------------------------------------- derived lists

  const visibleProjects = createMemo(() => {
    const q = query().toLowerCase()
    return projects().filter((p) => !q || `${p.name} ${targetLabel(p)} ${p.id}`.toLowerCase().includes(q))
  })
  const visibleCampaigns = createMemo(() => {
    const v = view()
    const q = query().toLowerCase()
    let list = campaigns()
    if (v.k === "campaigns" && v.purpose === "reports") list = list.filter((c) => c.report_path)
    return list.filter((c) => !q || `${c.id} ${campaignTarget(c)} ${c.status}`.toLowerCase().includes(q))
  })
  const listContext = () => {
    // the finding screen keeps the list it was opened from
    const s = stack()
    const v = s[s.length - 1]
    return v.k === "finding" ? s[s.length - 2] : v
  }
  const baseFindings = createMemo(() => {
    const v = listContext()
    return v?.k === "findings" && v.campaign ? (campaign()?.vulnerabilities ?? []) : globalFindings()
  })
  const filtered = createMemo(() => sortFindings(filterFindings(baseFindings(), filter()), sort()))
  const paged = createMemo(() => page(filtered(), pageIndex(), PAGE))
  const lastCampaign = (p: Project) => campaigns().find((c) => c.project_id === p.id)
  const toc = createMemo(() => tocOf(sections(), 3))
  const currentPath = () => {
    const v = view()
    return v.k === "path" ? (paths()?.paths?.find((p) => p.id === v.path.id) ?? v.path) : paths()?.paths?.[cur()]
  }

  // ---------------------------------------------------------------------------------------------- formatting

  const sevHex = (s: string | undefined) => {
    const p = P()
    const v = String(s ?? "").toLowerCase()
    return v === "critical" ? p.critical : v === "high" ? p.high : v === "medium" ? p.medium : v === "low" ? p.low : p.info
  }
  const statusGlyph = (s: string | undefined) => {
    const v = String(s ?? "").toLowerCase()
    if (G.mark !== "■") return v === "running" ? "*" : v === "completed" ? "v" : v === "stopped" ? "#" : v === "failed" ? "x" : "."
    return v === "running" ? "●" : v === "completed" ? "✓" : v === "stopped" ? "■" : v === "failed" ? "✗" : "·"
  }
  const statusHex = (s: string | undefined) => {
    const v = String(s ?? "").toLowerCase()
    return v === "running" ? P().jordy : v === "failed" ? P().criticalInk : v === "completed" ? P().ink2 : P().off
  }
  const num = (n: unknown) => String(Number(n ?? 0) || 0)

  // ---------------------------------------------------------------------------------------------- rows

  const rows = createMemo<Row[]>(() => {
    const v = listContext()
    const p = P()
    const wide = listWidth() >= 96
    switch (v?.k) {
      case "workspace": {
        const out: Row[] = [{ key: "h-recent", header: true, cells: [{ text: "RECENT CAMPAIGNS" }] }]
        for (const c of campaigns().slice(0, 6)) out.push(campaignRow(c, false))
        out.push({ key: "h-projects", header: true, cells: [{ text: "PROJECTS" }] })
        for (const pr of projects()) out.push(projectRow(pr, false))
        return out
      }
      case "projects":
        return [{ key: "h", header: true, cells: projectHeader(wide) }, ...visibleProjects().map((pr) => projectRow(pr, wide))]
      case "campaigns":
        return [{ key: "h", header: true, cells: campaignHeader(wide) }, ...visibleCampaigns().map((c) => campaignRow(c, wide))]
      case "campaign": {
        const c = campaign() ?? v.campaign
        const n = c.vulnerabilities?.length ?? Number((c.stats as any)?.total_findings ?? 0)
        const pc = pathCounts()[c.id]
        return [
          { key: "findings", cells: [{ text: "Findings", fg: p.ink }, { text: `${n}`, w: 10, right: true, fg: p.ink3 }] },
          { key: "report", cells: [{ text: "Report", fg: p.ink }, { text: c.report_path ? "markdown" : "not generated", w: 14, right: true, fg: p.ink3 }] },
          { key: "paths", cells: [{ text: "Attack paths", fg: p.ink }, { text: pc ? num(pc.paths_total) : "…", w: 10, right: true, fg: p.ink3 }] },
        ]
      }
      case "findings": {
        const compact = view().k === "finding" || listWidth() < 90
        return [{ key: "h", header: true, cells: findingHeader(compact) }, ...paged().items.map((f) => findingRow(f, compact))]
      }
      case "paths":
      case "path":
        return (paths()?.paths ?? []).map((pa) => {
          const proof = pathProof(pa)
          const narrowList = view().k !== "paths"
          return {
            key: pa.id,
            mark: { glyph: "■", fg: sevHex(pa.criticality) },
            cells: [
              { text: clean(pa.title.replace(/\s*\((inferred|declared)\)\s*$/i, ""), 200), fg: p.ink },
              ...(narrowList ? [] : [{ text: proof.short, w: 8, fg: proof.proven ? p.alice : p.ink3, bold: proof.proven }]),
            ],
          }
        })
      case "report":
        return toc().map((t) => ({
          key: String(t.index),
          cells: [{ text: `${"  ".repeat(Math.max(0, t.level - 1))}${t.title}`, fg: t.level <= 2 ? p.ink : p.ink3, bold: t.level <= 1 }],
        }))
      case "plan": {
        const narrow = listWidth() < 76
        // the status words are never cut: the column is as wide as the longest status of this plan
        const sw = Math.min(28, Math.max(12, ...(plan()?.actions ?? []).map((a) => treatmentLabel(a).length)))
        return [
          { key: "h", header: true, cells: [{ text: "#", w: 3, right: true }, { text: "ACTION" }, ...(narrow ? [] : [{ text: "SEV", w: 4 }, { text: "EFF", w: 3 }]), { text: "STATUS", w: sw }] },
          ...(plan()?.actions ?? []).map((a) => ({
            key: `a:${a.action_id}`,
            mark: { glyph: treatmentMark(a.status, G.mark === "■"), fg: treatmentHex(a.status) },
            cells: [
              { text: num(a.priority), w: 3, right: true, fg: p.off },
              { text: clean(a.title ?? a.action_id, 200), fg: p.ink },
              ...(narrow ? [] : [{ text: severityTag(a.severity).trim(), w: 4, fg: p.ink3 }, { text: effortText(a, true) || "—", w: 3, fg: p.ink3 }]),
              { text: treatmentLabel(a), w: sw, fg: treatmentHex(a.status) },
            ],
          })),
        ]
      }
      case "frameworks": {
        const narrow = listWidth() < 56
        return [
          { key: "h", header: true, cells: [{ text: "FRAMEWORK" }, { text: "WEAK", w: 4, right: true }, { text: "NONE", w: 4, right: true }, { text: "N/T", w: 3, right: true }, ...(narrow ? [] : [{ text: "NTA", w: 3, right: true }])] },
          ...(assessment()?.frameworks ?? []).map((f) => {
            const c = (f.counts ?? {}) as Record<string, number>
            const app = applicabilityOf(f)
            return {
              key: `w:${f.framework}`,
              mark: { glyph: applicabilityMark(app.status, G.mark === "■"), fg: p.ink3 },
              cells: [
                { text: clean(f.label ?? f.framework, 80), fg: p.ink },
                { text: num(c.weakness_observed), w: 4, right: true, fg: Number(c.weakness_observed) ? p.ink : p.off },
                { text: num(c.none_observed_in_tested_scope), w: 4, right: true, fg: p.ink3 },
                { text: num(c.not_tested), w: 3, right: true, fg: p.ink3 },
                ...(narrow ? [] : [{ text: num(c.not_technically_assessable), w: 3, right: true, fg: p.off }]),
              ],
            }
          }),
        ]
      }
      case "profile": {
        const doc = profiles()[v.project.id]?.doc
        const fields = Object.entries(doc?.profile?.fields ?? {})
        const narrow = listWidth() < 60
        const out: Row[] = []
        const groups = [...PROFILE_GROUPS, ...new Set(fields.map(([, f]) => String(f.group ?? "other")).filter((g) => !PROFILE_GROUPS.includes(g)))]
        for (const g of groups) {
          const fs = fields.filter(([, f]) => String(f.group ?? "other") === g)
          if (!fs.length) continue
          out.push({ key: `h-${g}`, header: true, cells: [{ text: g.toUpperCase() }] })
          for (const [name, f] of fs) {
            const b = provenanceBadge(f.provenance, G.mark === "■")
            out.push({
              key: `f-${name}`,
              mark: { glyph: b.mark, fg: f.provenance === "unknown" ? p.off : p.ink2 },
              cells: [
                { text: fieldLabel(name), w: narrow ? 18 : 24, fg: p.ink2 },
                { text: profileValue(f.value), fg: f.value == null ? p.off : p.ink },
                ...(narrow ? [] : [{ text: b.word, w: 12, fg: f.provenance === "unknown" ? p.off : p.ink3 }]),
              ],
            })
          }
        }
        return out
      }
      default:
        return []
    }
  })
  const treatmentHex = (s: string | undefined) => {
    const v = String(s ?? "")
    return v === "proposed" || !v ? P().ink3 : v === "deferred" ? P().off : P().ink2
  }

  function projectHeader(wide: boolean): Cell[] {
    return [
      { text: "PROJECT" },
      ...(wide ? [{ text: "TARGET", w: 24 }] : []),
      { text: "CAMP", w: 5, right: true },
      { text: "FINDINGS", w: 8, right: true },
      { text: "LAST RUN", w: 10, right: true },
    ]
  }
  function projectRow(pr: Project, wide: boolean): Row {
    const p = P()
    const last = lastCampaign(pr)
    return {
      key: `p:${pr.id}`,
      mark: { glyph: "■", fg: pr.latest_risk ? sevHex(pr.latest_risk) : p.rule },
      cells: [
        { text: clean(pr.name, 80), fg: p.ink },
        ...(wide ? [{ text: targetLabel(pr), w: 24, fg: p.ink3 }] : []),
        { text: num(pr.campaigns_count), w: 5, right: true, fg: p.ink2 },
        { text: num(pr.vulnerabilities_count), w: 8, right: true, fg: p.ink2 },
        { text: last ? String(last.date ?? "").slice(0, 10) : "—", w: 10, right: true, fg: p.off },
      ],
    }
  }
  function campaignHeader(wide: boolean): Cell[] {
    return [
      { text: "CAMPAIGN" },
      ...(wide ? [{ text: "TARGET", w: 20 }] : []),
      { text: "DATE", w: 11 },
      { text: "FIND", w: 4, right: true },
      { text: "EXPL", w: 4, right: true },
      { text: "REPORT", w: 6, right: true },
      { text: "PATHS", w: 5, right: true },
    ]
  }
  function campaignRow(c: Campaign, wide: boolean): Row {
    const p = P()
    const s = (c.stats ?? {}) as Record<string, number>
    const pc = pathCounts()[c.id]
    return {
      key: `c:${c.id}`,
      mark: { glyph: statusGlyph(c.status), fg: statusHex(c.status) },
      cells: [
        { text: shortCampaign(c.id), fg: p.ink },
        ...(wide ? [{ text: campaignTarget(c), w: 20, fg: p.ink3 }] : []),
        { text: shortDate(c.date).slice(5), w: 11, fg: p.off },
        { text: num(s.total_findings), w: 4, right: true, fg: p.ink2 },
        { text: num(s.exploited), w: 4, right: true, fg: Number(s.exploited) ? p.ink : p.off },
        { text: c.report_path ? "✓" : "—", w: 6, right: true, fg: c.report_path ? p.ink2 : p.off },
        { text: pc ? num(pc.paths_total) : "·", w: 5, right: true, fg: p.ink3 },
      ],
    }
  }
  function findingHeader(compact: boolean): Cell[] {
    return compact
      ? [{ text: "SEV", w: 4 }, { text: "FINDING" }, { text: "", w: 1 }]
      : [{ text: "SEV", w: 4 }, { text: "FINDING" }, { text: "PROOF", w: 13 }, { text: "TARGET", w: 18 }]
  }
  function findingRow(f: Finding, compact: boolean): Row {
    const p = P()
    const proof = proofTag(f.status)
    const proofFg = proof === "exploited" ? p.ink : p.ink3
    return {
      key: `f:${f.id}`,
      mark: { glyph: "■", fg: sevHex(f.severity) },
      cells: compact
        ? [
            { text: severityTag(f.severity).trim(), w: 4, fg: p.ink3 },
            { text: clean((f as any).short_title || f.title, 200), fg: p.ink },
            { text: pm(f.status), w: 1, right: true, fg: proofFg },
          ]
        : [
            { text: severityTag(f.severity).trim(), w: 4, fg: p.ink3 },
            { text: clean(f.title, 200), fg: p.ink },
            { text: `${pm(f.status)} ${proof}`, w: 13, fg: proofFg },
            { text: clean(targetOf(f), 40), w: 18, fg: p.ink3 },
          ],
    }
  }

  const selectable = createMemo(() => rows().map((r, i) => (r.header ? -1 : i)).filter((i) => i >= 0))
  const selectedRow = () => rows()[selectable()[cur()] ?? -1]
  const selectedKey = () => selectedRow()?.key ?? ""

  createEffect(on(selectedKey, () => (view().k === "findings" || view().k === "paths") && focus() === "list" && setStep(0)))

  // the executive block / profile of the row in context, fetched after the selection settles (cached)
  let execTimer: ReturnType<typeof setTimeout> | undefined
  const execKey = () => {
    const v = view()
    const key = selectedKey()
    if (v.k === "workspace") return key.startsWith("c:") || key.startsWith("p:") ? key : campaigns()[0] ? `c:${campaigns()[0].id}` : ""
    if (v.k === "campaigns") return key.startsWith("c:") ? key : ""
    if (v.k === "projects") return key.startsWith("p:") ? key : ""
    if (v.k === "campaign") return `c:${v.campaign.id}`
    return ""
  }
  createEffect(
    on(execKey, (key) => {
      if (execTimer) clearTimeout(execTimer)
      if (!key) return
      execTimer = setTimeout(() => {
        void loadExec(key)
        if (key.startsWith("p:") && view().k === "projects") void loadProfile(key.slice(2))
      }, 250)
    }),
  )
  createEffect(on(() => view().k, () => setFocus("list")))

  // keep the finding detail in sync with the list selection (cached: moving back and forth does not refetch)
  createEffect(
    on(selectedKey, (k) => {
      if (!k.startsWith("f:") || view().k !== "finding") return
      const id = k.slice(2)
      if (detail()?.id === id) return
      scroll?.scrollTo?.(0)
      void run(async () => setDetail(await src.finding(id)))
    }),
  )

  // ---------------------------------------------------------------------------------------------- actions

  function open() {
    const v = view()
    const row = selectedRow()
    if (v.k === "path") return openStep()
    if (!row) return
    const i = row.key.indexOf(":")
    const kind = i > 0 ? row.key.slice(0, i) : ""
    const id = i > 0 ? row.key.slice(i + 1) : row.key
    if (kind === "p") {
      const pr = projects().find((x) => x.id === id)
      if (pr) push({ k: "campaigns", project: pr })
    } else if (kind === "c") {
      const c = campaigns().find((x) => x.id === id)
      if (!c) return
      if (v.k === "campaigns" && v.purpose === "paths") push({ k: "paths", campaign: c })
      else if (v.k === "campaigns" && v.purpose === "reports") push({ k: "report", campaign: c })
      else if (v.k === "campaigns" && v.purpose === "plan") push({ k: "plan", campaign: c })
      else push({ k: "campaign", campaign: c })
    } else if (kind === "f") {
      if (v.k === "finding") return
      if (v.k === "findings" && inline()) {
        setFocus("detail")
        scroll?.scrollTo?.(0)
        if (detail()?.id !== id) void run(async () => setDetail(await src.finding(id)))
        return
      }
      const f = baseFindings().find((x) => x.id === id)
      setDetail(undefined)
      push({ k: "finding", id, title: f?.title ?? id }, cur()) // the finding screen keeps the list and its cursor
    } else if (v.k === "campaign") {
      const c = campaign() ?? v.campaign
      if (row.key === "findings") push({ k: "findings", campaign: c })
      if (row.key === "report") push({ k: "report", campaign: c })
      if (row.key === "paths") push({ k: "paths", campaign: c })
    } else if (v.k === "paths") {
      const pa = paths()?.paths?.find((x) => x.id === row.key)
      if (!pa) return
      if (focus() === "detail") return openStep()
      if (inline()) return (setStep(0), setFocus("detail"))
      push({ k: "path", campaign: v.campaign, path: pa }, cur())
    } else if (v.k === "report") {
      jumpSection(Number(row.key))
    } else if (v.k === "plan") {
      if (focus() === "detail") {
        const a = selectedAction()
        const fid = a?.head_finding_id ?? a?.finding_ids?.[0]
        if (!fid) return
        setDetail(undefined)
        return push({ k: "finding", id: String(fid), title: clean(a?.title ?? fid, 80) })
      }
      scroll?.scrollTo?.(0)
      setFocus("detail")
    } else if (v.k === "frameworks" || v.k === "profile") {
      scroll?.scrollTo?.(0)
      setFocus(focus() === "detail" ? "list" : "detail")
    }
  }
  const selectedAction = () => plan()?.actions?.find((a) => `a:${a.action_id}` === selectedKey())

  function openStep() {
    const pa = currentPath()
    const s = pa?.steps?.[step()]
    const id = s ? stepFinding(s) : undefined
    if (!id) return api.ui.toast({ variant: "info", message: "This step is an exposure: no finding behind it." })
    setDetail(undefined)
    push({ k: "finding", id, title: s?.node_label ?? id })
  }

  const scrolling = () => ["finding", "report"].includes(view().k)
  function move(delta: number) {
    const v = view()
    if (["findings", "plan", "frameworks", "profile"].includes(v.k) && focus() === "detail") return scroll?.scrollBy(delta)
    if (v.k === "path" || (v.k === "paths" && focus() === "detail")) {
      const n = currentPath()?.steps?.length ?? 0
      if (n) setStep(Math.min(n - 1, Math.max(0, step() + delta)))
      return
    }
    if (v.k === "report") {
      scroll?.scrollBy(delta)
      return trackSection()
    }
    if (v.k === "finding") return scroll?.scrollBy(delta)
    const n = selectable().length
    if (n) setCur(Math.min(n - 1, Math.max(0, cur() + delta)))
  }
  function nextItem(dir: 1 | -1) {
    const v = view()
    if (v.k === "finding" && listContext()?.k === "findings") {
      const n = selectable().length
      if (n) setCur(Math.min(n - 1, Math.max(0, cur() + dir)))
      return
    }
    if (v.k === "findings") {
      setPageIndex((x) => Math.min(Math.max(0, x + dir), paged().pages - 1))
      return setCur(0)
    }
    if (v.k === "report") {
      const t = toc()
      const here = currentSection()
      const next = dir === 1 ? t.find((e) => e.index > here) : [...t].reverse().find((e) => e.index < here)
      if (next) jumpSection(next.index)
    }
  }

  function jumpSection(i: number) {
    const node = sectionNodes.get(i)
    if (!scroll || !node) return
    scroll.scrollBy(node.y - scroll.viewport.y)
    setSection(i)
    syncToc(i)
  }
  function syncToc(s: number) {
    let t = -1
    toc().forEach((e, i) => {
      if (e.index <= s) t = i
    })
    if (t >= 0) setCur(t)
  }
  function currentSection() {
    if (!scroll) return 0
    let best = 0
    for (const [i, node] of sectionNodes) if (node.y - scroll.viewport.y <= 1) best = Math.max(best, i)
    return best
  }
  function trackSection() {
    const s = currentSection()
    setSection(s)
    syncToc(s)
  }

  // ---------------------------------------------------------------------------------------------- dialogs

  function promptText(title: string, value: string, done: (v: string) => void) {
    api.ui.dialog.replace(() => (
      <api.ui.DialogPrompt
        title={title}
        value={value}
        onConfirm={(v) => {
          api.ui.dialog.clear()
          done(v)
        }}
        onCancel={() => api.ui.dialog.clear()}
      />
    ))
  }
  function select(title: string, options: { title: string; value: string; description?: string }[], done: (v: string) => void) {
    api.ui.dialog.replace(() => (
      <api.ui.DialogSelect
        title={title}
        options={options}
        onSelect={(o) => {
          api.ui.dialog.clear()
          done(String(o.value))
        }}
      />
    ))
  }
  function search() {
    const v = view()
    if (v.k === "projects" || v.k === "campaigns" || v.k === "workspace")
      return promptText("Search", query(), (q) => (setQuery(q), setCur(0)))
    if (v.k === "findings")
      return promptText("Search findings · title, id, endpoint, CVE", filter().query ?? "", (q) => {
        setFilter((f) => ({ ...f, query: q || undefined }))
        setPageIndex(0)
        setCur(0)
      })
    if (v.k === "report")
      return promptText("Search in report", "", (q) => {
        const m = searchSections(sections(), q)
        setMatches(m)
        if (m.length) jumpSection(m[0])
        else api.ui.toast({ variant: "warning", message: `No match for « ${clean(q, 40)} »` })
      })
  }
  function filterBy(kind: "severity" | "status" | "target") {
    if (view().k !== "findings") return
    const options =
      kind === "severity"
        ? SEVERITIES.map((s) => ({ title: s, value: s }))
        : kind === "status"
          ? ["exploited", "confirmed", "unconfirmed"].map((s) => ({ title: s, value: s }))
          : targetsOf(baseFindings()).map((s) => ({ title: clean(s, 80), value: s }))
    select(`Filter by ${kind}`, [{ title: "All", value: "" }, ...options], (value) => {
      setFilter((f) => ({ ...f, [kind]: value || undefined }))
      setPageIndex(0)
      setCur(0)
    })
  }
  function sortBy() {
    if (view().k !== "findings") return
    select("Sort findings", SORT_KEYS.map((k) => ({ title: k, value: k, description: k === sort() ? "current" : undefined })), (k) => {
      setSort(k as SortKey)
      setCur(0)
    })
  }
  function gotoHeading() {
    if (view().k !== "report") return
    select("Go to chapter", toc().map((t) => ({ title: `${"  ".repeat(t.level - 1)}${t.title}`, value: String(t.index) })), (v) =>
      jumpSection(Number(v)),
    )
  }
  function citedPicker() {
    if (view().k !== "report") return
    const ids = citedFindings(sections()[section()]?.body ?? "")
    if (!ids.length) return api.ui.toast({ variant: "info", message: "No finding cited in this chapter." })
    select("Findings cited in this chapter", ids.map((id) => ({ title: id, value: id })), (id) => push({ k: "finding", id, title: id }))
  }
  function nextMatch(dir: 1 | -1) {
    const m = matches()
    if (!m.length) return
    const here = currentSection()
    jumpSection(dir === 1 ? (m.find((i) => i > here) ?? m[0]) : (m.findLast((i) => i < here) ?? m[m.length - 1]))
  }
  function switchFocus() {
    const k = view().k
    if (k === "plan" || k === "frameworks" || k === "profile") return setFocus((f) => (f === "list" ? "detail" : "list"))
    if ((k === "findings" || k === "paths") && inline()) {
      if (focus() === "list" && k === "findings") return open()
      setFocus((f) => (f === "list" ? "detail" : "list"))
    }
  }
  // the campaign in context (selected on the workspace or a list, or the one being viewed): F / R / P open it directly
  function contextCampaign(): Campaign | undefined {
    const v = view()
    if (v.k === "plan" || v.k === "frameworks") return v.campaign
    if (v.k === "campaign" || v.k === "report" || v.k === "paths" || v.k === "path") return campaign() ?? (v as any).campaign
    const key = selectedKey()
    if (key.startsWith("c:")) return campaigns().find((c) => `c:${c.id}` === key)
    if (key.startsWith("p:")) return campaigns().find((c) => `p:${c.project_id}` === key)
    return campaigns()[0]
  }
  // the project in context: the selected project row, the project of the campaign in context, or the open one
  function contextProject(): Project | undefined {
    const v = view()
    if (v.k === "profile") return v.project
    if (v.k === "campaigns" && v.project) return v.project
    const key = selectedKey()
    if (key.startsWith("p:")) return projects().find((p) => `p:${p.id}` === key)
    return projectOf(contextCampaign())
  }
  function quickExec(target: "plan" | "frameworks" | "profile") {
    if (target === "profile") {
      const pr = contextProject()
      if (!pr) return api.ui.toast({ variant: "info", message: "No project in context." })
      return push({ k: "profile", project: pr })
    }
    const c = contextCampaign()
    if (!c) return api.ui.toast({ variant: "info", message: "No campaign yet." })
    push({ k: target, campaign: c } as View)
  }
  async function showMaintenance() {
    const pr = contextProject()
    if (!pr) return api.ui.toast({ variant: "info", message: "No project in context." })
    let doc: MaintenanceDoc | undefined
    try {
      doc = await src.maintenance(pr.id)
    } catch {
      doc = undefined
    }
    api.ui.dialog.replace(() => (
      <api.ui.DialogAlert
        title="Maintenance windows"
        message={maintenanceLines(doc, pr.name ?? pr.id).join("\n")}
        onConfirm={() => api.ui.dialog.clear()}
      />
    ))
    api.ui.dialog.setSize(W() >= 120 ? "xlarge" : W() >= 92 ? "large" : "medium")
  }
  async function showLegend() {
    if (!legendDoc()) {
      try {
        setLegendDoc(await src.legend())
      } catch {
        // an older server: the words of the executive block in context, else the built-in labels
        setLegendDoc(Object.values(execDocs()).find((x) => x.doc?.legend)?.doc?.legend as Legend | undefined)
      }
    }
    api.ui.dialog.replace(() => <LegendDialog />)
    api.ui.dialog.setSize(legendSize())
  }
  const legendSize = () => (W() >= 120 ? "xlarge" : W() >= 92 ? "large" : "medium")
  // the full legend (with meanings), scrolled with ↑↓ PgUp PgDn Home End when taller than the terminal
  const LegendDialog = () => {
    const [off, setOff] = createSignal(0)
    const inner = () => Math.min(({ xlarge: 116, large: 88, medium: 60 } as const)[legendSize()], W() - 2) - 4
    const rows = createMemo(() =>
      wrapDialogLines([...legendLines(legendDoc(), G.mark === "■"), "", "The same words on the dashboard, in the report and here."], inner()),
    )
    // the dialog opens a quarter down the screen; title, gap, hint and paddings take 6 rows
    const height = () => Math.max(3, dims().height - Math.floor(dims().height / 4) - 6)
    const win = createMemo(() => scrollWindow(rows().length, height(), off()))
    useKeyboard((evt) => {
      if (evt.ctrl || evt.meta) return
      if (evt.name === "return") return evt.preventDefault(), evt.stopPropagation(), api.ui.dialog.clear()
      const next = scrollKey(evt.name, rows().length, height(), win().offset)
      if (next === undefined) return
      evt.preventDefault()
      evt.stopPropagation()
      setOff(next)
    })
    const uni = G.mark === "■"
    return (
      <box paddingLeft={2} paddingRight={2} paddingBottom={1}>
        <box flexDirection="row" justifyContent="space-between" height={1}>
          <T bold>Legend · Darkmoon vocabulary</T>
          <T fg={P().off}>esc</T>
        </box>
        <box height={1} />
        <text fg={C(P().ink2)} wrapMode="none">{rows().slice(win().offset, win().offset + height()).join("\n")}</text>
        <box flexDirection="row" height={1} marginTop={1}>
          <T fg={P().jordy}>{win().below ? `more ${uni ? "↓" : "v"} (${win().below})` : win().above ? "end" : ""}</T>
          <box flexGrow={1} />
          <T fg={P().off}>{win().max ? `${uni ? "↑↓" : "up/down"} PgUp PgDn Home End · enter close` : "enter close"}</T>
        </box>
      </box>
    )
  }
  function quick(target: "findings" | "report" | "paths") {
    const c = contextCampaign()
    if (!c) return api.ui.toast({ variant: "info", message: "No campaign yet." })
    if (target === "report" && !c.report_path) return api.ui.toast({ variant: "info", message: "No report for this campaign yet." })
    push({ k: target, campaign: c } as View)
  }

  function help() {
    api.ui.dialog.replace(() => (
      <api.ui.DialogAlert
        title="Darkmoon explorer"
        message={[
          "1–7      sections (5 = Prioritized Treatment Plan)",
          "↑↓ j k   move / scroll",
          "enter    open",
          "esc      back",
          "q        back to the console",
          "/        search",
          "f s t    filter severity / proof / target",
          "o        sort findings",
          "c        clear filters",
          "tab      switch pane (list / inspector, path)",
          "F R P    findings, report, attack paths of the campaign",
          "T X A    treatment plan, frameworks, application profile",
          "L        legend (paths, evidence status, treatment, score)",
          "W        maintenance windows of the project",
          "t        contents (report) / target filter",
          "] [      next / previous page, finding or chapter",
          "g        go to chapter",
          "F        findings cited in the chapter",
          "n N      next / previous match",
          "r        refresh",
          "",
          "Read-only. No model call.",
          "Evidence is masked before it reaches the screen.",
        ].join("\n")}
        onConfirm={() => api.ui.dialog.clear()}
      />
    ))
  }

  const navigating = () => view().k !== "login" && !api.ui.dialog.open
  useBindings(() =>
    navigating()
      ? {
          commands: [
            { name: "dmx.down", title: "Down", run: () => move(1) },
            { name: "dmx.up", title: "Up", run: () => move(-1) },
            { name: "dmx.pagedown", title: "Page down", run: () => move(scrolling() ? bodyH() - 2 : 10) },
            { name: "dmx.pageup", title: "Page up", run: () => move(scrolling() ? -(bodyH() - 2) : -10) },
            { name: "dmx.open", title: "Open", run: open },
            { name: "dmx.back", title: "Back", run: back },
            { name: "dmx.close", title: "Back to the console", run: () => props.close() },
            { name: "dmx.search", title: "Search", run: search },
            { name: "dmx.sev", title: "Filter severity", run: () => filterBy("severity") },
            { name: "dmx.status", title: "Filter proof", run: () => filterBy("status") },
            { name: "dmx.target", title: "Filter target / contents", run: () => (view().k === "report" ? setTocOpen((o) => !o) : filterBy("target")) },
            { name: "dmx.focus", title: "Switch pane", run: switchFocus },
            { name: "dmx.openreport", title: "Open the report", run: () => quick("report") },
            { name: "dmx.openpaths", title: "Open the attack paths", run: () => quick("paths") },
            { name: "dmx.sort", title: "Sort", run: sortBy },
            { name: "dmx.clear", title: "Clear", run: () => (setFilter({}), setQuery(""), setPageIndex(0), setCur(0)) },
            { name: "dmx.next", title: "Next", run: () => nextItem(1) },
            { name: "dmx.prev", title: "Previous", run: () => nextItem(-1) },
            { name: "dmx.match", title: "Next match", run: () => nextMatch(1) },
            { name: "dmx.matchprev", title: "Previous match", run: () => nextMatch(-1) },
            { name: "dmx.goto", title: "Go to chapter", run: gotoHeading },
            { name: "dmx.cited", title: "Cited findings / open findings", run: () => (view().k === "report" ? citedPicker() : quick("findings")) },
            { name: "dmx.refresh", title: "Refresh", run: () => (src.invalidate(), setPathCounts({}), void load(view())) },
            { name: "dmx.help", title: "Keys", run: help },
            { name: "dmx.plan", title: "Prioritized Treatment Plan", run: () => quickExec("plan") },
            { name: "dmx.frameworks", title: "Frameworks (technical assessment)", run: () => quickExec("frameworks") },
            { name: "dmx.profile", title: "Application profile", run: () => quickExec("profile") },
            { name: "dmx.legend", title: "Legend", run: () => void showLegend() },
            { name: "dmx.maintenance", title: "Maintenance windows", run: () => void showMaintenance() },
            ...TABS.map((t, i) => ({ name: `dmx.tab${i + 1}`, title: t.label, run: () => goTab(t.id) })),
          ],
          bindings: [
            { key: "j,down", cmd: "dmx.down", desc: "Down" },
            { key: "k,up", cmd: "dmx.up", desc: "Up" },
            { key: "pagedown,ctrl+d", cmd: "dmx.pagedown", desc: "Page down" },
            { key: "pageup,ctrl+u", cmd: "dmx.pageup", desc: "Page up" },
            { key: "return,right,l", cmd: "dmx.open", desc: "Open" },
            { key: "escape,left,h,backspace", cmd: "dmx.back", desc: "Back" },
            { key: "q", cmd: "dmx.close", desc: "Console" },
            { key: "/", cmd: "dmx.search", desc: "Search" },
            { key: "f", cmd: "dmx.sev", desc: "Severity" },
            { key: "s", cmd: "dmx.status", desc: "Proof" },
            { key: "t", cmd: "dmx.target", desc: "Target" },
            { key: "tab", cmd: "dmx.focus", desc: "Pane" },
            { key: "shift+r", cmd: "dmx.openreport", desc: "Report" },
            { key: "shift+p", cmd: "dmx.openpaths", desc: "Paths" },
            { key: "o", cmd: "dmx.sort", desc: "Sort" },
            { key: "c", cmd: "dmx.clear", desc: "Clear" },
            { key: "]", cmd: "dmx.next", desc: "Next" },
            { key: "[", cmd: "dmx.prev", desc: "Previous" },
            { key: "n", cmd: "dmx.match", desc: "Next match" },
            { key: "shift+n", cmd: "dmx.matchprev", desc: "Previous match" },
            { key: "g", cmd: "dmx.goto", desc: "Chapter" },
            { key: "shift+f", cmd: "dmx.cited", desc: "Cited" },
            { key: "r", cmd: "dmx.refresh", desc: "Refresh" },
            { key: "?,shift+/", cmd: "dmx.help", desc: "Keys" },
            { key: "shift+t", cmd: "dmx.plan", desc: "Plan" },
            { key: "shift+x", cmd: "dmx.frameworks", desc: "Frameworks" },
            { key: "shift+a", cmd: "dmx.profile", desc: "Profile" },
            { key: "shift+l", cmd: "dmx.legend", desc: "Legend" },
            { key: "shift+w", cmd: "dmx.maintenance", desc: "Windows" },
            ...TABS.map((t, i) => ({ key: String(i + 1), cmd: `dmx.tab${i + 1}`, desc: t.label })),
          ],
        }
      : { commands: [], bindings: [] },
  )

  // ---------------------------------------------------------------------------------------------- login

  const [user, setUser] = createSignal(String(api.kv.get("darkmoon.explorer.user", "admin")))
  const [pass, setPass] = createSignal("")
  const [field, setField] = createSignal<"user" | "pass">("pass")
  async function submitLogin() {
    const u = user().trim()
    const pw = pass()
    setPass("")
    if (!u || !pw) return setError("Username and password are required")
    const ok = await run(async () => {
      const r = await src.login(u, pw)
      if (r.mustChange) {
        src.logout()
        throw { kind: "http", message: "Change the default password in the web dashboard first" }
      }
      return true
    })
    if (!ok) return
    api.kv.set("darkmoon.explorer.user", u)
    setStack([{ k: "workspace" }])
    setCursors([0])
    void load({ k: "workspace" })
  }
  useKeyboard((evt) => {
    if (view().k !== "login" || api.ui.dialog.open) return
    const stop = () => (evt.preventDefault(), evt.stopPropagation())
    if (evt.name === "escape") return stop(), props.close()
    if (evt.name === "tab") return stop(), setField((f) => (f === "user" ? "pass" : "user"))
    if (evt.name === "return") return stop(), void submitLogin()
    const set = field() === "user" ? setUser : setPass
    if (evt.name === "backspace") return stop(), set((s) => s.slice(0, -1))
    const ch = evt.sequence
    if (ch && ch.length === 1 && ch >= " " && !evt.ctrl && !evt.meta) return stop(), set((s) => s + ch)
  })

  // ---------------------------------------------------------------------------------------------- rendering

  const syntax = createMemo(() => markdownSyntax(P()))
  const T = (p: { children: JSX.Element; fg?: string; bg?: string; bold?: boolean; wrap?: boolean; grow?: boolean }) => (
    <text fg={C(p.fg ?? P().ink)} bg={p.bg ? C(p.bg) : undefined} attributes={p.bold ? BOLD : 0} wrapMode={p.wrap ? "word" : "none"} flexGrow={p.grow ? 1 : 0} flexShrink={p.grow ? 1 : 0}>
      {p.children}
    </text>
  )
  const Label = (p: { children: string; fg?: string }) => <T fg={p.fg ?? P().off} bold>{p.children}</T>

  const crumbs = createMemo(() =>
    stack()
      .map((v) =>
        v.k === "campaigns" ? (v.project ? clean(v.project.name, 28) : v.purpose === "paths" ? "Attack paths" : v.purpose === "reports" ? "Reports" : v.purpose === "plan" ? "Prioritized Treatment Plan" : "Campaigns")
        : v.k === "campaign" ? clean(v.campaign.id, 28)
        : v.k === "findings" ? (v.campaign ? "Findings" : "All findings")
        : v.k === "finding" ? clean(v.title, 40)
        : v.k === "report" ? `Report · ${clean(v.campaign.id, 24)}`
        : v.k === "paths" ? `Paths · ${clean(v.campaign.id, 24)}`
        : v.k === "path" ? clean(v.path.title, 40)
        : v.k === "plan" ? `Plan · ${shortCampaign(v.campaign.id)}`
        : v.k === "frameworks" ? `Frameworks · ${shortCampaign(v.campaign.id)}`
        : v.k === "profile" ? `Profile · ${clean(v.project.name, 28)}`
        : v.k === "workspace" ? "Workspace"
        : v.k === "projects" ? "Projects"
        : "",
      )
      .filter(Boolean)
      .join("  ›  "),
  )
  const status = () => (error() ? `${fit(error() ?? "", 60)} · r retry` : busy() ? "loading…" : src.kind === "files" ? "local · read-only" : "read-only")

  // ---- chrome: section bar, breadcrumb, key hints

  const TopBar = () => {
    // full labels ≥ 130, short 100–129, four-letter labels 80–99 (every tab readable at 80 columns), none below
    const bar = createMemo(() => topTabs(TABS, W(), TABS.findIndex((t) => t.id === tab())))
    // the tabs never shrink: a long status (an error) is cut instead
    const tabsW = () => (view().k === "login" ? 0 : bar().total)
    return (
      <box flexDirection="row" height={1} backgroundColor={C(P().surface)} paddingLeft={2} paddingRight={2}>
        <T fg={P().alice} bold>DARKMOON</T>
        <box width={3} flexShrink={0} />
        <Show when={view().k !== "login" && bar().mode !== "none"}>
          <For each={bar().tabs}>
            {(t) => (
              <box flexDirection="row" flexShrink={0} backgroundColor={t.active ? C(P().hover) : undefined} paddingLeft={t.padL} paddingRight={t.padR}>
                <T fg={t.active ? P().jordy : P().off}>{t.text.slice(0, t.text.indexOf(" "))}</T>
                <T fg={t.active ? P().ink : P().ink3} bold={t.active}>{t.text.slice(t.text.indexOf(" "))}</T>
              </box>
            )}
          </For>
        </Show>
        <box flexGrow={1} />
        <T fg={error() ? P().criticalInk : busy() ? P().jordy : P().off}>{fit(status(), Math.max(10, W() - 17 - tabsW()))}</T>
      </box>
    )
  }
  const Crumbs = () => (
    <box flexDirection="row" height={1} paddingLeft={2} paddingRight={2}>
      <T fg={P().off} grow>{fitTail(crumbs(), W() - 4)}</T>
    </box>
  )
  const hints = createMemo(() => {
    const v = view().k
    const f = focus()
    if (v === "login") return [["tab", "field"], ["enter", "sign in"], ["esc", "close"]]
    if (v === "findings")
      return f === "detail"
        ? [["↑↓", "scroll"], ["] [", "page"], ["tab", "list"], ["esc", "list"], ["?", "keys"]]
        : [["↑↓", "move"], ["enter", "inspect"], ["/", "search"], ["f s t", "filter"], ["o", "sort"], ["c", "clear"], ["esc", "back"], ["?", "keys"]]
    if (v === "finding") return [["↑↓", "scroll"], ["] [", "next finding"], ["esc", "back"], ["?", "keys"]]
    if (v === "report") return [["↑↓", "scroll"], ["] [", "chapter"], ["g", "go to"], ["t", "contents"], ["/", "search"], ["n N", "match"], ["F", "cited"], ["esc", "back"]]
    if (v === "paths")
      return f === "detail"
        ? [["↑↓", "node"], ["enter", "open finding"], ["tab", "paths"], ["esc", "paths"], ["?", "keys"]]
        : [["↑↓", "path"], ["enter", "walk"], ["tab", "walk"], ["esc", "back"], ["?", "keys"]]
    if (v === "path") return [["↑↓", "node"], ["enter", "open finding"], ["esc", "paths"], ["?", "keys"]]
    if (v === "plan")
      return f === "detail"
        ? [["↑↓", "scroll"], ["enter", "finding"], ["esc", "actions"], ["L", "legend"], ["?", "keys"]]
        : [["↑↓", "move"], ["enter", "inspect"], ["X", "frameworks"], ["L", "legend"], ["esc", "back"], ["?", "keys"]]
    if (v === "frameworks" || v === "profile")
      return f === "detail" ? [["↑↓", "scroll"], ["esc", "list"], ["L", "legend"], ["?", "keys"]] : [["↑↓", "move"], ["enter", "details"], ["T", "plan"], ["L", "legend"], ["esc", "back"], ["?", "keys"]]
    if (v === "workspace" || v === "campaign") return [["↑↓", "move"], ["enter", "open"], ["T", "plan"], ["X", "frameworks"], ["L", "legend"], ["F R P", "open"], ["1–7", "sections"], ["q", "console"], ["?", "keys"]]
    return [["↑↓", "move"], ["enter", "open"], ["/", "search"], ["T X A", "exec"], ["F R P", "open"], ["1–7", "sections"], ["esc", "back"], ["?", "keys"]]
  })
  const Footer = () => (
    <box flexDirection="row" height={1} backgroundColor={C(P().surface)} paddingLeft={2} paddingRight={1} overflow="hidden">
      <For each={W() < 100 ? [...hints().filter((h) => h[0] !== "?").slice(0, 4), ...hints().filter((h) => h[0] === "?")] : hints()}>
        {(h) => (
          <box flexDirection="row" paddingRight={3} flexShrink={0}>
            <T fg={P().ink} bold>{h[0]}</T>
            <T fg={P().off}>{` ${h[1]}`}</T>
          </box>
        )}
      </For>
    </box>
  )

  // ---- pane: a title strip on the surface step (no border); the focused pane carries the accent bar and full ink
  const Pane = (p: { title: string; meta?: string; focused?: boolean; width?: number; height?: number; grow?: boolean; children?: JSX.Element; pad?: number }) => (
    <box
      flexDirection="column"
      width={p.width}
      height={p.height}
      flexGrow={p.grow ? 1 : 0}
      flexShrink={p.grow ? 1 : 0}
      minWidth={0}
      minHeight={0}
      overflow="hidden"
      border
      borderStyle="single"
      customBorderChars={G.mark === "■" ? undefined : ASCII_BORDER}
      borderColor={C(p.focused ? P().jordy : P().edge)}
      titleColor={C(p.focused ? P().jordy : P().off)}
      title={` ${p.title}${p.meta ? `  ${p.meta}` : ""} `}
      titleAlignment="left"
      paddingLeft={p.pad ?? 1}
      paddingRight={1}
    >
      {p.children}
    </box>
  )

  // ---- data visuals (real values only)
  const SevRows = (p: { counts: Record<string, number>; width: number }) => {
    const max = () => Math.max(1, ...SEVERITIES.map((s) => Number(p.counts[s]) || 0))
    return (
      <box flexDirection="column">
        <For each={SEVERITIES}>
          {(s) => {
            const n = () => Number(p.counts[s]) || 0
            const b = () => hbar(n(), max(), Math.max(4, p.width - 16))
            return (
              <box flexDirection="row" height={1}>
                <box width={9} flexShrink={0}>
                  <T fg={n() ? P().ink2 : P().off}>{s}</T>
                </box>
                <Show when={(b().fill) > 0}><T fg={sevHex(s)}>{G.bar.repeat(b().fill)}</T></Show>
                <Show when={(b().rest) > 0}><T fg={P().rule}>{G.track.repeat(b().rest)}</T></Show>
                <box width={5} flexShrink={0} flexDirection="row" justifyContent="flex-end">
                  <T fg={n() ? P().ink : P().off} bold={n() > 0}>{String(n())}</T>
                </box>
              </box>
            )
          }}
        </For>
      </box>
    )
  }
  const SevStrip = (p: { counts: Record<string, number>; width: number }) => {
    const total = () => SEVERITIES.reduce((n, s) => n + (Number(p.counts[s]) || 0), 0)
    const parts = () =>
      SEVERITIES.map((s) => {
        const n = Number(p.counts[s]) || 0
        return { s, w: total() ? Math.max(n ? 1 : 0, Math.round((n / total()) * p.width)) : 0 }
      }).filter((x) => x.w)
    return (
      <box flexDirection="row" height={1}>
        <Show when={total()} fallback={<Show when={(Math.max(1, p.width)) > 0}><T fg={P().rule}>{G.track.repeat(Math.max(1, p.width))}</T></Show>}>
          <For each={parts()}>{(x) => <Show when={(x.w) > 0}><T fg={sevHex(x.s)}>{G.bar.repeat(x.w)}</T></Show>}</For>
        </Show>
      </box>
    )
  }
  const Discovery = (p: { c: Campaign; findings: Finding[]; width: number }) => {
    const times = () => p.findings.map((f) => (f as any).discovered_at ?? (f as any).first_seen)
    const end = () => {
      const d = Date.parse(String(p.c.date ?? ""))
      const s = Number((p.c as any).duration_seconds)
      return Number.isFinite(d) && s > 0 ? new Date(d + s * 1000).toISOString() : undefined
    }
    const counts = () => buckets(times(), Math.max(8, p.width), p.c.date, end())
    const any = () => counts().some((n) => n > 0)
    return (
      <Show when={any()} fallback={<T fg={P().off}>No discovery time recorded.</T>}>
        <box flexDirection="column">
          <T fg={P().jordy}>{sparkline(counts(), G.spark)}</T>
          <box flexDirection="row" height={1}>
            <T fg={P().off}>{timeOf(p.c.date)}</T>
            <box flexGrow={1} />
            <T fg={P().off}>{`${p.findings.length} findings over ${durationText((p.c as any).duration_seconds)}`}</T>
            <box flexGrow={1} />
            <T fg={P().off}>{timeOf(end())}</T>
          </box>
        </box>
      </Show>
    )
  }
  const Kv = (p: { k: string; v: string; fg?: string; kw?: number }) => (
    <box flexDirection="row" height={1}>
      <box width={p.kw ?? 12} flexShrink={0}>
        <T fg={P().off}>{p.k}</T>
      </box>
      <T fg={p.fg ?? P().ink2} grow>{fit(p.v, 200)}</T>
    </box>
  )
  const Tile = (p: { label: string; value: string; sub?: JSX.Element; width: number; accent?: string }) => (
    <box flexDirection="column" width={p.width} flexShrink={0} paddingRight={3}>
      <Label>{p.label}</Label>
      <T fg={p.accent ?? P().ink} bold>{p.value}</T>
      <box height={1}>{p.sub}</box>
    </box>
  )

  // ---- generic list body (dense table, selection = hover fill + accent bar + full ink)
  const ListBody = (p: { width: number; height: number; focused: boolean }) => {
    const win = () => windowAround(rows().length, selectable()[cur()] ?? 0, Math.max(3, p.height))
    return (
      <Show
        when={rows().some((r) => !r.header)}
        fallback={<T fg={P().ink3}>{busy() ? "Loading…" : emptyText(view(), Boolean(query() || filter().query || filter().severity || filter().status || filter().target))}</T>}
      >
        <For each={rows().slice(win().start, win().end)}>
          {(r, i) => {
            const index = () => win().start + i()
            const selected = () => !r.header && selectable()[cur()] === index()
            const fixed = () => r.cells.reduce((n, c) => n + (c.w ? c.w + 1 : 0), 0)
            const flexW = () => Math.max(4, p.width - 5 - fixed())
            const fill = () => (selected() ? (p.focused ? P().hover : P().raised) : undefined)
            return (
              <box flexDirection="row" height={1} backgroundColor={fill() ? C(fill()!) : undefined} marginTop={r.header && index() > 0 ? 1 : 0}>
                <T fg={selected() && p.focused ? P().jordy : selected() ? P().off : P().canvas}>{selected() ? G.sel : " "}</T>
                <box width={2} flexShrink={0}>
                  <Show when={r.mark}>
                    <T fg={r.mark!.fg}>{r.mark!.glyph === "■" ? G.mark : r.mark!.glyph}</T>
                  </Show>
                </box>
                <For each={r.cells}>
                  {(cell) => (
                    <box width={cell.w ?? flexW()} flexShrink={0} marginLeft={1} flexDirection="row" justifyContent={cell.right ? "flex-end" : "flex-start"}>
                      <T
                        fg={r.header ? P().off : selected() && cell.fg === P().off ? P().ink3 : selected() && !cell.w ? P().ink : (cell.fg ?? P().ink)}
                        bold={r.header || cell.bold || (selected() && !cell.w)}
                      >
                        {fit(cell.text, cell.w ?? flexW())}
                      </T>
                    </box>
                  )}
                </For>
              </box>
            )
          }}
        </For>
      </Show>
    )
  }

  // ---- finding inspector: preview from the list record, full record once opened (evidence masked by the source)
  const FindingDoc = (p: { f: Finding; full: boolean; width: number }) => {
    const pal = P()
    const f = p.f
    const links = declaredLinks(f)
    const ev = evidenceSections(f.evidence)
    const withheld = (f.evidence as any)?.withheld === true
    const kv = (k: string, v: unknown) => (v ? <Kv k={k} v={clean(String(v), 120)} kw={11} /> : null)
    return (
      <box flexDirection="column" gap={1}>
        <box flexDirection="column">
          <box flexDirection="row" height={1}>
            <T fg={sevHex(f.severity)}>{`${G.mark} `}</T>
            <T fg={pal.ink} bold>{String(f.severity ?? "info").toUpperCase()}</T>
            <T fg={pal.off}>{`   ${pm(f.status)} `}</T>
            <T fg={proofTag(f.status) === "exploited" ? pal.ink : pal.ink3}>{proofTag(f.status)}</T>
            <box flexGrow={1} />
            <T fg={pal.off}>{f.id}</T>
          </box>
          <T fg={pal.ink} bold wrap>{clean(f.title, 300)}</T>
        </box>
        <box flexDirection="column">
          {kv("Target", targetOf(f))}
          {kv("Category", f.category)}
          {kv("CVSS", f.cvss_score != null ? `${f.cvss_score}` : "")}
          {kv("CVE", f.cve)}
          {kv("CWE", (f as any).cwe)}
          {kv("ATT&CK", f.mitre_attack_id ? `${f.mitre_attack_id} ${(f as any).mitre_attack_name ?? ""}` : "")}
          {kv("ISO 27001", (f as any).iso27001_control)}
          {kv("Agent", f.discovered_by_agent)}
          {kv("Found", shortDate((f as any).discovered_at ?? (f as any).first_seen))}
        </box>
        <Show when={f.description}>
          <box flexDirection="column">
            <Label>DESCRIPTION</Label>
            <T fg={pal.ink2} wrap>{clean(f.description ?? "", p.full ? 4000 : 420)}</T>
          </box>
        </Show>
        <Show when={p.full && remediationText(f.remediation)}>
          <box flexDirection="column">
            <Label>REMEDIATION</Label>
            <T fg={pal.ink2} wrap>{remediationText(f.remediation)}</T>
          </box>
        </Show>
        <Show when={p.full}>
          <box flexDirection="column">
            <Label>ENABLED BY</Label>
            <Show when={links.length} fallback={<T fg={pal.off}>No declared link.</T>}>
              <T fg={pal.ink2} wrap>{links.join(", ")}</T>
              <T fg={pal.ink3}>DECLARED · not verified</T>
            </Show>
          </box>
        </Show>
        <Show when={p.full}>
          <box flexDirection="column" gap={1}>
            <Label>EVIDENCE</Label>
            <Show when={!withheld} fallback={<T fg={pal.ink3}>Evidence withheld: it could not be masked on this machine.</T>}>
              <Show when={ev.length} fallback={<T fg={pal.off}>No evidence recorded.</T>}>
                <For each={ev}>
                  {(s) => (
                    <box flexDirection="column">
                      <T fg={pal.off}>{s.label}</T>
                      <Show
                        when={s.label !== "Explanation"}
                        fallback={<text fg={C(pal.ink2)} wrapMode="word">{s.text}</text>}
                      >
                        <box backgroundColor={C(pal.surface)} paddingLeft={1} paddingRight={1}>
                          <text fg={C(pal.code)} wrapMode="char">{s.text}</text>
                        </box>
                      </Show>
                    </box>
                  )}
                </For>
              </Show>
            </Show>
            <T fg={pal.off}>Masked by Darkmoon before display.</T>
          </box>
        </Show>
        <Show when={!p.full}>
          <T fg={pal.off}>enter  remediation, declared links and evidence</T>
        </Show>
      </box>
    )
  }

  // ---- attack path: node cards joined by connectors; the connector style carries the proof level
  const PathGraph = (p: { path: AttackPath; interactive: boolean; width: number }) => {
    const pal = P()
    const proof = () => pathProof(p.path)
    const steps = () => p.path.steps ?? []
    const w = () => Math.max(24, Math.min(64, p.width - 2))
    const pad = (s: string, n: number) => (s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length))
    return (
      <box flexDirection="column">
        <box flexDirection="row" height={1}>
          <T fg={proof().proven ? pal.alice : pal.ink3} bold>{`${proof().proven ? G.proven : G.hyp} ${proof().label}`}</T>
          <T fg={pal.off}>{`   ${steps().length} steps  ·  criticality ${p.path.criticality ?? "—"}`}</T>
        </box>
        <T fg={pal.off} wrap>{`${proof().why}  ·  L legend`}</T>
        <box height={1} />
        <For each={steps()}>
          {(s: PathStep, i) => {
            const fid = stepFinding(s)
            const f = () => (fid ? findingById(fid) : undefined)
            const sel = () => p.interactive && step() === i()
            const edge = () => (sel() ? pal.jordy : pal.off)
            const kind = () => (fid ? "finding" : String(s.kind ?? "exposure"))
            const inner = () => w() - 2
            const top = () => {
              const head = `${G.box.h} ${s.n} ${G.dot} ${kind()} `
              return G.box.tl + head + G.box.h.repeat(Math.max(0, inner() - head.length)) + G.box.tr
            }
            const label = () => pad(` ${clean(s.node_label ?? `step ${s.n}`, 200)}`, inner() - 2)
            const meta = () => (fid ? pad(`   ${fid}  ${pm(String(s.proof ?? f()?.status ?? ""))} ${proofTag(String(s.proof ?? f()?.status ?? ""))}`, inner()) : "")
            const bottom = () => {
              const last = i() === steps().length - 1
              const half = Math.floor(inner() / 2)
              return G.box.bl + G.box.h.repeat(half) + (last ? G.box.h : G.box.tee) + G.box.h.repeat(inner() - half - 1) + G.box.br
            }
            return (
              <box flexDirection="column">
                <T fg={edge()}>{top()}</T>
                <box flexDirection="row" height={1}>
                  <T fg={edge()}>{G.box.v}</T>
                  <T fg={fid ? sevHex(f()?.severity ?? p.path.criticality) : pal.off}>{` ${fid ? G.node : G.nodeOpen}`}</T>
                  <T fg={sel() ? pal.ink : fid ? pal.ink : pal.ink2} bold={sel()}>{label()}</T>
                  <T fg={edge()}>{G.box.v}</T>
                </box>
                <Show when={fid}>
                  <box flexDirection="row" height={1}>
                    <T fg={edge()}>{G.box.v}</T>
                    <T fg={pal.off}>{meta()}</T>
                    <T fg={edge()}>{G.box.v}</T>
                  </box>
                </Show>
                <T fg={edge()}>{bottom()}</T>
                <Show when={i() < steps().length - 1}>
                  <box flexDirection="row" height={1}>
                    <T fg={proof().proven ? pal.alice : pal.off}>{`${" ".repeat(Math.floor(inner() / 2) + 1)}${proof().proven ? G.proven : G.hyp}`}</T>
                    <T fg={pal.off}>{proof().proven ? "  evidence-backed" : "  possible · not observed"}</T>
                  </box>
                  <T fg={proof().proven ? pal.alice : pal.off}>{`${" ".repeat(Math.floor(inner() / 2) + 1)}${G.arrow}`}</T>
                </Show>
              </box>
            )
          }}
        </For>
      </box>
    )
  }
  const findingById = (id: string) => campaign()?.vulnerabilities?.find((v) => v.id === id) ?? globalFindings().find((v) => v.id === id)

  const NodeDetail = (p: { path: AttackPath }) => {
    const pal = P()
    const s = () => p.path.steps?.[step()]
    const fid = () => (s() ? stepFinding(s()!) : undefined)
    const f = () => (fid() ? findingById(fid()!) : undefined)
    return (
      <Show when={s()} fallback={<T fg={pal.off}>No step.</T>}>
        <box flexDirection="column" gap={1}>
          <box flexDirection="column">
            <T fg={pal.ink} bold wrap>{clean(s()!.node_label ?? "", 200)}</T>
            <T fg={pal.off}>{`step ${s()!.n} of ${p.path.steps?.length ?? 0}  ·  ${fid() ? "finding" : (s()!.kind ?? "exposure")}`}</T>
          </box>
          <Show when={s()!.plain}>
            <T fg={pal.ink2} wrap>{clean(s()!.plain ?? "", 600)}</T>
          </Show>
          <Show when={(s() as any).why}>
            <box flexDirection="column">
              <Label>WHY</Label>
              <T fg={pal.ink3} wrap>{clean((s() as any).why, 600)}</T>
            </box>
          </Show>
          <Show when={fid()}>
            <box flexDirection="column">
              <Label>FINDING</Label>
              <box flexDirection="row" height={1}>
                <T fg={sevHex(f()?.severity)}>{`${G.mark} `}</T>
                <T fg={pal.ink2}>{`${String(f()?.severity ?? "").toUpperCase()}  ${pm(f()?.status)} ${proofTag(f()?.status)}`}</T>
              </box>
              <T fg={pal.ink} wrap>{clean(f()?.title ?? fid()!, 200)}</T>
              <T fg={pal.off}>{fid()!}</T>
              <T fg={pal.jordy}>enter  open the finding</T>
            </box>
          </Show>
          <box flexDirection="column">
            <Label>PATH KIND</Label>
            <T fg={pathProof(p.path).proven ? pal.alice : pal.ink3} bold wrap>{pathProof(p.path).label}</T>
            <T fg={pal.off} wrap>{`${pathProof(p.path).why}. Only evidence the server recorded makes a path evidence-backed; declared and inferred paths stay possible.`}</T>
          </box>
        </box>
      </Show>
    )
  }

  // ---- campaign dashboard (overview): figures, severity, discovery over time, agents, latest findings
  const CampaignBoard = (p: { c: Campaign; width: number; compact?: boolean; noLatest?: boolean }) => {
    const pal = P()
    const list = () => (campaign()?.id === p.c.id ? (campaign()?.vulnerabilities ?? []) : globalFindings().filter((f) => (f as any).campaign_id === p.c.id))
    const counts = () => (list().length ? countsOf(list()) : ((p.c.stats ?? {}) as Record<string, number>))
    const pc = () => pathCounts()[p.c.id] as Record<string, number> | undefined
    const agents = () => ((campaign()?.id === p.c.id ? (campaign() as any)?.agents_dispatched : (p.c as any).agents_dispatched) ?? []) as { agent: string; findings: number }[]
    const latest = () => [...list()].sort((a, b) => String((b as any).discovered_at ?? "").localeCompare(String((a as any).discovered_at ?? ""))).slice(0, 5)
    const tileW = () => Math.max(14, Math.floor((p.width - 2) / 4))
    return (
      <box flexDirection="column" gap={1}>
        <box flexDirection="column" flexShrink={0}>
          <box flexDirection="row" height={1}>
            <T fg={statusHex(p.c.status)}>{`${statusGlyph(p.c.status)}  `}</T>
            <T fg={pal.ink} bold>{clean(p.c.id, 80)}</T>
          </box>
          <T fg={pal.ink3} wrap>{[campaignTarget(p.c), shortDate(p.c.date), p.c.status, durationText((p.c as any).duration_seconds)].filter((x) => x && x !== "—").join("  ·  ")}</T>
          <Show when={maintenanceCheckLine(p.c as any)}><T fg={pal.ink2} wrap>{maintenanceCheckLine(p.c as any)}</T></Show>
        </box>
        <box flexDirection="row" flexShrink={0}>
          <Tile label="FINDINGS" value={num(list().length || (counts() as any).total_findings)} width={tileW()} sub={<SevStrip counts={counts()} width={tileW() - 4} />} />
          <Tile label="EXPLOITED" value={num(counts().exploited)} width={tileW()} sub={<T fg={pal.off}>{`of ${num(list().length || (counts() as any).total_findings)}`}</T>} />
          <Tile label="RISK" value={String(p.c.overall_risk ?? "—")} accent={p.c.overall_risk ? sevHex(p.c.overall_risk) : pal.off} width={tileW()} sub={<T fg={pal.off}>{p.c.report_path ? "report ✓" : "no report"}</T>} />
          <Tile label="PATHS" value={pc() ? num(pc()!.paths_total) : "…"} width={tileW()} sub={<T fg={pal.off}>{pc() ? fit(`${num(pc()!.evidence_backed)} ${tileW() - 3 >= 18 ? "evidence-backed" : "evidence"}`, tileW() - 3) : ""}</T>} />
        </box>
        <box flexDirection="column" flexShrink={0}>
          <Label>SEVERITY</Label>
          <SevRows counts={counts()} width={Math.min(p.width, 70)} />
        </box>
        <Show when={!p.compact}>
          <box flexDirection="column">
            <Label>DISCOVERY</Label>
            <Discovery c={p.c} findings={list()} width={Math.min(p.width - 2, 70)} />
          </box>
        </Show>
        <Show when={!p.compact && agents().length}>
          <box flexDirection="column">
            <Label>AGENTS</Label>
            <For each={agents()}>
              {(a) => {
                const max = () => Math.max(1, ...agents().map((x) => Number(x.findings) || 0))
                const b = () => hbar(Number(a.findings) || 0, max(), Math.max(4, Math.min(p.width, 70) - 22))
                return (
                  <box flexDirection="row" height={1}>
                    <box width={16} flexShrink={0}>
                      <T fg={pal.ink2}>{fit(clean(a.agent, 30), 15)}</T>
                    </box>
                    <Show when={(b().fill) > 0}><T fg={pal.jordy}>{G.bar.repeat(b().fill)}</T></Show>
                    <Show when={(b().rest) > 0}><T fg={pal.rule}>{G.track.repeat(b().rest)}</T></Show>
                    <box width={5} flexDirection="row" justifyContent="flex-end">
                      <T fg={pal.ink}>{num(a.findings)}</T>
                    </box>
                  </box>
                )
              }}
            </For>
          </box>
        </Show>
        <Show when={!p.compact && !p.noLatest && latest().length}>
          <box flexDirection="column">
            <Label>LATEST FINDINGS</Label>
            <For each={latest()}>
              {(f) => (
                <box flexDirection="row" height={1}>
                  <T fg={pal.off}>{`${timeOf((f as any).discovered_at)}  `}</T>
                  <T fg={sevHex(f.severity)}>{`${G.mark} `}</T>
                  <T fg={pal.ink2}>{fit(clean((f as any).short_title || f.title, 200), Math.max(10, p.width - 12))}</T>
                </box>
              )}
            </For>
          </box>
        </Show>
      </box>
    )
  }

  // ---- executive block (H8): grade or « Not rated » / « Limited test », one coverage sentence, the first three
  //      actions of the Prioritized Treatment Plan, one collapsed regulatory line. Every word comes from exec_core.
  const ExecBlock = (p: { k: string; width: number; dense?: boolean }) => {
    const pal = P()
    const got = () => execDocs()[p.k]
    const d = () => got()?.doc
    const head = () => scoreHeadline(d()?.score)
    const lever = () => gradeLever(d()?.score, (d()?.legend as Legend | undefined) ?? legendDoc())
    const firstLine = () => clean(d()?.treatment_plan?.first_actions_line ?? "", 200)
    // dense block (80 columns): 6 rows inside the pane; the frameworks line only when the rows above leave room
    const denseUsed = () => 1 + Math.max(1, wrapLines(coverage(), w(), 2).length) + ((head().rated || head().limited) && lever().holds ? 1 : 0) + Math.max(1, top().length)
    const top = () => d()?.treatment_plan?.top_actions ?? []
    const total = () => Number(d()?.treatment_plan?.actions_total ?? 0)
    const reg = () => d()?.frameworks?.summary_line
    const w = () => Math.max(20, p.width)
    const project = () => p.k.startsWith("p:")
    const latest = () => d()?.latest_campaign as Record<string, any> | null | undefined
    const coverage = () => {
      const c = clean(d()?.score?.coverage_sentence ?? "", 400)
      return !c ? "" : /^coverage\b/i.test(c) ? c : `Coverage: ${c}`
    }
    const sub = () => (head().rated || head().limited ? clean(d()?.score?.grade_meaning ?? "", 200) : scoreWhy(d()?.score))
    return (
      <Show
        when={d()}
        fallback={<T fg={got()?.error ? pal.ink3 : pal.off} wrap>{got()?.error ? `Executive view not available from this source (${fit(got()!.error!, 60)}).` : "Loading the executive view…"}</T>}
      >
        <box flexDirection="column">
          <box flexDirection="row" height={1} flexShrink={0}>
            <T fg={pal.ink} bold>{head().big}</T>
            <Show when={head().rated || head().limited}>
              <T fg={pal.off}>{"   "}</T>
              <T fg={head().rated ? pal.ink2 : pal.ink3}>{head().status}</T>
            </Show>
            <Show when={p.dense && sub()}>
              <T fg={pal.off}>{`  ·  ${fit(sub(), Math.max(0, w() - head().big.length - (head().rated || head().limited ? head().status.length + 5 : 0) - 6))}`}</T>
            </Show>
          </box>
          <Show when={!p.dense && sub()}>
            <T fg={pal.ink3}>{fit(sub(), w())}</T>
          </Show>
          <Show when={coverage()} fallback={<T fg={pal.off}>Coverage not recorded.</T>}>
            <For each={wrapLines(coverage(), w(), 2)}>{(l) => <T fg={pal.ink2}>{l}</T>}</For>
          </Show>
          <Show when={(head().rated || head().limited) && lever().holds}>
            <Show when={p.dense} fallback={
              <box flexDirection="column">
                <For each={wrapLines(`What holds the grade: ${lever().holds}`, w(), 2)}>{(l) => <T fg={pal.ink3}>{l}</T>}</For>
                <Show when={lever().classes}><T fg={pal.off}>{fit(`Weigh most: ${lever().classes}`, w())}</T></Show>
              </box>
            }>
              <T fg={pal.ink3}>{fit(`Holds the grade: ${lever().classes ? `${lever().classes} of the penalties` : lever().holds}`, w())}</T>
            </Show>
          </Show>
          <Show when={project() && !p.dense}>
            <T fg={pal.off}>
              {fit(
                d()?.reference_campaign_id
                  ? `Reference: ${shortCampaign(String(d()!.reference_campaign_id))} of ${shortDate(String(d()!.reference_campaign_date ?? "")).slice(0, 10)}${latest() && latest()!.campaign_id !== d()!.reference_campaign_id ? ` · latest ${shortCampaign(String(latest()!.campaign_id))}: ${clean(latest()!.status_label, 20)}` : ""}`
                  : "No rated full campaign of this target yet.",
                w(),
              )}
            </T>
          </Show>
          <Show when={!p.dense}>
            <box height={1} />
          </Show>
          <Show when={d()?.treatment_plan} fallback={<T fg={pal.off}>{d()?.campaign_status === "running" ? "Plan available when the campaign ends." : "No treatment plan."}</T>}>
            <Show when={!p.dense}>
              <Label>{`PRIORITIZED TREATMENT PLAN · ${total()} action${total() === 1 ? "" : "s"}`}</Label>
              <Show when={firstLine()}><T fg={pal.off}>{fit(firstLine(), w())}</T></Show>
            </Show>
            <Show when={top().length} fallback={<T fg={pal.off}>No open finding to treat.</T>}>
              <For each={top()}>
                {(a: ActionRow) => {
                  const st = () => treatmentLabel(a)
                  // the status words are never cut (« Applied — not verified » must read in full)
                  const sw = () => Math.min(40, Math.max(8, ...top().map((x) => treatmentLabel(x).length)))
                  return (
                    <box flexDirection="row" height={1}>
                      <T fg={pal.off}>{`${String(a.priority ?? "").padStart(2)} `}</T>
                      <T fg={treatmentHex(a.status)}>{`${treatmentMark(a.status, G.mark === "■")} `}</T>
                      <T fg={pal.ink}>{fit(clean(a.title ?? a.action_id, 200), Math.max(6, w() - sw() - 7))}</T>
                      <box flexGrow={1} />
                      <T fg={treatmentHex(a.status)}>{fit(st(), sw())}</T>
                    </box>
                  )
                }}
              </For>
            </Show>
          </Show>
          <Show when={!project() && (!p.dense || denseUsed() < 6)}>
            <box flexDirection="row" height={1}>
              <T fg={pal.jordy}>{`${G.mark === "■" ? "▸" : ">"} `}</T>
              <T fg={pal.off}>{"Frameworks  "}</T>
              <T fg={pal.ink3}>{fit(reg() ? clean(reg(), 400).replace(/^Technical findings relevant to:\s*/, "") : "No framework assessment.", Math.max(4, w() - 18))}</T>
              <box flexGrow={1} />
              <T fg={pal.jordy}>X</T>
            </box>
          </Show>
        </box>
      </Show>
    )
  }

  // ---- screens

  const paneH = () => bodyH() - 3

  const WorkspaceScreen = () => {
    const pal = P()
    const all = () => globalFindings()
    const c = () => countsOf(all())
    const latestCampaign = () => campaigns()[0]
    const contextC = () => contextCampaign() ?? latestCampaign()
    const allPaths = () =>
      Object.values(pathCounts()).reduce(
        (a, s: any) => ({ t: a.t + (Number(s.paths_total) || 0), e: a.e + (Number(s.evidence_backed) || 0), p: a.p + (Number(s.possible) || 0) }),
        { t: 0, e: 0, p: 0 },
      )
    const leftW = () => (layout() === "single" || layout() === "compact" ? W() - 2 : Math.floor((W() - 3) * 0.48))
    const rightW = () => W() - 3 - leftW()
    const tileW = () => Math.max(16, Math.floor((W() - 6) / 4))
    const activity = () => activityOf(campaigns(), all(), 8)
    const two = () => layout() === "wide" || layout() === "split"
    const ek = () => execKey()
    const execTitle = () => {
      const k = ek()
      if (k.startsWith("p:")) return `EXECUTIVE · ${clean(projects().find((x) => x.id === k.slice(2))?.name ?? k.slice(2), 28)}`
      return k ? `EXECUTIVE · campaign ${shortCampaign(k.slice(2))}` : "EXECUTIVE"
    }
    const execH = () => (ek().startsWith("p:") ? 13 : 16)
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0}>
        <Show when={!two()}>
          <box flexDirection="column" paddingLeft={1} paddingRight={1} flexShrink={0}>
            <Pane title={execTitle()} meta="T plan · X frameworks · L legend" width={W() - 2} height={9}>
              <Show when={ek()} keyed>{(k) => <ExecBlock k={k} width={W() - 6} dense />}</Show>
            </Pane>
          </box>
        </Show>
        <Show when={two()}>
        <box flexDirection="row" paddingLeft={2} paddingTop={1} height={5} flexShrink={0}>
          <Tile label="FINDINGS" value={num(all().length)} width={tileW()} sub={<SevStrip counts={c()} width={tileW() - 4} />} />
          <Tile
            label="EXPLOITED"
            value={`${num(c().exploited)}`}
            width={tileW()}
            sub={
              <box flexDirection="row">
                <Show when={(hbar(c().exploited, all().length, tileW() - 10).fill) > 0}><T fg={pal.ink3}>{G.bar.repeat(hbar(c().exploited, all().length, tileW() - 10).fill)}</T></Show>
                <Show when={(hbar(c().exploited, all().length, tileW() - 10).rest) > 0}><T fg={pal.rule}>{G.track.repeat(hbar(c().exploited, all().length, tileW() - 10).rest)}</T></Show>
                <T fg={pal.off}>{`  ${all().length ? Math.round((c().exploited / all().length) * 100) : 0}%`}</T>
              </box>
            }
          />
          <Tile label="CRITICAL" value={num(c().critical)} accent={c().critical ? pal.criticalInk : pal.ink} width={tileW()} sub={<T fg={pal.off}>{`${num(c().high)} high  ·  ${num(c().medium)} medium`}</T>} />
          <Tile label="ATTACK PATHS" value={num(allPaths().t)} width={tileW()} sub={<T fg={pal.off}>{fit(tileW() >= 36 ? `${allPaths().e} evidence-backed · ${allPaths().p} possible` : `${allPaths().e} evidence-backed`, tileW() - 3)}</T>} />
        </box>
        </Show>
        <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1}>
          <box flexDirection="column" width={leftW()} flexShrink={0} minHeight={0} gap={1}>
            <Pane title="PROJECTS & CAMPAIGNS" meta={`${projects().length} · ${campaigns().length}`} focused width={leftW()} grow>
              <ListBody width={leftW() - 4} height={two() ? Math.floor(paneH() * 0.55) : paneH() - 8} focused />
            </Pane>
            <Show when={two()}>
              <Pane title="ACTIVITY" meta="newest first" width={leftW()} grow>
                <For each={activity()}>
                  {(a) => (
                    <box flexDirection="row" height={1}>
                      <T fg={pal.off}>{`${shortDate(a.at).slice(5)}  `}</T>
                      <T fg={a.kind === "campaign" ? pal.jordy : sevHex(a.severity)}>{a.kind === "campaign" ? `${G.node} ` : `${G.mark} `}</T>
                      <T fg={a.kind === "campaign" ? pal.ink : pal.ink2}>{fit(a.text, leftW() - 20)}</T>
                    </box>
                  )}
                </For>
              </Pane>
            </Show>
          </box>
          <Show when={two()}>
            <box flexDirection="column" width={rightW()} flexGrow={1} minHeight={0} gap={1}>
              <Pane title={execTitle()} meta={rightW() >= 70 ? "T plan  X frameworks  L legend" : "T X L"} width={rightW()} height={execH()}>
                <Show when={ek()} keyed>{(k) => <ExecBlock k={k} width={rightW() - 4} />}</Show>
              </Pane>
              <Show when={contextC()}>
                <Pane title="CAMPAIGN" meta="F findings  R report  P paths" width={rightW()} grow>
                  <CampaignBoard c={contextC()!} width={rightW() - 3} compact={bodyH() - 5 - execH() < 32} />
                </Pane>
              </Show>
            </box>
          </Show>
        </box>
      </box>
    )
  }

  const FilterBar = () => {
    const pal = P()
    const counts = () => countsOf(baseFindings())
    const q = () => filter().query ?? ""
    return (
      <box flexDirection="row" height={1} paddingLeft={2} paddingRight={2} gap={2} flexShrink={0}>
        <box flexDirection="row" backgroundColor={C(pal.raised)} paddingLeft={1} paddingRight={1} width={Math.min(30, Math.floor(W() * 0.24))} flexShrink={0}>
          <T fg={q() ? pal.ink : pal.off}>{q() ? `/ ${fit(q(), 24)}` : "/ search"}</T>
        </box>
        <Show when={W() >= 100}>
          <For each={SEVERITIES}>
            {(s) => {
              const on = () => filter().severity === s
              return (
                <box flexDirection="row" backgroundColor={on() ? C(pal.hover) : undefined} paddingLeft={on() ? 1 : 0} paddingRight={on() ? 1 : 0} flexShrink={0}>
                  <T fg={sevHex(s)}>{`${G.mark} `}</T>
                  <T fg={on() ? pal.ink : counts()[s] ? pal.ink2 : pal.off} bold={on()}>{`${counts()[s] ?? 0} ${({ critical: "crit", high: "high", medium: "med", low: "low", info: "info" } as Record<string, string>)[s]}`}</T>
                </box>
              )
            }}
          </For>
        </Show>
        <box flexGrow={1} />
        <T fg={filter().status ? pal.ink : pal.off}>{`proof ${filter().status ?? "all"}`}</T>
        <Show when={W() >= 120}>
          <T fg={filter().target ? pal.ink : pal.off}>{`target ${fit(filter().target ?? "all", 18)}`}</T>
        </Show>
        <T fg={pal.off}>{`sort ${sort()}`}</T>
      </box>
    )
  }

  const FindingsScreen = () => {
    const lw = () => (inline() ? listWidth() : W() - 2)
    const rw = () => W() - 3 - lw()
    const selected = () => baseFindings().find((x) => `f:${x.id}` === selectedKey())
    const full = () => focus() === "detail" && detail() && detail()!.id === selected()?.id
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0}>
        <box height={1} />
        <FilterBar />
        <box height={1} />
        <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1}>
          <Pane title="FINDINGS" meta={`${filtered().length} of ${baseFindings().length}  ·  ${paged().page + 1}/${paged().pages}`} focused={focus() === "list"} width={lw()}>
            <ListBody width={lw() - 4} height={paneH() - 3} focused={focus() === "list"} />
          </Pane>
          <Show when={inline()}>
            <Pane title={full() ? "FINDING" : "INSPECTOR"} meta={selected()?.id ?? ""} focused={focus() === "detail"} width={rw()} grow>
              <Show when={selected()} fallback={<T fg={P().off}>Select a finding.</T>}>
                <scrollbox ref={(el: ScrollBoxRenderable) => (scroll = el)} flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
                  <Show when={full() ? detail() : selected()} keyed>
                    {(f) => <FindingDoc f={f} full={Boolean(full())} width={rw() - 5} />}
                  </Show>
                </scrollbox>
              </Show>
            </Pane>
          </Show>
        </box>
      </box>
    )
  }

  const FindingScreen = () => {
    const lw = () => (inline() ? listWidth() : 0)
    const rw = () => W() - 3 - lw()
    return (
      <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
        <Show when={lw() > 0}>
          <Pane title={listContext()?.k === "findings" ? "FINDINGS" : listContext()?.k === "path" || listContext()?.k === "paths" ? "PATHS" : "LIST"} width={lw()}>
            <ListBody width={lw() - 4} height={paneH()} focused={false} />
          </Pane>
        </Show>
        <Pane title="FINDING" meta={detail()?.id ?? ""} focused width={rw()} grow>
          <scrollbox ref={(el: ScrollBoxRenderable) => (scroll = el)} flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
            <Show when={detail()} keyed fallback={<T fg={P().ink3}>{busy() ? "Loading…" : "Finding not available."}</T>}>
              {(f) => <FindingDoc f={f} full width={rw() - 5} />}
            </Show>
          </scrollbox>
        </Pane>
      </box>
    )
  }

  // report: chapter headings drawn by the explorer (number, title, rule), body rendered by the Markdown component
  const ReportScreen = () => {
    const pal = P()
    const tw = () => (inline() && tocOpen() ? listWidth() : 0)
    const iw = () => (layout() === "wide" ? 34 : 0)
    const dw = () => W() - 3 - tw() - (iw() ? iw() + 1 : 0)
    const docW = () => Math.min(dw() - 7, 96) // border (2) + left padding (3) + right padding (1) + 1 spare
    return (
      <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
        <Show when={tw() > 0}>
          <Pane title="CONTENTS" meta="t hide" width={tw()}>
            <ListBody width={tw() - 4} height={paneH()} focused={false} />
          </Pane>
        </Show>
        <Pane title="REPORT" meta={`${toc().length} chapters`} focused width={dw()} grow pad={3}>
          <scrollbox ref={(el: ScrollBoxRenderable) => (scroll = el)} flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
            <Show when={sections().length} fallback={<T fg={pal.ink3}>{busy() ? "Loading…" : "No report generated for this campaign yet."}</T>}>
              <For each={sections()}>
                {(s, i) => {
                  // wide pictographs (🔴, ✅…) take two cells and push the pane border: one-cell mark instead
                  const body = () => s.body.replace(/^\s{0,3}#{1,6}\s+.*\n?/, "").replace(/\p{Extended_Pictographic}\uFE0F?/gu, "●")
                  const major = () => s.level > 0 && s.level <= 2
                  return (
                    <box ref={(el: BoxRenderable) => sectionNodes.set(i(), el)} flexDirection="column" width={docW()} marginTop={s.title && i() > 0 ? 1 : 0}>
                      <Show when={s.title}>
                        <box flexDirection="column" marginBottom={major() ? 1 : 0}>
                          <T fg={s.level === 1 ? pal.alice : major() ? pal.ink : pal.ink2} bold wrap>
                            {clean(s.title.replace(/[*_`]/g, "").replace(/\p{Extended_Pictographic}\uFE0F?/gu, "●"), 200)}
                          </T>
                          <Show when={major()}>
                            <T fg={s.level === 1 ? pal.chrysler : pal.rule}>{(s.level === 1 ? "━" : G.track).repeat(Math.max(4, docW()))}</T>
                          </Show>
                        </box>
                      </Show>
                      <Show when={body().trim()}>
                        <markdown syntaxStyle={syntax()} content={body()} tableOptions={{ style: "grid" }} conceal={true} fg={C(pal.ink2)} bg={C(pal.canvas)} />
                      </Show>
                    </box>
                  )
                }}
              </For>
            </Show>
          </scrollbox>
        </Pane>
        <Show when={iw() > 0}>
          <Pane title="CHAPTER" width={iw()}>
            {(() => {
              const cited = () => citedFindings(sections()[section()]?.body ?? "")
              return (
                <box flexDirection="column" gap={1}>
                  <T fg={pal.ink} bold wrap>{clean(sections()[section()]?.title || "Introduction", 80)}</T>
                  <box flexDirection="column">
                    <Label>CITED FINDINGS</Label>
                    <Show when={cited().length} fallback={<T fg={pal.off}>None here.</T>}>
                      <For each={cited().slice(0, 12)}>
                        {(id) => {
                          const f = () => findingById(id)
                          return (
                            <box flexDirection="row" height={1}>
                              <T fg={sevHex(f()?.severity)}>{`${G.mark} `}</T>
                              <T fg={pal.ink2}>{id}</T>
                            </box>
                          )
                        }}
                      </For>
                      <T fg={pal.jordy}>F  open one</T>
                    </Show>
                  </box>
                  <Show when={matches().length}>
                    <box flexDirection="column">
                      <Label>SEARCH</Label>
                      <T fg={pal.ink3}>{`${matches().length} chapters match  ·  n N`}</T>
                    </box>
                  </Show>
                </box>
              )
            })()}
          </Pane>
        </Show>
      </box>
    )
  }

  const PathsScreen = () => {
    const lw = () => (inline() ? listWidth() : W() - 2)
    const nw = () => (layout() === "wide" ? 40 : 0)
    const cw = () => W() - 3 - lw() - (nw() ? nw() + 1 : 0)
    const kinds = () => pathKindCounts(paths())
    const pa = () => currentPath()
    return (
      <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
        <Pane
          title="PATHS"
          meta={fitMeta(lw() - 12, [`${num(kinds().evidence_backed)} evidence-backed · ${num(kinds().possible)} possible`, `${num(kinds().evidence_backed)} evid. · ${num(kinds().possible)} poss.`, `${num(kinds().total)}`])}
          focused={focus() === "list"}
          width={lw()}
        >
          <ListBody width={lw() - 4} height={paneH()} focused={focus() === "list"} />
        </Pane>
        <Show when={inline()}>
          <Pane title="PATH" meta={pa() ? `${pa()!.steps?.length ?? 0} steps` : ""} focused={focus() === "detail"} width={cw()} grow>
            <Show when={pa()} fallback={<T fg={P().off}>No path.</T>}>
              <scrollbox flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
                <box flexDirection="column">
                  <T fg={P().ink} bold wrap>{clean(pa()!.title.replace(/\s*\((inferred|declared)\)\s*$/i, ""), 200)}</T>
                  <box height={1} />
                  <PathGraph path={pa()!} interactive={focus() === "detail"} width={cw() - 5} />
                  <Show when={pa()!.note}>
                    <box height={1} />
                    <T fg={P().ink3} wrap>{clean(pa()!.note, 400)}</T>
                  </Show>
                </box>
              </scrollbox>
            </Show>
          </Pane>
        </Show>
        <Show when={nw() > 0 && pa()}>
          <Pane title="NODE" meta={focus() === "detail" ? `step ${step() + 1}` : "tab to walk"} width={nw()}>
            <NodeDetail path={pa()!} />
          </Pane>
        </Show>
      </box>
    )
  }

  const PathScreen = () => {
    const pa = () => currentPath()
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0} paddingLeft={1} paddingRight={1} paddingTop={1}>
        <Pane title="PATH" meta={pa() ? `step ${step() + 1} of ${pa()!.steps?.length ?? 0}` : ""} focused grow>
          <Show when={pa()}>
            <scrollbox flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
              <box flexDirection="column">
                <T fg={P().ink} bold wrap>{clean(pa()!.title, 200)}</T>
                <box height={1} />
                <PathGraph path={pa()!} interactive width={W() - 6} />
              </box>
            </scrollbox>
          </Show>
        </Pane>
      </box>
    )
  }


  // ---- Prioritized Treatment Plan: actions (list) + the selected action (inspector)
  const ActionDoc = (p: { a: ActionRow; width: number }) => {
    const pal = P()
    const a = p.a as Record<string, any>
    const pl = plan()
    const declared = (x: any) => (x && x.value != null && x.value !== "unknown" ? `${profileValue(x.value)}${x.provenance ? ` (${x.provenance === "declared" ? "declared" : clean(x.provenance, 20)})` : ""}` : "")
    const byId = new Map((paths()?.paths ?? []).map((x) => [x.id, x]))
    const rel: string[] = a.related_attack_paths ?? []
    const eb = rel.filter((id) => pathKind(byId.get(id)) === "evidence_backed").length
    const hist = [...(a.history ?? [])].reverse().slice(0, 4)
    const kv = (k: string, v: unknown) =>
      v ? (
        <box flexDirection="row" flexShrink={0}>
          <box width={14} flexShrink={0}>
            <T fg={pal.off}>{k}</T>
          </box>
          <T fg={pal.ink2} wrap grow>{clean(String(v), 400)}</T>
        </box>
      ) : null
    return (
      <box flexDirection="column" gap={1}>
        <box flexDirection="column">
          <box flexDirection="row" height={1}>
            <T fg={sevHex(a.severity)}>{`${G.mark} `}</T>
            <T fg={pal.ink2}>{`#${num(a.priority)} of ${num(pl?.actions?.length)}  ·  ${String(a.severity ?? "info").toUpperCase()}  ·  ${proofTag(a.proof)}`}</T>
          </box>
          <T fg={pal.ink} bold wrap>{clean(a.title ?? a.action_id, 300)}</T>
        </box>
        <box flexDirection="column">
          <box flexDirection="row" height={1}>
            <box width={14} flexShrink={0}><T fg={pal.off}>Status</T></box>
            <T fg={pal.ink}>{`${treatmentMark(a.status, G.mark === "■")} ${treatmentLabel(a)}`}</T>
          </box>
          {kv("", a.status_text && a.status_text !== treatmentLabel(a) ? a.status_text : "")}
          {kv("Retest", a.last_retest && (a.last_retest.coverage_ok === false || clean(a.last_retest.text ?? "", 200) !== clean(a.status_text ?? "", 200)) ? retestNote(a) : "")}
          {kv("Verification", a.status === "applied" ? "Declared by the owner, not verified: only a completed retest can verify it." : pl?.verification_note)}
          {kv("Unit", a.weakness_class_label ? `${clean(a.weakness_class_label, 60)} on ${clean(a.asset ?? "", 60)}` : "")}
          {kv("Effort", effortText(a))}
          {kv("Impact", a.expected_impact?.text)}
          {kv("Treatment", a.treatment_type ? `${clean(a.treatment_type.label, 40)} · ${clean(a.treatment_type.basis, 120)}` : "")}
          {kv("Owner", declared(a.owner))}
          {kv("Due date", declared(a.due_date))}
          {kv("Interruption", declared(a.service_interruption_risk))}
          {kv("Risk accepted", riskAcceptanceText(a) || declared(a.risk_accepted_until))}
        </box>
        <Show when={a.explanation}>
          <box flexDirection="column">
            <Label>WHY THIS RANK</Label>
            <T fg={pal.ink3} wrap>{clean(a.explanation, 600)}</T>
          </box>
        </Show>
        <box flexDirection="column">
          <Label>{`FINDINGS · ${num((a.finding_ids ?? []).length)}`}</Label>
          <Show when={(a.findings ?? []).length} fallback={<T fg={pal.ink2} wrap>{fit((a.finding_ids ?? []).map((x: string) => clean(x, 40)).join(", "), 600)}</T>}>
            <For each={(a.findings ?? []).slice(0, 12)}>
              {(f: any) => (
                <box flexDirection="row" height={1}>
                  <T fg={pal.ink3}>{`${pm(f.proof)} `}</T>
                  <T fg={sevHex(f.severity)}>{`${severityTag(f.severity).trim().padEnd(4)} `}</T>
                  <T fg={pal.ink2}>{fit(clean(f.title ?? f.finding_id, 200), Math.max(8, p.width - 7))}</T>
                </box>
              )}
            </For>
            <Show when={(a.findings ?? []).length > 12}>
              <T fg={pal.off}>{`… and ${num((a.findings ?? []).length - 12)} more`}</T>
            </Show>
          </Show>
          <T fg={pal.jordy}>enter  open the first finding</T>
        </box>
        <box flexDirection="column">
          <Label>ATTACK PATHS</Label>
          <T fg={pal.ink2} wrap>
            {rel.length
              ? `${rel.length} related: ${eb} ${PATH_KIND_LABEL.evidence_backed} · ${rel.length - eb} ${PATH_KIND_LABEL.possible}${(a.interrupts_attack_paths ?? []).length ? ` · interrupts ${(a.interrupts_attack_paths ?? []).length}` : ""}`
              : "None related."}
          </T>
        </box>
        <Show when={(a.related_controls ?? []).length}>
          <box flexDirection="column">
            <Label>FRAMEWORK CONTROLS</Label>
            <T fg={pal.ink2} wrap>{(a.related_controls ?? []).map((x: string) => clean(x, 40)).join(", ")}</T>
            <T fg={pal.off} wrap>{clean(a.related_controls_note ?? "", 300)}</T>
          </box>
        </Show>
        <Show when={a.recommended_treatment?.text}>
          <box flexDirection="column">
            <Label>RECOMMENDED</Label>
            <T fg={pal.off} wrap>{clean(a.recommended_treatment?.label ?? "Quoted as written, not verified", 200)}</T>
            <T fg={pal.ink2} wrap>{clean(a.recommended_treatment?.text, 1200)}</T>
          </box>
        </Show>
        <Show when={hist.length}>
          <box flexDirection="column">
            <Label>HISTORY · newest first</Label>
            <For each={hist}>
              {(h: any) => (
                <T fg={pal.ink3} wrap>
                  {fit(`${shortDate(h.at)}  ${clean(h.from ?? "", 24)}${h.from ? " → " : ""}${clean(h.to ?? h.status ?? "", 24)}  ${clean(h.by_role ?? "", 40)}${h.note ? `  · ${clean(h.note, 120)}` : ""}`, 400)}
                </T>
              )}
            </For>
          </box>
        </Show>
      </box>
    )
  }

  const PlanScreen = () => {
    const pal = P()
    const lw = () => (inline() ? listWidth() : W() - 2)
    const rw = () => W() - 3 - lw()
    const pl = () => plan()
    // counts by status: the server's labels (Pro sends ``statuses``; Community labels come with the actions)
    const counts = () => {
      const by = ((pl()?.summary as any)?.by_status ?? {}) as Record<string, number>
      const labels = new Map<string, string>()
      for (const st of pl()?.statuses ?? []) labels.set(st.value, st.label)
      for (const a of pl()?.actions ?? []) if (a.status && !labels.has(a.status)) labels.set(a.status, treatmentLabel(a))
      return Object.entries(by)
        .filter(([, n]) => Number(n) > 0)
        .map(([value, n]) => ({ value, label: labels.get(value) ?? value.replace(/_/g, " "), n: Number(n) }))
    }
    const showList = () => inline() || focus() === "list"
    const showDetail = () => inline() || focus() === "detail"
    const a = () => selectedAction()
    const tall = () => dims().height >= 40
    const expired = () => Number(((pl()?.summary as any) ?? {}).risk_acceptance_expired ?? 0) || 0
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0}>
        <box flexDirection="column" paddingLeft={2} paddingRight={2} paddingTop={1} flexShrink={0}>
          <box flexDirection="row" height={1}>
            <T fg={pal.alice} bold>{clean(pl()?.label ?? "Prioritized Treatment Plan", 60)}</T>
            <T fg={pal.off}>{fit(`  ·  ${num(pl()?.actions?.length)} actions  ·  ${clean(pl()?.basis_label ?? "", 60)}`, Math.max(0, W() - 34))}</T>
          </box>
          <T fg={pal.ink3}>{fit(clean(pl()?.definition ?? (busy() ? "Loading…" : ""), 400), W() - 4)}</T>
          <Show when={tall() && pl()?.unit}>
            <T fg={pal.ink3}>{fit(`${clean(pl()?.unit, 300)} ${clean(pl()?.effort_note ?? "", 300)}`, W() - 4)}</T>
          </Show>
          <T fg={pal.ink2}>{fit([...counts().map((c) => `${c.n} ${clean(c.label, 40)}`), ...(expired() ? [`${expired()} risk acceptance${expired() === 1 ? "" : "s"} expired`] : [])].join("  ·  ") || " ", W() - 4)}</T>
        </box>
        <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
          <Show when={showList()}>
            <Pane title="ACTIONS" meta={`${num(pl()?.actions?.length)}`} focused={focus() === "list"} width={lw()}>
              <ListBody width={lw() - 4} height={paneH() - 4 - (tall() && pl()?.unit ? 1 : 0)} focused={focus() === "list"} />
            </Pane>
          </Show>
          <Show when={showDetail()}>
            <Pane title="ACTION" meta={a() ? `#${num(a()!.priority)}` : ""} focused={focus() === "detail"} width={inline() ? rw() : W() - 2} grow>
              <Show when={a()} fallback={<T fg={pal.off}>Select an action.</T>}>
                <scrollbox ref={(el: ScrollBoxRenderable) => (scroll = el)} flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
                  <Show when={a()} keyed>
                    {(x) => <ActionDoc a={x} width={(inline() ? rw() : W() - 2) - 5} />}
                  </Show>
                </scrollbox>
              </Show>
            </Pane>
          </Show>
        </box>
        <box paddingLeft={2} paddingRight={2} height={1} flexShrink={0}>
          <T fg={pal.off}>{fit(`Applied = declared, not verified  ·  « Not reproduced at retest » only from a completed retest  ·  ${clean(pl()?.score_note ?? "statuses never change the rating", 120)}`, W() - 4)}</T>
        </box>
      </box>
    )
  }

  // ---- framework technical assessment: frameworks (list) + controls of the selected one, by state
  const FrameworksScreen = () => {
    const pal = P()
    const lw = () => (inline() ? listWidth() : W() - 2)
    const rw = () => W() - 3 - lw()
    const fa = () => assessment()
    const fw = () => fa()?.frameworks?.find((f) => `w:${f.framework}` === selectedKey())
    const stateLabel = (k: string) => clean(fa()?.states?.find((x) => x.value === k)?.label ?? k.replace(/_/g, " "), 60)
    const showList = () => inline() || focus() === "list"
    const showDetail = () => inline() || focus() === "detail"
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0}>
        <box flexDirection="column" paddingLeft={2} paddingRight={2} paddingTop={1} flexShrink={0}>
          <box flexDirection="row" height={1}>
            <T fg={pal.alice} bold>Technical assessment</T>
            <T fg={pal.off}>{fit(`  ·  ${clean((fa()?.coverage as any)?.sentence ?? "", 200)}`, Math.max(0, W() - 26))}</T>
          </box>
          <T fg={pal.ink3}>{fit(clean(fa()?.reading ?? (busy() ? "Loading…" : ""), 600), W() - 4)}</T>
        </box>
        <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
          <Show when={showList()}>
            <Pane title="FRAMEWORKS" meta="controls per state" focused={focus() === "list"} width={lw()}>
              <ListBody width={lw() - 4} height={paneH() - 3} focused={focus() === "list"} />
              <box height={1} />
              <T fg={pal.off} wrap>{`${applicabilityMark("declared_by_customer", G.mark === "■")} applicable (declared)  ${applicabilityMark("to_confirm", G.mark === "■")} to confirm  ${applicabilityMark("not_applicable_declared", G.mark === "■")} declared not applicable`}</T>
              <T fg={pal.off} wrap>WEAK weakness observed · NONE none observed in the tested scope · N/T not tested · NTA not technically assessable</T>
            </Pane>
          </Show>
          <Show when={showDetail()}>
            <Pane title="CONTROLS" meta={fw() ? clean(fw()!.label ?? fw()!.framework, 40) : ""} focused={focus() === "detail"} width={inline() ? rw() : W() - 2} grow>
              <Show when={fw()} fallback={<T fg={pal.off}>Select a framework.</T>}>
                <scrollbox ref={(el: ScrollBoxRenderable) => (scroll = el)} flexGrow={1} minHeight={0} verticalScrollbarOptions={{ visible: false }}>
                  <Show when={fw()} keyed>
                    {(f) => (
                      <box flexDirection="column" gap={1}>
                        <box flexDirection="column">
                          <T fg={pal.ink} bold wrap>{clean(f.label ?? f.framework, 120)}</T>
                          <T fg={pal.ink3} wrap>{applicabilityOf(f).label}</T>
                          <T fg={pal.ink2} wrap>{frameworkLine(f)}</T>
                        </box>
                        <For each={[...FRAMEWORK_STATES]}>
                          {(st) => {
                            const cs = () => ((f as any).controls ?? []).filter((c: any) => c.state === st)
                            return (
                              <Show when={cs().length}>
                                <box flexDirection="column">
                                  <Label>{`${stateLabel(st).toUpperCase()} · ${cs().length}`}</Label>
                                  <For each={cs()}>
                                    {(c: any) => (
                                      <box flexDirection="column">
                                        <box flexDirection="row">
                                          <box width={16} flexShrink={0}>
                                            <T fg={pal.ink}>{clean(c.control_id, 15)}</T>
                                          </box>
                                          <T fg={pal.ink2} wrap grow>{clean(st === "not_technically_assessable" ? (c.why ?? c.text) : c.text, 300)}</T>
                                        </box>
                                        <Show when={(c.finding_ids ?? []).length || (c.action_ids ?? []).length}>
                                          <T fg={pal.off}>{`${" ".repeat(16)}${plural((c.finding_ids ?? []).length, "finding")} · ${plural((c.action_ids ?? []).length, "action")}${c.to_confirm ? " · to confirm" : ""}`}</T>
                                        </Show>
                                      </box>
                                    )}
                                  </For>
                                </box>
                              </Show>
                            )
                          }}
                        </For>
                        <For each={((f as any).limitations ?? []).slice(0, 3)}>{(x: string) => <T fg={pal.off} wrap>{`· ${clean(x, 300)}`}</T>}</For>
                      </box>
                    )}
                  </Show>
                </scrollbox>
              </Show>
            </Pane>
          </Show>
        </box>
        <box paddingLeft={2} paddingRight={2} height={1} flexShrink={0}>
          <T fg={pal.off}>{fit("Technical findings relevant to these frameworks: not an audit, a certification or a legal opinion.", W() - 4)}</T>
        </box>
      </box>
    )
  }

  // ---- application profile: fields by group with their provenance badge (shape + word)
  const ProfileSummary = (p: { id: string; width: number }) => {
    const pal = P()
    const got = () => profiles()[p.id]
    const f = () => got()?.doc?.profile?.fields ?? {}
    const pc = () => (got()?.doc?.profile?.provenance_counts ?? {}) as Record<string, number>
    const keys = ["criticality", "availability_requirement", "personal_data", "sector", "rto", "rpo"]
    return (
      <Show when={got()?.doc} fallback={<T fg={pal.off}>{got()?.error ? "Profile not available from this source." : "Loading the profile…"}</T>}>
        <box flexDirection="column">
          <T fg={pal.ink3}>{fit(`${num(pc().declared_by_customer)} declared · ${num(pc().verified)} verified · ${num(pc().detected)} detected · ${num(pc().unknown)} not provided`, p.width)}</T>
          <For each={keys.filter((k) => f()[k])}>
            {(k) => {
              const x = () => f()[k]
              const b = () => provenanceBadge(x().provenance, G.mark === "■")
              return (
                <box flexDirection="row" height={1}>
                  <T fg={x().provenance === "unknown" ? pal.off : pal.ink2}>{`${b().mark} `}</T>
                  <box width={18} flexShrink={0}>
                    <T fg={pal.off}>{fit(fieldLabel(k), 17)}</T>
                  </box>
                  <T fg={x().value == null ? pal.off : pal.ink}>{fit(profileValue(x().value), Math.max(4, p.width - 34))}</T>
                  <box flexGrow={1} />
                  <T fg={pal.off}>{b().word}</T>
                </box>
              )
            }}
          </For>
          <T fg={pal.jordy}>A  full application profile</T>
        </box>
      </Show>
    )
  }

  const ProfileScreen = () => {
    const pal = P()
    const v = () => view() as Extract<View, { k: "profile" }>
    const doc = () => profiles()[v().project.id]?.doc
    const lw = () => (inline() ? listWidth() : W() - 2)
    const rw = () => W() - 3 - lw()
    const pc = () => (doc()?.profile?.provenance_counts ?? {}) as Record<string, number>
    const sel = () => {
      const k = selectedKey()
      return k.startsWith("f-") ? ([k.slice(2), doc()?.profile?.fields?.[k.slice(2)]] as const) : undefined
    }
    const decl = () => doc()?.declarations as Record<string, any> | undefined
    const showList = () => inline() || focus() === "list"
    const showDetail = () => inline() || focus() === "detail"
    return (
      <box flexDirection="column" flexGrow={1} minHeight={0}>
        <box flexDirection="column" paddingLeft={2} paddingRight={2} paddingTop={1} flexShrink={0}>
          <box flexDirection="row" height={1}>
            <T fg={pal.alice} bold>Application profile</T>
            <T fg={pal.off}>{fit(`  ·  ${num(pc().declared_by_customer)} declared · ${num(pc().verified)} verified · ${num(pc().detected)} detected · ${num(pc().unknown)} not provided`, Math.max(0, W() - 25))}</T>
          </box>
          <For each={wrapLines(
              decl()
                ? `Owner's file ${clean(decl()!.file, 80)} (${clean(decl()!.status, 12)}), edited by hand; no MCP tool writes it, but the local agent has shell access: not tamper-evident.`
                : "Declared by the organisation on the dashboard. Business facts are never guessed; detected values are not confirmed.",
              W() - 4, 2)}>
            {(l) => <T fg={pal.ink3}>{l}</T>}
          </For>
        </box>
        <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
          <Show when={showList()}>
            <Pane title="PROFILE" meta={`${provenanceBadge("declared", G.mark === "■").mark} declared  ${provenanceBadge("verified", G.mark === "■").mark} verified  ${provenanceBadge("detected", G.mark === "■").mark} detected`} focused={focus() === "list"} width={lw()}>
              <ListBody width={lw() - 4} height={paneH() - 3} focused={focus() === "list"} />
            </Pane>
          </Show>
          <Show when={showDetail()}>
            <Pane title="FIELD" focused={focus() === "detail"} width={inline() ? rw() : W() - 2} grow>
              <Show when={sel()?.[1]} fallback={<T fg={pal.off}>Select a field.</T>}>
                {(() => {
                  const [name, f] = sel()!
                  const b = provenanceBadge(f!.provenance, G.mark === "■")
                  return (
                    <box flexDirection="column" gap={1}>
                      <box flexDirection="column">
                        <T fg={pal.ink} bold>{fieldLabel(name)}</T>
                        <T fg={f!.value == null ? pal.off : pal.ink2} wrap>{profileValue(f!.value)}</T>
                      </box>
                      <box flexDirection="column">
                        <T fg={pal.ink2}>{`${b.mark} ${clean(f!.provenance_label ?? b.word, 80)}`}</T>
                        <Show when={declaredByText(f, !!decl())}><T fg={pal.ink3} wrap>{declaredByText(f, !!decl())}</T></Show>
                        <Show when={f!.at}><Kv k="When" v={shortDate(String(f!.at))} /></Show>
                        <Show when={f!.by_role}><Kv k={decl() ? "Role, as written" : "Role"} v={clean(f!.by_role, 80)} kw={18} /></Show>
                        <Show when={f!.campaign_id}><Kv k="Campaign" v={clean(f!.campaign_id, 60)} /></Show>
                      </box>
                      <Show when={f!.note}><T fg={pal.off} wrap>{clean(f!.note, 300)}</T></Show>
                      <Show when={["rto", "rpo", "availability_requirement", "criticality"].includes(name)}>
                        <T fg={pal.off} wrap>Declared by the organisation, not assessed by Darkmoon.</T>
                      </Show>
                    </box>
                  )
                })()}
              </Show>
            </Pane>
          </Show>
        </box>
      </box>
    )
  }

  // projects, campaigns, campaign menu: list + preview
  const ListScreen = () => {
    const lw = () => (inline() ? listWidth() : W() - 2)
    const rw = () => W() - 3 - lw()
    const v = () => view()
    const title = () => (v().k === "projects" ? "PROJECTS" : v().k === "campaign" ? "OPEN" : "CAMPAIGNS")
    const preview = () => {
      const k = v().k
      if (k === "campaign") return <CampaignBoard c={campaign() ?? (v() as any).campaign} width={rw() - 5} noLatest />
      if (k === "campaigns") {
        const c = campaigns().find((x) => `c:${x.id}` === selectedKey())
        if (!c) return null
        if ((v() as any).purpose === "plan")
          return (
            <box flexDirection="column" gap={1}>
              <T fg={P().ink3}>{[campaignTarget(c), shortDate(c.date), c.status].filter(Boolean).join("  ·  ")}</T>
              <Show when={`c:${c.id}`} keyed>{(k) => <ExecBlock k={k} width={rw() - 5} />}</Show>
              <T fg={P().jordy}>enter  open the Prioritized Treatment Plan</T>
            </box>
          )
        return <CampaignBoard c={c} width={rw() - 5} />
      }
      const pr = projects().find((x) => `p:${x.id}` === selectedKey())
      const last = pr ? campaigns().find((c) => c.project_id === pr.id) : undefined
      if (!pr) return null
      return (
        <box flexDirection="column" gap={1}>
          <box flexDirection="column" flexShrink={0}>
            <T fg={P().ink} bold>{clean(pr.name, 120)}</T>
            <T fg={P().ink3}>{targetLabel(pr) || "—"}</T>
          </box>
          <box flexDirection="column" flexShrink={0}>
            <Kv k="Campaigns" v={num(pr.campaigns_count)} />
            <Kv k="Findings" v={num(pr.vulnerabilities_count)} />
            <Kv k="Risk" v={pr.latest_risk ?? "—"} fg={pr.latest_risk ? sevHex(pr.latest_risk) : P().off} />
          </box>
          <box flexDirection="column" flexShrink={0}>
            <Label>CYBER SCORE · reference campaign</Label>
            <Show when={`p:${pr.id}`} keyed>{(k) => <ExecBlock k={k} width={rw() - 5} dense />}</Show>
          </box>
          <box flexDirection="column" flexShrink={0}>
            <Label>APPLICATION PROFILE</Label>
            <Show when={pr.id} keyed>{(id) => <ProfileSummary id={id} width={rw() - 5} />}</Show>
          </box>
          <Show when={last}>
            <box flexDirection="column" flexShrink={0}>
              <Label>LAST CAMPAIGN</Label>
              <CampaignBoard c={last!} width={rw() - 5} compact />
            </box>
          </Show>
        </box>
      )
    }
    const latest = () =>
      [...(campaign()?.vulnerabilities ?? [])].sort((a, b) => String((b as any).discovered_at ?? "").localeCompare(String((a as any).discovered_at ?? ""))).slice(0, Math.max(3, paneH() - 10))
    return (
      <box flexDirection="row" flexGrow={1} minHeight={0} gap={1} paddingLeft={1} paddingRight={1} paddingTop={1}>
        <Pane title={title()} meta={v().k === "campaign" ? "" : `${selectable().length}`} focused width={lw()}>
          <ListBody width={lw() - 4} height={v().k === "campaign" ? 3 : paneH()} focused />
          <Show when={v().k === "campaign" && latest().length}>
            <box height={2} />
            <Label>LATEST FINDINGS</Label>
            <For each={latest()}>
              {(f) => (
                <box flexDirection="row" height={1}>
                  <T fg={P().off}>{`${timeOf((f as any).discovered_at)}  `}</T>
                  <T fg={sevHex(f.severity)}>{`${G.mark} `}</T>
                  <T fg={P().ink2}>{fit(clean((f as any).short_title || f.title, 200), Math.max(10, lw() - 14))}</T>
                </box>
              )}
            </For>
          </Show>
        </Pane>
        <Show when={inline()}>
          <Pane title={v().k === "projects" ? "PROJECT" : "CAMPAIGN"} meta="F findings  R report  P paths" width={rw()} grow>
            {preview()}
          </Pane>
        </Show>
      </box>
    )
  }

  const Login = () => {
    const pal = P()
    return (
      <box flexGrow={1} justifyContent="center" alignItems="center">
        <box flexDirection="column" gap={1} width={Math.min(56, W() - 4)}>
          <box flexDirection="column">
            <T fg={pal.alice} bold>DARKMOON</T>
            <T fg={pal.ink3}>Sign in to browse projects, findings and reports.</T>
          </box>
          <box flexDirection="column">
            <T fg={field() === "user" ? pal.jordy : pal.off}>Username</T>
            <box backgroundColor={C(field() === "user" ? pal.hover : pal.raised)} paddingLeft={1} height={1}>
              <T fg={pal.ink}>{user() + (field() === "user" ? "▏" : "")}</T>
            </box>
          </box>
          <box flexDirection="column">
            <T fg={field() === "pass" ? pal.jordy : pal.off}>Password</T>
            <box backgroundColor={C(field() === "pass" ? pal.hover : pal.raised)} paddingLeft={1} height={1}>
              <T fg={pal.ink}>{"•".repeat(pass().length) + (field() === "pass" ? "▏" : "")}</T>
            </box>
          </box>
          <T fg={pal.off}>The session token stays in memory. Nothing is written to disk.</T>
          <Show when={error()}>
            <T fg={pal.criticalInk} wrap>{error()!}</T>
          </Show>
        </box>
      </box>
    )
  }

  const screen = () => {
    const k = view().k
    if (k === "workspace") return <WorkspaceScreen />
    if (k === "findings") return <FindingsScreen />
    if (k === "finding") return <FindingScreen />
    if (k === "report") return <ReportScreen />
    if (k === "paths") return <PathsScreen />
    if (k === "path") return <PathScreen />
    if (k === "plan") return <PlanScreen />
    if (k === "frameworks") return <FrameworksScreen />
    if (k === "profile") return <ProfileScreen />
    return <ListScreen />
  }

  return (
    <box position="absolute" zIndex={2500} left={0} top={0} width={dims().width} height={dims().height} backgroundColor={C(P().canvas)} flexDirection="column">
      <TopBar />
      <Show when={view().k !== "login"} fallback={<Login />}>
        <box height={1} />
        <Crumbs />
        <Show when={view().k} keyed>
          {() => screen()}
        </Show>
      </Show>
      <Footer />
    </box>
  )
}

function fit(s: string, w: number) {
  return w < 1 ? "" : s.length <= w ? s : w === 1 ? "…" : s.slice(0, w - 1) + "…"
}
// ASCII fallback for pane borders (same keys as OpenTUI's border chars)
const ASCII_BORDER = { topLeft: "+", topRight: "+", bottomLeft: "+", bottomRight: "+", horizontal: "-", vertical: "|", topT: "+", bottomT: "+", leftT: "+", rightT: "+", cross: "+" }

function shortCampaign(id: string) {
  const m = /^camp_\d{8}_(.+)$/.exec(id)
  return clean(m ? m[1] : id, 60)
}

const FIELD_LABEL: Record<string, string> = {
  rto: "RTO", rpo: "RPO", sla: "SLA", iso27001_isms_scope: "ISO 27001 ISMS scope", nis2_entity_type: "NIS2 entity type",
  ai_system_declared: "AI system declared", ai_act_role: "AI Act role", personal_data: "Personal data", ai_risk_class: "AI risk class",
}
function fieldLabel(name: string) {
  const n = String(name ?? "")
  if (FIELD_LABEL[n]) return FIELD_LABEL[n]
  const w = n.replace(/_/g, " ")
  return w.charAt(0).toUpperCase() + w.slice(1)
}

function plural(n: number, w: string) {
  return `${n} ${w}${n === 1 ? "" : "s"}`
}
/** The first pane-title meta that fits (a title that does not fit is not drawn at all by the host). */
function fitMeta(w: number, options: string[]) {
  return options.find((o) => o.length <= w) ?? ""
}

function fitTail(s: string, w: number) {
  return w <= 1 ? "" : s.length <= w ? s : "…" + s.slice(s.length - w + 1)
}

function emptyText(v: View, filtered: boolean) {
  if (filtered) return "Nothing matches. Press c to clear the filters."
  if (v.k === "campaigns" && v.purpose === "reports") return "No campaign has a report yet."
  if (v.k === "plan") return "No action to plan: no open finding, or the plan is not available from this source."
  return (
    ({
      workspace: "No project yet. Launch a campaign from the console to start.",
      projects: "No project yet.",
      campaigns: "No campaign yet.",
      findings: "No findings.",
      paths: "No attack path for this campaign.",
      frameworks: "No framework assessment for this campaign.",
      profile: "No profile field.",
      report: "This report has no chapters.",
    }) as Record<string, string>
  )[v.k] ?? ""
}

function markdownSyntax(p: Palette) {
  const c = (h: string) => RGBA.fromHex(h)
  const rule = (scope: string[], style: Record<string, unknown>) => ({ scope, style })
  return SyntaxStyle.fromTheme([
    rule(["default"], { foreground: c(p.ink2) }),
    rule(["markup.heading"], { foreground: c(p.ink), bold: true }),
    rule(["markup.heading.1"], { foreground: c(p.alice), bold: true }),
    rule(["markup.heading.2"], { foreground: c(p.ink), bold: true }),
    rule(["markup.heading.3", "markup.heading.4", "markup.heading.5", "markup.heading.6"], { foreground: c(p.ink2), bold: true }),
    rule(["markup.bold", "markup.strong"], { foreground: c(p.ink), bold: true }),
    rule(["markup.italic"], { foreground: c(p.ink2), italic: true }),
    rule(["markup.list"], { foreground: c(p.off) }),
    rule(["markup.quote"], { foreground: c(p.ink3), italic: true }),
    rule(["markup.raw", "markup.raw.inline"], { foreground: c(p.code) }),
    rule(["markup.raw.block"], { foreground: c(p.code), background: c(p.surface) }),
    rule(["markup.link", "markup.link.url"], { foreground: c(p.jordy), underline: true }),
    rule(["markup.link.label", "markup.link.text"], { foreground: c(p.jordy) }),
  ] as any)
}

const tui: TuiPlugin = async (api, options) => {
  const src = createSource((options ?? {}) as Options)
  let returnRoute: typeof api.route.current | undefined
  const close = () => {
    api.ui.dialog.clear()
    const r = returnRoute
    api.route.navigate(r?.name ?? "home", r && "params" in r ? r.params : undefined)
  }
  api.route.register([{ name: ROUTE, render: () => <Explorer api={api} src={src} close={close} /> }])
  api.keymap.registerLayer({
    commands: [
      {
        name: "darkmoon.explorer.open",
        title: "Darkmoon explorer",
        slashName: "explore",
        category: "Darkmoon",
        namespace: "palette",
        run() {
          if (api.route.current.name !== ROUTE) returnRoute = api.route.current
          api.ui.dialog.clear()
          api.route.navigate(ROUTE)
        },
      },
    ],
    bindings: [{ key: "<leader>d", cmd: "darkmoon.explorer.open", desc: "Darkmoon explorer" }],
  })
}

export default { id: "darkmoon-explorer", tui }
