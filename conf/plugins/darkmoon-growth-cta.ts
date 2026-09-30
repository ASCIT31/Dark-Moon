/**
 * Darkmoon growth star CTA plugin — the user-facing side of api/growth.py.
 *
 * WHAT IT DOES
 *   After the FIRST real delivered value (a completed campaign / validated finding
 *   / generated report — recorded by the MCP server in api/growth.py), it shows a
 *   single, non-blocking, dismissible line inviting the operator to star the open
 *   source project on GitHub. Shown once, then never again.
 *
 * WHY A PLUGIN
 *   The MCP server (which produces the report) runs as a separate process and its
 *   stdout is NOT the operator's terminal, so it cannot show the CTA itself. This
 *   plugin runs in-process with opencode (the user-facing side), reads the same
 *   local growth state the MCP wrote, and surfaces the CTA at session.idle.
 *
 * CONVENTIONS (identical to darkmoon-privacy.ts)
 *   - Uses only STABLE public hooks (`event`, `tool.execute.after`) and the
 *     `node:fs`/`node:path` builtins. ZERO external dependencies. No core imports.
 *   - FAIL-SAFE: every path is wrapped; any error is swallowed. A growth problem
 *     must never break a session, corrupt the TUI, or block the operator.
 *
 * PRIVACY / OPT-OUT (same model as api/growth.py)
 *   - Reads/writes only local JSON: event *types*, timestamps, counts, booleans.
 *     Never a target, host, IP, credential, finding or campaign id.
 *   - DARKMOON_DISABLE_GROWTH_CTA=1 disables the CTA. DARKMOON_NO_TELEMETRY=1 (or
 *     DARKMOON_GROWTH_DISABLE=1) disables all local growth state, hence the CTA too.
 *
 * DISPLAY
 *   - Best-effort toast via the opencode client (works in the TUI), AND a clean
 *     line to stderr in non-TTY (one-shot `run`) mode. In an interactive TUI we do
 *     NOT write raw stderr (it would corrupt the UI); the toast covers that case.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs"
import { join } from "node:path"
import { homedir } from "node:os"

const REPO_URL = "https://github.com/ASCIT31/Dark-Moon"
const OFF = new Set(["", "0", "false", "no", "off", "none"])

function flag(name: string): boolean {
  return !OFF.has((process.env[name] ?? "").trim().toLowerCase())
}
function telemetryDisabled(): boolean {
  return flag("DARKMOON_NO_TELEMETRY") || flag("DARKMOON_GROWTH_DISABLE")
}
function ctaDisabled(): boolean {
  return flag("DARKMOON_DISABLE_GROWTH_CTA") || telemetryDisabled()
}
function intEnv(name: string, def: number): number {
  const n = parseInt((process.env[name] ?? "").trim(), 10)
  return Number.isFinite(n) ? n : def
}
function maxShows(): number {
  return Math.max(1, intEnv("DARKMOON_GROWTH_CTA_MAX_SHOWS", 1))
}
function minDays(): number {
  return Math.max(0, intEnv("DARKMOON_GROWTH_CTA_MIN_DAYS", 30))
}

function growthDir(): string {
  const d = (process.env["DARKMOON_GROWTH_DIR"] ?? "").trim()
  if (d) return d
  const base = (process.env["XDG_DATA_HOME"] ?? "").trim() || join(homedir(), ".local", "share")
  return join(base, "darkmoon", "growth")
}
const p = (name: string) => join(growthDir(), name)
const MILESTONES = "milestones.json"
const CTA_STATE = "cta_state.json"
const FUNNEL = "funnel.jsonl"

function readJson(name: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(p(name), "utf8")) as Record<string, unknown>
  } catch {
    return {}
  }
}
function writeJson(name: string, obj: Record<string, unknown>): void {
  if (telemetryDisabled()) return
  try {
    mkdirSync(growthDir(), { recursive: true })
    const tmp = p(name) + ".tmp"
    writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf8")
    // rename is atomic on the same fs; fall back to a direct write if it fails.
    try {
      const { renameSync } = require("node:fs")
      renameSync(tmp, p(name))
    } catch {
      writeFileSync(p(name), JSON.stringify(obj, null, 2), "utf8")
    }
  } catch {
    /* ignore */
  }
}
function appendFunnel(stage: string): void {
  if (telemetryDisabled()) return
  try {
    mkdirSync(growthDir(), { recursive: true })
    appendFileSync(p(FUNNEL), JSON.stringify({ ts: new Date().toISOString(), stage }) + "\n", "utf8")
  } catch {
    /* ignore */
  }
}

// --- pure eligibility (unit-testable) -------------------------------------
export function firstValueReached(): boolean {
  return Boolean(readJson(MILESTONES)["first_value_at"])
}

export function shouldShow(now: Date = new Date()): boolean {
  try {
    if (ctaDisabled()) return false
    if (!firstValueReached()) return false
    const st = readJson(CTA_STATE)
    if (st["dismissed"]) return false
    const shows = Number(st["show_count"] ?? 0)
    if (shows >= maxShows()) return false
    const last = st["last_shown_at"] ? new Date(String(st["last_shown_at"])) : null
    if (last && !Number.isNaN(last.getTime()) && minDays() > 0) {
      const days = (now.getTime() - last.getTime()) / 86_400_000
      if (days < minDays()) return false
    }
    return true
  } catch {
    return false
  }
}

export function renderCta(): string {
  const line = "─".repeat(62)
  return (
    "\n" +
    line + "\n" +
    " Darkmoon just delivered your first real result.\n" +
    " If it was useful, a GitHub star helps the open source project grow:\n" +
    "   " + REPO_URL + "\n" +
    " (Shown once. Turn it off anytime: export DARKMOON_DISABLE_GROWTH_CTA=1)\n" +
    line + "\n"
  )
}

function markShown(now: Date): void {
  const st = readJson(CTA_STATE)
  st["star_cta_shown"] = true
  st["show_count"] = Number(st["show_count"] ?? 0) + 1
  st["last_shown_at"] = now.toISOString()
  if (!st["first_shown_at"]) st["first_shown_at"] = now.toISOString()
  writeJson(CTA_STATE, st)
  appendFunnel("STAR_CTA_SHOWN")
}

// Belt-and-braces: if the MCP-side hook did not record first value (but telemetry
// is on), observing the finalize tool succeed lets the CTA still fire. Only ever
// writes a timestamp — never any target/finding data.
function ensureFirstValueFromTool(): void {
  if (telemetryDisabled()) return
  const m = readJson(MILESTONES)
  if (m["first_value_at"]) return
  m["first_value_at"] = new Date().toISOString()
  const events = (m["events"] as Record<string, unknown>) ?? {}
  events["campaign_finalized"] = { first_at: m["first_value_at"], count: 1, last_at: m["first_value_at"] }
  m["events"] = events
  writeJson(MILESTONES, m)
}

async function display(client: unknown): Promise<void> {
  const now = new Date()
  if (!shouldShow(now)) return
  // 1) Best-effort toast (TUI). Never throws out.
  try {
    const c = client as { tui?: { showToast?: (a: unknown) => unknown } }
    if (c?.tui?.showToast) {
      await c.tui.showToast({
        body: {
          title: "Darkmoon",
          message: "First result delivered. A GitHub star helps the OSS project: " + REPO_URL,
          variant: "info",
        },
      })
    }
  } catch {
    /* ignore toast failures */
  }
  // 2) Clean stderr line for one-shot (non-TTY) `run` mode. We avoid raw stderr in
  //    an interactive TUI (isTTY) so we never corrupt the rendered UI.
  try {
    const isTty = Boolean((process.stdout as { isTTY?: boolean })?.isTTY)
    if (!isTty || flag("DARKMOON_CTA_FORCE_STDERR")) {
      process.stderr.write(renderCta())
    }
  } catch {
    /* ignore */
  }
  markShown(now)
}

// A plugin is `(input) => Promise<hooks>`. We do not import the plugin type; the
// shape below is the stable public contract (same approach as darkmoon-privacy.ts).
export const DarkmoonGrowthCtaPlugin = async ({ client }: { client?: unknown } = {}) => {
  return {
    // Fires at the end of every turn. Gating (first value + once-only) ensures a
    // single, well-timed CTA that appears only after real value was delivered.
    event: async (input: { event?: { type?: string } }) => {
      try {
        if (input?.event?.type === "session.idle") await display(client)
      } catch {
        /* fail-safe */
      }
    },
    // Fallback first-value signal, independent of the MCP-side hook.
    "tool.execute.after": async (input: { tool?: string }) => {
      try {
        if (typeof input?.tool === "string" && input.tool.includes("finalize_campaign")) {
          ensureFirstValueFromTool()
        }
      } catch {
        /* fail-safe */
      }
    },
  }
}

export default DarkmoonGrowthCtaPlugin
