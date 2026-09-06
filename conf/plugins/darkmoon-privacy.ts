/**
 * Darkmoon privacy plugin — pre-model prompt tokenization (issue #40, section 3).
 *
 * The Darkmoon privacy boundary (mcp/src/privacy) tokenizes tool calls and their
 * output, but the INITIAL launch prompt (`TARGET`, `CREDS`, `SCOPE`, `TOKEN`, IP,
 * port) reaches the model first, before any tool call, so without this it would
 * be sent to the model provider in clear.
 *
 * This closes that gap WITHOUT re-implementing any anonymization and WITHOUT
 * depending on opencode's internal architecture:
 *
 *   - It uses only the STABLE public `chat.message` hook (present and identical in
 *     ASCIT31/opencode and upstream anomalyco/opencode). No core imports.
 *   - It has ZERO external dependencies (only the `node:net` builtin), so the
 *     plugin loader never needs to install anything for it and an opencode update
 *     cannot break it. `node:net` is used because opencode's compiled Bun runtime
 *     honours node:net unix sockets but not `fetch({unix})` / http `socketPath`.
 *   - It reaches the tokenizer over a LOCAL unix socket exposed by the darkmoon
 *     MCP server (mcp/src/prompt_socket.py). That socket lives in the SAME MCP
 *     process the tool calls use, so the placeholders it returns are the exact
 *     ones the gateway rehydrates during the run and the report renderer restores
 *     locally. The model only ever sees IP_PRIVATE_001 / USER_001 / CRED_001.
 *
 * The MCP server (and thus the socket) may come up a few seconds after opencode
 * starts, and the first user message can be created before then, so a connection
 * failure is retried briefly (the launch prompt is worth a short wait).
 *
 * Fail-closed: if tokenization is still unavailable after the retries, the raw
 * text is NOT sent to the model — it is replaced with a marker — unless
 * DARKMOON_PROMPT_TOKENIZE_FALLBACK is "open". Disable with DARKMOON_PROMPT_TOKENIZE=0.
 */
import { connect } from "node:net"

const SOCK = process.env["DARKMOON_PRIVACY_SOCK"] ?? "/tmp/darkmoon-privacy.sock"
const OFF = new Set(["0", "false", "no", "off"])
const FAIL_OPEN = new Set(["open", "degrade"])
const RETRIES = 240 // ~120s at 500ms, generously covering MCP startup
const RETRY_DELAY_MS = 500

function enabled(): boolean {
  return !OFF.has((process.env["DARKMOON_PROMPT_TOKENIZE"] ?? "1").toLowerCase())
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// One newline-delimited JSON round-trip over the MCP's local unix socket.
// Resolves the tokenized text (or null for an empty/invalid reply); REJECTS on a
// connection error so the caller can retry while the MCP is still starting up.
function tokenizeOnce(text: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    let settled = false
    let buf = ""
    const sock = connect({ path: SOCK })
    const finish = (ok: boolean, value: string | null, err?: Error) => {
      if (settled) return
      settled = true
      try {
        sock.destroy()
      } catch {
        /* ignore */
      }
      if (ok) resolve(value)
      else reject(err ?? new Error("socket error"))
    }
    sock.setTimeout(15000, () => finish(false, null, new Error("timeout")))
    sock.on("connect", () => sock.write(JSON.stringify({ text }) + "\n"))
    sock.setEncoding("utf8")
    sock.on("data", (chunk: string) => {
      buf += chunk
      const nl = buf.indexOf("\n")
      if (nl < 0) return
      try {
        const obj = JSON.parse(buf.slice(0, nl)) as { tokenized?: string }
        finish(true, typeof obj?.tokenized === "string" ? obj.tokenized : null)
      } catch {
        finish(true, null)
      }
    })
    sock.on("error", (e: Error) => finish(false, null, e))
    sock.on("end", () => finish(true, null))
  })
}

async function tokenize(text: string): Promise<string | null> {
  for (let i = 0; i < RETRIES; i++) {
    try {
      return await tokenizeOnce(text) // reached the socket → done (even if null)
    } catch {
      await sleep(RETRY_DELAY_MS) // socket not up yet → wait and retry
    }
  }
  return null
}

type TextPart = { type?: string; text?: string }

async function tokenizeParts(parts: TextPart[] | undefined) {
  if (!Array.isArray(parts)) return
  const failOpen = FAIL_OPEN.has((process.env["DARKMOON_PROMPT_TOKENIZE_FALLBACK"] ?? "").toLowerCase())
  for (const part of parts) {
    if (part?.type !== "text" || typeof part.text !== "string" || part.text.length === 0) continue
    let safe: string | null = null
    try {
      safe = await tokenize(part.text)
    } catch {
      safe = null
    }
    if (safe !== null) {
      part.text = safe
    } else if (!failOpen) {
      // Fail-closed: never let an un-tokenized launch prompt reach the model.
      part.text =
        "[darkmoon-privacy] prompt withheld: local tokenization is unavailable, so the raw " +
        "TARGET/CREDS/SCOPE were not sent to the model. Check the darkmoon MCP server, or set " +
        "DARKMOON_PROMPT_TOKENIZE_FALLBACK=open to allow raw prompts."
    }
  }
}

// A plugin is `(input) => Promise<hooks>`. We deliberately do NOT import the
// `@opencode-ai/plugin` type; the shape below is the stable public contract.
//
// We tokenize at BOTH `chat.message` and `experimental.chat.messages.transform`:
//   - `chat.message` fires when the user message is created, BEFORE opencode's
//     separate session-title generation call, so tokenizing here keeps the raw
//     prompt out of that call too. It relies on the darkmoon MCP being reachable
//     at message-creation time, which is why the MCP runs persistently (started
//     at boot, opencode connects to it as a remote MCP) — the tokenization socket
//     is already up, so there is no wait/deadlock.
//   - `experimental.chat.messages.transform` fires just before the provider
//     request as a belt-and-braces re-tokenization of the whole message list.
// Both hooks are present and identical in ASCIT31/opencode and upstream
// anomalyco/opencode. Tokenization is idempotent, so running both is harmless.
export const DarkmoonPrivacyPlugin = async () => {
  return {
    "chat.message": async (
      _input: unknown,
      output: { parts?: TextPart[] },
    ) => {
      if (!enabled()) return
      await tokenizeParts(output?.parts)
    },
    "experimental.chat.messages.transform": async (
      _input: unknown,
      output: { messages?: Array<{ info?: { role?: string }; parts?: TextPart[] }> },
    ) => {
      if (!enabled()) return
      const messages = output?.messages
      if (!Array.isArray(messages)) return
      for (const message of messages) {
        // Only user messages carry operator-supplied values (TARGET/CREDS/...).
        // Assistant/tool messages are model output and are already placeholder-safe.
        if (message?.info?.role && message.info.role !== "user") continue
        await tokenizeParts(message?.parts)
      }
    },
  }
}

export default DarkmoonPrivacyPlugin
