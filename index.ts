import { homedir } from "node:os"
import { join } from "node:path"
import type { Plugin } from "@opencode-ai/plugin"
import {
  bashSegmentSignatures,
  callSignature,
  detectFailure,
  isIntendedNonzero,
  isNoiseError,
  parameterizeError,
  patternKey,
  scrubSecrets,
} from "./src/patterns"
import { GateStore, Stores, type Gate, PLUGIN_VERSION } from "./src/store"

// --- Tunables ---------------------------------------------------------------

/** distinct project dirs before a pattern is promoted to the global store */
const GLOBAL_PROJECTS = 2
/** gates expire when the pattern has not recurred for this many days */
const TTL_DAYS = 60
/** how often a long-lived process re-runs expiry */
const TTL_INTERVAL_MS = 6 * 60 * 60 * 1000
/** a gate firing this often without killing the error gets flagged for review */
const REVIEW_FIRES = 10
/** per-session state maps are capped to bound memory in long-lived processes */
const SESSION_MAP_CAP = 200
/** per-session key sets are capped too — one long session must not grow unbounded */
const SESSION_KEY_CAP = 500
/** a "retry" arriving this soon after a reminder was dispatched concurrently with it
 * (same tool-call burst) and never saw the reminder — it gets reminded as well.
 * A true agent retry needs a full model turn (≥1s in practice), so 500ms separates both. */
const REMINDER_RACE_WINDOW_MS = 500
/** handled part IDs are capped FIFO-style */
const HANDLED_CAP = 5000
const HANDLED_KEEP = 2500
/** pendingCalls capped — aborted calls never reach the after-hook, so a cap bounds the fallback map */
const PENDING_CAP = 1000

/** Sentinel: intentional gate/reminder throws (rethrown); our own bugs are swallowed. */
class GateSignal extends Error {}

function addToSetMap(map: Map<string, Set<string>>, outer: string, inner: string): void {
  let set = map.get(outer)
  if (!set) {
    set = new Set()
    map.set(outer, set)
  }
  set.add(inner)
  while (set.size > SESSION_KEY_CAP) {
    const oldest = set.values().next()
    if (oldest.done) break
    set.delete(oldest.value)
  }
}

/** Drop oldest entries (Map preserves insertion order) to bound memory. */
function capMap<K, V>(map: Map<K, V>, cap: number): void {
  while (map.size > cap) {
    const oldest = map.keys().next()
    if (oldest.done) break
    map.delete(oldest.value)
  }
}

function scrubbedArgs(args: Record<string, unknown>): Record<string, unknown> {
  if (typeof args.command === "string") return { ...args, command: scrubSecrets(args.command) }
  if (typeof args.pattern === "string") return { ...args, pattern: scrubSecrets(args.pattern) }
  return args
}

function remindMessage(gate: Gate): string {
  const correction = gate.correction
    ? `Correction: ${gate.correction}`
    : "Do NOT retry it unchanged. Diagnose the root cause first, or take a different approach."
  return [
    `[dejavu] REMINDER — this exact call has already failed ${gate.count}x across ${gate.sessions.length} session(s).`,
    `Last failure: ${gate.snippet}`,
    correction,
    `If you are certain it works now, retry — a repeated failure hardens this gate into a block. Explicit bypass: append the trailing comment "# dejavu:proceed" to the command — it is a marker read by the gate, NOT a shell command.`,
  ].join("\n")
}

function blockMessage(gate: Gate, storeDir: string): string {
  return [
    `[dejavu] BLOCKED — you were reminded about this failing call in this session, retried it, and it failed again.`,
    `CORRECTION: ${gate.correction ?? "Change approach entirely; do not repeat this exact call."}`,
    `EVIDENCE: ${gate.count} failures across ${gate.sessions.length} sessions, first seen ${gate.firstSeen.slice(0, 10)}.`,
    `Review or remove this gate: ${join(storeDir, "gates.json")} (key: ${gate.key})`,
  ].join("\n")
}

export const Dejavu: Plugin = async ({ directory, client }) => {
  // DEJAVU_HOME overrides the global store location (testing, custom setups).
  const globalDir = process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu")
  const globalStore = new GateStore(globalDir)
  const projectStore =
    typeof directory === "string" && directory !== ""
      ? new GateStore(join(directory, ".opencode", "dejavu"))
      : null
  const stores = new Stores(globalStore, projectStore)

  /** sessions in which a gate key was already reminded about; value = remind time (race guard) */
  const reminded = new Map<string, Map<string, number>>()
  /** sessions in which a reminded pattern failed again — next attempt is blocked */
  const failedAfterReminder = new Map<string, Set<string>>()
  /** callID -> signature fallback when the after-hook does not receive args */
  const pendingCalls = new Map<string, string>()
  /** message part IDs already counted as tool-level errors */
  let handledParts = new Set<string>()

  const logClient = async (level: "debug" | "info" | "warn" | "error", message: string): Promise<void> => {
    try {
      await client.app.log({ body: { service: "dejavu", level, message } })
    } catch {
      // logging must never break the plugin
    }
  }

  // Init: heal structural damage, migrate old data, expire stale gates,
  // rotate logs, warm the caches.
  try {
    await stores.reconcileAll(GLOBAL_PROJECTS)
    await stores.migrate()
    await stores.expireAll(TTL_DAYS)
    await stores.rotateLogs()
    await stores.logAll({ type: "init", key: "dejavu", version: PLUGIN_VERSION })
    await logClient("info", `dejavu initialized v${PLUGIN_VERSION}`)
  } catch (error) {
    // init failures must not prevent hook registration — but must be visible,
    // otherwise a corrupted store silently starts the plugin with no gates
    await logClient("error", `dejavu init failed: ${error instanceof Error ? error.message : String(error)}`)
  }

  // Long-lived processes re-run expiry periodically.
  const ttlTimer = setInterval(() => {
    // expiry is best-effort; the timer keeps running regardless
    stores.expireAll(TTL_DAYS).catch(() => {})
  }, TTL_INTERVAL_MS)
  ;(ttlTimer as { unref?: () => void }).unref?.()

  return {
    "tool.execute.before": async (input, output) => {
      try {
        const rawArgs = (output?.args ?? {}) as Record<string, unknown>
        const args = scrubbedArgs(rawArgs)
        const signature = callSignature(input.tool, args)
        if (!signature) return

        // Chain-bypass protection: a gate on "rm -rf /" must also fire when the
        // command hides inside "git status && rm -rf /".
        const candidates = [signature]
        if (input.tool === "bash" && typeof args.command === "string") {
          candidates.push(...bashSegmentSignatures(args.command))
        }

        let found: { gate: Gate; store: GateStore; via: "exact" | "fuzzy" | "segment" } | null = null
        for (let i = 0; i < candidates.length; i++) {
          const sig = candidates[i] ?? ""
          const match = await stores.findGate(patternKey(sig), sig)
          if (match && match.gate.status === "blocking") {
            found = { gate: match.gate, store: match.store, via: i > 0 && match.via === "exact" ? "segment" : match.via }
            break
          }
        }
        if (!found) return
        // Only track calls that will actually run: an aborted (thrown) call never
        // reaches the after-hook, so recording it earlier would leak forever.
        if (typeof input.callID === "string") {
          pendingCalls.set(input.callID, signature)
          while (pendingCalls.size > PENDING_CAP) {
            const oldest = pendingCalls.keys().next()
            if (oldest.done) break
            pendingCalls.delete(oldest.value)
          }
        }

        const gate = found.gate
        const via = found.via
        const session = typeof input.sessionID === "string" ? input.sessionID : "unknown"

        // Explicit escape hatch — checked only in the actionable text field,
        // with word boundaries, so unrelated args cannot bypass gates. Quoted
        // spans are stripped first: `echo "dejavu:proceed" && gated-cmd` must
        // NOT bypass the gate on the chained command — the marker is a
        // comment-style annotation, not data.
        const commandText =
          typeof rawArgs.command === "string"
            ? rawArgs.command
            : typeof rawArgs.pattern === "string"
              ? rawArgs.pattern
              : typeof rawArgs.filePath === "string"
                ? rawArgs.filePath
                : ""
        if (/\bdejavu:proceed\b/.test(commandText.replace(/"[^"]*"|'[^']*'/g, " "))) {
          await stores.logAll({ type: "override", key: gate.key, tool: gate.tool, session, project: directory })
          return
        }

        // Repeat offense: reminded in this session, retried, failed again -> hard block.
        if (failedAfterReminder.get(session)?.has(gate.key)) {
          gate.blockedCount += 1
          if (gate.blockedCount >= REVIEW_FIRES) gate.review = true
          await found.store.save()
          await stores.logAll({ type: "blocked", key: gate.key, tool: gate.tool, session, project: directory, via })
          throw new GateSignal(blockMessage(gate, found.store.dir))
        }

        // First encounter this session -> remind (the call is aborted; agent may retry corrected).
        // Race guard: calls dispatched in the same burst all arrive before the agent can
        // have seen any reminder, so a "retry" within REMINDER_RACE_WINDOW_MS of the
        // remind is itself a concurrent first encounter and gets reminded too.
        const sessionReminded = reminded.get(session) ?? new Map<string, number>()
        if (!reminded.has(session)) reminded.set(session, sessionReminded)
        const remindedAt = sessionReminded.get(gate.key)
        if (remindedAt === undefined || Date.now() - remindedAt < REMINDER_RACE_WINDOW_MS) {
          sessionReminded.set(gate.key, Date.now())
          sessionReminded.set(patternKey(signature), Date.now()) // exact key too: retry may fuzzy-match differently
          capMap(sessionReminded, SESSION_KEY_CAP)
          capMap(reminded, SESSION_MAP_CAP)
          gate.remindedCount += 1
          await found.store.save()
          await stores.logAll({ type: "reminded", key: gate.key, tool: gate.tool, session, project: directory, via })
          throw new GateSignal(remindMessage(gate))
        }

        // Already reminded, no repeated failure yet -> allow one retry.
        await stores.logAll({ type: "retry-allowed", key: gate.key, tool: gate.tool, session, project: directory, via })
      } catch (error) {
        if (error instanceof GateSignal) throw error
        // Our own bugs must never break the user's tool calls.
      }
    },

    "tool.execute.after": async (input, output) => {
      try {
        // Primary signal: the tool's exit code in metadata (verified against live
        // payloads — failed bash calls arrive as successful tool executions with
        // metadata.exit !== 0 and often "(no output)" as the text).
        const metadata = (output?.metadata ?? {}) as { exit?: unknown }
        const exitCode = typeof metadata.exit === "number" ? metadata.exit : null
        const isBash = input.tool === "bash"
        // Text signatures apply to bash ONLY: for read/edit/write the output is
        // file CONTENT, and scanning it for "TypeError" created false gates.
        const text = typeof output?.output === "string" ? output.output : ""
        const detection = isBash ? detectFailure(text) : { matched: false, snippet: "" }
        const rawCommand = isBash && typeof (input as { args?: { command?: unknown } }).args?.command === "string"
          ? String((input as { args: { command: string } }).args.command)
          : ""
        // grep/pytest/linters: exit 1 is often the INTENDED outcome, not a mistake.
        const intended = exitCode === 1 && isIntendedNonzero(rawCommand, 1)
        const failed = exitCode !== null ? exitCode !== 0 && !intended : detection.matched
        if (!failed) return
        const snippet = scrubSecrets(detection.matched ? detection.snippet : `exit code ${exitCode}`)

        const args = scrubbedArgs(((input as { args?: unknown }).args ?? {}) as Record<string, unknown>)
        let signature = callSignature(input.tool, args)
        if (typeof input.callID === "string") {
          if (!signature) signature = pendingCalls.get(input.callID) ?? null
          pendingCalls.delete(input.callID)
        }
        if (!signature) return

        // Attribution: if a segment of a failed chain matches an already-known
        // pattern, record the failure under that segment's key — the chain
        // wrapper changes every time, the recurring part does not.
        let recordSignature = signature
        if (input.tool === "bash" && typeof args.command === "string") {
          for (const segSig of bashSegmentSignatures(args.command)) {
            if (await stores.hasKey(patternKey(segSig))) {
              recordSignature = segSig
              break
            }
          }
        }

        const key = patternKey(recordSignature)
        const session = typeof input.sessionID === "string" ? input.sessionID : "unknown"

        const result = await stores.recordFailure({
          key,
          signature: recordSignature,
          tool: input.tool,
          sessionID: session,
          projectDir: typeof directory === "string" ? directory : "",
          snippet,
          globalProjects: GLOBAL_PROJECTS,
        })

        await stores.logAll({
          type: "detected",
          key,
          tool: input.tool,
          session,
          project: directory,
          snippet,
          channel: exitCode !== null ? "exit" : "text",
          exit: exitCode ?? undefined,
        })

        if (result.promoted) {
          await stores.logAll({ type: "promoted", key, tool: input.tool, session, project: directory })
          await logClient(
            "info",
            `dejavu: gate promoted — "${result.gate.signature}" (${result.gate.count}x, ${result.gate.sessions.length} sessions)`,
          )
        }
        if (result.wentGlobal) {
          await logClient("info", `dejavu: gate went global — "${result.gate.signature}"`)
        }

        // Metric: failure of an already-enforced pattern (the event that
        // promoted the gate does not count — the gate did not exist yet).
        if (result.gate.status === "blocking" && !result.promoted) {
          result.gate.recurredAfterGate += 1
          await result.store.save()
          await stores.logAll({ type: "recurred-after-gate", key, tool: input.tool, session, project: directory })
        }

        // Same-session repeat after a reminder -> escalate to hard block.
        if (reminded.get(session)?.has(key) || reminded.get(session)?.has(result.gate.key)) {
          addToSetMap(failedAfterReminder, session, result.gate.key)
          capMap(failedAfterReminder, SESSION_MAP_CAP)
          result.gate.recurredAfterReminder += 1
          await result.store.save()
        }
      } catch {
        // detection failures must never break the tool pipeline
      }
    },

    event: async ({ event }) => {
      try {
        const type = (event as { type?: unknown }).type

        // Free per-session state when a session is deleted.
        if (type === "session.deleted") {
          const props = (event as { properties?: unknown }).properties as { sessionID?: unknown } | undefined
          if (typeof props?.sessionID === "string") {
            reminded.delete(props.sessionID)
            failedAfterReminder.delete(props.sessionID)
          }
          return
        }

        if (type !== "message.part.updated") return
        // Tool-level failures (read of missing file, rejected edit, ...) never
        // reach tool.execute.after — capture them from the message stream.
        const props: unknown = (event as { properties?: unknown }).properties
        if (typeof props !== "object" || props === null) return
        const part: unknown = (props as { part?: unknown }).part
        if (typeof part !== "object" || part === null) return
        const p = part as { id?: unknown; type?: unknown; tool?: unknown; state?: unknown; sessionID?: unknown }
        if (p.type !== "tool" || typeof p.id !== "string") return
        if (handledParts.has(p.id)) return

        const state: unknown = p.state
        if (typeof state !== "object" || state === null) return
        if ((state as { status?: unknown }).status !== "error") return

        handledParts.add(p.id)
        if (handledParts.size > HANDLED_CAP) {
          handledParts = new Set([...handledParts].slice(-HANDLED_KEEP))
        }

        const toolName = typeof p.tool === "string" ? p.tool : "unknown"

        const rawError: unknown = (state as { error?: unknown }).error
        const rawText =
          typeof rawError === "string" ? rawError : rawError === undefined ? "unknown error" : JSON.stringify(rawError)
        // Never persist secrets or infrastructure details.
        const errorText = scrubSecrets(rawText)
        // Never count our own gate signals as failures — a thrown REMINDER/BLOCK
        // comes back through this channel as a tool error.
        if (errorText.includes("[dejavu]")) return
        // Aborted/cancelled executions are infrastructure noise, not mistakes.
        if (isNoiseError(errorText)) return
        const session = typeof p.sessionID === "string" ? p.sessionID : "unknown"

        // Prefer the real call signature from the tool input — it keeps the gate
        // enforceable by the before-hook. Fall back to a parameterized error
        // signature so "same root cause, different data" collapses to one key.
        const toolInput: unknown = (state as { input?: unknown }).input
        let signature: string | null = null
        if (typeof toolInput === "object" && toolInput !== null) {
          signature = callSignature(toolName, scrubbedArgs(toolInput as Record<string, unknown>))
        }
        if (!signature) {
          signature = `${toolName}:tool-error:${parameterizeError(errorText).slice(0, 120)}`
        }
        const key = patternKey(signature)

        const result = await stores.recordFailure({
          key,
          signature,
          tool: toolName,
          sessionID: session,
          projectDir: typeof directory === "string" ? directory : "",
          snippet: errorText.slice(0, 200),
          globalProjects: GLOBAL_PROJECTS,
        })
        await stores.logAll({
          type: "detected",
          key,
          tool: toolName,
          session,
          project: directory,
          snippet: errorText.slice(0, 200),
          channel: "event",
        })
        if (result.promoted) {
          await stores.logAll({ type: "promoted", key, tool: toolName, session, project: directory })
          await logClient("info", `dejavu: gate promoted — "${result.gate.signature}"`)
        }
      } catch {
        // event stream must never be broken by us
      }
    },

    "experimental.session.compacting": async (_input, output) => {
      try {
        const gates = await stores.blockingGates()
        if (gates.length === 0) return
        const lines = gates
          .slice(0, 20)
          .map(
            (g) =>
              `- \`${g.signature}\` — failed ${g.count}x in ${g.sessions.length} session(s). ${g.correction ?? "Do not retry unchanged; find the root cause first."}`,
          )
        output.context.push(
          `## dejavu — active error gates\nThese tool calls have repeatedly failed before. Do not attempt them unchanged:\n${lines.join("\n")}`,
        )
      } catch {
        // compaction enrichment is best-effort
      }
    },
  }
}

export default Dejavu
