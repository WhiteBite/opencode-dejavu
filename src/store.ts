import { appendFile, mkdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { canBlock, fuzzySimilar, scrubSecrets } from "./patterns"

/** Bumped on behavior changes; stamped into init log events so stale sessions are visible. */
export const PLUGIN_VERSION = "2.1.0"

export interface Gate {
  /** sha1 signature prefix — the pattern identity */
  key: string
  /** normalized call signature, e.g. "bash:npm install --legacy-peer-deps" */
  signature: string
  tool: string
  /** watching = collecting evidence; blocking = gate is enforced */
  status: "watching" | "blocking"
  count: number
  /** distinct session IDs where the failure was seen */
  sessions: string[]
  /** distinct project directories where the failure was seen */
  projects: string[]
  firstSeen: string
  lastSeen: string
  /** last observed error line, as evidence (secret-scrubbed) */
  snippet: string
  /** optional human/agent-written guidance shown in reminder/block messages */
  correction?: string
  remindedCount: number
  blockedCount: number
  recurredAfterReminder: number
  /** the core health metric: failures of this pattern AFTER it became a gate */
  recurredAfterGate: number
  /** flagged for manual review when the gate fires often but errors stopped */
  review?: boolean
}

interface GatesFile {
  version: 1
  gates: Gate[]
}

export type LogEventType =
  | "detected"
  | "promoted"
  | "reminded"
  | "retry-allowed"
  | "blocked"
  | "override"
  | "expired"
  | "recurred-after-gate"
  | "init"

export interface LogEvent {
  type: LogEventType
  key: string
  tool?: string
  session?: string
  project?: string
  snippet?: string
  /** which detection channel fired: metadata exit, bash text scan, or event stream */
  channel?: "exit" | "text" | "event"
  /** raw tool exit code when available */
  exit?: number
  /** how the gate matched the call */
  via?: "exact" | "fuzzy" | "segment"
  /** plugin version (init events) */
  version?: string
}

const MAX_SESSIONS = 50
const MAX_PROJECTS = 20
const LOG_ROTATE_BYTES = 512 * 1024
const LOG_ROTATE_KEEP_LINES = 1000
const DAY_MS = 24 * 60 * 60 * 1000

/** failures required before a pattern becomes an enforced gate */
export const PROMOTE_COUNT = 3
/** file-probe tools fail routinely during normal probing — higher bar, never block */
export const PROMOTE_COUNT_PROBE = 5
export const PROBE_TOOLS = new Set(["read", "glob", "grep", "write", "edit"])
/** distinct sessions required — same-session loops never promote */
export const PROMOTE_SESSIONS = 2

// --- Windows-safe fs helpers -------------------------------------------------

/** NT long-path prefix so deeply nested project dirs do not hit MAX_PATH. */
function ntPath(p: string): string {
  if (process.platform !== "win32") return p
  if (p.startsWith("\\\\?\\")) return p
  return `\\\\?\\${p}`
}

const RETRYABLE = new Set(["EPERM", "EACCES", "EBUSY"])

/** tmp + rename with exponential-backoff retry (Windows AV/indexer locks). */
async function atomicWrite(path: string, content: string): Promise<void> {
  const tmp = `${path}.${process.pid}.tmp`
  for (let attempt = 0; ; attempt++) {
    try {
      await writeFile(ntPath(tmp), content, "utf8")
      await rename(ntPath(tmp), ntPath(path))
      return
    } catch (error) {
      const code = (error as { code?: string }).code ?? ""
      if (RETRYABLE.has(code) && attempt < 5) {
        await new Promise((resolve) => setTimeout(resolve, 50 * 2 ** attempt))
        continue
      }
      try {
        await unlink(ntPath(tmp))
      } catch {
        // orphan tmp is harmless
      }
      throw error
    }
  }
}

const LOCK_STALE_MS = 5000
const LOCK_WAIT_MS = 3000

/**
 * Exclusive lockfile ("wx" create) with stale-lock stealing and graceful
 * degradation: if the lock cannot be acquired within LOCK_WAIT_MS the
 * critical section runs unlocked rather than hanging the tool pipeline.
 */
async function withLock<T>(lockTarget: string, fn: () => Promise<T>): Promise<T> {
  const lock = `${lockTarget}.lock`
  await mkdir(ntPath(dirname(lock)), { recursive: true })
  const started = Date.now()
  for (;;) {
    try {
      await writeFile(ntPath(lock), String(process.pid), { flag: "wx" })
      break
    } catch (error) {
      const code = (error as { code?: string }).code ?? ""
      if (code !== "EEXIST") throw error
      try {
        const info = await stat(ntPath(lock))
        if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
          await unlink(ntPath(lock)).catch(() => {})
          continue
        }
      } catch {
        continue // lock vanished between attempts
      }
      if (Date.now() - started > LOCK_WAIT_MS) break
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
  }
  try {
    return await fn()
  } finally {
    try {
      await unlink(ntPath(lock))
    } catch {
      // best effort
    }
  }
}

export class GateStore {
  private gates: Gate[] | null = null
  private mtimeMs = 0

  constructor(public readonly dir: string) {}

  private get gatesPath(): string {
    return join(this.dir, "gates.json")
  }

  private get logPath(): string {
    return join(this.dir, "log.jsonl")
  }

  /** Run a load→mutate→save section under the store's exclusive lock. */
  async runLocked<T>(fn: () => Promise<T>): Promise<T> {
    return withLock(this.gatesPath, fn)
  }

  /** force=true bypasses the mtime cache (always used inside locks). */
  async load(force = false): Promise<Gate[]> {
    try {
      const info = await stat(ntPath(this.gatesPath))
      if (!force && this.gates !== null && info.mtimeMs === this.mtimeMs) {
        return this.gates
      }
      const raw = await readFile(ntPath(this.gatesPath), "utf8")
      const parsed = JSON.parse(raw) as Partial<GatesFile>
      this.gates = Array.isArray(parsed.gates) ? parsed.gates : []
      this.mtimeMs = info.mtimeMs
      return this.gates
    } catch {
      if (this.gates === null) this.gates = []
      return this.gates
    }
  }

  async save(): Promise<void> {
    if (this.gates === null) return
    await mkdir(ntPath(this.dir), { recursive: true })
    const payload: GatesFile = { version: 1, gates: this.gates }
    await atomicWrite(this.gatesPath, `${JSON.stringify(payload, null, 2)}\n`)
    try {
      this.mtimeMs = (await stat(ntPath(this.gatesPath))).mtimeMs
    } catch {
      // mtime refresh is best-effort
    }
  }

  async log(event: LogEvent): Promise<void> {
    await mkdir(ntPath(this.dir), { recursive: true })
    const line = `${JSON.stringify({ ts: new Date().toISOString(), ...event })}\n`
    await appendFile(ntPath(this.logPath), line, "utf8")
  }

  /** Caller must hold the lock. */
  async expire(ttlDays: number): Promise<Gate[]> {
    const gates = await this.load(true)
    const cutoff = Date.now() - ttlDays * DAY_MS
    const expired = gates.filter((g) => Date.parse(g.lastSeen) < cutoff)
    if (expired.length === 0) return []
    this.gates = gates.filter((g) => Date.parse(g.lastSeen) >= cutoff)
    await this.save()
    return expired
  }

  async rotateLog(): Promise<void> {
    try {
      const info = await stat(ntPath(this.logPath))
      if (info.size < LOG_ROTATE_BYTES) return
      const raw = await readFile(ntPath(this.logPath), "utf8")
      const lines = raw.split("\n").filter((l) => l.trim() !== "")
      const kept = lines.slice(-LOG_ROTATE_KEEP_LINES)
      await writeFile(ntPath(this.logPath), `${kept.join("\n")}\n`, "utf8")
    } catch {
      // missing or unreadable log is fine
    }
  }
}

/**
 * Two-scope gate management: project-local gates live in the repo
 * (`.opencode/dejavu/`), cross-project agent habits are promoted to the
 * global store (`~/.config/opencode/dejavu/`).
 */
export class Stores {
  constructor(
    public readonly globalStore: GateStore,
    public readonly projectStore: GateStore | null,
  ) {}

  private scopes(): GateStore[] {
    return this.projectStore ? [this.projectStore, this.globalStore] : [this.globalStore]
  }

  /** True if a pattern with this key exists in any scope (chain attribution). */
  async hasKey(key: string): Promise<boolean> {
    for (const store of this.scopes()) {
      if ((await store.load()).some((g) => g.key === key)) return true
    }
    return false
  }

  /** Exact key match first (any status), then fuzzy near-duplicate over blocking gates. */
  async findGate(
    key: string,
    signature: string,
  ): Promise<{ gate: Gate; store: GateStore; via: "exact" | "fuzzy" } | null> {
    for (const store of this.scopes()) {
      const exact = (await store.load()).find((g) => g.key === key)
      if (exact) return { gate: exact, store, via: "exact" }
    }
    let best: { gate: Gate; store: GateStore; score: number } | null = null
    for (const store of this.scopes()) {
      for (const gate of await store.load()) {
        if (gate.status !== "blocking") continue
        if (!fuzzySimilar(signature, gate.signature)) continue
        const score = Math.abs(signature.length - gate.signature.length)
        if (best === null || score < best.score) best = { gate, store, score }
      }
    }
    return best === null ? null : { gate: best.gate, store: best.store, via: "fuzzy" }
  }

  /** All currently enforced gates, project scope first, highest-count first. */
  async blockingGates(): Promise<Gate[]> {
    const result: Gate[] = []
    for (const store of this.scopes()) {
      for (const gate of await store.load()) {
        if (gate.status === "blocking") result.push(gate)
      }
    }
    return result.sort((a, b) => b.count - a.count)
  }

  async logAll(event: LogEvent): Promise<void> {
    for (const store of this.scopes()) {
      await store.log(event)
    }
  }

  async expireAll(ttlDays: number): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const expired = await store.expire(ttlDays)
        for (const gate of expired) {
          await store.log({ type: "expired", key: gate.key, tool: gate.tool })
        }
      })
    }
  }

  async rotateLogs(): Promise<void> {
    for (const store of this.scopes()) {
      await store.rotateLog()
    }
  }

  /**
   * One-time (idempotent) schema/behavior migration:
   *  - probe-tool gates never block (they were learned under the old policy)
   *  - signatures and snippets are secret-scrubbed (cleans historical leaks)
   */
  async migrate(): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const gates = await store.load(true)
        let changed = false
        for (const gate of gates) {
          if (!canBlock(gate.tool, gate.signature) && gate.status === "blocking") {
            gate.status = "watching"
            changed = true
          }
          const signature = scrubSecrets(gate.signature)
          const snippet = scrubSecrets(gate.snippet)
          if (signature !== gate.signature) {
            gate.signature = signature
            changed = true
          }
          if (snippet !== gate.snippet) {
            gate.snippet = snippet
            changed = true
          }
        }
        if (changed) await store.save()
      })
    }
  }

  async recordFailure(input: {
    key: string
    signature: string
    tool: string
    sessionID: string
    projectDir: string
    snippet: string
    globalProjects: number
  }): Promise<{ gate: Gate; store: GateStore; promoted: boolean; wentGlobal: boolean }> {
    const now = new Date().toISOString()
    // Route to the store that already knows this key (cheap unlocked peek).
    let store = this.projectStore ?? this.globalStore
    if (!(await store.load()).some((g) => g.key === input.key)) {
      if ((await this.globalStore.load()).some((g) => g.key === input.key)) {
        store = this.globalStore
      }
    }

    return store.runLocked(async () => {
      const gates = await store.load(true)
      let gate = gates.find((g) => g.key === input.key)
      // Consolidation: same tool + near-duplicate signature merges into the
      // existing pattern instead of fragmenting ("gradlew :x:compiletestjava").
      if (!gate) {
        gate = gates.find((g) => g.tool === input.tool && fuzzySimilar(input.signature, g.signature))
      }
      if (!gate) {
        gate = {
          key: input.key,
          signature: scrubSecrets(input.signature),
          tool: input.tool,
          status: "watching",
          count: 0,
          sessions: [],
          projects: [],
          firstSeen: now,
          lastSeen: now,
          snippet: scrubSecrets(input.snippet),
          remindedCount: 0,
          blockedCount: 0,
          recurredAfterReminder: 0,
          recurredAfterGate: 0,
        }
        gates.push(gate)
      }

      gate.count += 1
      if (!gate.sessions.includes(input.sessionID)) gate.sessions.push(input.sessionID)
      if (gate.sessions.length > MAX_SESSIONS) gate.sessions = gate.sessions.slice(-MAX_SESSIONS)
      if (input.projectDir !== "" && !gate.projects.includes(input.projectDir)) {
        gate.projects.push(input.projectDir)
        if (gate.projects.length > MAX_PROJECTS) gate.projects = gate.projects.slice(-MAX_PROJECTS)
      }
      gate.lastSeen = now
      gate.snippet = scrubSecrets(input.snippet)

      let promoted = false
      const threshold = PROBE_TOOLS.has(input.tool) ? PROMOTE_COUNT_PROBE : PROMOTE_COUNT
      // Policy: only bash non-diagnostic commands may ever become gates.
      if (
        gate.status === "watching" &&
        canBlock(gate.tool, gate.signature) &&
        gate.count >= threshold &&
        gate.sessions.length >= PROMOTE_SESSIONS
      ) {
        gate.status = "blocking"
        promoted = true
      }

      await store.save()

      // Scope escalation: a pattern seen in enough distinct project directories
      // is an agent-level habit, not a repo quirk — move it to the global store.
      // Lock order is always project -> global, so no deadlock.
      let wentGlobal = false
      const moved = gate
      if (store !== this.globalStore && this.projectStore && gate.projects.length >= input.globalProjects) {
        const idx = gates.findIndex((g) => g.key === moved.key)
        if (idx >= 0) gates.splice(idx, 1)
        await store.save()
        await this.globalStore.runLocked(async () => {
          const globalGates = await this.globalStore.load(true)
          if (!globalGates.some((g) => g.key === moved.key)) globalGates.push(moved)
          await this.globalStore.save()
        })
        wentGlobal = true
      }

      return { gate: moved, store, promoted, wentGlobal }
    })
  }
}
