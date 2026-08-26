import { appendFile, mkdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { canBlock, canRemind, fuzzySimilar, FUZZY_MAX_LEN, isRepoLocal, scrubSecrets, suggestCorrection } from "./patterns"
import { coerceGateShape, repairGate } from "./validate"

/** Bumped on behavior changes; stamped into init log events so stale sessions are visible. */
export const PLUGIN_VERSION = "2.7.0"

export interface Gate {
  /** sha1 signature prefix — the pattern identity */
  key: string
  /** normalized call signature, e.g. "bash:npm install --legacy-peer-deps" */
  signature: string
  tool: string
  /** watching = collecting evidence; reminding = enforced as reminder only
   * (diagnostics — never block); blocking = reminder + hard block on repeat */
  status: "watching" | "reminding" | "blocking"
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
  /** consecutive successes after the gate was enforced — reaching HEAL_SUCCESSES
   * retires the gate to watching (the underlying command got fixed) */
  succeededAfterGate?: number
  /** flagged for manual review when the gate fires often but errors stopped */
  review?: boolean
  /** sessions currently reminded about this gate: sessionID -> remind time (ms).
   * Persisted on the gate so the remind→block chain survives process restarts
   * and is visible to every window serving the session. */
  remindedSessions?: Record<string, number>
  /** sessions that failed again after a reminder: sessionID -> fail time (ms).
   * Their next attempt blocks. Expires like remindedSessions — a stale block
   * with no live session is a leak, not enforcement. */
  failedSessions?: Record<string, number>
}

interface GatesFile {
  version: 1
  gates: Gate[]
}

/** Cross-project pattern index: which project dirs have seen each key. */
interface IndexEntry {
  projects: string[]
  lastSeen: string
}

interface IndexFile {
  version: 1
  keys: Record<string, IndexEntry>
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
  | "repaired"
  | "quarantined"
  | "degraded"
  | "retired-healed"
  | "healed"

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
/** the global log aggregates every project — rotate it later or forensics vanish in a day */
const GLOBAL_LOG_ROTATE_BYTES = 2048 * 1024
const LOG_ROTATE_KEEP_LINES = 1000
const DAY_MS = 24 * 60 * 60 * 1000
/** trust the loaded-gates cache this long without re-statting (hot path: every tool call) */
const LOAD_CACHE_TTL_MS = 1000

/** failures required before a pattern becomes an enforced gate */
export const PROMOTE_COUNT = 3
/** file-probe tools fail routinely during normal probing — higher bar, never block */
export const PROMOTE_COUNT_PROBE = 5
export const PROBE_TOOLS = new Set(["read", "glob", "grep", "write", "edit"])
/** distinct sessions required — same-session loops never promote */
export const PROMOTE_SESSIONS = 2
/** consecutive successes after a gate that retire it — the command is fixed,
 * so the gate must stop reminding (the ruff-check-false-positive case) */
export const HEAL_SUCCESSES = 3
/** store size bound: flooding with unique failures must not bloat gates.json
 * or slow the fuzzy scan — the weakest watching gate is evicted past this */
export const MAX_GATES = 2000

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
async function withLock<T>(lockTarget: string, fn: () => Promise<T>, onDegrade?: () => void): Promise<T> {
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
      if (Date.now() - started > LOCK_WAIT_MS) {
        // The only window where concurrent writes can lose updates — make it visible.
        if (onDegrade) onDegrade()
        break
      }
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
  /** hot-path caches: valid until LOAD_CACHE_TTL_MS / invalidated on mutation */
  private cacheUntilMs = 0
  private keyIndex: Map<string, Gate> | null = null
  private enforcedCache: Gate[] | null = null
  private index: IndexFile | null = null
  private indexMtimeMs = 0

  constructor(public readonly dir: string) {}

  private get gatesPath(): string {
    return join(this.dir, "gates.json")
  }

  private get logPath(): string {
    return join(this.dir, "log.jsonl")
  }

  private get indexPath(): string {
    return join(this.dir, "index.json")
  }

  /** Run a load→mutate→save section under the store's exclusive lock. */
  async runLocked<T>(fn: () => Promise<T>): Promise<T> {
    return withLock(this.gatesPath, fn, () => {
      this.log({ type: "degraded", key: "gates.lock", snippet: `lock contention exceeded ${LOCK_WAIT_MS}ms; critical section ran unlocked` }).catch(() => {})
    })
  }

  /**
   * force=true bypasses the mtime cache (always used inside locks).
   * Every record crosses the validation boundary: hopeless records are
   * dropped, repairable ones coerced — enforcement never sees raw state.
   */
  async load(force = false): Promise<Gate[]> {
    // TTL fast path: the hot path (every tool call) must not pay a stat per
    // call. Gates change rarely (promotion, manual edit); 1s staleness is
    // invisible to enforcement and our own saves refresh the cache directly.
    if (!force && this.gates !== null && Date.now() < this.cacheUntilMs) {
      return this.gates
    }
    try {
      const info = await stat(ntPath(this.gatesPath))
      if (!force && this.gates !== null && info.mtimeMs === this.mtimeMs) {
        this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
        return this.gates
      }
      const raw = await readFile(ntPath(this.gatesPath), "utf8")
      const parsed = JSON.parse(raw) as Partial<GatesFile>
      const records = Array.isArray(parsed.gates) ? parsed.gates : []
      const gates: Gate[] = []
      for (const record of records) {
        const gate = coerceGateShape(record)
        if (gate === null) continue
        repairGate(gate)
        gates.push(gate)
      }
      this.gates = gates
      this.keyIndex = new Map(gates.map((g) => [g.key, g]))
      this.enforcedCache = gates.filter((g) => g.status !== "watching")
      this.mtimeMs = info.mtimeMs
      this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
      return this.gates
    } catch {
      // missing or unreadable gates.json — treat as an empty store
      if (this.gates === null) {
        this.gates = []
        this.keyIndex = new Map()
        this.enforcedCache = []
      }
      this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
      return this.gates
    }
  }

  /** O(1) exact lookup over the cached gates (call load() first to refresh). */
  byKey(key: string): Gate | undefined {
    if (this.keyIndex === null) {
      this.keyIndex = new Map((this.gates ?? []).map((g) => [g.key, g]))
    }
    return this.keyIndex.get(key)
  }

  /** Cached enforced subset (blocking + reminding) — the fuzzy scan iterates this, not all gates. */
  enforcedOnly(): Gate[] {
    if (this.enforcedCache === null) {
      this.enforcedCache = (this.gates ?? []).filter((g) => g.status !== "watching")
    }
    return this.enforcedCache
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
    // We know the content we just wrote — refresh the TTL cache directly.
    // (keyIndex/enforcedCache hold references into this.gates, still valid.)
    this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
  }

  /** Cross-project pattern index; meaningful only on the global store. */
  async loadIndex(force = false): Promise<IndexFile> {
    try {
      const info = await stat(ntPath(this.indexPath))
      if (!force && this.index !== null && info.mtimeMs === this.indexMtimeMs) {
        return this.index
      }
      const raw = await readFile(ntPath(this.indexPath), "utf8")
      const parsed = JSON.parse(raw) as Partial<IndexFile>
      const keys = parsed.keys
      this.index = { version: 1, keys: keys !== null && typeof keys === "object" ? keys : {} }
      this.indexMtimeMs = info.mtimeMs
      return this.index
    } catch {
      // missing or unreadable index — treat as empty
      if (this.index === null) this.index = { version: 1, keys: {} }
      return this.index
    }
  }

  async saveIndex(): Promise<void> {
    if (this.index === null) return
    await mkdir(ntPath(this.dir), { recursive: true })
    await atomicWrite(this.indexPath, `${JSON.stringify(this.index, null, 2)}\n`)
    try {
      this.indexMtimeMs = (await stat(ntPath(this.indexPath))).mtimeMs
    } catch {
      // mtime refresh is best-effort
    }
  }

  /** Run an index load→mutate→save section under the index's own lock. */
  async runLockedIndex<T>(fn: () => Promise<T>): Promise<T> {
    return withLock(this.indexPath, fn, () => {
      this.log({ type: "degraded", key: "index.lock", snippet: `lock contention exceeded ${LOCK_WAIT_MS}ms; critical section ran unlocked` }).catch(() => {})
    })
  }

  /**
   * Append under the log lock: every OpenCode window shares the global log,
   * and unlocked concurrent appends interleave into broken JSON lines.
   */
  async log(event: LogEvent): Promise<void> {
    await withLock(this.logPath, async () => {
      await mkdir(ntPath(this.dir), { recursive: true })
      const line = `${JSON.stringify({ ts: new Date().toISOString(), ...event })}\n`
      await appendFile(ntPath(this.logPath), line, "utf8")
    })
  }

  /**
   * Caller must hold the lock. Weak one-off patterns (below the promotion
   * threshold, never enforced) rot faster than proven ones — a pattern that
   * never recurred enough to matter is noise, not memory.
   */
  async expire(ttlDays: number, noiseTtlDays: number): Promise<Gate[]> {
    const gates = await this.load(true)
    const now = Date.now()
    const expired = gates.filter((g) => {
      const ttl = g.status !== "watching" || g.count >= PROMOTE_COUNT ? ttlDays : noiseTtlDays
      return Date.parse(g.lastSeen) < now - ttl * DAY_MS
    })
    if (expired.length === 0) return []
    const expiredKeys = new Set(expired.map((g) => g.key))
    this.gates = gates.filter((g) => !expiredKeys.has(g.key))
    this.keyIndex = null
    this.enforcedCache = null
    await this.save()
    return expired
  }

  /** Remove gates by key; caller must hold the lock. Returns the removed gates. */
  extract(keys: Set<string>): Gate[] {
    if (this.gates === null) return []
    const removed = this.gates.filter((g) => keys.has(g.key))
    if (removed.length > 0) {
      this.gates = this.gates.filter((g) => !keys.has(g.key))
      this.keyIndex = null
      this.enforcedCache = null
    }
    return removed
  }

  async rotateLog(rotateBytes: number = LOG_ROTATE_BYTES): Promise<void> {
    await withLock(this.logPath, async () => {
      try {
        const info = await stat(ntPath(this.logPath))
        if (info.size < rotateBytes) return
        const raw = await readFile(ntPath(this.logPath), "utf8")
        const lines = raw.split("\n").filter((l) => l.trim() !== "")
        const kept = lines.slice(-LOG_ROTATE_KEEP_LINES)
        await atomicWrite(this.logPath, `${kept.join("\n")}\n`)
      } catch {
        // missing or unreadable log is fine
      }
    })
  }

  /**
   * Structural self-healing (idempotent): unparseable gates.json is
   * quarantined with its bytes preserved; parseable records are coerced,
   * repaired and deduped; unparseable log lines are excised to
   * log.jsonl.corrupt. Every repair is logged — healing must be visible.
   */
  async reconcile(): Promise<void> {
    await withLock(this.gatesPath, async () => {
      let raw: string | null = null
      try {
        raw = await readFile(ntPath(this.gatesPath), "utf8")
      } catch {
        // no gates file yet — nothing structural to heal
      }
      if (raw !== null && raw.trim() !== "") {
        let parsed: Partial<GatesFile> | null = null
        try {
          parsed = JSON.parse(raw) as Partial<GatesFile>
        } catch {
          parsed = null
        }
        if (parsed === null || typeof parsed !== "object" || !Array.isArray(parsed.gates)) {
          // SQLite-style quarantine: move aside, keep the bytes, start clean.
          // Scrub before preserving — raw bytes may carry unredacted secrets.
          const quarantine = `${this.gatesPath}.corrupt-${Date.now()}`
          try {
            await writeFile(ntPath(quarantine), scrubSecrets(raw), "utf8")
            await unlink(ntPath(this.gatesPath))
            this.gates = []
            this.keyIndex = null
            this.enforcedCache = null
            this.mtimeMs = 0
            await this.save()
            await this.log({ type: "quarantined", key: "gates.json", snippet: `unparseable gates file quarantined (scrubbed) to ${quarantine}` })
          } catch {
            // quarantine failed — next reconcile retries; never destroy the file
          }
        } else {
          let dropped = 0
          let repaired = 0
          const byKey = new Map<string, Gate>()
          for (const record of parsed.gates) {
            const gate = coerceGateShape(record)
            if (gate === null) {
              dropped += 1
              continue
            }
            if (repairGate(gate)) repaired += 1
            const existing = byKey.get(gate.key)
            if (existing) {
              mergeGate(existing, gate)
            } else {
              byKey.set(gate.key, gate)
            }
          }
          const merged = parsed.gates.length - dropped - byKey.size
          this.gates = [...byKey.values()]
          this.mtimeMs = 0
          await this.save()
          if (dropped > 0 || repaired > 0 || merged > 0) {
            await this.log({
              type: "repaired",
              key: "gates.json",
              snippet: `dropped ${dropped} hopeless record(s), repaired ${repaired}, merged ${merged} duplicate key(s)`,
            })
          }
        }
      }
      await this.exciseCorruptLogLines()
    })
  }

  /** Move unparseable JSONL lines to log.jsonl.corrupt; good lines stay. */
  private async exciseCorruptLogLines(): Promise<void> {
    let raw: string
    try {
      raw = await readFile(ntPath(this.logPath), "utf8")
    } catch {
      return // no log yet
    }
    const good: string[] = []
    const bad: string[] = []
    for (const line of raw.split("\n")) {
      if (line.trim() === "") continue
      try {
        JSON.parse(line)
        good.push(line)
      } catch {
        bad.push(line)
      }
    }
    if (bad.length === 0) return
    await withLock(this.logPath, async () => {
      // Scrub: excised raw lines may carry unredacted secrets.
      await appendFile(ntPath(`${this.logPath}.corrupt`), `${scrubSecrets(bad.join("\n"))}\n`, "utf8")
      await atomicWrite(this.logPath, good.length > 0 ? `${good.join("\n")}\n` : "")
    })
    await this.log({ type: "repaired", key: "log.jsonl", snippet: `excised ${bad.length} corrupt line(s) to log.jsonl.corrupt` })
  }
}

/** Merge a gate's accumulated evidence into an existing gate with the same key. */
export function mergeGate(target: Gate, source: Gate): void {
  // blocking is the stronger state — a merge must never demote an enforced gate
  if (source.status === "blocking") target.status = "blocking"
  target.count += source.count
  for (const session of source.sessions) {
    if (!target.sessions.includes(session)) target.sessions.push(session)
  }
  if (target.sessions.length > MAX_SESSIONS) target.sessions = target.sessions.slice(-MAX_SESSIONS)
  for (const project of source.projects) {
    if (!target.projects.includes(project)) target.projects.push(project)
  }
  if (target.projects.length > MAX_PROJECTS) target.projects = target.projects.slice(-MAX_PROJECTS)
  if (source.firstSeen < target.firstSeen) target.firstSeen = source.firstSeen
  if (source.lastSeen > target.lastSeen) {
    target.lastSeen = source.lastSeen
    target.snippet = source.snippet
  }
  target.remindedCount += source.remindedCount
  target.blockedCount += source.blockedCount
  target.recurredAfterReminder += source.recurredAfterReminder
  target.recurredAfterGate += source.recurredAfterGate
  if (target.correction === undefined && source.correction !== undefined) target.correction = source.correction
  if (source.review === true) target.review = true
  // Session enforcement state must survive merges — dropping it silently
  // resets the remind→block chain on every escalation/dedupe.
  if (source.remindedSessions !== undefined) {
    if (target.remindedSessions === undefined) target.remindedSessions = {}
    for (const session of Object.keys(source.remindedSessions)) {
      const at = source.remindedSessions[session] ?? 0
      const existing = target.remindedSessions[session]
      if (existing === undefined || at > existing) target.remindedSessions[session] = at
    }
  }
  if (source.failedSessions !== undefined) {
    if (target.failedSessions === undefined) target.failedSessions = {}
    for (const session of Object.keys(source.failedSessions)) {
      const at = source.failedSessions[session] ?? 0
      const existing = target.failedSessions[session]
      if (existing === undefined || at > existing) target.failedSessions[session] = at
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
      await store.load()
      if (store.byKey(key) !== undefined) return true
    }
    return false
  }

  /** Exact key match first (any status), then fuzzy near-duplicate over blocking gates. */
  async findGate(
    key: string,
    signature: string,
  ): Promise<{ gate: Gate; store: GateStore; via: "exact" | "fuzzy" } | null> {
    for (const store of this.scopes()) {
      await store.load()
      const exact = store.byKey(key)
      if (exact) return { gate: exact, store, via: "exact" }
    }
    // Over-long signatures match exactly only — see FUZZY_MAX_LEN.
    if (signature.length > FUZZY_MAX_LEN) return null
    let best: { gate: Gate; store: GateStore; score: number } | null = null
    for (const store of this.scopes()) {
      for (const gate of store.enforcedOnly()) {
        if (!fuzzySimilar(signature, gate.signature)) continue
        const score = Math.abs(signature.length - gate.signature.length)
        if (best === null || score < best.score) best = { gate, store, score }
      }
    }
    return best === null ? null : { gate: best.gate, store: best.store, via: "fuzzy" }
  }

  /** All currently enforced gates (blocking + reminding), project scope first, highest-count first. */
  async enforcedGates(): Promise<Gate[]> {
    const result: Gate[] = []
    for (const store of this.scopes()) {
      await store.load()
      for (const gate of store.enforcedOnly()) result.push(gate)
    }
    return result.sort((a, b) => b.count - a.count)
  }

  async logAll(event: LogEvent): Promise<void> {
    for (const store of this.scopes()) {
      await store.log(event)
    }
  }

  async expireAll(ttlDays: number, noiseTtlDays: number): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const expired = await store.expire(ttlDays, noiseTtlDays)
        for (const gate of expired) {
          // Correction lifecycle: a corrected gate that never recurred after
          // promotion means the pattern died out — the mechanical signal that
          // the teaching worked.
          if (gate.correction !== undefined && gate.recurredAfterGate === 0) {
            await store.log({ type: "retired-healed", key: gate.key, tool: gate.tool, snippet: gate.correction.slice(0, 200) })
          } else {
            await store.log({ type: "expired", key: gate.key, tool: gate.tool })
          }
        }
      })
    }
    // The cross-project index rots on the same schedule as the gates.
    await this.globalStore.runLockedIndex(async () => {
      const index = await this.globalStore.loadIndex(true)
      const cutoff = Date.now() - ttlDays * DAY_MS
      let changed = false
      for (const key of Object.keys(index.keys)) {
        const entry = index.keys[key]
        if (entry && Date.parse(entry.lastSeen) < cutoff) {
          delete index.keys[key]
          changed = true
        }
      }
      if (changed) await this.globalStore.saveIndex()
    })
  }

  async rotateLogs(): Promise<void> {
    for (const store of this.scopes()) {
      // The global log aggregates every project — give it more room.
      await store.rotateLog(store === this.globalStore ? GLOBAL_LOG_ROTATE_BYTES : LOG_ROTATE_BYTES)
    }
  }

  /** Forget per-session enforcement state when a session dies. */
  async forgetSession(sessionID: string): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const gates = await store.load(true)
        let changed = false
        for (const gate of gates) {
          if (gate.remindedSessions && gate.remindedSessions[sessionID] !== undefined) {
            delete gate.remindedSessions[sessionID]
            if (Object.keys(gate.remindedSessions).length === 0) delete gate.remindedSessions
            changed = true
          }
          if (gate.failedSessions !== undefined && gate.failedSessions[sessionID] !== undefined) {
            delete gate.failedSessions[sessionID]
            if (Object.keys(gate.failedSessions).length === 0) delete gate.failedSessions
            changed = true
          }
        }
        if (changed) await store.save()
      })
    }
  }

  /**
   * One-time (idempotent) schema/behavior migration:
   *  - probe-tool gates never block (they were learned under the old policy)
   *  - signatures and snippets are secret-scrubbed (cleans historical leaks)
   *  - project copies of already-global keys merge into the global gate
   */
  async migrate(): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const gates = await store.load(true)
        let changed = false
        for (const gate of gates) {
          if (gate.status === "blocking" && !canBlock(gate.tool, gate.signature)) {
            // Over-blocking learned under an older policy: keep the signal if
            // the shape can at least remind (diagnostics), else drop to watching.
            gate.status = canRemind(gate.tool, gate.signature) ? "reminding" : "watching"
            changed = true
          }
          if (gate.status === "reminding" && !canRemind(gate.tool, gate.signature)) {
            gate.status = "watching"
            changed = true
          }
          if (
            gate.status === "watching" &&
            canRemind(gate.tool, gate.signature) &&
            gate.count >= PROMOTE_COUNT &&
            gate.sessions.length >= PROMOTE_SESSIONS
          ) {
            // Recurring diagnostics already proven under the old policy start
            // reminding immediately instead of waiting for the next failure.
            gate.status = "reminding"
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
          if (gate.correction !== undefined) {
            const correction = scrubSecrets(gate.correction)
            if (correction !== gate.correction) {
              gate.correction = correction
              changed = true
            }
          }
          // Backfill: an enforced gate with no correction gets a mechanical
          // default so it teaches immediately instead of sitting "NOT TEACHING".
          if (gate.status !== "watching" && gate.correction === undefined) {
            gate.correction = suggestCorrection(gate.signature, gate.snippet)
            changed = true
          }
        }
        if (changed) await store.save()
      })
    }

    // A key that reached the global store is global everywhere: merge any
    // leftover project-local copy into the global gate so evidence does not
    // fragment across scopes (stale local copies kept enforcing from the old
    // scope while the global gate starved).
    const projectStore = this.projectStore
    if (projectStore) {
      await projectStore.runLocked(async () => {
        const projGates = await projectStore.load(true)
        const globalKeys = new Set((await this.globalStore.load()).map((g) => g.key))
        const dupes = projGates.filter((g) => globalKeys.has(g.key))
        if (dupes.length === 0) return
        await this.globalStore.runLocked(async () => {
          const globalGates = await this.globalStore.load(true)
          for (const dupe of dupes) {
            const target = globalGates.find((g) => g.key === dupe.key)
            if (target) {
              mergeGate(target, dupe)
            } else {
              globalGates.push(dupe)
            }
          }
          await this.globalStore.save()
        })
        projectStore.extract(new Set(dupes.map((g) => g.key)))
        await projectStore.save()
      })
    }
  }

  /**
   * Structural self-healing across both scopes plus index reconciliation.
   * Idempotent; runs at plugin init and via `doctor --repair`.
   */
  async reconcileAll(globalProjects = 2): Promise<void> {
    for (const store of this.scopes()) {
      await store.reconcile()
    }

    // Index-driven escalation healing: a key proven in enough project dirs
    // belongs in the global store even if recordFailure never moved it
    // (racing instances, or stores that predate the index).
    const projectStore = this.projectStore
    if (projectStore) {
      const index = await this.globalStore.loadIndex()
      const toEscalate = (await projectStore.load(true)).filter((g) => {
        const entry = index.keys[g.key]
        return entry !== undefined && entry.projects.length >= globalProjects && !isRepoLocal(g.signature)
      })
      if (toEscalate.length > 0) {
        await projectStore.runLocked(async () => {
          await this.globalStore.runLocked(async () => {
            const globalGates = await this.globalStore.load(true)
            for (const gate of toEscalate) {
              const target = globalGates.find((g) => g.key === gate.key)
              if (target) {
                mergeGate(target, gate)
              } else {
                globalGates.push(gate)
              }
            }
            await this.globalStore.save()
          })
          projectStore.extract(new Set(toEscalate.map((g) => g.key)))
          await projectStore.save()
        })
        await this.globalStore.log({
          type: "repaired",
          key: "index.json",
          snippet: `escalated ${toEscalate.length} gate(s) proven in ${globalProjects}+ project dirs`,
        })
      }
    }

    // The index must mirror reality: a key absent from every scope is an
    // orphan (its gate expired or was deleted); a global gate missing from
    // the index loses cross-project history. Heal both directions.
    const knownKeys = new Set<string>()
    for (const store of this.scopes()) {
      for (const gate of await store.load(true)) knownKeys.add(gate.key)
    }
    await this.globalStore.runLockedIndex(async () => {
      const index = await this.globalStore.loadIndex(true)
      let pruned = 0
      for (const key of Object.keys(index.keys)) {
        const entry = index.keys[key]
        // Young entries may belong to a promotion in flight in another window
        // (its gates were snapshotted after this key was written) — only prune
        // orphans that have been stale for a day.
        if (entry && !knownKeys.has(key) && Date.now() - Date.parse(entry.lastSeen) > DAY_MS) {
          delete index.keys[key]
          pruned += 1
        }
      }
      let rebuilt = 0
      for (const gate of await this.globalStore.load(true)) {
        if (!index.keys[gate.key]) {
          index.keys[gate.key] = { projects: [...gate.projects], lastSeen: gate.lastSeen }
          rebuilt += 1
        }
      }
      if (pruned > 0 || rebuilt > 0) {
        await this.globalStore.saveIndex()
        await this.globalStore.log({
          type: "repaired",
          key: "index.json",
          snippet: `pruned ${pruned} orphan key(s), rebuilt ${rebuilt} missing entr(y/ies)`,
        })
      }
    })
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
      let fuzzyConsolidated = false
      // Consolidation: same tool + near-duplicate signature merges into the
      // existing pattern instead of fragmenting ("gradlew :x:compiletestjava").
      if (!gate) {
        // Prefer the gate this session was already reminded about: the
        // before-hook enforced from it, so the failure must land there too —
        // otherwise the remind→block chain desyncs between the hooks.
        const fuzzyMatches = gates.filter((g) => g.tool === input.tool && fuzzySimilar(input.signature, g.signature))
        gate = fuzzyMatches.find((g) => g.remindedSessions?.[input.sessionID] !== undefined) ?? fuzzyMatches[0]
        if (gate !== undefined) fuzzyConsolidated = true
      }
      if (!gate) {
        // Flood guard: unique-failure spam must not grow the store unbounded.
        if (gates.length >= MAX_GATES) {
          let victimIdx = -1
          for (let i = 0; i < gates.length; i++) {
            const candidate = gates[i]
            if (candidate === undefined || candidate.status !== "watching") continue
            const victim = victimIdx >= 0 ? gates[victimIdx] : undefined
            if (victim === undefined || candidate.count < victim.count || (candidate.count === victim.count && candidate.lastSeen < victim.lastSeen)) {
              victimIdx = i
            }
          }
          if (victimIdx < 0) {
            // Every gate is enforced — do not create; degrade gracefully with
            // an ephemeral gate that is never persisted.
            const ephemeral: Gate = {
              key: input.key,
              signature: scrubSecrets(input.signature),
              tool: input.tool,
              status: "watching",
              count: 1,
              sessions: [input.sessionID],
              projects: input.projectDir !== "" ? [input.projectDir] : [],
              firstSeen: now,
              lastSeen: now,
              snippet: scrubSecrets(input.snippet),
              remindedCount: 0,
              blockedCount: 0,
              recurredAfterReminder: 0,
              recurredAfterGate: 0,
            }
            return { gate: ephemeral, store, promoted: false, wentGlobal: false }
          }
          gates.splice(victimIdx, 1)
        }
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
      // Only an exact-key failure updates the evidence: a crafted near-duplicate
      // must not overwrite a legitimate gate's snippet via fuzzy consolidation.
      if (!fuzzyConsolidated) gate.snippet = scrubSecrets(input.snippet)
      // A failure breaks any heal streak — the command is still broken.
      gate.succeededAfterGate = 0

      let promoted = false
      const threshold = PROBE_TOOLS.has(input.tool) ? PROMOTE_COUNT_PROBE : PROMOTE_COUNT
      // Policy: non-diagnostic bash may hard-block; diagnostics promote to
      // remind-only (they never block — see canRemind). Everything else stays watching.
      if (gate.status === "watching" && gate.count >= threshold && gate.sessions.length >= PROMOTE_SESSIONS) {
        if (canBlock(gate.tool, gate.signature)) {
          gate.status = "blocking"
          promoted = true
        } else if (canRemind(gate.tool, gate.signature)) {
          gate.status = "reminding"
          promoted = true
        }
        // A promoted gate always ships with SOME teaching text (mechanical
        // default, overridable) so it never sits "NOT TEACHING" awaiting a human.
        if (promoted && gate.correction === undefined) {
          gate.correction = suggestCorrection(gate.signature, gate.snippet)
        }
      }

      await store.save()

      // Cross-project evidence lives in the global index: gate.projects only
      // ever sees its own store's directory, so alone it can never reach two
      // projects. A pattern seen in enough distinct project dirs is an
      // agent-level habit, not a repo quirk — move it to the global store.
      // Keyed by the gate's OWN key (post fuzzy-consolidation), not the raw
      // failure key — otherwise consolidated failures index a key that has no
      // gate, orphaning the entry and starving the gate's escalation.
      // Lock order is always gates -> index and project -> global: no cycles.
      const moved = gate
      const indexProjects = await this.globalStore.runLockedIndex(async () => {
        const index = await this.globalStore.loadIndex(true)
        let entry = index.keys[moved.key]
        if (!entry) {
          entry = { projects: [], lastSeen: now }
          index.keys[moved.key] = entry
        }
        if (input.projectDir !== "" && !entry.projects.includes(input.projectDir)) {
          entry.projects.push(input.projectDir)
          if (entry.projects.length > MAX_PROJECTS) entry.projects = entry.projects.slice(-MAX_PROJECTS)
        }
        entry.lastSeen = now
        await this.globalStore.saveIndex()
        return entry.projects.length
      })

      let wentGlobal = false
      // Repo-local verbs (npm/git/gradle/...) never escalate: their failures are
      // repo quirks, not agent habits — escalating them would let a broken
      // `npm install` in one project block every other project.
      if (
        store !== this.globalStore &&
        this.projectStore &&
        indexProjects >= input.globalProjects &&
        !isRepoLocal(moved.signature)
      ) {
        // Global FIRST, then remove the local copy: a crash between the two
        // writes must leave a duplicate (healed by migrate), never a hole.
        await this.globalStore.runLocked(async () => {
          const globalGates = await this.globalStore.load(true)
          const existing = globalGates.find((g) => g.key === moved.key)
          if (existing) {
            mergeGate(existing, moved)
          } else {
            globalGates.push(moved)
          }
          await this.globalStore.save()
        })
        const idx = gates.findIndex((g) => g.key === moved.key)
        if (idx >= 0) gates.splice(idx, 1)
        await store.save()
        wentGlobal = true
      }

      return { gate: moved, store, promoted, wentGlobal }
    })
  }

  /**
   * A SUCCESS matching an enforced gate is evidence the underlying command got
   * fixed. Track a streak; once it reaches HEAL_SUCCESSES the gate retires to
   * watching so it stops reminding on a now-healthy command (the
   * `ruff check .` false-positive case). Only enforced (blocking/reminding)
   * gates heal; a failure resets the streak in recordFailure.
   */
  async recordSuccess(input: { key: string; signature: string; tool: string }): Promise<void> {
    const match = await this.findGate(input.key, input.signature)
    if (match === null || match.gate.status === "watching") return
    const store = match.store
    const gateKey = match.gate.key
    await store.runLocked(async () => {
      const fresh = (await store.load(true)).find((g) => g.key === gateKey)
      if (fresh === undefined || fresh.status === "watching") return
      fresh.succeededAfterGate = (fresh.succeededAfterGate ?? 0) + 1
      const healed = fresh.succeededAfterGate >= HEAL_SUCCESSES
      if (healed) fresh.status = "watching"
      await store.save()
      if (healed) {
        await store.log({
          type: "healed",
          key: fresh.key,
          tool: fresh.tool,
          snippet: `succeeded ${fresh.succeededAfterGate}x in a row after the gate — retired to watching`,
        })
      }
    })
  }
}
