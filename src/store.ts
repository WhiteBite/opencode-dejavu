import { existsSync } from "node:fs"
import { appendFile, mkdir, readFile, rename, stat, unlink, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { canBlock, canRemind, fuzzySimilar, FUZZY_MAX_LEN, hasResidualIdentity, isRepoLocal, sanitizeForStore, scrubSecrets, suggestCorrection } from "./patterns"
import { coerceGateShape, repairGate } from "./validate"

/** Bumped on behavior changes; stamped into init log events so stale sessions are visible. */
export const PLUGIN_VERSION = "2.17.0"

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
  /** explicit bypasses (dejavu:proceed) against this gate — negative feedback:
   * a gate the agent keeps overriding is friction, not teaching */
  overrideCount: number
  /** demoted once by behavioral feedback (recurrences/overrides). Such gates
   * never re-promote mechanically — a human re-enforces by clearing the flag */
  feedbackDemoted?: boolean
  /** counters at the moment of feedback demotion. A human re-enforcement
   * (status set back to enforced) must get a FRESH grace window — without the
   * baseline, the stale counters would re-demotion on the very next failure */
  feedbackBaseline?: { recurred: number; overrides: number }
  /** consecutive successes after the gate was enforced — reaching HEAL_SUCCESSES
   * retires the gate to watching (the underlying command got fixed) */
  succeededAfterGate?: number
  /** count at the moment the gate retired (healed or taught). `count`/`sessions`
   * are lifetime-cumulative, so without damping a retired gate re-promoted on the
   * VERY NEXT single failure (promote→heal→promote oscillation). Re-promotion now
   * requires a full fresh bar: `count - retireBaseline.count >= threshold`. */
  retireBaseline?: { count: number }
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
  /** distinct sessions that reoffended AFTER being reminded (capped). The
   * demotion vote counts only failures the gate had a chance to prevent —
   * first-encounter failures never saw a reminder and must not demote. */
  reoffenseSessions?: string[]
}

interface GatesFile {
  version: 1
  gates: Gate[]
  /** PLUGIN_VERSION that last ran migrate() on this file — lets subsequent
   * starts skip the full per-gate scan (init storm killer) */
  migrated?: string
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
  | "demoted"
  | "init"
  | "repaired"
  | "quarantined"
  | "degraded"
  | "retired-healed"
  | "retired-taught"
  | "healed"

/** Events that change what the machine remembers — the only ones worth the
 * global log lock (the most-contended lock, shared by every window of every
 * project). High-volume events (detected/reminded/blocked/retry-allowed/
 * recurred-after-gate) stay in the project log only. */
const GLOBAL_LOG_EVENTS = new Set<LogEventType>([
  "init",
  "promoted",
  "demoted",
  "healed",
  "retired-healed",
  "retired-taught",
  "override",
])

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

export const MAX_SESSIONS = 50
const MAX_PROJECTS = 20
const LOG_ROTATE_BYTES = 512 * 1024
/** the global log aggregates every project — rotate it later or forensics vanish in a day */
const GLOBAL_LOG_ROTATE_BYTES = 2048 * 1024
const LOG_ROTATE_KEEP_LINES = 1000
const DAY_MS = 24 * 60 * 60 * 1000
/** trust the loaded-gates cache this long without re-statting (hot path: every tool call) */
const LOAD_CACHE_TTL_MS = 1000

/** distinct project dirs in the global index before a pattern escalates to
 * the global store (agent-level habit, not a repo quirk) */
export const GLOBAL_PROJECTS = 2
/** gates expire when the pattern has not recurred for this many days */
export const TTL_DAYS = 60
/** weak one-off patterns (below promotion threshold, never enforced) rot this fast */
export const NOISE_TTL_DAYS = 7
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
/** enforcement feedback: an enforced gate whose pattern fails this many times
 * AFTER promotion is not teaching (iteration or a useless correction) —
 * demote it instead of nagging/blocking forever */
export const DEMOTE_RECURRENCES = 3
/** enforcement feedback: this many explicit bypasses mean the agent considers
 * the gate friction — demote it regardless of recurrence */
export const DEMOTE_OVERRIDES = 5
/** recurrence demotion additionally requires this many DISTINCT sessions that
 * reoffended after a reminder — one bad session (or one bad model in a shared
 * store) must not be able to demote a gate for everyone else */
export const DEMOTE_REOFFENSE_SESSIONS = 2

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
 * Stealing is pid-liveness-gated and reported via onSteal.
 */
async function withLock<T>(
  lockTarget: string,
  fn: () => Promise<T>,
  onDegrade?: () => void,
  onSteal?: (heldMs: number, previousPid: string) => void,
): Promise<T> {
  const lock = `${lockTarget}.lock`
  await mkdir(ntPath(dirname(lock)), { recursive: true })
  const started = Date.now()
  let acquired = false
  for (;;) {
    try {
      await writeFile(ntPath(lock), String(process.pid), { flag: "wx" })
      acquired = true
      break
    } catch (error) {
      const code = (error as { code?: string }).code ?? ""
      if (code !== "EEXIST") throw error
      try {
        const info = await stat(ntPath(lock))
        if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
          // Steal only if the recorded holder is dead: a live holder may
          // simply be slow (>5s critical section), and stealing from it
          // opens the critical section to concurrent entry — the residual
          // corruption window. ESRCH = dead; EPERM = alive but not ours.
          let holderPid = ""
          try {
            holderPid = ((await readFile(ntPath(lock), "utf8")) ?? "").trim()
          } catch {
            // unreadable lockfile — treat as stealable
          }
          let holderAlive = false
          const holderPidNum = Number(holderPid)
          if (holderPid !== "" && Number.isFinite(holderPidNum) && holderPidNum > 0) {
            if (holderPidNum === process.pid) {
              // Same-process holder (another async context / window in this
              // process) always releases via finally — wait for it, never steal
              // (stealing from ourselves breaks in-process serialization).
              holderAlive = true
            } else {
              try {
                process.kill(holderPidNum, 0)
                holderAlive = true
              } catch (killError) {
                // ESRCH = dead; EPERM/other = alive but not signalable by us
                holderAlive = (killError as { code?: string }).code !== "ESRCH"
              }
            }
          }
          if (!holderAlive) {
            await unlink(ntPath(lock)).catch(() => {})
            if (onSteal) onSteal(Date.now() - info.mtimeMs, holderPid)
            continue
          }
          // live slow holder — fall through to the timeout check
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
    // A degraded waiter never owned the lock — unlinking it would delete the
    // LIVE holder's lockfile and let a third process enter the critical
    // section concurrently (the corruption seen in production logs).
    // Even a legitimate holder must verify ownership: if a stale-steal gave
    // the lock away mid-hold, unlinking would delete the STEALER's lockfile.
    if (acquired) {
      try {
        const owner = await readFile(ntPath(lock), "utf8").catch(() => "")
        if (owner === String(process.pid)) await unlink(ntPath(lock))
      } catch {
        // best effort
      }
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
  /** PLUGIN_VERSION that last ran migrate() — persisted in gates.json so the
   * 2nd..Nth start of the same version skips the full per-gate scan */
  private migratedStamp: string | null = null
  /** events queued inside the gates lock, flushed on the next log() — logging
   * under the gates lock extends the critical section into degrade storms */
  private deferredEvents: LogEvent[] = []
  /** Set by Stores on the PROJECT store → the global store. Deferred events
   * bypass logAll's routing, so a salient event deferred on the project store
   * (demoted in migrate, retired-healed in expireAll) would never reach the
   * global forensics; on flush/log the salient subset of the drained batch is
   * mirrored here. Direct (non-deferred) events are NOT mirrored — logAll
   * already routes those, so mirroring them would double-write. */
  routeSalientTo: GateStore | null = null

  constructor(public readonly dir: string) {}

  /** PLUGIN_VERSION that last ran migrate() on this store (null = never). */
  get migratedVersion(): string | null {
    return this.migratedStamp
  }

  /** Set the migration stamp (persisted by the next save()). */
  set migratedVersion(version: string | null) {
    this.migratedStamp = version
  }

  /** Queue an event while holding the gates lock; the next log() flushes it. */
  deferEvent(event: LogEvent): void {
    this.deferredEvents.push(event)
  }

  /**
   * Flush queued deferred events now. Scripts (doctor, migrate) repair stores
   * and then exit without any further log() call — without this, the deferred
   * repaired/quarantined/demoted/expired events are silently lost, breaking
   * the "every repair is logged" invariant. No-op when the queue is empty.
   */
  async flushDeferred(): Promise<void> {
    if (this.deferredEvents.length === 0) return
    let salient: LogEvent[] = []
    await withLock(this.logPath, async () => {
      if (this.deferredEvents.length === 0) return
      const batch = this.deferredEvents
      this.deferredEvents = []
      if (this.routeSalientTo !== null) salient = batch.filter((e) => GLOBAL_LOG_EVENTS.has(e.type))
      await mkdir(ntPath(this.dir), { recursive: true })
      for (const e of batch) {
        const line = `${JSON.stringify({ ts: new Date().toISOString(), ...e })}\n`
        await appendFile(ntPath(this.logPath), line, "utf8")
      }
    })
    if (salient.length > 0 && this.routeSalientTo !== null) await this.routeSalientTo.appendBatch(salient)
  }

  /** Append an already-formed batch of events under the log lock. Used by a peer
   * store mirroring its salient deferred events into the global forensics — the
   * batch is fully captured before this runs, so nothing here can be lost. */
  async appendBatch(events: LogEvent[]): Promise<void> {
    if (events.length === 0) return
    await withLock(this.logPath, async () => {
      await mkdir(ntPath(this.dir), { recursive: true })
      for (const e of events) {
        const line = `${JSON.stringify({ ts: new Date().toISOString(), ...e })}\n`
        await appendFile(ntPath(this.logPath), line, "utf8")
      }
    })
  }

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
    return withLock(
      this.gatesPath,
      fn,
      () => {
        this.deferEvent({ type: "degraded", key: "gates.lock", snippet: `lock contention exceeded ${LOCK_WAIT_MS}ms; critical section ran unlocked` })
      },
      (heldMs, previousPid) => {
        this.deferEvent({ type: "repaired", key: "gates.lock", snippet: `stale lock stolen (held ${heldMs}ms, previous pid ${previousPid || "?"})` })
      },
    )
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
    let info: Awaited<ReturnType<typeof stat>>
    let raw: string
    try {
      info = await stat(ntPath(this.gatesPath))
      if (!force && this.gates !== null && info.mtimeMs === this.mtimeMs) {
        this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
        return this.gates
      }
      raw = await readFile(ntPath(this.gatesPath), "utf8")
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
    let records: unknown[] | null = null
    try {
      const parsed = JSON.parse(raw) as Partial<GatesFile>
      if (Array.isArray(parsed.gates)) {
        records = parsed.gates
        this.migratedStamp = typeof parsed.migrated === "string" ? parsed.migrated : null
      }
    } catch {
      // fall through to the corruption branch
    }
    if (records === null) {
      // Corruption ≠ absence: an unparseable file quarantines (bytes kept,
      // fresh store started) instead of silently emptying — the silent path
      // let the next save() overwrite recoverable gates with a blank store.
      // Only under the lock (force): unlocked reads never write.
      if (force) await this.quarantineGatesFile(raw)
      if (this.gates === null) {
        this.gates = []
        this.keyIndex = new Map()
        this.enforcedCache = []
      }
      this.cacheUntilMs = Date.now() + LOAD_CACHE_TTL_MS
      return this.gates
    }
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
    if (this.migratedStamp !== null) payload.migrated = this.migratedStamp
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
    return withLock(
      this.indexPath,
      fn,
      () => {
        this.deferEvent({ type: "degraded", key: "index.lock", snippet: `lock contention exceeded ${LOCK_WAIT_MS}ms; critical section ran unlocked` })
      },
      (heldMs, previousPid) => {
        this.deferEvent({ type: "repaired", key: "index.lock", snippet: `stale lock stolen (held ${heldMs}ms, previous pid ${previousPid || "?"})` })
      },
    )
  }

  /**
   * Append under the log lock: every OpenCode window shares the global log,
   * and unlocked concurrent appends interleave into broken JSON lines.
   * Also flushes events deferred from inside the gates lock — logging there
   * extends the critical section into degrade storms. The drain happens INSIDE
   * the log lock so events deferred between the call and lock acquisition are
   * included in this flush (draining before the lock dropped them).
   */
  async log(event: LogEvent): Promise<void> {
    let salientDeferred: LogEvent[] = []
    await withLock(this.logPath, async () => {
      const batch = this.deferredEvents
      this.deferredEvents = []
      // Route only the deferred batch — it bypassed logAll. The direct `event`
      // is routed by the caller (logAll); mirroring it here too would write it
      // to the global log twice.
      if (this.routeSalientTo !== null) salientDeferred = batch.filter((e) => GLOBAL_LOG_EVENTS.has(e.type))
      batch.push(event)
      await mkdir(ntPath(this.dir), { recursive: true })
      for (const e of batch) {
        const line = `${JSON.stringify({ ts: new Date().toISOString(), ...e })}\n`
        await appendFile(ntPath(this.logPath), line, "utf8")
      }
    })
    // Mirror runs after our own log lock releases — leaf locks, one at a time.
    if (salientDeferred.length > 0 && this.routeSalientTo !== null) await this.routeSalientTo.appendBatch(salientDeferred)
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
      // The long TTL belongs to patterns that reached THEIR promotion bar —
      // probe tools promote at 5, so a probe gate at count 3-4 is still noise.
      const threshold = PROBE_TOOLS.has(g.tool) ? PROMOTE_COUNT_PROBE : PROMOTE_COUNT
      const ttl = g.status !== "watching" || g.count >= threshold ? ttlDays : noiseTtlDays
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
    // runLocked (not bare withLock) so stale-steal/degrade are reported.
    await this.runLocked(async () => {
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
          await this.quarantineGatesFile(raw)
        } else {
          // Preserve the migration stamp: reconcile parses the file directly
          // (bypassing load()) and save() only writes the stamp it knows — if
          // we dropped it here, the next migrate() would re-run its full scan
          // on every startup, killing the init-storm optimization.
          this.migratedStamp = typeof parsed.migrated === "string" ? parsed.migrated : null
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
            this.deferEvent({
              type: "repaired",
              key: "gates.json",
              snippet: `dropped ${dropped} hopeless record(s), repaired ${repaired}, merged ${merged} duplicate key(s)`,
            })
          }
        }
      }
    })
    // Log hygiene runs OUTSIDE the gates lock: the log lock is a leaf, and
    // holding the gates lock across a full log read+parse+rewrite extends the
    // critical section exactly at init-storm time (round-4 lesson).
    await this.exciseCorruptLogLines()
  }

  /**
   * SQLite-style quarantine: unparseable gates bytes move aside (scrubbed —
   * they may carry unredacted secrets), a clean empty store starts. Caller
   * must hold the store lock. Never destroys the bytes.
   */
  private async quarantineGatesFile(raw: string): Promise<void> {
    const quarantine = `${this.gatesPath}.corrupt-${Date.now()}`
    try {
      await writeFile(ntPath(quarantine), scrubSecrets(raw), "utf8")
      await unlink(ntPath(this.gatesPath))
      this.gates = []
      this.keyIndex = new Map()
      this.enforcedCache = []
      this.mtimeMs = 0
      this.migratedStamp = null
      await this.save()
      this.deferEvent({ type: "quarantined", key: "gates.json", snippet: `unparseable gates file quarantined (scrubbed) to ${quarantine}` })
    } catch {
      // quarantine failed — next reconcile retries; never destroy the file
    }
  }

  /** Move unparseable JSONL lines to log.jsonl.corrupt; good lines stay.
   * The read happens INSIDE the log lock: reading outside and rewriting
   * inside dropped every line another window appended between the two
   * (concurrent OpenCode startups all reconcile at once). */
  private async exciseCorruptLogLines(): Promise<void> {
    let excised = 0
    await withLock(this.logPath, async () => {
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
      // Scrub: excised raw lines may carry unredacted secrets.
      await appendFile(ntPath(`${this.logPath}.corrupt`), `${scrubSecrets(bad.join("\n"))}\n`, "utf8")
      await atomicWrite(this.logPath, good.length > 0 ? `${good.join("\n")}\n` : "")
      excised = bad.length
    })
    if (excised > 0) {
      this.deferEvent({ type: "repaired", key: "log.jsonl", snippet: `excised ${excised} corrupt line(s) to log.jsonl.corrupt` })
    }
  }
}

/** Merge a gate's accumulated evidence into an existing gate with the same key. */
export function mergeGate(target: Gate, source: Gate): void {
  // Rank-preserving: blocking > reminding > watching — a merge never demotes
  // (a reminding source merged into a watching target used to lose its tier).
  if (source.status === "blocking" || (source.status === "reminding" && target.status === "watching")) {
    target.status = source.status
  }
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
  target.overrideCount += source.overrideCount
  if (target.correction === undefined && source.correction !== undefined) target.correction = source.correction
  if (source.review === true) target.review = true
  // A demotion is earned behavior — merging must never launder it away.
  if (source.feedbackDemoted === true) target.feedbackDemoted = true
  // Baselines track the counters' scale: counters sum across merges, so the
  // baseline sums too (the grace-window delta is preserved).
  if (source.feedbackBaseline !== undefined) {
    if (target.feedbackBaseline === undefined) {
      target.feedbackBaseline = { recurred: source.feedbackBaseline.recurred, overrides: source.feedbackBaseline.overrides }
    } else {
      target.feedbackBaseline.recurred += source.feedbackBaseline.recurred
      target.feedbackBaseline.overrides += source.feedbackBaseline.overrides
    }
  }
  // Retirement damping baseline: keep the target's if present (its count already
  // anchors it); otherwise adopt the source's. Never fabricate one — merging
  // retired gates is rare (dedupe/escalation) and a wrong baseline would either
  // re-open the oscillation or lock the gate out of re-promotion.
  if (target.retireBaseline === undefined && source.retireBaseline !== undefined) {
    target.retireBaseline = { count: source.retireBaseline.count }
  }
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
  if (source.reoffenseSessions !== undefined) {
    if (target.reoffenseSessions === undefined) target.reoffenseSessions = []
    for (const session of source.reoffenseSessions) {
      if (!target.reoffenseSessions.includes(session)) target.reoffenseSessions.push(session)
    }
    if (target.reoffenseSessions.length > MAX_SESSIONS) target.reoffenseSessions = target.reoffenseSessions.slice(-MAX_SESSIONS)
  }
}

/**
 * Enforcement feedback (the negative twin of `healed`): a gate that keeps
 * failing after promotion, or keeps getting explicitly bypassed, is friction
 * — it does not teach. Demote to watching and mark `feedbackDemoted` so the
 * promotion logic never re-enforces it mechanically. The baseline records
 * WHERE the counters stood at demotion: a human re-enforcement starts a fresh
 * grace window instead of re-demoting on the next failure.
 *
 * Recurrence demotion additionally requires DISTINCT reoffense sessions
 * (failures after a reminder — failures the gate had a chance to prevent):
 * first-encounter failures never saw a reminder and must not demote, and one
 * bad session/model in a shared store must not demote a gate for everyone.
 * Returns true when the gate changed; the caller saves and logs.
 */
export function checkFeedbackDemotion(gate: Gate): boolean {
  if (gate.status === "watching") return false
  const baseRecurred = gate.feedbackBaseline?.recurred ?? 0
  const baseOverrides = gate.feedbackBaseline?.overrides ?? 0
  const recurredEnough = gate.recurredAfterGate - baseRecurred >= DEMOTE_RECURRENCES
  const reoffenseVotes = gate.reoffenseSessions?.length ?? 0
  if ((recurredEnough && reoffenseVotes >= DEMOTE_REOFFENSE_SESSIONS) || gate.overrideCount - baseOverrides >= DEMOTE_OVERRIDES) {
    gate.status = "watching"
    gate.feedbackDemoted = true
    gate.feedbackBaseline = { recurred: gate.recurredAfterGate, overrides: gate.overrideCount }
    return true
  }
  return false
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
  ) {
    // Deferred events bypass logAll's routing, so wire the project store to
    // mirror its salient deferred events (demoted in migrate, retired-healed in
    // expireAll) into the global forensics. The global store gets no peer — it
    // must never route to itself.
    if (this.projectStore !== null && this.projectStore !== this.globalStore) {
      this.projectStore.routeSalientTo = this.globalStore
    }
  }

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
    // Over-generic bash shapes match exactly only: fuzzy-matching them onto
    // concrete gates would enforce/pollute unrelated calls (family noise).
    if (signature.startsWith("bash:") && !hasResidualIdentity(signature)) return null
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
    if (this.projectStore) {
      // Project log keeps the complete forensics (low contention). The global
      // log is shared by every window of every project — the most-contended
      // lock — so it only gets the events that change what the machine
      // remembers. Detected/reminded/blocked are high-volume and stay local.
      await this.projectStore.log(event)
      if (GLOBAL_LOG_EVENTS.has(event.type)) await this.globalStore.log(event)
    } else {
      // Sole store: it is the only forensics — keep everything.
      await this.globalStore.log(event)
    }
  }

  async expireAll(ttlDays: number, noiseTtlDays: number): Promise<void> {
    for (const store of this.scopes()) {
      await store.runLocked(async () => {
        const expired = await store.expire(ttlDays, noiseTtlDays)
        for (const gate of expired) {
          // Correction lifecycle: a corrected gate that never recurred after
          // promotion means the pattern died out — the mechanical signal that
          // the teaching worked. Deferred: logging under the gates lock
          // extends the critical section (a big sweep = N log-lock takes).
          if (gate.correction !== undefined && gate.recurredAfterGate === 0) {
            store.deferEvent({ type: "retired-healed", key: gate.key, tool: gate.tool, snippet: gate.correction.slice(0, 200) })
          } else {
            store.deferEvent({ type: "expired", key: gate.key, tool: gate.tool })
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

  /** Flush deferred events on every scope (timer sweeps defer expired/
   * retired-healed events that would otherwise wait for the next hook log,
   * and are lost if the process exits first). */
  async flushDeferredAll(): Promise<void> {
    for (const store of this.scopes()) {
      await store.flushDeferred()
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
        // Init-storm killer: the 2nd..Nth start of the same version skips the
        // full per-gate scan. Policy re-checks still run on every load via
        // repairGate, and new gates are created compliant, so the stamp is safe.
        if (store.migratedVersion === PLUGIN_VERSION) return
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
            gate.feedbackDemoted !== true &&
            gate.retireBaseline === undefined &&
            canRemind(gate.tool, gate.signature) &&
            gate.count >= PROMOTE_COUNT &&
            gate.sessions.length >= PROMOTE_SESSIONS
          ) {
            // Recurring diagnostics already proven under the old policy start
            // reminding immediately instead of waiting for the next failure.
            // feedbackDemoted gates are exempt: the agent's behavior already
            // voted against enforcement — re-enforcing on every restart would
            // violate "never re-promotes mechanically".
            // retireBaseline gates are exempt for the same reason: they RETIRED
            // on evidence (healed/taught) — the lifetime count that clears this
            // bar is the pre-retirement evidence the damping baseline exists to
            // discount. Re-promoting them here on every migrate would re-open the
            // promote→heal→promote oscillation the baseline was added to kill;
            // their re-promotion must earn a fresh bar via recordFailure.
            gate.status = "reminding"
            changed = true
          }
          const signature = sanitizeForStore(gate.signature)
          const snippet = sanitizeForStore(gate.snippet)
          if (signature !== gate.signature) {
            gate.signature = signature
            changed = true
          }
          if (snippet !== gate.snippet) {
            gate.snippet = snippet
            changed = true
          }
          if (gate.correction !== undefined) {
            const correction = sanitizeForStore(gate.correction)
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
          // Feedback catch-up: gates that already crossed the demotion
          // thresholds before the counters existed are demoted on the spot —
          // enforcement must reflect the agent's actual behavior.
          if (checkFeedbackDemotion(gate)) {
            changed = true
            store.deferEvent({
              type: "demoted",
              key: gate.key,
              tool: gate.tool,
              snippet: `feedback demotion (recurred ${gate.recurredAfterGate}, overridden ${gate.overrideCount})`,
            })
          }
        }
        // Stamp the migration and persist repairs (save is idempotent when
        // nothing changed beyond the stamp itself).
        store.migratedVersion = PLUGIN_VERSION
        changed = true
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
  async reconcileAll(globalProjects = GLOBAL_PROJECTS): Promise<void> {
    for (const store of this.scopes()) {
      await store.reconcile()
    }

    // Index-driven escalation healing: a key proven in enough project dirs
    // belongs in the global store even if recordFailure never moved it
    // (racing instances, or stores that predate the index).
    const projectStore = this.projectStore
    if (projectStore) {
      const index = await this.globalStore.loadIndex()
      // Non-force load: this is a routing-hint read (the authoritative
      // load(true) happens under the locks below). The force path would
      // quarantine an unparseable file WITHOUT the gates lock — the very
      // write-without-lock class round 3 fixed in doctor.
      const toEscalate = (await projectStore.load()).filter((g) => {
        const entry = index.keys[g.key]
        // Count only project dirs that still exist on disk (ghost dirs from
        // renamed/moved repos must not strengthen escalation).
        return (
          entry !== undefined &&
          entry.projects.filter((p) => existsSync(p)).length >= globalProjects &&
          !isRepoLocal(g.signature)
        )
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

    // The index must mirror reality: a global gate missing from the index
    // loses cross-project history — rebuild it. No orphan pruning here: this
    // process sees ONE project store + global, so an index key whose gate
    // lives in ANOTHER project is invisible, not dead — pruning it would
    // destroy cross-project escalation evidence. Genuine rot is handled by
    // the TTL sweep in expireAll; doctor reports true orphans across ALL
    // scopes (it discovers them from the index itself).
    // Log OUTSIDE the index lock (the log lock is the most-contended lock;
    // acquiring it while holding the index lock extends the index critical
    // section at exactly init-storm time).
    let rebuilt = 0
    await this.globalStore.runLockedIndex(async () => {
      const index = await this.globalStore.loadIndex(true)
      // Non-force load: we hold the INDEX lock, not the gates lock — the force
      // path could quarantine global gates.json without its lock. reconcile()
      // refreshed this cache moments ago, so the peek is fresh.
      for (const gate of await this.globalStore.load()) {
        if (!index.keys[gate.key]) {
          index.keys[gate.key] = { projects: [...gate.projects], lastSeen: gate.lastSeen }
          rebuilt += 1
        }
      }
      if (rebuilt > 0) await this.globalStore.saveIndex()
    })
    if (rebuilt > 0) {
      await this.globalStore.log({
        type: "repaired",
        key: "index.json",
        snippet: `rebuilt ${rebuilt} missing index entr(y/ies)`,
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
    await store.load()
    if (store.byKey(input.key) === undefined) {
      await this.globalStore.load()
      if (this.globalStore.byKey(input.key) !== undefined) {
        store = this.globalStore
      }
    }

    // FLAT lock phases — the previous implementation held the project gates
    // lock across the index lock + the global gates lock + two saves: the
    // longest critical section in the system, and every other window's waiter
    // degraded to unlocked after LOCK_WAIT_MS (the lost-update window the
    // `degraded` event documents). Each phase now holds exactly one lock.
    // Race windows introduced are benign/self-healing:
    //  (a) a failure landing between the Phase-1 save and the Phase-3 extract
    //      adds at most one concurrent failure's evidence delta to a gate that
    //      is about to move — the pattern re-converges from its next failure;
    //  (b) a concurrent escalation of the same key just merges (mergeGate);
    //  (c) if the gate vanishes between phases (flood eviction / migrate), the
    //      escalation aborts — a duplicate heals, never a hole.
    // Phase 1 — this store's gates lock (short): find/create/mutate the gate,
    // promotion, save. Returns the mutated gate (or an ephemeral gate that is
    // never persisted when the flood guard leaves no eviction candidate).
    const phase1 = await store.runLocked(async (): Promise<{ moved: Gate | null; ephemeral: Gate | null; promoted: boolean }> => {
      let promoted = false
      let ephemeral: Gate | null = null
      const gates = await store.load(true)
      let gate = gates.find((g) => g.key === input.key)
      let fuzzyConsolidated = false
      // Consolidation: same tool + near-duplicate signature merges into the
      // existing pattern instead of fragmenting ("gradlew :x:compiletestjava").
      if (!gate) {
        // Prefer the gate this session was already reminded about: the
        // before-hook enforced from it, so the failure must land there too —
        // otherwise the remind→block chain desyncs between the hooks.
        // Over-generic bash shapes never consolidate into concrete gates:
        // family noise must not inflate a specific call's evidence.
        const fuzzyAllowed = input.tool !== "bash" || hasResidualIdentity(input.signature)
        const fuzzyMatches = fuzzyAllowed ? gates.filter((g) => g.tool === input.tool && fuzzySimilar(input.signature, g.signature)) : []
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
            if (victim === undefined) {
              victimIdx = i
              continue
            }
            // Feedback-demoted gates already proved unteachable — evict them
            // before evidence still trying to teach (under the old
            // lowest-count rule they were the STICKIEST residents: high
            // count, demoted, never enforcing).
            const candidateDemoted = candidate.feedbackDemoted === true
            const victimDemoted = victim.feedbackDemoted === true
            if (candidateDemoted !== victimDemoted) {
              if (candidateDemoted) victimIdx = i
              continue
            }
            if (candidate.count < victim.count || (candidate.count === victim.count && candidate.lastSeen < victim.lastSeen)) {
              victimIdx = i
            }
          }
          if (victimIdx < 0) {
            // Every gate is enforced — do not create; degrade gracefully with
            // an ephemeral gate that is never persisted.
            ephemeral = {
              key: input.key,
              signature: sanitizeForStore(input.signature),
              tool: input.tool,
              status: "watching",
              count: 1,
              sessions: [input.sessionID],
              projects: input.projectDir !== "" ? [input.projectDir] : [],
              firstSeen: now,
              lastSeen: now,
              snippet: sanitizeForStore(input.snippet),
              remindedCount: 0,
              blockedCount: 0,
              recurredAfterReminder: 0,
              recurredAfterGate: 0,
              overrideCount: 0,
            }
            return { moved: null, ephemeral, promoted: false }
          }
          const evicted = gates[victimIdx]
          gates.splice(victimIdx, 1)
          if (evicted !== undefined) {
            store.deferEvent({
              type: "expired",
              key: evicted.key,
              tool: evicted.tool,
              snippet: `flood guard evicted this watching gate to stay at ${MAX_GATES}`,
            })
          }
        }
        gate = {
          key: input.key,
          signature: sanitizeForStore(input.signature),
          tool: input.tool,
          status: "watching",
          count: 0,
          sessions: [],
          projects: [],
          firstSeen: now,
          lastSeen: now,
          snippet: sanitizeForStore(input.snippet),
          remindedCount: 0,
          blockedCount: 0,
          recurredAfterReminder: 0,
          recurredAfterGate: 0,
          overrideCount: 0,
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
      if (!fuzzyConsolidated) gate.snippet = sanitizeForStore(input.snippet)
      // A failure breaks any heal streak — the command is still broken.
      gate.succeededAfterGate = 0

      const threshold = PROBE_TOOLS.has(input.tool) ? PROMOTE_COUNT_PROBE : PROMOTE_COUNT
      // Oscillation damping: a retired gate (healed/taught) keeps its lifetime
      // count/sessions, which already clear the promotion bar — so it would
      // re-promote on the VERY NEXT single failure (promote→heal→promote).
      // Require a full fresh bar of failures SINCE retirement instead.
      const effectiveCount = gate.retireBaseline !== undefined ? Math.max(0, gate.count - gate.retireBaseline.count) : gate.count
      // Policy: non-diagnostic bash may hard-block; diagnostics promote to
      // remind-only (they never block — see canRemind). Everything else stays
      // watching. feedbackDemoted gates never re-promote mechanically: the
      // agent's behavior already voted against enforcement once.
      if (gate.status === "watching" && gate.feedbackDemoted !== true && effectiveCount >= threshold && gate.sessions.length >= PROMOTE_SESSIONS) {
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
        // Fresh enforcement lifecycle: re-promotion (after heal/taught
        // retirement) must not inherit the previous round's counters — stale
        // cumulative zeros caused retire↔re-promote oscillation (a re-promoted
        // gate re-retired on its first reminder) and permanently locked out
        // taught retirement after any early recurrence. Session chains are
        // cleared too: a stale remindedSessions entry from the retiring round
        // would let the session skip its reminder with "one retry allowed".
        if (promoted) {
          gate.remindedCount = 0
          gate.recurredAfterReminder = 0
          gate.recurredAfterGate = 0
          gate.overrideCount = 0
          gate.succeededAfterGate = 0
          delete gate.feedbackBaseline
          delete gate.reoffenseSessions
          delete gate.remindedSessions
          delete gate.failedSessions
          // The damping baseline is consumed by this promotion — the next
          // retirement will capture a fresh one.
          delete gate.retireBaseline
        }
      }

      await store.save()
      return { moved: gate ?? null, ephemeral, promoted }
    })
    if (phase1.ephemeral !== null) return { gate: phase1.ephemeral, store, promoted: false, wentGlobal: false }
    if (phase1.moved === null) {
      // Unreachable: Phase 1 always yields a gate unless the ephemeral
      // early-return fired. Degrade to an ephemeral record rather than throw.
      return {
        gate: {
          key: input.key,
          signature: sanitizeForStore(input.signature),
          tool: input.tool,
          status: "watching",
          count: 1,
          sessions: [input.sessionID],
          projects: input.projectDir !== "" ? [input.projectDir] : [],
          firstSeen: now,
          lastSeen: now,
          snippet: sanitizeForStore(input.snippet),
          remindedCount: 0,
          blockedCount: 0,
          recurredAfterReminder: 0,
          recurredAfterGate: 0,
          overrideCount: 0,
        },
        store,
        promoted: false,
        wentGlobal: false,
      }
    }
    const movedGate = phase1.moved
    const promoted = phase1.promoted

    // Phase 2 — index lock (no gates lock held): cross-project evidence.
    // gate.projects only ever sees its own store's directory, so alone it can
    // never reach two projects. A pattern seen in enough distinct project dirs
    // is an agent-level habit, not a repo quirk — move it to the global store.
    // Keyed by the gate's OWN key (post fuzzy-consolidation), not the raw
    // failure key — otherwise consolidated failures index a key that has no
    // gate, orphaning the entry and starving the gate's escalation.
    let indexProjects = 0
    await this.globalStore.runLockedIndex(async () => {
      const index = await this.globalStore.loadIndex(true)
      let entry = index.keys[movedGate.key]
      // Index churn gate: the FIRST failure of a brand-new pattern (no entry
      // yet, seen once) carries no escalation value — skip the machine-wide
      // rewrite. Anything already indexed or recurring updates as before, so
      // cross-project escalation sees the same evidence minus one-off noise.
      if (entry === undefined && movedGate.count < 2) return
      if (!entry) {
        entry = { projects: [], lastSeen: now }
        index.keys[movedGate.key] = entry
      }
      if (input.projectDir !== "" && !entry.projects.includes(input.projectDir)) {
        entry.projects.push(input.projectDir)
        if (entry.projects.length > MAX_PROJECTS) entry.projects = entry.projects.slice(-MAX_PROJECTS)
      }
      entry.lastSeen = now
      await this.globalStore.saveIndex()
      // Escalation evidence counts only project dirs that still exist on
      // disk: a repo renamed/moved (common on Windows dev machines) is a
      // ghost — escalation must not rest on its strength. The index entry
      // keeps the ghost (evidence preserved; it may be a removable drive).
      indexProjects = entry.projects.filter((p) => existsSync(p)).length
    })

    // Phase 3 — escalation (only if warranted): three short locked phases.
    let wentGlobal = false
    // Repo-local verbs (npm/git/gradle/...) never escalate: their failures are
    // repo quirks, not agent habits — escalating them would let a broken
    // `npm install` in one project block every other project.
    if (
      store !== this.globalStore &&
      this.projectStore &&
      indexProjects >= input.globalProjects &&
      !isRepoLocal(movedGate.signature)
    ) {
      // 3a — project gates lock: copy the gate fresh. If it is gone, someone
      // else escalated/expired it — abort (a duplicate heals, never a hole).
      let gateCopy: Gate | null = null
      await store.runLocked(async () => {
        const fresh = (await store.load(true)).find((g) => g.key === movedGate.key)
        if (fresh !== undefined) gateCopy = JSON.parse(JSON.stringify(fresh)) as Gate
      })
      if (gateCopy !== null) {
        const copy = gateCopy
        // 3b — global gates lock FIRST: write the global copy before removing
        // the local one, so a crash between the two writes leaves a duplicate
        // (healed by migrate), never a hole.
        await this.globalStore.runLocked(async () => {
          const globalGates = await this.globalStore.load(true)
          const existing = globalGates.find((g) => g.key === movedGate.key)
          if (existing) {
            mergeGate(existing, copy)
          } else {
            globalGates.push(copy)
          }
          await this.globalStore.save()
        })
        // 3c — project gates lock: remove the now-escalated local copy.
        await store.runLocked(async () => {
          const gates = await store.load(true)
          const idx = gates.findIndex((g) => g.key === movedGate.key)
          if (idx >= 0) gates.splice(idx, 1)
          await store.save()
        })
        wentGlobal = true
      }
    }

    return { gate: movedGate, store, promoted, wentGlobal }
  }

  /**
   * A SUCCESS matching an enforced gate is evidence the underlying command got
   * fixed. Track a streak; once it reaches HEAL_SUCCESSES the gate retires to
   * watching so it stops reminding on a now-healthy command (the
   * `ruff check .` false-positive case). Only enforced (blocking/reminding)
   * gates heal; a failure resets the streak in recordFailure.
   *
   * A success ALSO clears the succeeding session from the remind→block chain.
   * Without this, a session that proved the fix (often via `dejavu:proceed`)
   * stayed permanently blocked and could only keep overriding — the override
   * count then demoted the very gate the agent had just vindicated. Success is
   * the proof; the chain for that session must reset.
   *
   * EXACT matches only: healing and chain-clearing are state mutations, and a
   * fuzzy-similar success is evidence about a DIFFERENT command — proxy
   * successes would heal a gate that still fails and unblock sessions that
   * never proved the gated call.
   */
  async recordSuccess(input: { key: string; signature: string; tool: string; sessionID: string }): Promise<void> {
    // Exact matches only — healing and chain-clearing are state mutations,
    // and a fuzzy-similar success is evidence about a DIFFERENT command.
    // Exact-only also lets us skip findGate's fuzzy scan entirely: this runs
    // on EVERY successful bash call, and fuzzy matches are rejected anyway.
    let owner: GateStore | null = null
    for (const scope of this.scopes()) {
      await scope.load()
      if (scope.byKey(input.key) !== undefined) {
        owner = scope
        break
      }
    }
    if (owner === null) return
    const store = owner
    const gateKey = input.key
    let healedEvent: LogEvent | null = null
    await store.runLocked(async () => {
      const fresh = (await store.load(true)).find((g) => g.key === gateKey)
      if (fresh === undefined || fresh.status === "watching") return
      fresh.succeededAfterGate = (fresh.succeededAfterGate ?? 0) + 1
      if (fresh.remindedSessions !== undefined && fresh.remindedSessions[input.sessionID] !== undefined) {
        delete fresh.remindedSessions[input.sessionID]
        if (Object.keys(fresh.remindedSessions).length === 0) delete fresh.remindedSessions
      }
      if (fresh.failedSessions !== undefined && fresh.failedSessions[input.sessionID] !== undefined) {
        delete fresh.failedSessions[input.sessionID]
        if (Object.keys(fresh.failedSessions).length === 0) delete fresh.failedSessions
      }
      const healed = fresh.succeededAfterGate >= HEAL_SUCCESSES
      if (healed) {
        fresh.status = "watching"
        // Oscillation damping: capture the count at retirement so re-promotion
        // needs a full fresh bar of failures, not the very next single one.
        fresh.retireBaseline = { count: fresh.count }
      }
      await store.save()
      if (healed) {
        healedEvent = {
          type: "healed",
          key: fresh.key,
          tool: fresh.tool,
          snippet: `succeeded ${fresh.succeededAfterGate}x in a row after the gate — retired to watching`,
        }
      }
    })
    // Log OUTSIDE the gates lock (heals are rare but can land on a hot gate
    // while other windows wait — logging under the lock cascades contention).
    // Routed via logAll so the heal reaches the global log too (healed is
    // machine-memory-salient).
    if (healedEvent !== null) await this.logAll(healedEvent)
  }
}
