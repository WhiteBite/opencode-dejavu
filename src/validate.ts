/**
 * Invariant layer: strict parsing and repair of persisted gate state.
 * Pure functions — no I/O. Used at the persistence boundary (store reconcile)
 * and by diagnostics (doctor). Parse, don't validate: what survives
 * coerceGateShape + repairGate satisfies the data-model invariants.
 */
import type { Gate } from "./store"
import { canBlock, scrubSecrets } from "./patterns"

/** sha1 prefix-12, the only key shape patternKey ever emits */
const KEY_SHAPE = /^[0-9a-f]{12}$/
/** detection truncates snippets at 200 chars on ingest */
const SNIPPET_MAX = 200
/** per-session enforcement state rots after a day — sessions do not live longer */
const SESSION_STATE_TTL_MS = 24 * 60 * 60 * 1000
/** bound per-gate session state so long-lived gates cannot bloat */
const SESSION_STATE_CAP = 50

/**
 * Structural parse of one persisted gate object. Returns a well-shaped Gate
 * or null when the record is hopeless (missing identity fields, unknown
 * status) — hopeless records are dropped, not guessed at.
 */
export function coerceGateShape(raw: unknown): Gate | null {
  if (typeof raw !== "object" || raw === null) return null
  const r = raw as Record<string, unknown>
  if (typeof r.key !== "string" || !KEY_SHAPE.test(r.key)) return null
  if (typeof r.signature !== "string" || r.signature.trim() === "") return null
  if (typeof r.tool !== "string" || r.tool.trim() === "") return null
  if (r.status !== "watching" && r.status !== "blocking") return null

  const num = (v: unknown, fallback: number): number =>
    typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : fallback
  const strings = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []
  const str = (v: unknown, fallback: string): string => (typeof v === "string" ? v : fallback)
  const now = new Date().toISOString()

  const gate: Gate = {
    key: r.key,
    signature: r.signature,
    tool: r.tool,
    status: r.status,
    count: num(r.count, 0),
    sessions: strings(r.sessions),
    projects: strings(r.projects),
    firstSeen: str(r.firstSeen, now),
    lastSeen: str(r.lastSeen, now),
    snippet: str(r.snippet, ""),
    remindedCount: num(r.remindedCount, 0),
    blockedCount: num(r.blockedCount, 0),
    recurredAfterReminder: num(r.recurredAfterReminder, 0),
    recurredAfterGate: num(r.recurredAfterGate, 0),
  }
  if (typeof r.correction === "string") gate.correction = r.correction
  if (r.review === true) gate.review = true
  if (r.remindedSessions !== null && typeof r.remindedSessions === "object" && !Array.isArray(r.remindedSessions)) {
    const sessions: Record<string, number> = {}
    for (const [session, at] of Object.entries(r.remindedSessions as Record<string, unknown>)) {
      if (typeof at === "number" && Number.isFinite(at)) sessions[session] = at
    }
    if (Object.keys(sessions).length > 0) gate.remindedSessions = sessions
  }
  if (Array.isArray(r.failedSessions)) {
    // Legacy shape (string[]) — convert with fresh timestamps
    const sessions: Record<string, number> = {}
    const now = Date.now()
    for (const session of r.failedSessions) {
      if (typeof session === "string") sessions[session] = now
    }
    if (Object.keys(sessions).length > 0) gate.failedSessions = sessions
  } else if (r.failedSessions !== null && typeof r.failedSessions === "object") {
    const sessions: Record<string, number> = {}
    for (const [session, at] of Object.entries(r.failedSessions as Record<string, unknown>)) {
      if (typeof at === "number" && Number.isFinite(at)) sessions[session] = at
    }
    if (Object.keys(sessions).length > 0) gate.failedSessions = sessions
  }
  return gate
}

/**
 * In-place coercion of everything mechanically repairable. Returns true when
 * anything changed. What it cannot repair (identity fields, hopeless shapes)
 * is rejected earlier by coerceGateShape.
 */
export function repairGate(gate: Gate): boolean {
  let changed = false
  if (gate.firstSeen > gate.lastSeen) {
    const swap = gate.firstSeen
    gate.firstSeen = gate.lastSeen
    gate.lastSeen = swap
    changed = true
  }
  if (gate.snippet.length > SNIPPET_MAX) {
    gate.snippet = gate.snippet.slice(0, SNIPPET_MAX)
    changed = true
  }
  const signature = scrubSecrets(gate.signature)
  if (signature !== gate.signature) {
    gate.signature = signature
    changed = true
  }
  const snippet = scrubSecrets(gate.snippet)
  if (snippet !== gate.snippet) {
    gate.snippet = snippet
    changed = true
  }
  if (gate.correction !== undefined) {
    let correction = scrubSecrets(gate.correction)
    if (correction.length > SNIPPET_MAX) {
      // Unbounded corrections are a context-pollution vector; the companion
      // skill mandates one actionable line anyway.
      correction = correction.slice(0, SNIPPET_MAX)
    }
    if (correction !== gate.correction) {
      gate.correction = correction
      changed = true
    }
  }
  // Per-session enforcement state hygiene: rot stale entries, bound the rest.
  if (gate.remindedSessions !== undefined) {
    const now = Date.now()
    const reminded = gate.remindedSessions
    for (const session of Object.keys(reminded)) {
      if (now - (reminded[session] ?? 0) > SESSION_STATE_TTL_MS) {
        delete reminded[session]
        changed = true
      }
    }
    const sessions = Object.keys(reminded)
    if (sessions.length > SESSION_STATE_CAP) {
      sessions.sort((a, b) => (reminded[a] ?? 0) - (reminded[b] ?? 0))
      for (const session of sessions.slice(0, sessions.length - SESSION_STATE_CAP)) {
        delete reminded[session]
      }
      changed = true
    }
    if (Object.keys(reminded).length === 0) delete gate.remindedSessions
  }
  if (gate.failedSessions !== undefined) {
    const now = Date.now()
    const failed = gate.failedSessions
    for (const session of Object.keys(failed)) {
      if (now - (failed[session] ?? 0) > SESSION_STATE_TTL_MS) {
        delete failed[session]
        changed = true
      }
    }
    const sessions = Object.keys(failed)
    if (sessions.length > SESSION_STATE_CAP) {
      sessions.sort((a, b) => (failed[a] ?? 0) - (failed[b] ?? 0))
      for (const session of sessions.slice(0, sessions.length - SESSION_STATE_CAP)) {
        delete failed[session]
      }
      changed = true
    }
    if (Object.keys(failed).length === 0) delete gate.failedSessions
  }
  // Policy is the single source of truth: a blocking gate that cannot block
  // is a leftover from an older policy and must be demoted.
  if (gate.status === "blocking" && !canBlock(gate.tool, gate.signature)) {
    gate.status = "watching"
    changed = true
  }
  return changed
}

/**
 * Corruption fingerprint of a placeholder re-parameterized inside another
 * token (`<code: <n> >` — a fingerprint eaten by the number rule). Only the
 * `<code:` token carries nested content, so the check is scoped to it —
 * shell text like heredoc `<<eof:` must NOT trip the detector.
 */
export function hasNestedTokens(signature: string): boolean {
  return /<code:\s*</.test(signature)
}
