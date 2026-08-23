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
    const correction = scrubSecrets(gate.correction)
    if (correction !== gate.correction) {
      gate.correction = correction
      changed = true
    }
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
 * Corruption fingerprint of tokens re-parameterized inside other tokens
 * (e.g. `<code: <n> >` — a fingerprint eaten by the number rule). Such a
 * signature is stable under re-normalization, so only an explicit shape
 * check catches it.
 */
export function hasNestedTokens(signature: string): boolean {
  return /<[a-z]+:\s*</.test(signature)
}
