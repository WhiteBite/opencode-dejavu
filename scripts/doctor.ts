/**
 * One-command pathology report for dejavu stores. Checks every invariant the
 * data model implies, so debugging starts from facts, not guesses.
 *
 * Usage: bun scripts/doctor.ts [--repair] [projectDir ...]
 *   --repair  heal first (reconcile + migrate), then report
 */
import { readFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { canBlock, scrubSecrets } from "../src/patterns"
import { GateStore, Stores, PLUGIN_VERSION, PROMOTE_SESSIONS, type Gate } from "../src/store"
import { coerceGateShape, hasNestedTokens } from "../src/validate"

const repair = process.argv.includes("--repair")
const projectDirs = process.argv.slice(2).filter((a) => a !== "--repair")
const globalDir = process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu")

// --- repair pass (idempotent): heal structure, then policy ---
if (repair) {
  const targets = projectDirs.length > 0 ? projectDirs : [""]
  for (const dir of targets) {
    const stores = new Stores(new GateStore(globalDir), dir === "" ? null : new GateStore(join(dir, ".opencode", "dejavu")))
    await stores.reconcileAll()
    await stores.migrate()
    console.log(`repaired: ${dir === "" ? "(global only)" : dir}`)
  }
}

// --- report pass ---
interface Scope {
  dir: string
  isGlobal: boolean
  gates: Gate[]
  /** raw records from disk, for strict-parse checks */
  records: unknown[]
  rawState: "missing" | "unparseable" | "ok"
  corruptLogLines: number
  degradedEvents: number
}

async function loadScope(dir: string, isGlobal: boolean): Promise<Scope> {
  let rawState: Scope["rawState"] = "missing"
  let records: unknown[] = []
  try {
    const raw = await readFile(join(dir, "gates.json"), "utf8")
    if (raw.trim() !== "") {
      try {
        const parsed = JSON.parse(raw) as { gates?: unknown }
        rawState = "ok"
        records = Array.isArray(parsed.gates) ? parsed.gates : []
      } catch {
        rawState = "unparseable"
      }
    }
  } catch {
    rawState = "missing"
  }
  let corruptLogLines = 0
  let degradedEvents = 0
  try {
    const raw = await readFile(join(dir, "log.jsonl"), "utf8")
    for (const line of raw.split("\n")) {
      if (line.trim() === "") continue
      if (line.includes('"type":"degraded"')) degradedEvents++
      try {
        JSON.parse(line)
      } catch {
        corruptLogLines++
      }
    }
  } catch {
    // no log yet
  }
  const store = new GateStore(dir)
  return { dir, isGlobal, gates: await store.load(), records, rawState, corruptLogLines, degradedEvents }
}

const scopes: Scope[] = [await loadScope(globalDir, true)]
for (const p of projectDirs) scopes.push(await loadScope(join(p, ".opencode", "dejavu"), false))

const allKeys = new Set(scopes.flatMap((s) => s.gates.map((g) => g.key)))
const globalScope = scopes[0] as Scope
const globalKeys = new Set(globalScope.gates.map((g) => g.key))
const index = await new GateStore(globalDir).loadIndex()

let issues = 0
for (const scope of scopes) {
  console.log(`\n== ${scope.dir}`)

  if (scope.rawState === "unparseable") {
    issues++
    console.log("   UNPARSEABLE gates.json — run doctor --repair (file is quarantined, bytes kept)")
  }
  const badRecords = scope.records.filter((r) => coerceGateShape(r) === null).length
  if (badRecords > 0) {
    issues++
    console.log(`   BAD GATE RECORDS (${badRecords}) — fail strict parse; doctor --repair drops them`)
  }

  const gates = scope.gates
  if (gates.length === 0 && scope.rawState !== "unparseable" && badRecords === 0) console.log("   (empty)")

  const seen = new Set<string>()
  let dupes = 0
  for (const g of gates) {
    if (seen.has(g.key)) dupes++
    seen.add(g.key)
  }
  if (dupes > 0) {
    issues++
    console.log(`   DUPLICATE KEYS (${dupes}) — doctor --repair merges them`)
  }

  const inverted = gates.filter((g) => g.firstSeen > g.lastSeen)
  if (inverted.length > 0) {
    issues++
    console.log(`   TEMPORAL INVERSION firstSeen>lastSeen (${inverted.length}) — doctor --repair swaps them`)
  }

  const nested = gates.filter((g) => hasNestedTokens(g.signature))
  if (nested.length > 0) {
    issues += nested.length
    console.log(`   NESTED TOKEN corruption (${nested.length}) — a placeholder re-parameterized another token; delete these gates:`)
    for (const g of nested.slice(0, 10)) console.log(`     - ${g.signature}`)
  }

  const blockingNoEvidence = gates.filter((g) => g.status === "blocking" && g.sessions.length < PROMOTE_SESSIONS)
  if (blockingNoEvidence.length > 0) {
    issues += blockingNoEvidence.length
    console.log(`   BLOCKING WITHOUT EVIDENCE sessions<${PROMOTE_SESSIONS} (${blockingNoEvidence.length}) — promoted outside policy (hand-edited?):`)
    for (const g of blockingNoEvidence.slice(0, 10)) console.log(`     - ${g.signature}`)
  }

  const staleBlocking = gates.filter((g) => g.status === "blocking" && !canBlock(g.tool, g.signature))
  if (staleBlocking.length > 0) {
    issues += staleBlocking.length
    console.log(`   STALE BLOCKING outside policy (${staleBlocking.length}) — doctor --repair demotes:`)
    for (const g of staleBlocking.slice(0, 10)) console.log(`     - ${g.signature}`)
  }

  // Gates that can never block could never teach — counters are pre-policy history
  const notTeaching = gates.filter((g) => g.recurredAfterGate >= 3 && canBlock(g.tool, g.signature))
  if (notTeaching.length > 0) {
    issues += notTeaching.length
    console.log(`   NOT TEACHING recurredAfterGate>=3 (${notTeaching.length}) — gate fires but error recurs; write a correction or delete:`)
    for (const g of notTeaching.slice(0, 10)) console.log(`     - recurred ${g.recurredAfterGate} | ${g.signature}`)
  }

  // Positive signal: correction exists and the pattern never recurred after promotion
  const teaching = gates.filter((g) => g.correction !== undefined && g.recurredAfterGate === 0 && g.count >= 3)
  if (teaching.length > 0) {
    console.log(`   note: TEACHING (${teaching.length}) — corrected gates with zero recurrences after promotion`)
  }

  const annoying = gates.filter((g) => g.remindedCount >= 10 && canBlock(g.tool, g.signature))
  if (annoying.length > 0) {
    issues += annoying.length
    console.log(`   ANNOYING reminded>=10 (${annoying.length}):`)
    for (const g of annoying.slice(0, 10)) console.log(`     - reminded ${g.remindedCount} | ${g.signature}`)
  }

  const leaky = gates.filter(
    (g) =>
      scrubSecrets(g.signature) !== g.signature ||
      scrubSecrets(g.snippet) !== g.snippet ||
      (g.correction !== undefined && scrubSecrets(g.correction) !== g.correction),
  )
  if (leaky.length > 0) {
    issues += leaky.length
    console.log(`   SECRETS ON DISK (${leaky.length}) — doctor --repair scrubs`)
  }

  if (!scope.isGlobal) {
    const staleCopies = gates.filter((g) => globalKeys.has(g.key))
    if (staleCopies.length > 0) {
      issues += staleCopies.length
      console.log(`   STALE PROJECT COPIES (${staleCopies.length}) — key already global; doctor --repair merges into the global gate`)
    }
  }

  if (scope.corruptLogLines > 0) {
    issues++
    console.log(`   CORRUPT LOG LINES (${scope.corruptLogLines}) — doctor --repair excises them to log.jsonl.corrupt`)
  }

  if (scope.degradedEvents > 0) {
    // Observability, not a defect: the degrade-to-unlocked design trades rare
    // lost updates for never hanging the tool pipeline. Watch the trend — a
    // growing count is the signal to revisit the storage backend.
    console.log(`   note: LOCK DEGRADATIONS (${scope.degradedEvents}) — contention exceeded the wait window; updates may have been lost there`)
  }

  try {
    const raw = await readFile(join(scope.dir, "log.jsonl"), "utf8")
    const inits = raw.split("\n").filter((l) => l.includes('"type":"init"'))
    const last = inits[inits.length - 1]
    let version = "none"
    if (last) {
      try {
        version = (JSON.parse(last) as { version?: string }).version ?? "unknown"
      } catch {
        // a corrupt init line must not crash the diagnostic tool itself
        version = "unknown"
      }
    }
    if (version !== PLUGIN_VERSION) {
      issues++
      console.log(`   VERSION DRIFT: last init in log = ${version}, current = ${PLUGIN_VERSION} — stale plugin sessions were writing here; restart OpenCode`)
    } else {
      console.log(`   version ok (${version})`)
    }
  } catch {
    console.log("   (no log yet)")
  }
}

// --- cross-store invariants (need the full scope list) ---
console.log(`\n== ${globalDir} (cross-store)`)
let crossIssues = 0
const indexEntries = Object.entries(index.keys)

const orphans = indexEntries.filter(([key]) => !allKeys.has(key))
if (orphans.length > 0) {
  crossIssues++
  console.log(`   INDEX ORPHANS (${orphans.length}) — keys with no gate in any scope; doctor --repair prunes`)
}

const missing = globalScope.gates.filter((g) => index.keys[g.key] === undefined)
if (missing.length > 0) {
  crossIssues++
  console.log(`   INDEX MISSING (${missing.length}) — global gates without cross-project tracking; doctor --repair rebuilds`)
}

// GLOBAL_PROJECTS = 2 (index.ts tunable): 2+ project dirs = agent-level habit
const missed = indexEntries.filter(([key, entry]) => entry.projects.length >= 2 && !globalKeys.has(key))
if (missed.length > 0) {
  crossIssues += missed.length
  console.log(`   MISSED ESCALATION (${missed.length}) — index shows 2+ projects but the gate is not global; doctor --repair escalates:`)
  for (const [key, entry] of missed.slice(0, 10)) console.log(`     - ${key} projects=${entry.projects.length}`)
}
if (crossIssues === 0) console.log("   ok")
issues += crossIssues

console.log(`\n${issues === 0 ? "OK: no pathologies" : `ISSUES: ${issues}`}`)
