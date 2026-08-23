/**
 * One-command pathology report for dejavu stores. Surfaces every known
 * defect class so debugging starts from facts, not guesses.
 *
 * Usage: bun scripts/doctor.ts [projectDir ...]
 */
import { readFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { canBlock, scrubSecrets } from "../src/patterns"
import { GateStore, PLUGIN_VERSION } from "../src/store"

const dirs = [
  process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu"),
  ...process.argv.slice(2).map((p) => join(p, ".opencode", "dejavu")),
]

let issues = 0
for (const dir of dirs) {
  const store = new GateStore(dir)
  const gates = await store.load()
  console.log(`\n== ${dir}`)
  if (gates.length === 0) console.log("   (empty)")

  const staleBlocking = gates.filter((g) => g.status === "blocking" && !canBlock(g.tool, g.signature))
  if (staleBlocking.length > 0) {
    issues += staleBlocking.length
    console.log(`   STALE BLOCKING outside policy (${staleBlocking.length}) — run scripts/migrate.ts:`)
    for (const g of staleBlocking.slice(0, 10)) console.log(`     - ${g.signature}`)
  }

  const notTeaching = gates.filter((g) => g.recurredAfterGate >= 3)
  if (notTeaching.length > 0) {
    issues += notTeaching.length
    console.log(`   NOT TEACHING recurredAfterGate>=3 (${notTeaching.length}) — gate fires but error recurs; write a correction or delete:`)
    for (const g of notTeaching.slice(0, 10)) console.log(`     - recurred ${g.recurredAfterGate} | ${g.signature}`)
  }

  const annoying = gates.filter((g) => g.remindedCount >= 10)
  if (annoying.length > 0) {
    issues += annoying.length
    console.log(`   ANNOYING reminded>=10 (${annoying.length}):`)
    for (const g of annoying.slice(0, 10)) console.log(`     - reminded ${g.remindedCount} | ${g.signature}`)
  }

  const leaky = gates.filter((g) => scrubSecrets(g.signature) !== g.signature || scrubSecrets(g.snippet) !== g.snippet)
  if (leaky.length > 0) {
    issues += leaky.length
    console.log(`   SECRETS ON DISK (${leaky.length}) — run scripts/migrate.ts`)
  }

  try {
    const raw = await readFile(join(dir, "log.jsonl"), "utf8")
    const inits = raw.split("\n").filter((l) => l.includes('"type":"init"'))
    const last = inits[inits.length - 1]
    const version = last ? ((JSON.parse(last) as { version?: string }).version ?? "unknown") : "none"
    if (version !== PLUGIN_VERSION) {
      issues += 1
      console.log(`   VERSION DRIFT: last init in log = ${version}, current = ${PLUGIN_VERSION} — stale plugin sessions were writing here; restart OpenCode`)
    } else {
      console.log(`   version ok (${version})`)
    }
  } catch {
    console.log("   (no log yet)")
  }
}

console.log(`\n${issues === 0 ? "OK: no pathologies" : `ISSUES: ${issues}`}`)
