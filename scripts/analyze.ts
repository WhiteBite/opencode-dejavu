/**
 * Read-only summary of dejavu stores: statuses, tools, diagnostic-gate
 * leftovers, recurrence health, top patterns.
 *
 * Usage: bun scripts/analyze.ts [projectDir ...]
 */
import { homedir } from "node:os"
import { join } from "node:path"
import { isDiagnosticSignature } from "../src/patterns"
import { GateStore } from "../src/store"

const dirs = [
  process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu"),
  ...process.argv.slice(2).map((p) => join(p, ".opencode", "dejavu")),
]

for (const dir of dirs) {
  const store = new GateStore(dir)
  const gates = await store.load()
  console.log(`\n== ${dir}`)
  if (gates.length === 0) {
    console.log("   (empty)")
    continue
  }
  const blocking = gates.filter((g) => g.status === "blocking")
  const watching = gates.filter((g) => g.status === "watching")
  const byTool = new Map<string, number>()
  for (const g of gates) byTool.set(g.tool, (byTool.get(g.tool) ?? 0) + 1)
  console.log(
    `   total ${gates.length} | blocking ${blocking.length} | watching ${watching.length} | tools: ${[...byTool.entries()].map(([t, n]) => `${t}:${n}`).join(" ")}`,
  )

  const diag = blocking.filter((g) => isDiagnosticSignature(g.signature))
  console.log(`   blocking diagnostic gates (v1 leftovers): ${diag.length}`)
  for (const g of diag.slice(0, 10)) {
    console.log(`     - [${g.count}x, recurred ${g.recurredAfterGate}] ${g.signature}`)
  }

  const recurred = gates.filter((g) => g.recurredAfterGate > 0).sort((a, b) => b.recurredAfterGate - a.recurredAfterGate)
  console.log(`   gates with recurredAfterGate > 0: ${recurred.length}`)
  for (const g of recurred.slice(0, 8)) {
    console.log(
      `     - recurred ${g.recurredAfterGate} | reminded ${g.remindedCount} | blocked ${g.blockedCount} | ${g.signature}`,
    )
  }

  const top = [...gates].sort((a, b) => b.count - a.count).slice(0, 8)
  console.log("   top by count:")
  for (const g of top) {
    console.log(`     - ${g.count}x / ${g.sessions.length} sess [${g.status}] ${g.signature}`)
  }
}
