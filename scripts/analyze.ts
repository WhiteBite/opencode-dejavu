/**
 * Read-only summary of dejavu stores: statuses, tools, recurrence health,
 * top patterns.
 *
 * Usage: bun scripts/analyze.ts [projectDir ...]
 *   without arguments, project stores are discovered from the global index
 */
import { existsSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { GateStore } from "../src/store"

const globalDir = process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu")
let projectArgs = process.argv.slice(2)
if (projectArgs.length === 0) {
  const discovered = new Set<string>()
  const index = await new GateStore(globalDir).loadIndex()
  for (const entry of Object.values(index.keys)) {
    if (!entry || !Array.isArray(entry.projects)) continue
    for (const project of entry.projects) {
      if (typeof project === "string" && existsSync(join(project, ".opencode", "dejavu"))) discovered.add(project)
    }
  }
  projectArgs = [...discovered].sort()
}
const dirs = [globalDir, ...projectArgs.map((p) => join(p, ".opencode", "dejavu"))]

for (const dir of dirs) {
  const store = new GateStore(dir)
  const gates = await store.load()
  console.log(`\n== ${dir}`)
  if (gates.length === 0) {
    console.log("   (empty)")
    continue
  }
  const blocking = gates.filter((g) => g.status === "blocking")
  const reminding = gates.filter((g) => g.status === "reminding")
  const watching = gates.filter((g) => g.status === "watching")
  const feedbackDemoted = gates.filter((g) => g.feedbackDemoted === true)
  const byTool = new Map<string, number>()
  for (const g of gates) byTool.set(g.tool, (byTool.get(g.tool) ?? 0) + 1)
  console.log(
    `   total ${gates.length} | blocking ${blocking.length} | reminding ${reminding.length} | watching ${watching.length}${feedbackDemoted.length > 0 ? ` | feedback-demoted ${feedbackDemoted.length}` : ""} | tools: ${[...byTool.entries()].map(([t, n]) => `${t}:${n}`).join(" ")}`,
  )

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
