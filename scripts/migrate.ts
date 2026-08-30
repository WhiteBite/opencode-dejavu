/**
 * One-off migration runner for existing dejavu stores.
 * Re-tiers gates learned under older policies (probe-tool blocking → watching,
 * diagnostics → reminding), backfills mechanical corrections, sanitizes
 * signatures/snippets/corrections (secrets + terminal control chars), applies
 * feedback-demotion catch-up, and merges stale project copies of global gates.
 * Idempotent; also runs automatically at plugin init.
 *
 * WARNING: the log-scrub step below rewrites log.jsonl WITHOUT the log lock —
 * run this while OpenCode is closed, or appends racing the rewrite are lost.
 *
 * Usage: bun scripts/migrate.ts <projectDir> [moreProjectDirs...]
 */
import { readFile, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { scrubSecrets } from "../src/patterns"
import { GateStore, Stores } from "../src/store"

const globalStore = new GateStore(process.env.DEJAVU_HOME ?? join(homedir(), ".config", "opencode", "dejavu"))
const projects = process.argv.slice(2)
const targets = projects.length > 0 ? projects : [process.cwd()]

for (const project of targets) {
  const projectStore = new GateStore(join(project, ".opencode", "dejavu"))
  const stores = new Stores(globalStore, projectStore)
  await stores.migrate()
  // The script exits after this — flush deferred demotion events now, or they
  // are silently lost ("every repair is logged" invariant).
  await globalStore.flushDeferred()
  await projectStore.flushDeferred()
  console.log(`migrated: ${project}`)
}

// Historical logs are scrubbed too — secrets must not linger on disk.
const logDirs = [globalStore.dir, ...targets.map((t) => join(t, ".opencode", "dejavu"))]
for (const dir of logDirs) {
  const logPath = join(dir, "log.jsonl")
  try {
    const raw = await readFile(logPath, "utf8")
    const scrubbed = scrubSecrets(raw)
    if (scrubbed !== raw) {
      await writeFile(logPath, scrubbed, "utf8")
      console.log(`scrubbed log: ${logPath}`)
    }
  } catch {
    // missing log is fine
  }
}
