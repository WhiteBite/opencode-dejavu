/**
 * One-off migration runner for existing dejavu stores.
 * Demotes probe-tool blocking gates to watching and secret-scrubs all
 * signatures/snippets. Idempotent; also runs automatically at plugin init.
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
  const stores = new Stores(globalStore, new GateStore(join(project, ".opencode", "dejavu")))
  await stores.migrate()
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
