/**
 * Behavioral smoke test for the dejavu state machine.
 * Run: bun test/smoke.ts
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Dejavu } from "../index"
import { callSignature, parameterizeError, splitChain } from "../src/patterns"

type Ctx = Parameters<typeof Dejavu>[0]
type Hooks = Awaited<ReturnType<typeof Dejavu>>
type BeforeHook = NonNullable<Hooks["tool.execute.before"]>
type AfterHook = NonNullable<Hooks["tool.execute.after"]>
type EventHook = NonNullable<Hooks["event"]>
type BeforeInput = Parameters<BeforeHook>[0]
type BeforeOutput = Parameters<BeforeHook>[1]
type AfterInput = Parameters<AfterHook>[0]
type AfterOutput = Parameters<AfterHook>[1]
type EventInput = Parameters<EventHook>[0]

interface GateRow {
  key: string
  signature: string
  tool: string
  status: string
  count: number
  sessions: string[]
  snippet: string
}

let failures = 0
function check(name: string, ok: boolean): void {
  if (ok) {
    console.log(`ok   - ${name}`)
  } else {
    failures += 1
    console.error(`FAIL - ${name}`)
  }
}

const tmp = await mkdtemp(join(tmpdir(), "dejavu-test-"))
process.env.DEJAVU_HOME = join(tmp, "global")

const ctx = {
  directory: join(tmp, "project"),
  client: { app: { log: async () => ({}) } },
} as unknown as Ctx

// --- Pre-seed: gates learned under the OLD policy, one with a leaked secret ---
await mkdir(join(tmp, "project", ".opencode", "dejavu"), { recursive: true })
const SECRET = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXyz0123456789"
await writeFile(
  join(tmp, "project", ".opencode", "dejavu", "gates.json"),
  JSON.stringify(
    {
      version: 1,
      gates: [
        {
          key: "aaaa00000001",
          signature: "read:legacy_probe.py",
          tool: "read",
          status: "blocking",
          count: 5,
          sessions: ["old1", "old2"],
          projects: ["oldproj"],
          firstSeen: "2026-08-01T00:00:00.000Z",
          lastSeen: "2026-08-20T00:00:00.000Z",
          snippet: "12: except (TypeError, ValueError):",
          remindedCount: 3,
          blockedCount: 1,
          recurredAfterReminder: 1,
          recurredAfterGate: 1,
        },
        {
          key: "aaaa00000002",
          signature: `bash:echo ${SECRET}`,
          tool: "bash",
          status: "watching",
          count: 1,
          sessions: ["old1"],
          projects: ["oldproj"],
          firstSeen: "2026-08-01T00:00:00.000Z",
          lastSeen: "2026-08-20T00:00:00.000Z",
          snippet: SECRET,
          remindedCount: 0,
          blockedCount: 0,
          recurredAfterReminder: 0,
          recurredAfterGate: 0,
        },
      ],
    },
    null,
    2,
  ),
  "utf8",
)

const hooks = await Dejavu(ctx)
const before = hooks["tool.execute.before"] as BeforeHook
const after = hooks["tool.execute.after"] as AfterHook

const gatesPath = join(tmp, "project", ".opencode", "dejavu", "gates.json")
const readGates = async (): Promise<GateRow[]> =>
  (JSON.parse(await readFile(gatesPath, "utf8")) as { gates: GateRow[] }).gates

// --- 0. migration: probe gates demoted, secrets scrubbed from old data ---
const migrated = await readGates()
const legacy = migrated.find((g) => g.key === "aaaa00000001")
const leaky = migrated.find((g) => g.key === "aaaa00000002")
check("migration demotes read-gates to watching", legacy?.status === "watching")
check("migration scrubs secrets from old gates", leaky !== undefined && !leaky.signature.includes("sk-proj-") && !leaky.snippet.includes("sk-proj-") && leaky.snippet.includes("<redacted>"))

const emitToolError = async (
  partId: string,
  tool: string,
  sessionID: string,
  error: string,
  input?: Record<string, unknown>,
): Promise<void> => {
  await (hooks.event as EventHook)({
    event: {
      type: "message.part.updated",
      properties: {
        part: { id: partId, type: "tool", tool, sessionID, state: { status: "error", error, input } },
      },
    },
  } as unknown as EventInput)
}

function fail(command: string, session: string, callID: string): Promise<void> {
  return after(
    { tool: "bash", sessionID: session, callID, args: { command } } as unknown as AfterInput,
    { title: CMD, output: "npm ERR! boom\nExit code: 1", metadata: {} } as unknown as AfterOutput,
  )
}

const CMD = "npm run definitely-broken-xyz"

async function attempt(command: string, session: string, callID: string): Promise<Error | null> {
  try {
    await before(
      { tool: "bash", sessionID: session, callID } as unknown as BeforeInput,
      { args: { command } } as unknown as BeforeOutput,
    )
    return null
  } catch (error) {
    return error as Error
  }
}

// --- 1. three failures across two sessions promote the pattern to a gate ---
await fail(CMD, "s1", "c1")
await fail(CMD, "s1", "c2")
await fail(CMD, "s2", "c3")
let gates = await readGates()
const gate1 = gates.find((g) => g.signature === `bash:${CMD}`)
check("gate promoted after 3 failures in 2 sessions", gate1?.status === "blocking" && gate1.count === 3 && gate1.sessions.length === 2)

// --- 2. first attempt in a fresh session is aborted with a REMINDER ---
const first = await attempt(CMD, "s3", "c4")
check("first attempt throws REMINDER", first !== null && first.message.includes("[dejavu] REMINDER"))

// --- 3. one retry after the reminder is allowed through ---
const retry = await attempt(CMD, "s3", "c5")
check("retry after reminder is allowed", retry === null)

// --- 4. the retry fails again -> next attempt is hard-blocked ---
await fail(CMD, "s3", "c5")
const blocked = await attempt(CMD, "s3", "c6")
check("repeat failure after reminder throws BLOCKED", blocked !== null && blocked.message.includes("[dejavu] BLOCKED"))

// --- 5. explicit override bypasses the gate ---
const override = await attempt(`${CMD} # dejavu:proceed`, "s3", "c7")
check("dejavu:proceed bypasses the gate", override === null)

// --- 6. unrelated commands are untouched ---
const unrelated = await attempt("git status", "s3", "c8")
check("unrelated command passes", unrelated === null)

// --- 7. metadata.exit detection: failure with no error text in output ---
const CMD2 = 'bun -e "process.exit(7)"'
for (const [session, callID] of [["s4", "d1"], ["s4", "d2"], ["s5", "d3"]] as const) {
  await after(
    { tool: "bash", sessionID: session, callID, args: { command: CMD2 } } as unknown as AfterInput,
    { title: CMD2, output: "(no output)", metadata: { output: "(no output)", exit: 1, truncated: false } } as unknown as AfterOutput,
  )
}
gates = await readGates()
const gate2 = gates.find((g) => g.signature === "bash:bun -e <str>")
check("metadata.exit promotes gate with empty output text", gate2?.status === "blocking")

// --- 8. chain bypass: a gated command hidden behind && still gets reminded ---
const chained = await attempt(`echo ok && ${CMD}`, "s9", "c9")
check("chain bypass is caught via segment match", chained !== null && chained.message.includes("[dejavu] REMINDER"))

// --- 9. normalization unit checks ---
check(
  "agent comments stripped from signatures",
  callSignature("bash", { command: "# probe the api\ngit status" }) === callSignature("bash", { command: "git status" }),
)
check(
  "chain split separates &&, ||, |, ;",
  JSON.stringify(splitChain("a && b || c | d;e")) === JSON.stringify(["a", "b", "c", "d", "e"]),
)
check("chain split respects subshell parens", splitChain("(cd /tmp && ls)").length === 1)
check("chain split is quote-aware", splitChain('echo "a;b"').length === 1)
check(
  "glob/grep signatures tracked",
  callSignature("glob", { pattern: "**/*.ts" }) === "glob:**/*.ts" && callSignature("grep", { pattern: "TODO" }) === "grep:todo",
)
check(
  "error parameterization dedupes variable parts",
  parameterizeError("Cannot find module 'lodash' at C:\\x\\y.ts") === parameterizeError("Cannot find module 'axios' at C:\\x\\z.ts"),
)

// --- 10. event channel: parameterized error text collapses across uuids ---
await emitToolError("p1", "todo", "s20", "ENOENT: no such file 7c1811ed-e98f-4c9c-a9f9-58c757ff494f.json")
await emitToolError("p2", "todo", "s21", "ENOENT: no such file 0751007c-1234-5678-9abc-def012345678.json")
gates = await readGates()
const todoGates = gates.filter((g) => g.tool === "todo")
check(
  "parameterized errors collapse into one pattern",
  todoGates.length === 1 && todoGates[0]?.count === 2 && todoGates[0]?.sessions.length === 2,
)

// --- 11. file-probe tools never promote to blocking (policy) ---
for (const [sess, call] of [["r1", "q1"], ["r2", "q2"], ["r3", "q3"], ["r4", "q4"]] as const) {
  await emitToolError(`rp-${sess}`, "read", sess, "File not found", { filePath: "src/missing_probe_target.py" })
}
gates = await readGates()
check("read failure stays watching at 4 occurrences", gates.find((g) => g.signature === "read:missing_probe_target.py")?.status === "watching")
await emitToolError("rp-r5", "read", "r5", "File not found", { filePath: "src/missing_probe_target.py" })
gates = await readGates()
check("read failure NEVER promotes (policy: probes cannot block)", gates.find((g) => g.signature === "read:missing_probe_target.py")?.status === "watching")

// --- 11b. diagnostics never promote either ---
const TSC = "npx tsc --noEmit"
await after(
  { tool: "bash", sessionID: "s50", callID: "t1", args: { command: TSC } } as unknown as AfterInput,
  { title: TSC, output: "src/x.ts(1,1): error TS2322: Type 'string' is not assignable", metadata: {} } as unknown as AfterOutput,
)
await after(
  { tool: "bash", sessionID: "s50", callID: "t2", args: { command: TSC } } as unknown as AfterInput,
  { title: TSC, output: "src/x.ts(1,1): error TS2322: Type 'string' is not assignable", metadata: {} } as unknown as AfterOutput,
)
await after(
  { tool: "bash", sessionID: "s51", callID: "t3", args: { command: TSC } } as unknown as AfterInput,
  { title: TSC, output: "src/x.ts(1,1): error TS2322: Type 'string' is not assignable", metadata: {} } as unknown as AfterOutput,
)
gates = await readGates()
check("diagnostic (tsc) never promotes to blocking", gates.find((g) => g.signature === `bash:${TSC.toLowerCase()}`)?.status === "watching")

// --- 12. read output is file CONTENT: text signatures must not apply ---
await after(
  { tool: "read", sessionID: "s10", callID: "e1", args: { filePath: "src/other.py" } } as unknown as AfterInput,
  { title: "src/other.py", output: "def f():\n    raise TypeError('boom')", metadata: {} } as unknown as AfterOutput,
)
gates = await readGates()
check("file content containing 'TypeError' is NOT a failure", !gates.some((g) => g.signature === "read:other.py"))

// --- 13. intended non-zero exits: grep exit 1 is normal, exit 2 is a failure ---
await after(
  { tool: "bash", sessionID: "s11", callID: "g1", args: { command: "grep -n foo bar.txt" } } as unknown as AfterInput,
  { title: "grep", output: "(no output)", metadata: { exit: 1 } } as unknown as AfterOutput,
)
gates = await readGates()
check("grep exit 1 (no match) is not recorded", !gates.some((g) => g.signature === "bash:grep -n foo bar.txt"))
await after(
  { tool: "bash", sessionID: "s11", callID: "g2", args: { command: "grep -n foo bar.txt" } } as unknown as AfterInput,
  { title: "grep", output: "grep: bar.txt: No such file or directory", metadata: { exit: 2 } } as unknown as AfterOutput,
)
gates = await readGates()
check("grep exit 2 (real error) IS recorded", gates.some((g) => g.signature === "bash:grep -n foo bar.txt"))

// --- 14. fuzzy near-duplicate matching (Levenshtein) reminds on variants ---
const CMD3 = "npm run broken-thing"
await fail(CMD3, "s30", "f1")
await fail(CMD3, "s30", "f2")
await fail(CMD3, "s31", "f3")
const variant = await attempt(`${CMD3} --extra`, "s32", "f4")
check("near-duplicate variant is reminded via fuzzy match", variant !== null && variant.message.includes("[dejavu] REMINDER"))

// --- 15. secrets are scrubbed on ingest (event channel) ---
await emitToolError("sec1", "todo", "s40", `boom ${SECRET} boom`)
gates = await readGates()
const secGate = gates.find((g) => g.tool === "todo" && g.snippet.includes("<redacted>"))
check("ingested snippets are secret-scrubbed", secGate !== undefined && !gates.some((g) => g.snippet.includes("sk-proj-")))

// --- 16. reminder wording teaches the trailing-comment bypass ---
check("reminder explains trailing-comment bypass", first !== null && first.message.includes("# dejavu:proceed"))

// --- 17. log events carry forensic fields (channel, version) ---
const logRaw = await readFile(join(tmp, "project", ".opencode", "dejavu", "log.jsonl"), "utf8")
const logLines = logRaw
  .split("\n")
  .filter((l) => l.trim() !== "")
  .map((l) => JSON.parse(l) as { type: string; channel?: string; version?: string })
check("init event stamps plugin version", logLines.some((l) => l.type === "init" && typeof l.version === "string"))
check(
  "detected events carry detection channel",
  logLines.some((l) => l.type === "detected" && l.channel === "exit") && logLines.some((l) => l.type === "detected" && l.channel === "text"),
)

// --- 18. init works in a fresh project dir (no pre-created .opencode) ---
const freshDir = join(tmp, "fresh-project")
await Dejavu({ directory: freshDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const freshLog = await readFile(join(freshDir, ".opencode", "dejavu", "log.jsonl"), "utf8").catch(() => "")
check("init writes log in fresh project dir", freshLog.includes('"type":"init"'))

await rm(tmp, { recursive: true, force: true })

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`)
  process.exit(1)
}
console.log("\nall checks passed")
