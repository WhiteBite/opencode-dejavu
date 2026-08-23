/**
 * Behavioral smoke test for the dejavu state machine.
 * Run: bun test/smoke.ts
 */
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Dejavu } from "../index"
import { callSignature, canBlock, fuzzySimilar, parameterizeError, scrubSecrets, splitChain } from "../src/patterns"
import { GateStore, Stores } from "../src/store"

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
  firstSeen: string
  lastSeen: string
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
await new Promise((resolve) => setTimeout(resolve, 600)) // out of the concurrent-dispatch race window
const retry = await attempt(CMD, "s3", "c5")
check("retry after reminder is allowed", retry === null)

// --- 4. the retry fails again -> next attempt is hard-blocked ---
await fail(CMD, "s3", "c5")
const blocked = await attempt(CMD, "s3", "c6")
check("repeat failure after reminder throws BLOCKED", blocked !== null && blocked.message.includes("[dejavu] BLOCKED"))

// --- 5. explicit override bypasses the gate ---
const override = await attempt(`${CMD} # dejavu:proceed`, "s3", "c7")
check("dejavu:proceed bypasses the gate", override === null)

// --- 5b. override marker inside quoted strings must NOT bypass ---
const smuggle = await attempt(`echo "dejavu:proceed" && ${CMD}`, "s-smuggle", "c-smuggle1")
check("override marker inside quotes does not bypass", smuggle !== null && smuggle.message.includes("[dejavu] REMINDER"))

// --- 5c. concurrent first encounters are all reminded; a true retry comes later ---
const raceFirst = await attempt(CMD, "s-race", "r1")
const raceSibling = await attempt(CMD, "s-race", "r2")
check(
  "call dispatched in the reminder burst is reminded too (race guard)",
  raceFirst !== null && raceSibling !== null && raceSibling.message.includes("[dejavu] REMINDER"),
)
await new Promise((resolve) => setTimeout(resolve, 600))
const raceRetry = await attempt(CMD, "s-race", "r3")
check("retry after the race window is allowed", raceRetry === null)

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
const gate2 = gates.find((g) => g.signature.startsWith("bash:bun -e <code:"))
check("metadata.exit promotes gate with empty output text", gate2?.status === "blocking")
check("interpreter payload is fingerprinted, not flattened to <str>", gate2 !== undefined && !gates.some((g) => g.signature === "bash:bun -e <str>"))

// --- 7b. interpreter one-liners: the code IS the identity ---
const PY_A = 'python -c "print(\'alpha\')"'
const PY_B = 'python -c "print(\'beta\')"'
check("same one-liner normalizes to one key", callSignature("bash", { command: PY_A }) === callSignature("bash", { command: PY_A }))
check("different one-liner code gets different keys", callSignature("bash", { command: PY_A }) !== callSignature("bash", { command: PY_B }))
// sha1 fingerprint of this payload is 14021754 — ALL digits (~2.3% of payloads);
// the number-parameterization rule must not eat it or every such one-liner collapses
const PY_DIGIT_FP = 'python -c "print(16)"'
check("all-digit code fingerprint survives number parameterization", (callSignature("bash", { command: PY_DIGIT_FP }) ?? "").includes("<code:14021754>"))
check(
  "legacy bare-<str> interpreter shapes cannot block",
  !canBlock("bash", "bash:python -c <str>") && !canBlock("bash", "bash:node -e <str>") && !canBlock("bash", "bash:& <str> -c @ <str> @"),
)
check("fingerprinted one-liners can still block", canBlock("bash", callSignature("bash", { command: PY_A }) ?? ""))

// --- 8. chain bypass: a gated command hidden behind && still gets reminded ---
const chained = await attempt(`echo ok && ${CMD}`, "s9", "c9")
check("chain bypass is caught via segment match", chained !== null && chained.message.includes("[dejavu] REMINDER"))

// --- 9. normalization unit checks ---
check(
  "agent comments stripped from signatures",
  callSignature("bash", { command: "# probe the api\ngit status" }) === callSignature("bash", { command: "git status" }),
)
check(
  "CRLF commands normalize identically to LF",
  callSignature("bash", { command: "echo a\r\necho b" }) === callSignature("bash", { command: "echo a\necho b" }),
)
check("chain split handles CRLF", JSON.stringify(splitChain("echo a\r\necho b")) === JSON.stringify(["echo a", "echo b"]))
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

// --- 15b. aborted/cancelled executions are noise, not failures ---
await emitToolError("noise1", "background_output", "s60", "Tool execution aborted")
await emitToolError("noise2", "background_output", "s61", "The tool execution was aborted by the user")
gates = await readGates()
check("aborted tool executions are not recorded", !gates.some((g) => g.tool === "background_output"))

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

// --- 19. scrubSecrets covers Google keys, full PEM blocks, KEY=VALUE secrets ---
const PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADKCAQEAtest\n-----END PRIVATE KEY-----"
check(
  "google api keys scrubbed",
  scrubSecrets("export GOOGLE_API_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678").includes("<redacted>"),
)
check("pem body scrubbed, not just header", !scrubSecrets(PEM).includes("MIIEvQIBADKCAQEAtest"))
check("env-style KEY=VALUE scrubbed", scrubSecrets("curl -H x --token SECRET_KEY_BASE=abcdefghij1234567890abcd").includes("<redacted>"))

// --- 20. fuzzy floor: verb-level-different commands must NOT merge ---
check("git push vs git pull not fuzzy-similar", !fuzzySimilar("bash:git push <str>", "bash:git pull <str>"))
check("real near-duplicates still fuzzy-similar", fuzzySimilar("bash:gradlew :app:compiletestjava", "bash:gradlew :web:compiletestjava"))
check(
  "different code fingerprints never fuzzy-merge (3-char hash distance passes the ratio rule)",
  !fuzzySimilar("bash:python -c <code:14021754>", "bash:python -c <code:14021abc>"),
)
check(
  "same fingerprint with surrounding variation still fuzzy-matches",
  fuzzySimilar("bash:python -c <code:14021754>", "bash:python -c <code:14021754> --verbose"),
)

// --- 21. scope escalation, production-shaped: two project windows, one global store ---
// Each Dejavu instance only sees its own project store — cross-project
// visibility comes exclusively from the global index.
const projA = join(tmp, "projA")
const projB = join(tmp, "projB")
const ctxA = { directory: projA, client: { app: { log: async () => ({}) } } } as unknown as Ctx
const ctxB = { directory: projB, client: { app: { log: async () => ({}) } } } as unknown as Ctx
const hooksA = await Dejavu(ctxA)
const hooksB = await Dejavu(ctxB)
const afterA = hooksA["tool.execute.after"] as AfterHook
const afterB = hooksB["tool.execute.after"] as AfterHook
const readJson = async (p: string): Promise<GateRow[]> =>
  (JSON.parse(await readFile(p, "utf8")) as { gates: GateRow[] }).gates
const failIn = (hook: AfterHook) => (session: string, callID: string, command: string): Promise<void> =>
  hook(
    { tool: "bash", sessionID: session, callID, args: { command } } as unknown as AfterInput,
    { title: command, output: "npm ERR! boom\nExit code: 1", metadata: {} } as unknown as AfterOutput,
  )
const failA = failIn(afterA)
const failB = failIn(afterB)
const ESC_CMD = "deploy-tool --broken-flag"
const escSig = `bash:${ESC_CMD}`
const gatesAPath = join(projA, ".opencode", "dejavu", "gates.json")
const gatesBPath = join(projB, ".opencode", "dejavu", "gates.json")
const globalGatesPath = join(tmp, "global", "gates.json")

await failA("ea1", "x1", ESC_CMD)
await failA("ea1", "x2", ESC_CMD)
await failA("ea2", "x3", ESC_CMD)
check("pattern promotes in its own project store first", (await readJson(gatesAPath)).some((g) => g.signature === escSig && g.status === "blocking"))

await failB("eb1", "x4", ESC_CMD)
check("second project escalates the pattern to the global store", (await readJson(globalGatesPath)).some((g) => g.signature === escSig))
check("escalated gate is spliced out of the second project store", !(await readJson(gatesBPath)).some((g) => g.signature === escSig))

await Dejavu(ctxA) // next init in project A merges the leftover local copy into global
const aGatesAfter = await readJson(gatesAPath)
const globalGate = (await readJson(globalGatesPath)).find((g) => g.signature === escSig)
check(
  "project copy dedupes into the global gate on next init",
  !aGatesAfter.some((g) => g.signature === escSig) && globalGate !== undefined && globalGate.count >= 4 && globalGate.sessions.length >= 3,
)

// --- 22. self-healing: corrupt gates.json is quarantined, plugin keeps working ---
const sickDir = join(tmp, "sick-project")
const sickDejavu = join(sickDir, ".opencode", "dejavu")
await mkdir(sickDejavu, { recursive: true })
await writeFile(join(sickDejavu, "gates.json"), "{ this is not json", "utf8")
await Dejavu({ directory: sickDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const quarantineFiles = (await readdir(sickDejavu)).filter((f) => f.startsWith("gates.json.corrupt-"))
check("corrupt gates.json is quarantined with bytes kept", quarantineFiles.length === 1)
check("quarantined bytes are preserved", (await readFile(join(sickDejavu, quarantineFiles[0] ?? ""), "utf8")).includes("this is not json"))
check("plugin starts with a fresh store after quarantine", (await readJson(join(sickDejavu, "gates.json"))).length === 0)

// --- 23. self-healing: reconcile merges duplicate keys and swaps inverted dates ---
const healDir = join(tmp, "heal-project")
const healDejavu = join(healDir, ".opencode", "dejavu")
await mkdir(healDejavu, { recursive: true })
const healBase = {
  key: "beef00000001",
  signature: "bash:heal me",
  tool: "bash",
  status: "watching",
  count: 1,
  sessions: ["h1"],
  projects: [healDir],
  firstSeen: "2026-08-20T00:00:00.000Z",
  lastSeen: "2026-08-10T00:00:00.000Z",
  snippet: "exit code 1",
  remindedCount: 0,
  blockedCount: 0,
  recurredAfterReminder: 0,
  recurredAfterGate: 0,
}
await writeFile(
  join(healDejavu, "gates.json"),
  JSON.stringify({ version: 1, gates: [{ ...healBase }, { ...healBase, count: 2, sessions: ["h2"] }] }),
  "utf8",
)
await Dejavu({ directory: healDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const healed = await readJson(join(healDejavu, "gates.json"))
const healedGate = healed[0]
check(
  "duplicate keys merge and inverted dates swap on reconcile",
  healed.length === 1 &&
    healedGate !== undefined &&
    healedGate.count === 3 &&
    healedGate.sessions.length === 2 &&
    healedGate.firstSeen <= healedGate.lastSeen,
)

// --- 24. self-healing: corrupt log lines excised, bytes preserved ---
const logDir = join(tmp, "log-project")
const logDejavu = join(logDir, ".opencode", "dejavu")
await mkdir(logDejavu, { recursive: true })
await writeFile(
  join(logDejavu, "log.jsonl"),
  `{"ts":"2026-08-23T00:00:00.000Z","type":"init","key":"dejavu","version":"2.1.0"}\n{broken line\n`,
  "utf8",
)
await Dejavu({ directory: logDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const healedLog = (await readFile(join(logDejavu, "log.jsonl"), "utf8")).split("\n").filter((l) => l.trim() !== "")
check(
  "live log has zero unparseable lines after reconcile",
  healedLog.every((l) => {
    try {
      JSON.parse(l)
      return true
    } catch {
      return false
    }
  }),
)
check("excised bytes preserved in log.jsonl.corrupt", (await readFile(join(logDejavu, "log.jsonl.corrupt"), "utf8").catch(() => "")).includes("{broken line"))

// --- 25. self-healing: index orphans pruned, missing rebuilt, proven gates escalated ---
const idxGlobalDir = join(tmp, "idx-global")
const idxProjectDir = join(tmp, "idx-project")
await mkdir(idxGlobalDir, { recursive: true })
await mkdir(join(idxProjectDir, ".opencode", "dejavu"), { recursive: true })
const idxGate = (key: string, signature: string): Record<string, unknown> => ({
  key,
  signature,
  tool: "bash",
  status: "watching",
  count: 1,
  sessions: ["i1"],
  projects: [idxProjectDir],
  firstSeen: "2026-08-23T00:00:00.000Z",
  lastSeen: "2026-08-23T00:00:00.000Z",
  snippet: "exit code 1",
  remindedCount: 0,
  blockedCount: 0,
  recurredAfterReminder: 0,
  recurredAfterGate: 0,
})
// global store: gate dddd without an index entry + orphan index key ffff
await writeFile(join(idxGlobalDir, "gates.json"), JSON.stringify({ version: 1, gates: [idxGate("dddd00000001", "bash:index me")] }), "utf8")
await writeFile(
  join(idxGlobalDir, "index.json"),
  JSON.stringify({
    version: 1,
    keys: {
      ffff00000001: { projects: ["nowhere"], lastSeen: "2026-08-20T00:00:00.000Z" },
      eeee00000001: { projects: ["projA", "projB"], lastSeen: "2026-08-23T00:00:00.000Z" },
    },
  }),
  "utf8",
)
// project store: gate eeee proven in 2 project dirs (per index) but never escalated
await writeFile(
  join(idxProjectDir, ".opencode", "dejavu", "gates.json"),
  JSON.stringify({ version: 1, gates: [idxGate("eeee00000001", "bash:escalate via index")] }),
  "utf8",
)
const idxStores = new Stores(new GateStore(idxGlobalDir), new GateStore(join(idxProjectDir, ".opencode", "dejavu")))
await idxStores.reconcileAll()
const idxAfter = await new GateStore(idxGlobalDir).loadIndex(true)
const idxGlobalGates = await new GateStore(idxGlobalDir).load(true)
const idxProjectGates = await new GateStore(join(idxProjectDir, ".opencode", "dejavu")).load(true)
check("orphan index key pruned", idxAfter.keys["ffff00000001"] === undefined)
check("missing index entry rebuilt from the global gate", idxAfter.keys["dddd00000001"] !== undefined)
check(
  "gate proven in 2+ projects escalates to global on reconcile",
  idxGlobalGates.some((g) => g.key === "eeee00000001") && !idxProjectGates.some((g) => g.key === "eeee00000001"),
)

// --- 26. multi-window: session state lives on the gate, not in a process ---
const winDir = join(tmp, "win-project")
const hooksW1 = await Dejavu({ directory: winDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const hooksW2 = await Dejavu({ directory: winDir, client: { app: { log: async () => ({}) } } } as unknown as Ctx)
const w1Before = hooksW1["tool.execute.before"] as BeforeHook
const w2Before = hooksW2["tool.execute.before"] as BeforeHook
const w1After = hooksW1["tool.execute.after"] as AfterHook
const w2After = hooksW2["tool.execute.after"] as AfterHook
const WIN_CMD = "deploy --to prod"
const winFail = async (hook: AfterHook, session: string, callID: string): Promise<void> => {
  await hook(
    { tool: "bash", sessionID: session, callID, args: { command: WIN_CMD } } as unknown as AfterInput,
    { title: WIN_CMD, output: "npm ERR! boom\nExit code: 1", metadata: {} } as unknown as AfterOutput,
  )
}
await winFail(w1After, "wa", "p1")
await winFail(w1After, "wa", "p2")
await winFail(w1After, "wb", "p3")
check(
  "gate promoted for multi-window test",
  (await readJson(join(winDir, ".opencode", "dejavu", "gates.json"))).some((g) => g.signature === `bash:${WIN_CMD}` && g.status === "blocking"),
)
const attemptOn = (hook: BeforeHook) => async (session: string, callID: string): Promise<Error | null> => {
  try {
    await hook({ tool: "bash", sessionID: session, callID } as unknown as BeforeInput, { args: { command: WIN_CMD } } as unknown as BeforeOutput)
    return null
  } catch (error) {
    return error as Error
  }
}
const remindW1 = await attemptOn(w1Before)("shared-ses", "p4")
check("window 1 reminds on first encounter", remindW1 !== null && remindW1.message.includes("[dejavu] REMINDER"))
await new Promise((resolve) => setTimeout(resolve, 1100)) // session moves to window 2: past the TTL and the race window
const seenByW2 = await attemptOn(w2Before)("shared-ses", "p5")
check("window 2 sees window 1's reminder (state is on the gate, not in the process)", seenByW2 === null)
await winFail(w2After, "shared-ses", "p6")
const blockedW1 = await attemptOn(w1Before)("shared-ses", "p7")
check("block escalates across processes", blockedW1 !== null && blockedW1.message.includes("[dejavu] BLOCKED"))

// --- 27. fuzzy pre-filters: length band + over-long cap ---
check(
  "length-band pre-filter rejects impossible fuzzy matches",
  !fuzzySimilar("bash:git push <str>", "bash:completely different and much longer command shape here"),
)
check(
  "over-long signatures never fuzzy-match (exact only)",
  !fuzzySimilar(`bash:${"x".repeat(320)}`, `bash:${"x".repeat(320)} tail`),
)

await rm(tmp, { recursive: true, force: true })

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`)
  process.exit(1)
}
console.log("\nall checks passed")
