/**
 * Property-based tests for the normalization pipeline — no framework needed.
 * A seeded generator composes bash-like commands from structural fragments
 * (chains, quotes, one-liners, paths, hashes, comments, markers); every
 * generated input must satisfy the mechanical invariants below. These are the
 * invariants the escaping edge cases kept violating before they were found.
 *
 * Run: bun test/property.ts
 */
import {
  callSignature,
  fuzzySimilar,
  normalizeCommand,
  parameterizeError,
  scrubSecrets,
  splitChain,
} from "../src/patterns"
import { hasNestedTokens } from "../src/validate"

// --- seeded RNG (reproducible) -----------------------------------------------

let seed = 20260824
function rnd(): number {
  seed ^= seed << 13
  seed ^= seed >>> 17
  seed ^= seed << 5
  return (seed >>> 0) / 4294967296
}
function rint(max: number): number {
  return Math.floor(rnd() * max)
}
function pick<T>(arr: readonly T[]): T {
  return arr[rint(arr.length)] as T
}

// --- generator ----------------------------------------------------------------

const VERBS = [
  "npm run build",
  "git status",
  "./gradlew test",
  "python main.py",
  "bun install",
  "cargo build",
  "curl -s http://localhost:3000/api",
  "docker compose up",
  "npx tsc --noEmit",
  "flutter analyze",
  "grep -n foo bar.txt",
]
const CHAINS = [" && ", " || ", " | ", "; ", "\n", "\r\n"]
const QUOTED = ['"hello world"', "'single'", '"with spaces"', '"a;b"', '"nested \\"quote\\""', "'it''s'"]
const ONELINERS = [
  'python -c "print(1)"',
  'node -e "process.exit(1)"',
  'bun -e "throw new Error(1)"',
  'python -c "import os; print(os.name)"',
  'pwsh -Command "Get-Process"',
  "python3 -u -c \"open('f').read()\"",
]
const PATHS = ["C:\\Users\\dev\\project\\file.ts", "/usr/local/bin/tool", "./relative/path.txt", "D:\\Sources\\AI\\repo\\src\\index.ts"]
const HEXES = ["abc123def456", "7f3a9b2c", "deadbeefcafe0123", "1234567"]
const NUMS = ["0", "1", "42", "3.14", "8080", "192.168.1.100"]
const COMMENTS = ["# probe", "# dejavu:proceed", "# comment with 'quotes'"]
const SECRETS = ["sk-proj-ABCDEFGHIJKLMNOPQRSTuv012345", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"]

function genCommand(): string {
  const parts: string[] = []
  const n = 1 + rint(4)
  for (let i = 0; i < n; i++) {
    const roll = rnd()
    if (roll < 0.25) parts.push(pick(VERBS))
    else if (roll < 0.4) parts.push(`${pick(VERBS)} ${pick(QUOTED)}`)
    else if (roll < 0.55) parts.push(pick(ONELINERS))
    else if (roll < 0.7) parts.push(`cd ${pick(PATHS)}`)
    else if (roll < 0.8) parts.push(`echo ${pick(NUMS)}`)
    else if (roll < 0.9) parts.push(`git log ${pick(HEXES)}`)
    else parts.push(pick(COMMENTS))
  }
  let cmd = parts.join(pick(CHAINS))
  if (rnd() < 0.1) cmd += ` ${pick(COMMENTS)}`
  return cmd
}

function genErrorText(): string {
  const templates = [
    "ENOENT: no such file or directory, open '/tmp/x'",
    "Error: connect ECONNREFUSED 192.168.1.100:3000",
    "error TS2322: Type 'string' is not assignable to type 'number'",
    "Cannot find module 'lodash' at C:\\x\\y.ts",
    "timeout after 30000ms",
    "AssertionError: assert 'a' == 'b'",
    "exit code 1: command not found",
  ]
  return pick(templates)
}

// --- runner ---------------------------------------------------------------------

let failures = 0
function fail(name: string, detail: string): void {
  failures += 1
  if (failures <= 10) console.error(`FAIL - ${name}\n       ${detail}`)
}

const RUNS = 3000

for (let i = 0; i < RUNS; i++) {
  const cmd = genCommand()

  let norm: string
  try {
    norm = normalizeCommand(cmd)
  } catch (error) {
    fail("normalizeCommand threw", `${String(error)} on ${JSON.stringify(cmd)}`)
    continue
  }
  if (normalizeCommand(norm) !== norm) {
    fail("normalizeCommand not idempotent", `${JSON.stringify(cmd)} -> ${JSON.stringify(norm)} -> ${JSON.stringify(normalizeCommand(norm))}`)
  }
  if (hasNestedTokens(norm)) {
    fail("nested placeholder tokens", `${JSON.stringify(cmd)} -> ${JSON.stringify(norm)}`)
  }
  if (norm.length > cmd.length * 5 + 64) {
    fail("output explosion", `${JSON.stringify(cmd)} (${cmd.length}) -> ${norm.length} chars`)
  }

  // splitChain: no empty segments; every segment is atomic (re-splits to itself)
  const segments = splitChain(cmd)
  for (const seg of segments) {
    if (seg.trim() === "") fail("splitChain produced empty segment", JSON.stringify(cmd))
    if (splitChain(seg).length !== 1) {
      fail("segment is not atomic under re-split", `${JSON.stringify(cmd)} -> segment ${JSON.stringify(seg)} -> ${JSON.stringify(splitChain(seg))}`)
    }
  }
}

// one-liner identity: different code = different key, same code = same key
const oneLinerA = 'python -c "fetch(\'alpha\')"'
const oneLinerB = 'python -c "fetch(\'beta\')"'
if (callSignature("bash", { command: oneLinerA }) === callSignature("bash", { command: oneLinerB })) {
  fail("one-liner distinctness", "different payloads collapsed to one signature")
}
if (callSignature("bash", { command: oneLinerA }) !== callSignature("bash", { command: oneLinerA })) {
  fail("one-liner determinism", "same payload produced different signatures")
}
if (!/<code:[0-9a-f]{8}>/.test(callSignature("bash", { command: oneLinerA }) ?? "")) {
  fail("one-liner fingerprint shape", callSignature("bash", { command: oneLinerA }) ?? "(null)")
}

// override marker neutrality: appending the marker never changes the signature
for (let i = 0; i < 200; i++) {
  const cmd = genCommand()
  const plain = callSignature("bash", { command: cmd })
  const marked = callSignature("bash", { command: `${cmd} # dejavu:proceed` })
  if (plain !== marked) {
    fail("override marker changed the signature", `${JSON.stringify(cmd)}: ${plain} vs ${marked}`)
    break
  }
}

// secrets must never survive the normalize+scrub pipeline
for (const secret of SECRETS) {
  const cmd = `curl -H "Authorization: ${secret}" https://api.example.com`
  const out = scrubSecrets(normalizeCommand(cmd))
  if (out.includes(secret)) fail("secret survived normalize+scrub", JSON.stringify(cmd))
}

// parameterizeError: idempotent and collapses variable parts
for (let i = 0; i < 500; i++) {
  const text = genErrorText()
  const once = parameterizeError(text)
  if (parameterizeError(once) !== once) {
    fail("parameterizeError not idempotent", `${JSON.stringify(text)} -> ${JSON.stringify(once)}`)
    break
  }
}
if (
  parameterizeError("fail 7c1811ed-e98f-4c9c-a9f9-58c757ff494f.json") !==
  parameterizeError("fail 0751007c-1234-5678-9abc-def012345678.json")
) {
  fail("parameterizeError uuid collapse", "distinct uuids produced distinct signatures")
}

// fuzzy similarity is symmetric
for (let i = 0; i < 500; i++) {
  const a = `bash:${genCommand()}`
  const b = `bash:${genCommand()}`
  if (fuzzySimilar(a, b) !== fuzzySimilar(b, a)) {
    fail("fuzzySimilar not symmetric", `${JSON.stringify(a)} vs ${JSON.stringify(b)}`)
    break
  }
}

if (failures > 0) {
  console.error(`\n${failures} property failure(s) out of ${RUNS} generated inputs`)
  process.exit(1)
}
console.log(`all properties held across ${RUNS} generated inputs`)
