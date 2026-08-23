/**
 * Mutation fuzzer for the normalization pipeline with a metamorphic oracle —
 * no ground-truth spec needed, the invariants ARE the spec. Seeded by default
 * so CI is reproducible; explore other regions with --seed=<n> --runs=<n>.
 *
 * Run: bun test/fuzz.ts [--seed=N] [--runs=N]
 */
import { normalizeCommand, splitChain } from "../src/patterns"
import { hasNestedTokens } from "../src/validate"

// --- seeded RNG ------------------------------------------------------------------

const seedArg = process.argv.find((a) => a.startsWith("--seed="))
const runsArg = process.argv.find((a) => a.startsWith("--runs="))
let seed = seedArg ? Number(seedArg.split("=")[1]) : 20260824
const RUNS = runsArg ? Number(runsArg.split("=")[1]) : 5000
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

// --- corpus: real-world command shapes ---------------------------------------------

const CORPUS = [
  "npm run definitely-broken-xyz",
  "git push origin main",
  './gradlew :app:compileTestJava 2>&1 | Select-Object -Last 30',
  'python -c "import json; print(json.dumps({\'a\': 1}))"',
  'node -e "process.exit(7)"',
  'curl -s -o C:\\tmp\\out.json -w "%{http_code}" https://api.example.com/v1',
  "npx tsc --noEmit 2>&1",
  'cd D:\\Sources\\StartUp\\Muffin && ./gradlew cucumberTest "smoke" 1>&2',
  'ssh user@192.168.1.100 -p 2222 "sudo systemctl restart app"',
  "docker run --rm -p 8080:80 image:1.2.3",
  'echo "line1\nline2" | grep -n foo',
  "python -m pytest -q tests\\test_phase4.py 2>&1 | Select-Object -Last 10",
  'bun scripts/doctor.ts "D:\\Sources\\AI\\AiApiRadar"',
  '& "C:\\Python312\\python.exe" -c @"print(1)"@',
  "grep -rn 'TODO' src/ | head -5",
  "flutter analyze --no-fatal-infos --machine 1>&2 | select-string warning",
]

// --- mutation -----------------------------------------------------------------------

const SPECIALS = ['"', "'", "(", ")", ";", "|", "&", "#", "\\", "$", "`", "\n", "\r", "<", ">", "@", "-", " ", "\t", "{", "}"]

function mutate(s: string): string {
  const op = rint(6)
  const at = rint(Math.max(s.length, 1))
  switch (op) {
    case 0: // insert special
      return s.slice(0, at) + pick(SPECIALS) + s.slice(at)
    case 1: // delete char
      return s.length > 0 ? s.slice(0, at) + s.slice(at + 1) : s
    case 2: // substitute char
      return s.length > 0 ? s.slice(0, at) + pick(SPECIALS) + s.slice(at + 1) : pick(SPECIALS)
    case 3: // swap neighbors
      if (s.length < 2) return s
      return s.slice(0, at) + s.charAt(Math.min(at + 1, s.length - 1)) + s.charAt(at) + s.slice(at + 2)
    case 4: // duplicate char
      return s.length > 0 ? s.slice(0, at) + s.charAt(at) + s.slice(at) : s
    default: {
      // splice in a bash-significant fragment
      const fragments = ["&&", "||", "|", ";", "$(", ")", "`", '"', "'", " # dejavu:proceed", "\r\n", "<<EOF"]
      return s.slice(0, at) + pick(fragments) + s.slice(at)
    }
  }
}

// --- metamorphic oracle: returns a failure reason, or null when the input is sane ---

function oracle(cmd: string): string | null {
  let norm: string
  try {
    norm = normalizeCommand(cmd)
  } catch (error) {
    return `normalizeCommand threw: ${String(error)}`
  }
  try {
    if (normalizeCommand(norm) !== norm) return `not idempotent: ${JSON.stringify(norm)} -> ${JSON.stringify(normalizeCommand(norm))}`
  } catch (error) {
    return `second pass threw: ${String(error)}`
  }
  if (hasNestedTokens(norm)) return `nested tokens: ${JSON.stringify(norm)}`
  if (norm.length > cmd.length * 5 + 64) return `output explosion: ${cmd.length} -> ${norm.length}`
  try {
    for (const seg of splitChain(cmd)) {
      if (seg.trim() === "") return "splitChain produced an empty segment"
      if (splitChain(seg).length !== 1) return `segment not atomic: ${JSON.stringify(seg)} -> ${JSON.stringify(splitChain(seg))}`
    }
  } catch (error) {
    return `splitChain threw: ${String(error)}`
  }
  return null
}

// --- greedy shrinking: keep the shortest input that still fails -----------------------

function shrink(cmd: string): string {
  let current = cmd
  for (let pass = 0; pass < 4; pass++) {
    let i = 0
    while (i < current.length) {
      const candidate = current.slice(0, i) + current.slice(i + 1)
      if (oracle(candidate) !== null) {
        current = candidate
      } else {
        i++
      }
    }
  }
  return current
}

// --- main loop: random walk from corpus seeds -------------------------------------------

let found = 0
let current = pick(CORPUS)
for (let i = 0; i < RUNS; i++) {
  if (rnd() < 0.05) current = pick(CORPUS) // occasionally reseed
  current = mutate(current)

  const failure = oracle(current)
  if (failure !== null) {
    found += 1
    const minimal = shrink(current)
    console.error(`FAIL - ${failure}`)
    console.error(`       mutated (${current.length} chars): ${JSON.stringify(current.slice(0, 300))}`)
    console.error(`       shrunk  (${minimal.length} chars): ${JSON.stringify(minimal)}`)
    if (found >= 5) break
    current = pick(CORPUS) // step away from the failing region
  }
}

if (found > 0) {
  console.error(`\n${found} fuzz failure(s) in ${RUNS} mutations (seed ${seed})`)
  process.exit(1)
}
console.log(`no failures across ${RUNS} mutations (seed ${seed})`)
