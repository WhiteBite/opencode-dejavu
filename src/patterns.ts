import { createHash } from "node:crypto"

/** Override marker stripped before normalization so bypassed failures land on the original pattern. */
const OVERRIDE_MARKER = /#?\s*dejavu:proceed/gi

/** Agent commentary lines ("# probing the api...") carry no signal — strip them. */
const COMMENT_LINE = /(^|\n)[ \t]*#[^\n]*/g

// --- Secret scrubbing --------------------------------------------------------

/**
 * Minimal curated secret/infrastructure patterns (~90% of real-world leaks,
 * zero deps). Applied to every signature and snippet BEFORE persistence.
 */
const SECRET_PATTERNS: RegExp[] = [
  /sk-proj-\S*/gi, // OpenAI keys incl. fragmented PowerShell continuations ("sk-proj-\")
  /sk-[a-zA-Z0-9_-]{20,}/g, // OpenAI / Anthropic style keys
  /gh[pousr]_[A-Za-z0-9_]{36,}/g, // GitHub PATs
  /github_pat_[A-Za-z0-9_]{22,}[A-Za-z0-9_]{59}/g, // GitHub fine-grained
  /AKIA[A-Z0-9]{16}/g, // AWS access keys
  /xox[baprs]-[0-9A-Za-z-]{10,}/g, // Slack tokens
  /sk_(?:live|test)_[A-Za-z0-9]{24,}/g, // Stripe
  /glpat-[A-Za-z0-9_-]{20,}/g, // GitLab
  /npm_[A-Za-z0-9]{36}/g, // npm tokens
  /PMAK-[A-Za-z0-9-]{20,}/g, // Postman
  /gsk_[A-Za-z0-9]{20,}/g, // Groq
  /Bearer\s+[A-Za-z0-9_.-]{20,}/gi, // bearer tokens
  /\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:\s"']+:[^@\s"']+@[^\s"']+/gi, // db conn strings
  /-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE KEY-----[\s\S]*?(?:-----END\s+(?:[A-Z]+\s+)?PRIVATE KEY-----|$)/g, // PEM private keys — full block incl. base64 body
  /\bAIza[0-9A-Za-z_-]{35}/g, // Google API keys
  /\b[A-Z][A-Z0-9_]{2,}=[A-Za-z0-9+=_-]{20,}/g, // .env-style KEY=<long-secret> assignments
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
  /\broot@[\w.-]+/gi, // ssh root@host — infrastructure exposure
]

export function scrubSecrets(text: string): string {
  let s = text
  for (const rule of SECRET_PATTERNS) {
    s = s.replace(rule, "<redacted>")
  }
  return s
}

// --- Normalization -----------------------------------------------------------

/**
 * Interpreter one-liners: the quoted argument IS the program. Parameterizing
 * it to <str> collapsed every script into one key — "python -c <str>" ended up
 * blocking ALL python -c calls after three unrelated failures. Fingerprint the
 * payload instead: same code = same key, different code = different key.
 * Secrets are scrubbed before hashing so they neither persist nor fragment.
 */
const INTERPRETER_ONELINER =
  /(?:^|[|;&(\n]\s*)(?:\S+[\\/])?(python3?|node|bun|deno|perl|ruby|pwsh|powershell)(?:\.exe)?(?:\s+-\w+)*\s+(-c|-e|--eval|-command)\s*/i

function hashInterpreterPayload(command: string): string {
  const match = INTERPRETER_ONELINER.exec(command)
  if (!match) return command
  const payload = command.slice(match.index + match[0].length)
  if (payload.trim() === "") return command
  // Already fingerprinted (re-normalization) — keep the existing token so
  // normalizeCommand stays idempotent.
  if (/^<code:[0-9a-f]+>$/.test(payload.trim())) return command
  // Already-parameterized placeholders are data, not code — never hash them
  // (idempotency: a second pass must not fingerprint a <str>).
  if (/^(?:<(?:str|path|n|hash|uuid|sha|md5|ip|url|email|date)>\s*)+$/.test(payload.trim())) return command
  // For whole (unchained) commands the payload runs to end of string; chain
  // segments are normalized separately, so segment keys stay exact.
  // Trim before hashing: trailing whitespace (e.g. a stripped override marker)
  // is not part of the code's identity.
  const fingerprint = createHash("sha1").update(scrubSecrets(payload.trim())).digest("hex").slice(0, 8)
  return `${command.slice(0, match.index + match[0].length)}<code:${fingerprint}>`
}

/**
 * Normalize a bash command into a stable signature.
 * Paths, numbers, quoted strings, hashes and agent comments are abstracted
 * away so that "same failure, different instance" collapses into one pattern.
 */
export function normalizeCommand(command: string): string {
  // CRLF/CR commands (Windows pastes, agent multi-line) normalize to LF —
  // otherwise the same command fragments across line-ending styles.
  let s = command.replace(/\r\n?/g, "\n")
  s = s.replace(COMMENT_LINE, "$1").toLowerCase()
  s = hashInterpreterPayload(s)
  // Quoted spans come out FIRST: they are data, and removing them before the
  // path rules keeps normalization idempotent — a <str> replacement inserts
  // spaces that would otherwise expose an adjacent "/" to the path rule only
  // on a second pass.
  s = s.replace(/"[^"]*"|'[^']*'/g, " <str> ")
  s = s.replace(/[a-z]:[\\/][^\s"']+/gi, " <path> ")
  s = s.replace(/(^|\s)\/[^\s"']+/g, "$1<path> ")
  // lookbehind: never re-parameterize the <code:...> fingerprint hex
  s = s.replace(/(?<!<code:)\b[0-9a-f]{7,64}\b/gi, " <hash> ")
  s = s.replace(/(?<!<code:)\b\d[\d.]*\b/g, " <n> ")
  s = s.replace(/\s+/g, " ").trim()
  return s
}

/**
 * Sentry-style parameterization for free-form error text (event channel).
 * Same root cause must collapse to one signature regardless of variable data.
 * Order matters: quoted strings first, then specific tokens, numbers last.
 */
const PARAM_RULES: [RegExp, string][] = [
  [/"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'/g, "<str>"], // unrolled loop: no catastrophic backtracking
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<uuid>"],
  [/\b[0-9a-f]{40}\b/gi, "<sha>"],
  [/\b[0-9a-f]{32}\b/gi, "<md5>"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g, "<ip>"],
  [/\bhttps?:\/\/[^\s"'<>]+/gi, "<url>"],
  [/\b[\w.+-]+@[\w-]+\.[\w.]+\b/g, "<email>"],
  [/\b\d{4}-\d{2}-\d{2}([t ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(z|[+-]\d{2}:?\d{2})?)?/gi, "<date>"],
  [/\b[a-z]:[\\/][^\s"'<>|]+/gi, "<path>"],
  [/(^|\s)\/[^\s"'<>|]+/g, "$1<path>"],
  [/\b[0-9a-f]{7,64}\b/gi, "<hash>"],
  [/\b\d{2,}\b/g, "<n>"],
]

export function parameterizeError(text: string): string {
  let s = text.toLowerCase()
  for (const [rule, token] of PARAM_RULES) {
    s = s.replace(rule, token)
  }
  return s.replace(/\s+/g, " ").trim()
}

// --- Intended non-zero exits / diagnostic detection --------------------------

/**
 * Verb patterns of diagnostic commands: their exit 1 is a NORMAL, intended
 * outcome (no match / findings / failed tests during development), not a
 * mistake. Used both for raw commands (exit-code allowlist) and normalized
 * signatures (blocking policy), so there is one source of truth.
 */
const DIAGNOSTIC_VERBS: RegExp[] = [
  /(^|[\s|;&:])(grep|rg|findstr|select-string)\b/i,
  /\bgit grep\b/i,
  /(^|[\s|;&:])diff\b/i,
  /\b(pytest|jest|vitest|mocha|cucumbertest)\b/i,
  /\bplaywright test\b/i,
  /\bflutter (test|analyze)\b/i,
  /\bdart (analyze|format|fix)\b/i,
  /\bgradlew\b[^\n;|&]*(test|compilejava|compiletestjava)/i,
  /\b(eslint|prettier --check)\b/i,
  /\btsc\b/i,
  /\bcurl\b/i,
  /\bls\b/i,
]

export function isDiagnosticText(text: string): boolean {
  return DIAGNOSTIC_VERBS.some((rule) => rule.test(text))
}

export function isDiagnosticSignature(signature: string): boolean {
  return isDiagnosticText(signature)
}

/** OpenCode normalizes non-zero exits to 1 in metadata, so discriminate by command shape. */
export function isIntendedNonzero(command: string, exitCode: number): boolean {
  return exitCode === 1 && isDiagnosticText(command)
}

/**
 * A code flag whose payload was entirely parameterized away (`-c <str>`)
 * carries no identity — blocking that shape blocks the whole command family.
 * New one-liners get <code:...> fingerprints in normalizeCommand; this guard
 * keeps legacy pre-fingerprint gates (and lookalikes) from ever blocking.
 */
const GENERIC_ONELINER_SHAPE = /(^|\s)(-c|-e|--eval|-command)\s+(?:@\s+)?<str>(?:\s+@)?\s*$/i

/**
 * Blocking policy: only bash commands that are NOT diagnostics may ever
 * become enforced gates. File probes and diagnostic queries are measured
 * (watching) but never interrupt the agent — the data showed blocking them
 * punishes normal work.
 */
export function canBlock(tool: string, signature: string): boolean {
  if (tool !== "bash") return false
  if (isDiagnosticSignature(signature)) return false
  return !GENERIC_ONELINER_SHAPE.test(signature)
}

// --- Chain splitting ---------------------------------------------------------

/**
 * Quote- and paren-aware split of a command chain: &&, ||, ;, | and newlines
 * separate segments ONLY at paren depth 0. A gate on a single command must
 * also fire when that command hides inside "git status && rm -rf /", but
 * "(cd /tmp && ls)" stays one segment.
 */
export function splitChain(command: string): string[] {
  const segments: string[] = []
  let current = ""
  let quote: string | null = null
  let depth = 0
  const flush = (): void => {
    const trimmed = current.trim()
    if (trimmed !== "") segments.push(trimmed)
    current = ""
  }
  let i = 0
  while (i < command.length) {
    const ch = command.charAt(i)
    const next = command.charAt(i + 1)
    if (quote !== null) {
      current += ch
      if (ch === quote) quote = null
      i += 1
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      current += ch
      i += 1
      continue
    }
    if (ch === "(") {
      depth += 1
      current += ch
      i += 1
      continue
    }
    if (ch === ")") {
      depth = Math.max(0, depth - 1)
      current += ch
      i += 1
      continue
    }
    if (depth === 0) {
      if (ch === ";" || ch === "\n" || ch === "\r") {
        flush()
        i += 1
        continue
      }
      if (ch === "&" && next === "&") {
        flush()
        i += 2
        continue
      }
      if (ch === "|") {
        flush()
        i += next === "|" ? 2 : 1
        continue
      }
    }
    current += ch
    i += 1
  }
  flush()
  return segments
}

/** Per-segment signatures for a bash command (bypass protection for chains). */
export function bashSegmentSignatures(command: string): string[] {
  const clean = command.replace(OVERRIDE_MARKER, "")
  return splitChain(clean).map((segment) => `bash:${normalizeCommand(segment)}`)
}

/** Normalize a file path: keep basename + extension, drop directories. */
export function normalizeFilePath(filePath: string): string {
  const unified = filePath.replace(/\\/g, "/")
  const base = unified.split("/").pop() ?? unified
  return base.toLowerCase()
}

/**
 * Stable identity of a planned tool call for recurrence matching.
 * For bash this is the WHOLE command; use bashSegmentSignatures() in
 * addition when matching gates. Returns null for tools we do not track.
 */
export function callSignature(tool: string, args: Record<string, unknown>): string | null {
  switch (tool) {
    case "bash": {
      const command = args.command
      return typeof command === "string" && command.trim() !== ""
        ? `bash:${normalizeCommand(command.replace(OVERRIDE_MARKER, ""))}`
        : null
    }
    case "read":
    case "edit":
    case "write": {
      const filePath = args.filePath
      return typeof filePath === "string" && filePath.trim() !== ""
        ? `${tool}:${normalizeFilePath(filePath)}`
        : null
    }
    case "glob":
    case "grep": {
      const pattern = args.pattern
      return typeof pattern === "string" && pattern.trim() !== ""
        ? `${tool}:${pattern.toLowerCase().replace(/\s+/g, " ").trim()}`
        : null
    }
    default:
      return null
  }
}

export function patternKey(signature: string): string {
  return createHash("sha1").update(signature).digest("hex").slice(0, 12)
}

// --- Fuzzy matching ----------------------------------------------------------

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0
  const m = a.length
  const n = b.length
  if (m === 0) return n
  if (n === 0) return m
  let prev = new Array<number>(n + 1)
  let curr = new Array<number>(n + 1)
  for (let j = 0; j <= n; j++) prev[j] = j
  for (let i = 1; i <= m; i++) {
    curr[0] = i
    const ca = a.charAt(i - 1)
    for (let j = 1; j <= n; j++) {
      const cost = ca === b.charAt(j - 1) ? 0 : 1
      const del = (prev[j] ?? 0) + 1
      const ins = (curr[j - 1] ?? 0) + 1
      const sub = (prev[j - 1] ?? 0) + cost
      curr[j] = Math.min(del, ins, sub)
    }
    const tmp = prev
    prev = curr
    curr = tmp
  }
  return prev[n] ?? 0
}

/** Code fingerprints are IDENTITY, not data — they must match exactly. */
const CODE_FINGERPRINTS = /<code:[0-9a-f]+>/g

/** Signatures longer than this match exactly only: a 300-char normalized
 * command is already specific enough that "30% near" is meaningless, and
 * Levenshtein on long signatures is the hot-path cost cliff. */
export const FUZZY_MAX_LEN = 300

/**
 * Near-duplicate match: normalized edit distance <= 30% AND absolute distance
 * >= 3. Unlike token-set Jaccard, this does not collapse commands that merely
 * share placeholder tokens; the absolute floor stops verb-level-different
 * commands ("git push <str>" vs "git pull <str>" = distance 2) from merging.
 * Signatures carrying <code:...> fingerprints only match if the fingerprints
 * are identical — random hashes differing in 3 chars would otherwise pass the
 * distance rule and merge unrelated one-liners into one gate.
 */
export function fuzzySimilar(a: string, b: string): boolean {
  if (a === b) return true
  const codesA = a.match(CODE_FINGERPRINTS)
  const codesB = b.match(CODE_FINGERPRINTS)
  if (codesA !== null || codesB !== null) {
    if (codesA === null || codesB === null || codesA.join("\u0000") !== codesB.join("\u0000")) return false
  }
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return true
  if (maxLen > FUZZY_MAX_LEN) return false
  // Triangle inequality: distance >= |lenA - lenB|. If even that floor
  // exceeds the ratio threshold, no Levenshtein result can pass — an O(1)
  // pre-filter with zero false negatives that skips most DP computations.
  if (Math.abs(a.length - b.length) / maxLen > 0.3) return false
  const distance = levenshtein(a, b)
  return distance >= 3 && distance / maxLen <= 0.3
}

// --- Failure detection -------------------------------------------------------

export interface FailureDetection {
  matched: boolean
  snippet: string
}

/**
 * Conservative failure signatures scanned line-by-line in BASH output only.
 * File-tool output is file CONTENT — scanning it for "TypeError" produced
 * dozens of false gates on legitimate reads; file tools are covered by the
 * event channel instead.
 */
const FAILURE_SIGNATURES: RegExp[] = [
  /exit code:?\s*[1-9]\d*/i,
  /\berror TS\d+\b/,
  /\bENOENT\b|\bEACCES\b|\bEPERM\b/,
  /command not found/i,
  /is not recognized as an internal or external command/i,
  /\b(SyntaxError|TypeError|ReferenceError|AssertionError)\b/,
  /Tests:\s+\d+\s+failed/i,
  /\bFAIL\s+\S/,
  /thread '[^']*' panicked/,
  /\bFATAL\b/,
]

export function detectFailure(outputText: string): FailureDetection {
  for (const line of outputText.split("\n")) {
    for (const signature of FAILURE_SIGNATURES) {
      if (signature.test(line)) {
        return { matched: true, snippet: line.trim().slice(0, 200) }
      }
    }
  }
  return { matched: false, snippet: "" }
}

// --- Noise filtering ----------------------------------------------------------

/**
 * Infrastructure noise, not agent mistakes: aborted/cancelled executions
 * (user hit stop, background task reaped) teach nothing and fragmented the
 * store with unactionable patterns. Aborted != failed.
 */
const NOISE_ERRORS: RegExp[] = [
  /tool execution aborted/i,
  /execution was aborted/i,
  /\baborted by user\b/i,
  /\bcancelled by user\b/i,
  /\bcanceled by user\b/i,
]

export function isNoiseError(errorText: string): boolean {
  return NOISE_ERRORS.some((rule) => rule.test(errorText))
}
