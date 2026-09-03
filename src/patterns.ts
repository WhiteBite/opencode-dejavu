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
  /hf_[A-Za-z0-9]{20,}/g, // Hugging Face
  /dop_v1_[A-Za-z0-9]{20,}/g, // DigitalOcean
  /vercel_[A-Za-z0-9]{20,}/g, // Vercel
  /NRAK-[A-Z0-9]{20,}/g, // New Relic
  /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, // SendGrid
  /\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)\b\s*[:=]\s*['"]?[A-Za-z0-9+/_=.-]{16,}/gi, // generic key=<long value> assignments
  /\broot@[\w.-]+/gi, // ssh root@host — infrastructure exposure
]

export function scrubSecrets(text: string): string {
  let s = text
  for (const rule of SECRET_PATTERNS) {
    s = s.replace(rule, "<redacted>")
  }
  return s
}

/**
 * Terminal control characters (PowerShell VT-colored errors, bells, NULs)
 * carry no signal — persisted they corrupt snippets/corrections with raw
 * escape sequences (`ESC[31;1m...`) and fragmented identities when the
 * coloring varies between runs. ANSI sequences first (they end in a letter,
 * which bare C0 stripping would strand), then all C0 except LF/CR/TAB —
 * those three carry structure (multi-line commands, indentation).
 */
export function stripControl(text: string): string {
  return text
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\u001b./g, "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
}

/** The persistence boundary: control-char strip + secret scrub, in one call. */
export function sanitizeForStore(text: string): string {
  return scrubSecrets(stripControl(text))
}

// --- Normalization -----------------------------------------------------------

/**
 * Interpreter one-liners: the quoted argument IS the program. Parameterizing
 * it to <str> collapsed every script into one key — "python -c <str>" ended up
 * blocking ALL python -c calls after three unrelated failures. Fingerprint the
 * payload instead: same code = same key, different code = different key.
 * Secrets are scrubbed before hashing so they neither persist nor fragment.
 */
/**
 * PowerShell shapes included: call operator + QUOTED exe path
 * (`& "C:\...\python.exe" -c ...`) and bare interpreter alike. The quoted
 * path needs the quote in the prefix class and an optional closing quote,
 * otherwise `-c` never lines up and the payload escapes fingerprinting.
 * Leading env assignments (`PYTHONPATH=x python -c ...`) are allowed in the
 * anchor and stay in the prefix — without them the one-liner escaped
 * fingerprinting entirely. Flag alternatives run LONGEST FIRST: regex
 * alternatives are ordered, and `-c` matching inside `-command` swallowed
 * `ommand` into the payload — fragmenting keys across spellings of the same
 * call. `py` is the Windows Python launcher (`py -3 -c ...`).
 */
const INTERPRETER_ONELINER =
  /(?:^|[|;&(\n]\s*)(?:\w+=\S+\s+)*(?:["']?\S*[\\/])?(python3?|py|node|bun|deno|perl|ruby|pwsh|powershell)(?:\.exe)?["']?(?:\s+-\w+)*\s+(-command|-encodedcommand|--eval|-c|-e)\s*/i

function hashInterpreterPayload(command: string): string {
  const match = INTERPRETER_ONELINER.exec(command)
  if (!match) return command
  // PowerShell here-string payloads (`@"..."@` / `@'...'@`) — the wrapper
  // markers are part of the payload and hash with it. Previously the `@`
  // markers survived normalization and the quoted body collapsed to <str>,
  // leaving raw code tokens leaking into signatures when quotes unbalanced.
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
  // Long PowerShell flags converge to -c: `-command`/`-encodedcommand` are
  // spellings of the same one-liner call — one identity, not three families.
  const prefix = command.slice(0, match.index + match[0].length).replace(/-(?:command|encodedcommand)(\s*)$/i, "-c$1")
  return `${prefix}<code:${fingerprint}>`
}

/**
 * Windows wrapper verb: `cmd /c "real command"` — the payload IS the call.
 * Unwrapped, the payload normalizes with its own identity and its real verb
 * stays visible to the diagnostic policy; left wrapped, `/c` becomes `<path>`
 * and the payload becomes `<str>`, so `cmd <path> <str>` matched every cmd
 * invocation on the machine. Recursion terminates: the payload is strictly
 * shorter than the wrapper command.
 */
const CMD_WRAPPER = /^cmd(?:\.exe)?\s+(?:\/s\s+)?\/(c|k)\s+/i

/**
 * Raw payload of a `cmd /c|/k` wrapper, one wrapper-quote layer removed —
 * null when the command is not wrapped. Shared by normalization (unwrap),
 * segment expansion (inner chains) and override-marker visibility.
 */
export function cmdWrapperPayload(command: string): string | null {
  const match = CMD_WRAPPER.exec(command)
  if (!match) return null
  let payload = command.slice(match[0].length).trim()
  if ((payload.startsWith('"') && payload.endsWith('"') && payload.length >= 2) || (payload.startsWith("'") && payload.endsWith("'") && payload.length >= 2)) {
    payload = payload.slice(1, -1).trim()
  }
  return payload === "" ? null : payload
}

function unwrapCmdWrapper(command: string): string {
  const payload = cmdWrapperPayload(command)
  return payload === null ? command : normalizeCommand(payload)
}

/**
 * Normalize a bash command into a stable signature.
 * Paths, numbers, quoted strings, hashes and agent comments are abstracted
 * away so that "same failure, different instance" collapses into one pattern.
 */
export function normalizeCommand(command: string): string {
  // Terminal control characters (PowerShell VT colors) carry no identity and
  // fragmented signatures when coloring varied between runs — strip first.
  let s = stripControl(command)
  // CRLF/CR commands (Windows pastes, agent multi-line) normalize to LF —
  // otherwise the same command fragments across line-ending styles.
  s = s.replace(/\r\n?/g, "\n")
  s = s.replace(COMMENT_LINE, "$1").toLowerCase()
  s = unwrapCmdWrapper(s)
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
  let s = stripControl(text).toLowerCase()
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
  // npm/yarn/pnpm test / typecheck / lint scripts are iteration work — their
  // exit 1 is "tests failed / types wrong / lint found issues", not an
  // infrastructure error. The second rule covers flags between the package
  // manager and the verb (e.g. `pnpm --filter <pkg> typecheck`).
  /\b(npm|pnpm|yarn) (run )?(test|typecheck|lint)\b/i,
  /\b(npm|pnpm|yarn)\b[^\n;|&]*\b(typecheck|lint)\b/i,
  /\bplaywright test\b/i,
  /\bflutter (test|analyze)\b/i,
  /\bdart (analyze|format|fix)\b/i,
  // Iteration runners: `dart run <script>`, `go run|build`, `cargo run|build`
  // fail repeatedly WHILE the agent fixes the code — the failures are the
  // work itself. Blocking them produced arms races (dozens of overrides in
  // production data); they remind but never block, and their exit 1 is the
  // intended "still broken" outcome of iteration.
  /\bdart run\b/i,
  /\bgo (run|build|test|vet)\b/i,
  /\bcargo (run|build|test|clippy)\b/i,
  /\bgradlew\b[^\n;|&]*(test|compilejava|compiletestjava)/i,
  /\b(eslint|prettier --check)\b/i,
  /\btsc\b/i,
  /\bmypy\b/i,
  /\bcurl\b/i,
  /\bls\b/i,
]

export function isDiagnosticText(text: string): boolean {
  return DIAGNOSTIC_VERBS.some((rule) => rule.test(text))
}

export function isDiagnosticSignature(signature: string): boolean {
  return isDiagnosticText(signature)
}

/** Pipeline formatters shape output but are never the failing producer WHEN
 * they are a pipe tail: PowerShell cmdlets don't set `$LASTEXITCODE` (it stays
 * with the producing native command), and unix head/tail/column/uniq tails exit
 * 0 on piped input. So piping a diagnostic into one (`tsc | Select-Object -Last
 * 5`, `vitest | head -5`) must not break the diagnostic's exit-1 immunity.
 * Position matters: a formatter standing alone or as the TERMINAL producer of a
 * sequence (`npm test && tail -5 missing.log`) IS the failing producer — its
 * exit must still count. isIntendedNonzero only grants the transparency to
 * segments splitChainTagged marks as pipe tails. */
const PIPE_FORMATTERS =
  /^\s*(select-object|sort-object|format-table|format-list|format-wide|format-custom|out-string|out-host|out-null|tee-object|foreach-object|where-object|measure-object|group-object|convertto-json|convertfrom-json|head|tail|column|uniq|tee)\b/i
/** Navigation changes directory, never the outcome — `cd X && <diagnostic>`
 * must not lose the diagnostic's exit-1 immunity to the `cd` segment. */
const NAVIGATION_VERBS = /^\s*(cd|set-location|pushd|popd)\b/i

/** Flatten subshell parens to `;` segment separators, but ONLY outside `{}`
 * script blocks and quotes. `(deploy && grep)` must split (a diagnostic inside
 * parens must not blanket-immunize a non-diagnostic verb), but method-call
 * parens inside a PowerShell script block (`ForEach-Object { $_.trim() }`) are
 * part of that segment and must NOT split it. */
function flattenSubshellParens(command: string): string {
  let result = ""
  let quote: string | null = null
  let braceDepth = 0
  for (let i = 0; i < command.length; i++) {
    const ch = command.charAt(i)
    if (quote !== null) {
      result += ch
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      result += ch
      continue
    }
    if (ch === "{") {
      braceDepth += 1
      result += ch
      continue
    }
    if (ch === "}") {
      braceDepth = Math.max(0, braceDepth - 1)
      result += ch
      continue
    }
    if ((ch === "(" || ch === ")") && braceDepth === 0) {
      result += ";"
      continue
    }
    result += ch
  }
  return result
}

/** Like splitChain but tags each segment with whether it immediately follows a
 * pipe (`|`). Formatter transparency is position-dependent (pipe tail only), so
 * the immunity check needs this. `||` is a sequence (OR) separator, not a pipe:
 * the segment after it is a producer, NOT a pipe tail. */
function splitChainTagged(command: string): Array<{ text: string; pipeTail: boolean }> {
  const segments: Array<{ text: string; pipeTail: boolean }> = []
  let current = ""
  let quote: string | null = null
  let depth = 0
  let pipeTail = false
  const flush = (): void => {
    const trimmed = current.trim()
    if (trimmed !== "") segments.push({ text: trimmed, pipeTail })
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
        pipeTail = false
        i += 1
        continue
      }
      if (ch === "&" && next === "&") {
        flush()
        pipeTail = false
        i += 2
        continue
      }
      if (ch === "|") {
        flush()
        if (next === "|") {
          // `||` is a sequence (OR) separator — next segment is a producer.
          pipeTail = false
          i += 2
        } else if (next === "&") {
          // `|&` is bash's pipe-stdout-and-stderr — still a pipe, next is a tail.
          pipeTail = true
          i += 2
        } else {
          pipeTail = true
          i += 1
        }
        continue
      }
    }
    current += ch
    i += 1
  }
  flush()
  return segments
}

/**
 * OpenCode normalizes non-zero exits to 1 in metadata, so discriminate by
 * command shape. Exit-1 immunity requires EVERY producer segment to be
 * diagnostic: in `deploy --broken && grep done log.txt` the exit is deploy's
 * failure — granting immunity because grep appears later would hide it.
 * Two segment kinds are transparent because they cannot be the failing
 * producer: navigation (`cd`) — but ONLY when the segment is pure navigation,
 * so `cd <path> npx vitest run` (no separator) keeps the diagnostic instead of
 * being dropped wholesale — and pipe formatters, but the latter ONLY as a pipe
 * tail. A formatter standing alone or as the terminal producer of a sequence
 * (`npm test && tail -5 missing.log`) IS the producer, so its failure still
 * counts. A real non-diagnostic command still breaks immunity — `npm install |
 * select-object` still counts (npm install is not a diagnostic).
 * Subshell paren groups are flattened to segment separators (`;`), NOT spaces,
 * and only OUTSIDE `{}` script blocks: `(deploy && grep)` splits so a
 * diagnostic nested in parens can't blanket-immunize a non-diagnostic verb,
 * while method-call parens inside a script block (`ForEach-Object { $_.trim()
 * }`) stay part of their segment and don't split it.
 */
export function isIntendedNonzero(command: string, exitCode: number): boolean {
  if (exitCode !== 1) return false
  let sawProducer = false
  for (const { text, pipeTail } of splitChainTagged(flattenSubshellParens(command))) {
    // Navigation is transparent only when it is PURE navigation. A segment that
    // pairs a navigation verb with a diagnostic and no separator between them
    // (`cd <path> npx vitest run ...`) must keep that diagnostic — dropping the
    // whole segment as navigation would hide the command and break immunity.
    if (NAVIGATION_VERBS.test(text) && !isDiagnosticText(text)) continue
    if (pipeTail && PIPE_FORMATTERS.test(text)) continue
    if (!isDiagnosticText(text)) return false
    sawProducer = true
  }
  return sawProducer
}

// --- Residual identity (over-generic shape guard) ----------------------------

/** Placeholder tokens carry no identity — except `<code:...>`: the
 * fingerprint IS the identity of a one-liner payload. */
const PLACEHOLDER_TOKEN = /^<(?:str|path|n|hash|uuid|sha|md5|ip|url|email|date)>$/

/** Shell plumbing: redirections and here-string/call-operator debris. */
const OPERATOR_TOKENS = new Set(["&", "@", ">", "<", ">&", ">>", "2>&1", "2>"])

/** Tokens that pass code/module to an interpreter — structure, not identity.
 * `-m`/`--module` included: the NEXT token is the program, exactly like -c —
 * `python -m <str>` (quoted module) must not gain identity from the flag. */
const CODE_PASSING_FLAGS = new Set(["-c", "-e", "--eval", "-command", "-encodedcommand", "-m", "--module"])

/** Shell builtins that only position the session: a chain headed by one
 * (`cd <path> && python <path>`) must not borrow identity from the builtin —
 * the whole chain may be parameterized away. */
const NO_IDENTITY_HEADS = new Set(["cd", "pushd", "popd", "set-location", "exit"])

/** Pipe-stage cmdlets that only post-process output: a segment made of
 * plumbing (`... | select-object -last <n>`) contributes no identity. */
const PLUMBING_HEADS = new Set([
  "select-object",
  "select-string",
  "out-string",
  "out-file",
  "out-null",
  "foreach-object",
  "where-object",
  "sort-object",
  "measure-object",
  "tee-object",
  "write-host",
  "write-output",
  "more",
])

/** Wrappers whose bare name is not a call identity: their ARGUMENTS are the
 * call. If the arguments were all parameterized away, the signature matches
 * an entire command family — enforcing it would punish unrelated calls. */
const WRAPPER_BASENAMES = new Set(["cmd", "py", "node", "python", "python3", "bun", "deno", "perl", "ruby", "pwsh", "powershell"])

function baseName(token: string): string {
  const bare = token.replace(/^["']+|["']+$/g, "")
  const parts = bare.split(/[\\/]/)
  const last = parts[parts.length - 1] ?? bare
  return last.toLowerCase().replace(/\.exe$/, "")
}

function segmentHasIdentity(segment: string): boolean {
  const tokens = segment.split(/\s+/).filter((t) => t !== "")
  let head = ""
  let headIdx = -1
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i] ?? ""
    if (PLACEHOLDER_TOKEN.test(token) || OPERATOR_TOKENS.has(token) || CODE_PASSING_FLAGS.has(token)) continue
    head = token
    headIdx = i
    break
  }
  if (head === "") return false
  if (head.startsWith("<code:")) return true
  if (PLUMBING_HEADS.has(head)) return false
  if (NO_IDENTITY_HEADS.has(head)) return false
  if (!WRAPPER_BASENAMES.has(baseName(head))) return true
  // Wrapper/interpreter head: identity must come from a surviving argument
  // (a literal path/script, or a <code:...> fingerprint).
  for (let i = headIdx + 1; i < tokens.length; i++) {
    const token = tokens[i] ?? ""
    if (token.startsWith("<code:")) return true
    if (PLACEHOLDER_TOKEN.test(token) || CODE_PASSING_FLAGS.has(token) || OPERATOR_TOKENS.has(token)) continue
    return true
  }
  return false
}

/**
 * A signature keeps residual identity when at least one chain segment names
 * a concrete call. Signatures whose substance was entirely parameterized —
 * `cmd <path> <str>`, `node <str> <n> >& <n>`, `& <str> -c @ <str> @`,
 * chains starting with an unknown `<str>` head — match whole command
 * families: they may be measured (watching) but never enforced. This
 * generalizes the legacy bare-one-liner guard: ANY future normalization gap
 * degrades to watching instead of blocking arbitrary calls.
 */
export function hasResidualIdentity(signature: string): boolean {
  const body = signature.startsWith("bash:") ? signature.slice("bash:".length) : signature
  return body.split(/\s*(?:\|\||&&|[|;&])\s*|\n+/).some((segment) => segmentHasIdentity(segment))
}

/**
 * Blocking policy: only bash commands that are NOT diagnostics may ever
 * become enforced gates. File probes and diagnostic queries are measured
 * (watching) but never interrupt the agent — the data showed blocking them
 * punishes normal work. Signatures without residual identity never enforce
 * at any tier — they are too broad to interrupt anything.
 */
export function canBlock(tool: string, signature: string): boolean {
  if (tool !== "bash") return false
  if (!hasResidualIdentity(signature)) return false
  return !isDiagnosticSignature(signature)
}

/**
 * Remind-only policy: diagnostic bash commands still surface a REMINDER when
 * they recur (the old behavior gave them zero signal), but they NEVER block —
 * blocking a test/lint the agent is iterating on punishes normal work.
 */
export function canRemind(tool: string, signature: string): boolean {
  if (tool !== "bash") return false
  if (!hasResidualIdentity(signature)) return false
  return isDiagnosticSignature(signature)
}

/**
 * Repo-local verbs: their success depends on THIS repo's state (deps, lockfile,
 * remote, build cache), not on agent behavior — so a failure is a repo quirk,
 * not an agent habit, and must never escalate to the global store (an
 * `npm install` that broke in project A would otherwise block project B).
 */
const REPO_LOCAL_VERBS: RegExp[] = [
  /\b(npm|yarn|pnpm|bun|npx)\b/i,
  /\bgit\b/i,
  /\b(gradlew|gradle|mvn|maven)\b/i,
  /\b(cargo|go|pip3?|poetry|uv)\b/i,
  /\bdocker(-compose)?\b/i,
  /\b(make|cmake|bazel)\b/i,
]

export function isRepoLocal(signature: string): boolean {
  return REPO_LOCAL_VERBS.some((rule) => rule.test(signature))
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
        // `||` (OR) and `|&` (bash pipe stdout+stderr) are 2-char; bare `|` is 1.
        i += next === "|" || next === "&" ? 2 : 1
        continue
      }
    }
    current += ch
    i += 1
  }
  flush()
  return segments
}

/**
 * Per-segment signatures for a bash command (bypass protection for chains).
 * cmd wrappers expand recursively: quote-aware splitChain keeps
 * `cmd /c "a && gated"` as ONE segment, so the inner chain must unfold here —
 * a gate on the inner command must fire through the wrapper. Depth-bounded:
 * nested wrappers are pathological.
 */
export function bashSegmentSignatures(command: string): string[] {
  const clean = command.replace(OVERRIDE_MARKER, "")
  const signatures: string[] = []
  const expand = (text: string, depth: number): void => {
    for (const segment of splitChain(text)) {
      const payload = depth < 3 ? cmdWrapperPayload(segment) : null
      if (payload === null) {
        signatures.push(`bash:${normalizeCommand(segment)}`)
      } else {
        expand(payload, depth + 1)
      }
    }
  }
  expand(clean, 0)
  return signatures
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

/** Flag tokens ("-x", "--foo") are the operation's switches. Two commands with
 * DISJOINT flag sets are different operations and must never fuzzy-merge
 * ("train --lr <n>" vs "train --epochs <n>"). A subset IS allowed — extra
 * switches on the same operation ("gradlew test --no-daemon") still belong to
 * the same gate, otherwise enforcement fragments across harmless variants.
 * Cached: the flood path calls fuzzySimilar per gate under the gates lock and
 * would otherwise re-split/sort the SAME incoming signature on every pair. */
const FLAG_TOKEN_CACHE_CAP = 512
const flagTokenCache = new Map<string, string[]>()
function flagTokens(signature: string): string[] {
  const cached = flagTokenCache.get(signature)
  if (cached !== undefined) return cached
  const tokens = signature
    .split(/\s+/)
    .filter((token) => token.startsWith("-"))
    .sort()
  if (flagTokenCache.size >= FLAG_TOKEN_CACHE_CAP) {
    // Evict an arbitrary (oldest-inserted) entry to bound memory.
    const oldest = flagTokenCache.keys().next().value
    if (oldest !== undefined) flagTokenCache.delete(oldest)
  }
  flagTokenCache.set(signature, tokens)
  return tokens
}

function flagSubset(a: string[], b: string[]): boolean {
  const set = new Set(b)
  return a.every((token) => set.has(token))
}

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
 * distance rule and merge unrelated one-liners into one gate. Flag sets must
 * also be comparable (one a subset of the other) — disjoint switches mean
 * different operations.
 */
export function fuzzySimilar(a: string, b: string): boolean {
  if (a === b) return true
  // Cheapest rejects FIRST: the length band is O(1) with zero allocation and
  // zero false negatives — it must run before any regex/flag work, because
  // the flood path calls this per gate under the gates lock.
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return true
  if (maxLen > FUZZY_MAX_LEN) return false
  // Triangle inequality: distance >= |lenA - lenB|. If even that floor
  // exceeds the ratio threshold, no Levenshtein result can pass — an O(1)
  // pre-filter with zero false negatives that skips most DP computations.
  if (Math.abs(a.length - b.length) / maxLen > 0.3) return false
  const codesA = a.match(CODE_FINGERPRINTS)
  const codesB = b.match(CODE_FINGERPRINTS)
  if (codesA !== null || codesB !== null) {
    if (codesA === null || codesB === null || codesA.join("\u0000") !== codesB.join("\u0000")) return false
  }
  const flagsA = flagTokens(a)
  const flagsB = flagTokens(b)
  if (!flagSubset(flagsA, flagsB) && !flagSubset(flagsB, flagsA)) return false
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
  // PowerShell colors errors with VT sequences — strip before scanning, or
  // the escapes persist into snippets/corrections shown to the agent.
  for (const line of stripControl(outputText).split("\n")) {
    for (const signature of FAILURE_SIGNATURES) {
      if (signature.test(line)) {
        return { matched: true, snippet: line.trim().slice(0, 200) }
      }
    }
  }
  return { matched: false, snippet: "" }
}

/**
 * For exit-code failures whose output matched no signature, a bare
 * "exit code N" gives a human/agent nothing to write a correction from.
 * Bash output is command output (safe to surface), so keep the last non-empty
 * line — compilers/test runners print their summary at the end.
 */
export function failureSnippet(outputText: string, exitCode: number | null): string {
  const lines = stripControl(outputText)
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "")
  const tail = lines[lines.length - 1]
  if (tail !== undefined && tail !== "") return tail.slice(0, 200)
  return `exit code ${exitCode}`
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
  /no results found for your query/i, // grep_app empty search: the tool worked, nothing matched
  /user dismissed this question/i, // question tool: the user's choice, not a failure
]

export function isNoiseError(errorText: string): boolean {
  return NOISE_ERRORS.some((rule) => rule.test(errorText))
}

// --- Default corrections ------------------------------------------------------

/**
 * Mechanical, overridable default correction chosen by command family, so a
 * promoted gate always ships with SOME teaching text instead of sitting
 * "NOT TEACHING" until a human writes one. Rules, not an LLM — the hot path
 * stays mechanical; a human/agent may refine the text later.
 */
export function suggestCorrection(signature: string, snippet: string): string {
  if (/(^|\s)(--check|--dry-run|verify|check)\b/i.test(signature) && /dart run|generate|sync/i.test(signature)) {
    return "Generated artifacts are stale — run the same script WITHOUT the check flag to regenerate, then commit the result."
  }
  if (/\b(pytest|jest|vitest|mocha|cucumbertest|flutter test|npm test|gradlew\b[^\n]*test|dart test)\b/i.test(signature)) {
    return "A test is failing — read the failing assertion in the output and fix the code or the expectation; do not re-run the suite blindly."
  }
  if (/\b(tsc|typecheck|type-check)\b/i.test(signature)) {
    return "Type errors — run the compiler, read the reported file:line diagnostics, and fix the types before retrying."
  }
  if (/\b(curl|wget)\b/i.test(signature)) {
    return "Network/endpoint failure — verify the URL is reachable, check rate limits and timeouts; retry with backoff, not immediately."
  }
  if (/\b(npm|yarn|pnpm|bun)\s+(install|ci)\b/i.test(signature)) {
    return "Dependency install failed — inspect the resolver error; try the lockfile/legacy-peer-deps route the repo documents."
  }
  if (snippet !== "" && snippet !== "exit code 1") {
    return `Last error: "${snippet}" — address that specific error before retrying this exact call.`
  }
  return "This exact call keeps failing — inspect the last output line and change approach before retrying."
}
