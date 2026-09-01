# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-22 (refreshed 2026-08-30)
**Commit:** 14ca0c1+
**Branch:** main

## OVERVIEW

dejavu — OpenCode plugin ("memory prosthesis with teeth"): mechanically detects recurring tool-call failures and promotes them into enforced gates (3 failures across 2 distinct sessions). Remind first, hard-block on same-session repeat offense. TypeScript ESM, runs under Bun, ships as raw `.ts` (no build step).

## STRUCTURE

```
dejavu-opencode-plugin/
├── index.ts            # Plugin entry — exports Dejavu (Plugin factory) + all 4 hooks
├── src/
│   ├── patterns.ts     # Pure engine: signatures, normalization, secret scrub, detection, blocking policy
│   ├── store.ts        # GateStore/Stores: two-scope persistence, locks, promotion, TTL, migration, reconcile
│   └── validate.ts     # Invariant layer: strict gate parsing + mechanical repair (parse-don't-validate boundary)
├── test/smoke.ts       # Behavioral smoke test — plain bun script, no framework, temp-dir isolated
├── scripts/            # doctor.ts (pathology report), analyze.ts (store summary), migrate.ts (demote+scrub)
├── command/dejavu.md   # /dejavu slash-command definition (install → ~/.config/opencode/command/)
├── skills/dejavu/      # Companion agent-protocol skill (install → ~/.config/opencode/skills/)
└── .omo/, .codegraph/  # Tooling artifacts — not project code
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Gate enforcement (remind/block/override) | `index.ts` `tool.execute.before` | session state lives ON THE GATE (`remindedSessions`/`failedSessions`), read fresh under the store lock |
| Failure detection + recording | `index.ts` `tool.execute.after` + `event` | two channels: exit/text vs message stream; a cross-channel dedup guard counts one call once |
| Signature/normalization | `src/patterns.ts` | `callSignature`, `normalizeCommand`, `parameterizeError` |
| Enforcement policy | `src/patterns.ts:canBlock()`/`canRemind()` | three tiers — bash non-diagnostics block, diagnostics remind-only, everything else just watches |
| Persistence, locks, promotion, global escalation | `src/store.ts` | `Stores.recordFailure()` is the core; cross-project evidence lives in global `index.json` |
| Self-healing / reconcile | `src/store.ts` + `src/validate.ts` | `Stores.reconcileAll()` at every init; `doctor --repair` on demand |
| Tunables | top of `index.ts` **and** `src/store.ts` | split: TTL/review caps in index, promote thresholds in store |
| Pathology checks | `scripts/doctor.ts` | defect classes: unparseable/bad records, duplicate keys, temporal inversion, nested tokens, enforced-without-evidence, stale blocking/reminding, not-teaching, annoying, review-flagged, reminders-ignored, unsanitized, stale copies, corrupt logs, version drift, cross-store index checks; no-arg run discovers projects from the index |

## CODE MAP

Line numbers intentionally omitted — they rot every round; locate by symbol name.

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Dejavu` | Plugin factory | index.ts | entry point; wires 4 hooks, also `export default` |
| `GateSignal` | class | index.ts | sentinel error — the ONLY error rethrown from hooks |
| `scrubSecrets` | fn | src/patterns.ts | secret redaction (half of the persistence boundary) |
| `stripControl` / `sanitizeForStore` | fn | src/patterns.ts | C0/ANSI strip; `sanitizeForStore` = stripControl + scrubSecrets — the persistence boundary |
| `hashInterpreterPayload` | fn | src/patterns.ts | `-c`/`-e` code payload → `<code:hash>` (identity of one-liners, incl. PowerShell here-strings + env prefixes) |
| `cmdWrapperPayload` / `unwrapCmdWrapper` | fn | src/patterns.ts | `cmd /c\|/k` payload extraction; unwrap normalizes the inner command |
| `normalizeCommand` | fn | src/patterns.ts | bash → signature; strips control chars, unwraps `cmd /c`, fingerprints one-liner payloads |
| `isIntendedNonzero` | fn | src/patterns.ts | exit-1 immunity for diagnostic chains (all segments diagnostic; paren groups flattened first) |
| `hasResidualIdentity` | fn | src/patterns.ts | over-generic shape guard — gates every enforcement tier |
| `canBlock` / `canRemind` | fn | src/patterns.ts | blocking tier / remind-only tier (diagnostics + iteration verbs) |
| `isRepoLocal` | fn | src/patterns.ts | repo-local verbs that never escalate globally |
| `splitChain` / `bashSegmentSignatures` | fn | src/patterns.ts | quote/paren-aware chain split; per-segment signatures (chain-bypass protection) |
| `callSignature` | fn | src/patterns.ts | stable call identity per tool (bash/read/edit/write/glob/grep) |
| `patternKey` | fn | src/patterns.ts | sha1 prefix-12 of signature — the gate key |
| `fuzzySimilar` | fn | src/patterns.ts | near-duplicate merge; length-band pre-filter + `FUZZY_MAX_LEN` cap |
| `detectFailure` / `failureSnippet` | fn | src/patterns.ts | line-by-line bash-output failure scan / evidence line selection |
| `isNoiseError` | fn | src/patterns.ts | aborted/cancelled/empty-result/dismissed executions are not failures |
| `suggestCorrection` | fn | src/patterns.ts | mechanical default corrections by command family |
| `GLOBAL_PROJECTS` | const | src/store.ts | cross-project escalation threshold |
| `GateStore` | class | src/store.ts | one scope: gates.json + index.json + log.jsonl, TTL caches, key index |
| `mergeGate` | fn | src/store.ts | evidence merge for dedupe/escalation (rank-preserving, preserves session state + feedback marks) |
| `checkFeedbackDemotion` | fn | src/store.ts | negative feedback: recurrences/overrides → watching + `feedbackDemoted` |
| `Stores` | class | src/store.ts | two-scope manager: findGate/recordFailure/recordSuccess/migrate/expireAll/reconcileAll/forgetSession |
| `recordSuccess` | method | src/store.ts | heal streak + session-chain clearing (exact matches only) |
| `coerceGateShape` | fn | src/validate.ts | strict parse of a persisted gate record (hopeless → null) |
| `repairGate` | fn | src/validate.ts | mechanical repair: inverted dates, truncation, re-sanitize, demote, session-state hygiene |
| `hasNestedTokens` | fn | src/validate.ts | nested-placeholder corruption fingerprint |
| `atomicWrite` / `withLock` | fn | src/store.ts | Windows-safe fs primitives (ownership-verified unlock) |

## CONVENTIONS

- ESM (`"type": "module"`) + Bun runtime; scripts run directly (`bun scripts/x.ts`); no build, no bundling
- No semicolons, double quotes, explicit return types on everything, `node:` prefix on builtins
- No linter/formatter config exists — style is maintained by hand, match neighboring code
- JSDoc `/** */` on exports; inline `//` comments explain WHY (design rationale), not WHAT
- Catch blocks swallow deliberately with a rationale comment; only `GateSignal` is rethrown
- Tunables are named UPPER_SNAKE constants grouped under `// --- Section ---` dividers

## ANTI-PATTERNS (THIS PROJECT)

- Do NOT scan read/edit/write output for failure text — it is file CONTENT, not command output (caused false gates); file-tool failures come exclusively from the event channel
- Do NOT count exit 1 from diagnostic verbs (grep/tsc/pytest/curl/ls...) as failure — intended outcome; exit ≥ 2 always counts (OpenCode normalizes exits to 1, so discriminate by command shape)
- Do NOT count aborted/cancelled tool executions as failures — `isNoiseError()` filters them; they are infrastructure noise, not agent mistakes
- Do NOT flatten interpreter one-liner payloads (`python -c`, `node -e`, PowerShell `& "...\python.exe" -c @"..."@`) to `<str>` — the code IS the call; `hashInterpreterPayload` fingerprints it so distinct scripts never share a gate
- Do NOT enforce signatures without residual identity — if normalization parameterized the whole command away (`cmd <path> <str>`, `node <str> <n>`), it matches a command family; `hasResidualIdentity()` guards every tier, such shapes may only watch
- Do NOT keep `cmd /c` wrappers in signatures — `unwrapCmdWrapper()` normalizes the payload so identity and the diagnostic tier see the real verb
- Do NOT persist anything before `sanitizeForStore()` (control-char strip + secret scrub) — signatures, snippets, args, error text, logs; PowerShell VT colors in persisted text are a bug
- Do NOT throw from hooks except `GateSignal` — plugin bugs must never break the tool pipeline
- Do NOT let file-probe or diagnostic tools reach `blocking` status — `canBlock()` is the single source of truth; `migrate()` auto-demotes violations (diagnostics land in `reminding`, never `blocking`)
- Do NOT create gates manually — promotion is mechanical (3 failures × 2 sessions)
- Do NOT delete quarantine files (`gates.json.corrupt-*`, `log.jsonl.corrupt`) without inspection — they are the preserved forensic bytes of corrupted data
- Do NOT bypass the validation boundary — gates enter memory through `coerceGateShape`/`repairGate` (in `load()`) and structural healing through `reconcile()`; never hand-roll raw JSON reads/writes of store files

## UNIQUE STYLES

- Two-scope store: project gates in `<repo>/.opencode/dejavu/` (committable) escalate to global `~/.config/opencode/dejavu/` after appearing in 2+ project dirs (agent habits vs repo quirks) — except repo-local verbs (npm/git/gradle/docker/...), which are repo quirks by nature and stay project-scoped forever
- Three enforcement tiers: `blocking` (remind, then hard-block on same-session repeat), `reminding` (diagnostics — signal without punishing iteration), `watching` (evidence only); `fuzzySimilar` never merges disjoint flag sets but allows subset additions
- Self-healing stores: every init runs `reconcileAll()` — unparseable files are quarantined (bytes preserved in `*.corrupt-*`, never deleted), records are strictly parsed + mechanically repaired, index is reconciled, and every repair is logged (`repaired`/`quarantined` events); `doctor --repair` does the same on demand — one command replaces hand-debugging
- Multi-window safe: the remind→block chain is persisted on the gate, not in process memory — several OpenCode windows (each its own process on the shared store) and process restarts all see the same escalation; hot-path reads use a 1s TTL cache + O(1) key index
- `dejavu:proceed` escape hatch: trailing marker comment, matched with word boundaries, stripped before normalization so bypassed failures land on the original pattern
- `recurredAfterGate` is THE health metric — gates that fire without killing the error get `review: true`; its mirror `succeededAfterGate` heals gates — 3 consecutive successes on an enforced gate retire it to `watching`, so a fixed command stops reminding
- Enforcement has negative feedback: 3+ post-gate recurrences or 5+ explicit overrides demote a gate to `watching` + `feedbackDemoted` (never re-promotes mechanically; `feedbackBaseline` gives a human re-enforcement a fresh grace window) — a gate the agent keeps fighting is friction, not teaching; overrides are counted on the gate (`overrideCount`, blocking gates only), demotions log `demoted`
- The loop closes on success: a SUCCESS on an enforced gate clears that session from the remind→block chain (override + prove-the-fix leaves the session clean) and grows the heal streak — enforcement listens to behavior in both directions; iteration runners (`dart run`, `go run|build|test|vet`, `cargo run|build|test|clippy`) remind but never block
- Taught retirement: a gate reminded 5+ times with zero reoffense has taught its lesson (no success can ever heal it — the agent changed behavior) and retires to watching (`retired-taught`); re-promotion on new failures stays possible
- Retirement damping: a healed/taught-retired gate keeps its lifetime `count`/`sessions`, which alone would clear the promotion bar and re-promote it on the very next single failure (a promote→heal→promote loop). Retirement captures `retireBaseline.count`; re-promotion needs a full fresh bar of failures since retirement (`count − retireBaseline.count ≥ threshold`). Doctor's FLAPPY report watches for the oscillation
- Cross-channel dedup: one tool call must never be counted twice — the after-hook (exit/text) and the event stream (error parts) are disjoint by construction, but a runtime guard keyed on (key, session) + channel-mismatch window counts a double-firing call once (doctor's CROSS-CHANNEL DOUBLE-COUNT is the observable tripwire). The dedup key is the WHOLE-CALL signature, not the segment-attributed key — the event channel signs the entire call, so a chained command must dedup on one shared identity or it slips through on mismatched keys
- Global forensics for deferred events: deferred events bypass `logAll`'s routing, so the project store mirrors its salient deferred events (`demoted`/`retired-healed`) into the global log via `routeSalientTo` — direct events are not mirrored there (logAll already routes them)
- Windows-first fs: `\\?\` long-path prefix, tmp+rename with EPERM/EACCES/EBUSY backoff, lockfile with stale-steal and 3s degrade-to-unlocked (never hang the tool pipeline)

## GIT HOOKS

- commit-msg hygiene hook: `scripts/githooks/commit-msg` — header ≤100 chars, no emoji, no AI attribution trailers; matches trailer structure, so plain tool-name mentions pass
- Activate once per clone: `git config core.hooksPath scripts/githooks`

## COMMANDS

```bash
bun install
bun run typecheck            # tsc --noEmit — covers index.ts, src/**, scripts/**, test/**
bun test/smoke.ts            # full behavioral test; exit 1 on any failure
bun scripts/doctor.ts [projectDirs...]
bun scripts/analyze.ts [projectDirs...]
bun scripts/migrate.ts <projectDirs...>
```

## NOTES

- `tsconfig.json` covers `index.ts`, `src/**`, `scripts/**`, `test/**` — everything typechecks
- CI: GitHub Actions (`bun install --frozen-lockfile` + typecheck + smoke) on every push/PR
- Install = npm (`{ "plugin": ["opencode-dejavu"] }`) or clone + re-export from `~/.config/opencode/plugins/dejavu.ts` (see README)
- `DEJAVU_HOME` env var overrides the global store dir — smoke test and scripts rely on it
- Bump `PLUGIN_VERSION` (src/store.ts) on behavior changes — doctor detects version drift via `init` log events — AND keep `package.json` `version` in sync (npm publish uses the package version)
- gates.json files are human-editable by design: delete a gate object to disable, edit `correction` to teach
