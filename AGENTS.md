# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-22 (refreshed 2026-08-23)
**Commit:** ec439cd+
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
| Failure detection + recording | `index.ts` `tool.execute.after` + `event` | two channels: exit/text vs message stream |
| Signature/normalization | `src/patterns.ts` | `callSignature`, `normalizeCommand`, `parameterizeError` |
| Enforcement policy | `src/patterns.ts:canBlock()`/`canRemind()` | three tiers — bash non-diagnostics block, diagnostics remind-only, everything else just watches |
| Persistence, locks, promotion, global escalation | `src/store.ts` | `Stores.recordFailure()` is the core; cross-project evidence lives in global `index.json` |
| Self-healing / reconcile | `src/store.ts` + `src/validate.ts` | `Stores.reconcileAll()` at every init; `doctor --repair` on demand |
| Tunables | top of `index.ts` **and** `src/store.ts` | split: TTL/review caps in index, promote thresholds in store |
| Pathology checks | `scripts/doctor.ts` | 5 defect classes: stale-blocking, not-teaching, annoying, secrets, version drift |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Dejavu` | Plugin factory | index.ts:66 | entry point; wires 4 hooks, also `export default` |
| `GateSignal` | class | index.ts:37 | sentinel error — the ONLY error rethrown from hooks |
| `callSignature` | fn | src/patterns.ts:272 | stable call identity per tool (bash/read/edit/write/glob/grep) |
| `patternKey` | fn | src/patterns.ts:300 | sha1 prefix-12 of signature — the gate key |
| `canBlock` | fn | src/patterns.ts:184 | blocking policy gate |
| `canRemind` / `isRepoLocal` | fn | src/patterns.ts:197/215 | remind-only tier (diagnostics) / repo-local verbs that never escalate globally |
| `normalizeCommand` | fn | src/patterns.ts:80 | bash → signature; fingerprints interpreter one-liner payloads |
| `hashInterpreterPayload` | fn | src/patterns.ts:56 | `-c`/`-e` code payload → `<code:hash>` (identity of one-liners) |
| `fuzzySimilar` | fn | src/patterns.ts:349 | near-duplicate merge; length-band pre-filter + `FUZZY_MAX_LEN` cap |
| `detectFailure` | fn | src/patterns.ts:393 | line-by-line bash-output failure scan |
| `isNoiseError` | fn | src/patterns.ts:419 | aborted/cancelled executions are not failures |
| `scrubSecrets` | fn | src/patterns.ts:36 | redaction before ANY persistence |
| `GateStore` | class | src/store.ts:190 | one scope: gates.json + index.json + log.jsonl, TTL caches, key index |
| `Stores` | class | src/store.ts:513 | two-scope manager: findGate/recordFailure/migrate/expire/reconcileAll/forgetSession |
| `mergeGate` | fn | src/store.ts:483 | evidence merge for dedupe/escalation (never demotes blocking, preserves session state) |
| `coerceGateShape` | fn | src/validate.ts:24 | strict parse of a persisted gate record (hopeless → null) |
| `repairGate` | fn | src/validate.ts:76 | mechanical repair: inverted dates, truncation, re-scrub, demote, session-state hygiene |
| `atomicWrite` / `withLock` | fn | src/store.ts:120/151 | Windows-safe fs primitives |

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
- Do NOT flatten interpreter one-liner payloads (`python -c`, `node -e`) to `<str>` — the code IS the call; `hashInterpreterPayload` fingerprints it so distinct scripts never share a gate
- Do NOT persist anything before `scrubSecrets()` — signatures, snippets, args, error text, logs
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
- Windows-first fs: `\\?\` long-path prefix, tmp+rename with EPERM/EACCES/EBUSY backoff, lockfile with stale-steal and 3s degrade-to-unlocked (never hang the tool pipeline)

## COMMANDS

```bash
bun install
bun run typecheck            # tsc --noEmit — covers index.ts + src/** ONLY
bun test/smoke.ts            # full behavioral test; exit 1 on any failure
bun scripts/doctor.ts [projectDirs...]
bun scripts/analyze.ts [projectDirs...]
bun scripts/migrate.ts <projectDirs...>
```

## NOTES

- `tsconfig.json` covers `index.ts`, `src/**`, `scripts/**`, `test/**` — everything typechecks
- CI: GitHub Actions (`bun install --frozen-lockfile` + typecheck + smoke) on every push/PR
- Install = clone + re-export from `~/.config/opencode/plugins/dejavu.ts` (see README); npm publish planned
- `DEJAVU_HOME` env var overrides the global store dir — smoke test and scripts rely on it
- Bump `PLUGIN_VERSION` (src/store.ts:6) on behavior changes — doctor detects version drift via `init` log events — AND keep `package.json` `version` in sync (npm publish uses the package version)
- gates.json files are human-editable by design: delete a gate object to disable, edit `correction` to teach
