# PROJECT KNOWLEDGE BASE

**Generated:** 2026-08-22
**Commit:** none (fresh repo — all files untracked)
**Branch:** master

## OVERVIEW

dejavu — OpenCode plugin ("memory prosthesis with teeth"): mechanically detects recurring tool-call failures and promotes them into enforced gates (3 failures across 2 distinct sessions). Remind first, hard-block on same-session repeat offense. TypeScript ESM, runs under Bun, ships as raw `.ts` (no build step).

## STRUCTURE

```
dejavu-opencode-plugin/
├── index.ts            # Plugin entry — exports Dejavu (Plugin factory) + all 4 hooks
├── src/
│   ├── patterns.ts     # Pure engine: signatures, normalization, secret scrub, detection, blocking policy
│   └── store.ts        # GateStore/Stores: two-scope persistence, locks, promotion, TTL, migration
├── test/smoke.ts       # Behavioral smoke test — plain bun script, no framework, temp-dir isolated
├── scripts/            # doctor.ts (pathology report), analyze.ts (store summary), migrate.ts (demote+scrub)
├── command/dejavu.md   # /dejavu slash-command definition (install → ~/.config/opencode/command/)
├── skills/dejavu/      # Companion agent-protocol skill (install → ~/.config/opencode/skills/)
└── .omo/, .codegraph/  # Tooling artifacts — not project code
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Gate enforcement (remind/block/override) | `index.ts` `tool.execute.before` | state machine lives in per-session Maps |
| Failure detection + recording | `index.ts` `tool.execute.after` + `event` | two channels: exit/text vs message stream |
| Signature/normalization | `src/patterns.ts` | `callSignature`, `normalizeCommand`, `parameterizeError` |
| Blocking policy | `src/patterns.ts:canBlock()` | single source of truth — bash non-diagnostics only |
| Persistence, locks, promotion, global escalation | `src/store.ts` | `Stores.recordFailure()` is the core |
| Tunables | top of `index.ts` **and** `src/store.ts` | split: TTL/review caps in index, promote thresholds in store |
| Pathology checks | `scripts/doctor.ts` | 5 defect classes: stale-blocking, not-teaching, annoying, secrets, version drift |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Dejavu` | Plugin factory | index.ts:79 | entry point; wires 4 hooks, also `export default` |
| `GateSignal` | class | index.ts:32 | sentinel error — the ONLY error rethrown from hooks |
| `callSignature` | fn | src/patterns.ts:222 | stable call identity per tool (bash/read/edit/write/glob/grep) |
| `patternKey` | fn | src/patterns.ts:250 | sha1 prefix-12 of signature — the gate key |
| `canBlock` | fn | src/patterns.ts:130 | blocking policy gate |
| `detectFailure` | fn | src/patterns.ts:320 | line-by-line bash-output failure scan |
| `scrubSecrets` | fn | src/patterns.ts:34 | redaction before ANY persistence |
| `GateStore` | class | src/store.ts:161 | one scope: gates.json + log.jsonl, mtime cache |
| `Stores` | class | src/store.ts:246 | two-scope manager: findGate/recordFailure/migrate/expire |
| `atomicWrite` / `withLock` | fn | src/store.ts:95/126 | Windows-safe fs primitives |

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
- Do NOT persist anything before `scrubSecrets()` — signatures, snippets, args, error text, logs
- Do NOT throw from hooks except `GateSignal` — plugin bugs must never break the tool pipeline
- Do NOT let file-probe or diagnostic tools reach `blocking` status — `canBlock()` is the single source of truth; `migrate()` auto-demotes violations
- Do NOT create gates manually — promotion is mechanical (3 failures × 2 sessions)

## UNIQUE STYLES

- Two-scope store: project gates in `<repo>/.opencode/dejavu/` (committable) escalate to global `~/.config/opencode/dejavu/` after appearing in 2+ project dirs (agent habits vs repo quirks)
- `dejavu:proceed` escape hatch: trailing marker comment, matched with word boundaries, stripped before normalization so bypassed failures land on the original pattern
- `recurredAfterGate` is THE health metric — gates that fire without killing the error get `review: true`
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

- `tsconfig.json` include = `index.ts` + `src/**` only → `scripts/` and `test/` are NOT typechecked
- No CI, no commits yet; install = re-export from `~/.config/opencode/plugins/dejavu.ts` (README uses absolute path)
- `DEJAVU_HOME` env var overrides the global store dir — smoke test and scripts rely on it
- Bump `PLUGIN_VERSION` (src/store.ts:6) on behavior changes — doctor detects version drift via `init` log events
- gates.json files are human-editable by design: delete a gate object to disable, edit `correction` to teach
