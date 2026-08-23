# Contributing

Small repo, tight conventions — read `AGENTS.md` first, it is the source of truth for layout, style, and anti-patterns.

## Dev setup

```bash
bun install
bun run typecheck     # strict tsc over index.ts, src/, scripts/, test/
bun test/smoke.ts     # behavioral suite; exits 1 on any failure
```

Every PR must pass both. New behavior = new smoke check (`test/smoke.ts` is a plain bun script, no framework).

## Rules that matter

- No semicolons, double quotes, explicit return types, `node:` prefixes, JSDoc on exports.
- Catch blocks swallow deliberately **with a rationale comment**; only `GateSignal` is rethrown from hooks.
- Anything persisted goes through `scrubSecrets()` first — signatures, snippets, args, corrections, logs.
- `canBlock()` in `src/patterns.ts` is the single source of truth for blocking policy; file probes and diagnostics never block.
- Bump `PLUGIN_VERSION` in `src/store.ts` on behavior changes (doctor detects version drift via init log events) and add a `CHANGELOG.md` entry.

## PRs

- One behavior change per PR; no refactors mixed with fixes.
- Describe the failure mode you prevent, not just the diff.
- Security-sensitive changes (scrub patterns, blocking policy, lock handling) need a smoke check proving the new behavior.

## Security

Found a way to leak a secret into `gates.json`/`log.jsonl`, or to poison gates from an untrusted repo? Open an issue titled `security:` — do not post the payload publicly.
