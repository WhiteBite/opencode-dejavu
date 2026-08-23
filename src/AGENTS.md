# src/ — pattern engine + gate persistence

## OVERVIEW

Two dependency-free modules: `patterns.ts` (pure functions — call identity, normalization, detection, policy) and `store.ts` (stateful — gates.json/log.jsonl I/O under locks, promotion, scope escalation).

## WHERE TO LOOK

| Task | File | Symbols |
|------|------|---------|
| Call identity / gate keys | patterns.ts | `callSignature` → `normalizeCommand`/`normalizeFilePath` → `patternKey` |
| Chain-bypass protection | patterns.ts | `splitChain` (quote/paren-aware) → `bashSegmentSignatures` |
| Free-form error collapsing | patterns.ts | `parameterizeError` (event channel) vs `normalizeCommand` (bash) |
| Near-duplicate merge | patterns.ts | `fuzzySimilar` = normalized `levenshtein` ≤ 0.3 |
| Failure text scan | patterns.ts | `detectFailure` + `FAILURE_SIGNATURES` |
| Diagnostic/intended-exit logic | patterns.ts | `DIAGNOSTIC_VERBS`, `isIntendedNonzero`, `canBlock` |
| One scope (gates.json + log.jsonl) | store.ts | `GateStore` — `load`/`save`/`log`/`expire`/`rotateLog` |
| Two-scope logic + promotion | store.ts | `Stores` — `findGate`/`recordFailure`/`migrate`/`blockingGates` |
| fs safety | store.ts | `ntPath`, `atomicWrite`, `withLock` |

## INVARIANTS (do not break)

- Rule order in `PARAM_RULES` matters: quoted strings first, specific tokens (uuid/sha/ip/url/date), generic numbers last — reordering fragments signatures
- `scrubSecrets()` runs on every string before it touches disk; `recordFailure` re-scrubs defensively
- `canBlock(tool, sig)` = `tool === "bash" && !diagnostic` — the ONLY path to `blocking`; probe tools use `PROMOTE_COUNT_PROBE` and never block
- `DIAGNOSTIC_VERBS` serves two callers (exit-1 allowlist + blocking policy) — one list, two uses; edit knowing both move
- Lock order is always project → global (see `recordFailure` escalation) — reversing deadlocks
- Inside `runLocked` always `load(true)`; unlocked `load()` peeks are routing hints only, never a basis for mutation
- `GateStore.load` caches by mtime — after external edits the cache refreshes on next stat; `save()` refreshes it manually
- Fuzzy matching is Levenshtein-based on purpose: token Jaccard collapsed all `<str>` placeholders into one bucket

## ANTI-PATTERNS

- Do NOT add a tool to `callSignature` without deciding its class: `PROBE_TOOLS` (higher bar, never blocks) or bash-class
- Do NOT widen `FAILURE_SIGNATURES` to cover file-tool output — that text is file content; extend the event channel instead
- Do NOT write gates.json directly — always `runLocked` + `save()` (atomicWrite); logs are append-only via `log()`
- Do NOT let `withLock` throw on contention — it degrades to unlocked after `LOCK_WAIT_MS` by design (pipeline must not hang)
