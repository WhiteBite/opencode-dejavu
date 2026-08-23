# src/ — pattern engine + gate persistence

## OVERVIEW

Two dependency-free modules: `patterns.ts` (pure functions — call identity, normalization, detection, policy) and `store.ts` (stateful — gates.json/log.jsonl I/O under locks, promotion, scope escalation).

## WHERE TO LOOK

| Task | File | Symbols |
|------|------|---------|
| Call identity / gate keys | patterns.ts | `callSignature` → `normalizeCommand`/`normalizeFilePath` → `patternKey` |
| Interpreter one-liner identity | patterns.ts | `hashInterpreterPayload` — `-c`/`-e` code payload → `<code:hash>` |
| Chain-bypass protection | patterns.ts | `splitChain` (quote/paren-aware) → `bashSegmentSignatures` |
| Free-form error collapsing | patterns.ts | `parameterizeError` (event channel) vs `normalizeCommand` (bash) |
| Near-duplicate merge | patterns.ts | `fuzzySimilar` = normalized `levenshtein` ≤ 0.3 |
| Failure text scan | patterns.ts | `detectFailure` + `FAILURE_SIGNATURES` |
| Noise filtering | patterns.ts | `isNoiseError` + `NOISE_ERRORS` (aborted/cancelled ≠ failed) |
| Diagnostic/intended-exit logic | patterns.ts | `DIAGNOSTIC_VERBS`, `isIntendedNonzero`, `canBlock` |
| One scope (gates.json + index.json + log.jsonl) | store.ts | `GateStore` — `load`/`save`/`loadIndex`/`saveIndex`/`log`/`expire`/`extract`/`rotateLog`/`reconcile` |
| Two-scope logic + promotion | store.ts | `Stores` — `findGate`/`recordFailure`/`migrate`/`blockingGates`/`reconcileAll`; `mergeGate` merges duplicate keys |
| Gate parse/repair boundary | validate.ts | `coerceGateShape` (strict parse), `repairGate` (mechanical coercion), `hasNestedTokens` (corruption fingerprint) |
| fs safety | store.ts | `ntPath`, `atomicWrite`, `withLock` |

## INVARIANTS (do not break)

- Rule order in `PARAM_RULES` matters: quoted strings first, specific tokens (uuid/sha/ip/url/date), generic numbers last — reordering fragments signatures
- `scrubSecrets()` runs on every string before it touches disk; `recordFailure` re-scrubs defensively
- `canBlock(tool, sig)` = bash && non-diagnostic && not a bare one-liner shape — the ONLY path to `blocking`; probe tools use `PROMOTE_COUNT_PROBE` and never block
- `DIAGNOSTIC_VERBS` serves two callers (exit-1 allowlist + blocking policy) — one list, two uses; edit knowing both move
- Lock order is always project → global, gates → index (see `recordFailure` escalation) — reversing deadlocks; the log lock is separate and leaf-level
- Cross-project evidence lives ONLY in the global `index.json` — a gate's own `projects` array sees one store and never drives escalation alone
- Inside `runLocked` always `load(true)`; unlocked `load()` peeks are routing hints only, never a basis for mutation
- `GateStore.load` caches by mtime — after external edits the cache refreshes on next stat; `save()` refreshes it manually
- Log appends and rotation take the log lock — every OpenCode window shares the global log; unlocked appends interleave into broken JSON
- Every gate read from disk crosses `coerceGateShape` + `repairGate` in `load()` — enforcement never sees raw state; hopeless records are dropped, repairable ones coerced
- Quarantine preserves bytes: unparseable files are renamed to `*.corrupt-*`, never deleted; every repair emits a `repaired`/`quarantined` log event
- Fuzzy matching is Levenshtein-based on purpose: token Jaccard collapsed all `<str>` placeholders into one bucket; ratio ≤ 0.3 PLUS absolute distance ≥ 3 (verb-level-different commands must never merge)

## ANTI-PATTERNS

- Do NOT add a tool to `callSignature` without deciding its class: `PROBE_TOOLS` (higher bar, never blocks) or bash-class
- Do NOT widen `FAILURE_SIGNATURES` to cover file-tool output — that text is file content; extend the event channel instead
- Do NOT flatten interpreter one-liner payloads to `<str>` — `hashInterpreterPayload` must run before string parameterization; a bare `-c <str>` gate would block the whole command family
- Do NOT count aborted/cancelled executions as failures — filter with `isNoiseError()` at the event channel
- Do NOT widen `coerceGateShape` drop rules casually — records it deems hopeless are silently dropped on every load; a bad rule silently empties stores
- Do NOT write gates.json directly — always `runLocked` + `save()` (atomicWrite); logs are append-only via `log()`
- Do NOT let `withLock` throw on contention — it degrades to unlocked after `LOCK_WAIT_MS` by design (pipeline must not hang)
