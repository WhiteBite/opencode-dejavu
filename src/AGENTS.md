# src/ — pattern engine + gate persistence

## OVERVIEW

Three dependency-free modules: `patterns.ts` (pure functions — call identity, normalization, detection, policy), `store.ts` (stateful — gates.json/log.jsonl I/O under locks, promotion, scope escalation, feedback demotion) and `validate.ts` (the parse/repair boundary every persisted gate crosses).

## WHERE TO LOOK

| Task | File | Symbols |
|------|------|---------|
| Call identity / gate keys | patterns.ts | `callSignature` → `normalizeCommand`/`normalizeFilePath` → `patternKey` |
| Interpreter one-liner identity | patterns.ts | `hashInterpreterPayload` — `-c`/`-e` code payload → `<code:hash>` |
| Chain-bypass protection | patterns.ts | `splitChain` (quote/paren-aware) → `bashSegmentSignatures` |
| Free-form error collapsing | patterns.ts | `parameterizeError` (event channel) vs `normalizeCommand` (bash) |
| Near-duplicate merge | patterns.ts | `fuzzySimilar` = normalized `levenshtein` ≤ 0.3 + flag-subset rule |
| Failure text scan | patterns.ts | `detectFailure` + `FAILURE_SIGNATURES` |
| Noise filtering | patterns.ts | `isNoiseError` + `NOISE_ERRORS` (aborted/cancelled ≠ failed) |
| Diagnostic/intended-exit logic | patterns.ts | `DIAGNOSTIC_VERBS`, `isIntendedNonzero`, `canBlock`, `canRemind` |
| Over-generic shape guard | patterns.ts | `hasResidualIdentity` — parameterized-away substance ⇒ watching only |
| Wrapper unwrapping | patterns.ts | `unwrapCmdWrapper` — `cmd /c\|/k` payload normalizes as the inner command |
| Persistence boundary | patterns.ts | `sanitizeForStore` = `stripControl` (ANSI/C0) + `scrubSecrets` |
| Escalation scope policy | patterns.ts | `isRepoLocal` + `REPO_LOCAL_VERBS` — repo-local verbs never escalate globally |
| One scope (gates.json + index.json + log.jsonl) | store.ts | `GateStore` — `load`/`save`/`loadIndex`/`saveIndex`/`log`/`expire`/`extract`/`rotateLog`/`reconcile`; deferred events `deferEvent`/`flushDeferred`/`appendBatch` + `routeSalientTo` |
| Two-scope logic + promotion | store.ts | `Stores` — `findGate`/`recordFailure`/`migrate`/`enforcedGates`/`reconcileAll`; `mergeGate` merges duplicate keys |
| Enforcement negative feedback | store.ts | `checkFeedbackDemotion` + `DEMOTE_RECURRENCES`/`DEMOTE_OVERRIDES`; counters `overrideCount`/`recurredAfterGate`, grace via `feedbackBaseline` |
| Gate parse/repair boundary | validate.ts | `coerceGateShape` (strict parse), `repairGate` (mechanical coercion), `hasNestedTokens` (corruption fingerprint) |
| fs safety | store.ts | `ntPath`, `atomicWrite`, `withLock` |

## INVARIANTS (do not break)

- Rule order in `PARAM_RULES` matters: quoted strings first, specific tokens (uuid/sha/ip/url/date), generic numbers last — reordering fragments signatures
- Rule order in `normalizeCommand` matters too: control-char strip first, then quoted strings are parameterized BEFORE path rules — a `<str>` substitution inserts spaces that would expose an adjacent `/` to the path rule on a second pass (idempotency); `unwrapCmdWrapper` runs before `hashInterpreterPayload` so a wrapped one-liner still fingerprints; interpreter payload hashing runs while the payload is still raw
- `sanitizeForStore()` (control-char strip + `scrubSecrets`) runs on every string before it touches disk; `recordFailure` re-sanitizes defensively
- Three enforcement tiers: `canBlock` (bash && non-diagnostic && residual identity) is the ONLY path to `blocking`; `canRemind` (diagnostic bash && residual identity) is the only path to `reminding`; probe tools use `PROMOTE_COUNT_PROBE` and never leave `watching`; `hasResidualIdentity` guards BOTH tiers — a fully parameterized shape may only watch
- Feedback demotion is the negative twin of healing: recurrences (`DEMOTE_RECURRENCES`) or overrides (`DEMOTE_OVERRIDES`) past threshold demote to `watching` + `feedbackDemoted`, which blocks mechanical re-promotion; `feedbackBaseline` (counter values at demotion) gives a human re-enforcement a fresh grace window; `mergeGate` sums `overrideCount` and baselines and preserves the demotion mark
- Index entries are never pruned on one project's initiative (`reconcileAll` rebuilds missing entries only) — a process sees one project store, so "absent here" ≠ "dead"; rot is bounded by the TTL sweep in `expireAll`
- Repo-local verbs (`isRepoLocal`) never escalate to the global store — their failures are repo quirks; both escalation paths (`recordFailure` + `reconcileAll`) and doctor's MISSED-ESCALATION honor this
- Fuzzy merging requires comparable flag sets (one a subset of the other) — disjoint switches are different operations and must never merge; subset additions still consolidate
- `DIAGNOSTIC_VERBS` serves two callers (exit-1 allowlist + blocking policy) — one list, two uses; edit knowing both move
- Lock order is always project → global, gates → index (see `recordFailure` escalation) — reversing deadlocks; the log lock is separate and leaf-level, acquired alone or outermost, NEVER while holding a gates/index lock — log-hygiene helpers (`exciseCorruptLogLines`/rotate) run OUTSIDE the scope lock, else the scope critical section stretches across a full log read+parse+rewrite at init-storm time
- A degraded lock waiter NEVER unlinks the lockfile (`withLock` tracks `acquired`) — deleting the live holder's lock destroys mutual exclusion for every subsequent acquirer (the production corrupt-log root cause)
- Incoming bash signatures without residual identity match concrete gates EXACTLY only (`findGate` fuzzy + `recordFailure` consolidation both guard it) — family noise must neither enforce nor pollute another gate's evidence
- `bashSegmentSignatures` unfolds `cmd /c` payloads recursively (depth-bounded) — inner-chain gates fire through the wrapper, and the before-hook honors `dejavu:proceed` inside a LEADING wrapper payload (unwrap before quote-strip)
- `INTERPRETER_ONELINER` alternatives run longest-first — `-c` matching inside `-command` swallowed the flag tail into the payload and fragmented keys across flag spellings
- Cross-project evidence lives ONLY in the global `index.json` — a gate's own `projects` array sees one store and never drives escalation alone
- Escalation writes the global gate FIRST, then removes the project copy — a crash between the two writes must leave a duplicate (healed by migrate), never a hole
- `mergeGate` preserves session enforcement state (`remindedSessions`/`failedSessions`) — merging must never reset the remind→block chain
- Fuzzy consolidation in `recordFailure` prefers the gate holding the session's reminded state (before/after hooks must stay in sync) and never overwrites the evidence snippet
- Snippets and corrections are UNTRUSTED text re-injected into agent context — keep the data-label framing in messages, the 200-char correction bound, and scrub quarantine bytes
- Inside `runLocked` always `load(true)`; OUTSIDE the gates lock always non-force `load()` — `load(true)` quarantines an unparseable file (a WRITE), so forcing outside the lock is a write-without-lock (the class round 3 fixed in doctor); unlocked peeks are routing hints only, never a basis for mutation
- Hot-path reads use the 1s TTL cache + key index (`byKey`/`enforcedOnly`); mutations inside locks use `load(true)`; `save()` refreshes the cache directly
- The remind→block chain is persisted ON THE GATE (`remindedSessions`/`failedSessions`) and enforced under the store lock — process memory holds nothing authoritative, so several windows and restarts share one escalation
- Successes heal: `recordSuccess` grows `succeededAfterGate` on an enforced gate; at `HEAL_SUCCESSES` (3) it retires to `watching` and logs `healed`. A failure resets the streak in `recordFailure`. Only bash successes heal (only bash gates enforce). A success ALSO clears the succeeding session from `remindedSessions`/`failedSessions` — override + success must leave the session clean, otherwise the only exit from a block is permanent overriding (the arms-race engine)
- Iteration verbs (`dart run`, `go run|build|test|vet`, `cargo run|build|test|clippy`) are diagnostic: their failures are the work itself — they remind but never block, and their exit 1 is the intended "still broken" outcome of iteration
- Overrides count toward demotion ONLY on blocking gates — a reminding gate never blocks, its marker just skips one interrupting reminder; avoiding that is rational, not friction (the `override` event is still logged for visibility)
- Index churn gate: the first-ever failure of a brand-new pattern (no entry yet, count 1) skips the machine-wide index rewrite; anything indexed or recurring updates as before — escalation evidence preserved, one-off noise not rewritten
- Unparseable gate dates reset to now at the parse boundary — `expire` compares `Date.parse < cutoff`, and NaN is never `<` anything (immortal gates)
- `migrate()` never re-promotes `feedbackDemoted` gates (the watching→reminding catch-up checks the flag) — "never re-promotes mechanically" must hold on EVERY mechanical path, not just `recordFailure`. The catch-up ALSO exempts `retireBaseline` gates: a healed/taught-retired gate's lifetime count already clears the catch-up bar, so re-promoting it on every migrate would re-open the promote→heal→promote oscillation the damping baseline exists to kill — retirement is evidence-based and only a fresh bar of failures (via `recordFailure`) may lift it
- `recordSuccess` heals and clears session chains on EXACT matches only — fuzzy matches are attribution convenience, never a basis for state mutation (proxy successes would heal the wrong gate)
- The override marker requires comment syntax (`# dejavu:proceed`) — quote-stripping alone let unquoted markers smuggled as data (`echo dejavu:proceed && gated`) bypass gates
- Exit-1 immunity requires every NON-transparent chain segment to be diagnostic — a diagnostic later in the chain must not hide a non-diagnostic's failure (`deploy && grep`). Pipe formatters (`select-object`/`tee-object`/`tee`/`head`/`tail`/...) are transparent ONLY in pipe-tail position (after a `|`, including bash's `|&` pipe-stdout-and-stderr, which is a pipe so its tail is a pipe tail too): they never produce the pipeline's exit code there, so `tsc | Select-Object` keeps immunity; but a formatter standing alone or as the TERMINAL producer of a sequence (`npm test && tail -5 missing.log`) IS the failing producer and still counts. Navigation (`cd`/`set-location`) is transparent anywhere. A real non-diagnostic producer still breaks immunity (`npm install | select-object` counts). Position comes from `splitChainTagged`; `||` is a sequence separator, so the segment after it is a producer, not a pipe tail. A single `&` is deliberately NOT a separator — on Windows it is the PowerShell call operator (`& "C:\…\exe"`), and splitting on it would break those invocations
- `load()` distinguishes corruption from absence: unparseable gates.json quarantines under the lock (bytes kept) instead of silently emptying — the silent path let the next save overwrite recoverable gates
- `withLock` verifies ownership (pid in the lockfile) before unlinking — after a stale-steal the original holder would otherwise delete the stealer's lock and open the critical section
- Retire-on-taught: reminded `TAUGHT_REMINDERS`+ times with zero reoffense AND zero post-gate failures → softly to watching (`retired-taught`, no feedbackDemoted — re-promotion stays possible). Healing via success is impossible there: the agent changed behavior, the gated call never runs again. Only TRUE first encounters count — raced calls (same dispatch burst) never saw the reminder
- Anti-nag retirement (the negative twin of taught): BLOCKING gates only (`status === "blocking"` in the condition) reminded `ANTI_NAG_REMINDERS`+ times AND `recurredAfterReminder >= ANTI_NAG_REOFFENSE` (the agent keeps reoffending in-session right after the reminder) → the gate NAGS instead of teaching: watching + `feedbackDemoted`, the call proceeds with NO reminder, and the counters are reset (so a manual re-enforce starts fresh instead of instantly re-triggering). Same hook point/lock/first-encounter discipline as taught, but `feedbackDemoted` blocks mechanical re-promotion (else the nag loop restarts); a human re-enforces manually. `recurredAfterReminder` accrues only while blocking; the status guard is defense-in-depth so a reminding gate is never anti-nag-retired, and `repairGate` zeroes the counter once a gate is no longer blocking (a stale value left by a tier demotion would otherwise block taught-retirement and let the gate nag until TTL) — the plugin should help, not nag
- Retirement damping (`retireBaseline`): heal and teach-retire both capture `{count}` at the moment of retirement, and re-promotion requires `count − retireBaseline.count ≥ threshold` — a full fresh bar — which promotion then consumes (deletes). Without it a retired gate re-promotes on the VERY NEXT single failure, because its lifetime `count`/`sessions` already clear the bar (promote→heal→promote oscillation). `mergeGate` preserves an existing baseline, `repairGate` clamps it to ≤ `count` (a corrupted overshoot must keep damping active, not re-open instant re-promotion). feedbackDemoted gates are orthogonal — they never re-promote at all
- Enforcement counters are lifecycle-scoped: promotion resets remindedCount/recurrences/overrides/heal streak/baseline AND clears session chains (remindedSessions/failedSessions) — a re-promoted gate must not inherit the previous retire/heal round's evidence, and stale chains must not let a session skip its reminder
- Demotion votes count only failures the gate had a chance to prevent: recurrence demotion additionally requires `DEMOTE_REOFFENSE_SESSIONS` distinct sessions that reoffended AFTER a reminder (`reoffenseSessions`) — first-encounter failures never saw a reminder, and one bad session/model must not demote a gate for everyone
- Exit-1 immunity flattens paren groups before splitting (`isIntendedNonzero`): `(deploy && grep)` is a container, not an atom — a diagnostic inside parens must not immunize a non-diagnostic failure
- Hook events are queued inside the store lock and logged AFTER release — logging under the gates lock extends the critical section and cascades contention into degrade storms
- `recordSuccess` is exact-only (byKey across scopes, no fuzzy scan): it runs on every successful bash call, and healing/chain-clearing are state mutations — fuzzy matches are attribution convenience, never a basis for mutation
- Log appends and rotation take the log lock — every OpenCode window shares the global log; unlocked appends interleave into broken JSON
- Nothing logs under the gates lock — events are deferred (`deferEvent`) and flushed by the next `log()`/`flushDeferred()`; scripts (doctor/migrate) MUST call `flushDeferred()` before exiting or repair events are lost ("every repair is logged"). The drain happens INSIDE the log lock (draining before the lock dropped events)
- `reconcile()` preserves the migration stamp when it rewrites gates.json — dropping it forces a full `migrate()` scan on every startup (init storm)
- `logAll` scopes events: high-volume events (`detected`/`reminded`/`blocked`/`retry-allowed`/`recurred-after-gate`) stay in the project log; only machine-memory-salient events (`GLOBAL_LOG_EVENTS` = init/promoted/demoted/healed/retired-*/override) reach the global log — the global log lock is the most-contended lock
- Deferred events bypass `logAll`'s routing, so the project store mirrors them itself: `routeSalientTo` (project→global, wired in the `Stores` constructor; the global store gets NO peer) makes `log()`/`flushDeferred()` forward the salient subset of the DRAINED deferred batch via the peer's `appendBatch`, AFTER the store's own log lock releases (leaf locks, one at a time). Direct events are NEVER mirrored here — `logAll` already routes them; mirroring the direct `event` inside `log()` would double-write it to the global log
- `recordFailure` uses FLAT lock phases — the project gates lock is released before the index lock and the global gates lock (never nested); escalation is three short phases (copy → global-first write → remove-local); a crash between the two writes leaves a duplicate healed by migrate, never a hole
- The TTL sweep timer is jittered (0.75–1.25× interval) and flushes deferred events (`flushDeferredAll`) so a quiet long-lived process doesn't lose sweep events on exit
- Every gate read from disk crosses `coerceGateShape` + `repairGate` in `load()` — enforcement never sees raw state; hopeless records are dropped, repairable ones coerced
- Quarantine preserves bytes: unparseable files are renamed to `*.corrupt-*`, never deleted; every repair emits a `repaired`/`quarantined` log event
- Fuzzy matching is Levenshtein-based on purpose: token Jaccard collapsed all `<str>` placeholders into one bucket; ratio ≤ 0.3 PLUS absolute distance ≥ 3 (verb-level-different commands must never merge)

## ANTI-PATTERNS

- Do NOT add a tool to `callSignature` without deciding its class: `PROBE_TOOLS` (higher bar, never blocks) or bash-class
- Do NOT widen `FAILURE_SIGNATURES` to cover file-tool output — that text is file content; extend the event channel instead
- Do NOT flatten interpreter one-liner payloads to `<str>` — `hashInterpreterPayload` must run before string parameterization; a bare `-c <str>` gate would block the whole command family
- Do NOT enforce signatures without residual identity — if normalization parameterized the whole command away (`cmd <path> <str>`, `node <str> <n>`), it matches a command family; `hasResidualIdentity()` guards every tier, such shapes may only watch
- Do NOT keep `cmd /c` wrappers in signatures — `unwrapCmdWrapper()` normalizes the payload so identity and the diagnostic tier see the real verb
- Do NOT prune global index entries because the CURRENT scope lacks the key — the gate may live in another project's store; only the TTL sweep removes entries
- Do NOT persist anything before `sanitizeForStore()` — terminal control chars in signatures/snippets/corrections are a bug (PowerShell colors errors with VT sequences)
- Do NOT count aborted/cancelled executions as failures — filter with `isNoiseError()` at the event channel
- Do NOT widen `coerceGateShape` drop rules casually — records it deems hopeless are silently dropped on every load; a bad rule silently empties stores
- Do NOT write gates.json directly — always `runLocked` + `save()` (atomicWrite); logs are append-only via `log()`
- Do NOT let `withLock` throw on contention — it degrades to unlocked after `LOCK_WAIT_MS` by design (pipeline must not hang)
- Do NOT reorder `INTERPRETER_ONELINER` alternatives shortest-first and do NOT add a code-passing interpreter flag without adding it to `CODE_PASSING_FLAGS` (the guard and the fingerprint must agree on what is structure)
- Do NOT promise blocks in reminding-tier messages — tier-truthful wording only; a wrong enforcement model teaches the agent wrongly
- Do NOT read `log.jsonl` outside the log lock for rewrite-style operations (excise/rotate) — an unlocked read + locked rewrite drops concurrent appends
- Do NOT count reminding-tier overrides toward `DEMOTE_OVERRIDES` — only blocking friction demotes
