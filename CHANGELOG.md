# Changelog

## 2.17.0 — 2026-08-31

### Fixed (production-data analysis: exit-1 immunity was breaking on real-world command shapes)
Found by reading the accumulated store data (doctor + analyze across all projects): the dominant NOT-TEACHING / REMINDERS-IGNORED / ANNOYING / FLAPPY noise was test and type-check commands being **gated on ordinary test failures** — exactly the "the failures are the work" case the immunity exists for. Three root causes:

- **Piping a diagnostic into a PowerShell formatter broke immunity** — `flutter test --no-pub 2>&1 | Select-Object -Last 5` (and `Tee-Object`, etc.): the formatter segment is not in `DIAGNOSTIC_VERBS`, so the "every chain segment must be diagnostic" rule denied immunity and the test's exit-1 became a gate. PowerShell pipeline formatters never set the exit code (`$LASTEXITCODE` stays with the producing native command), so they are now transparent to the check. A real non-diagnostic producer still gates (`npm install | select-object` still counts).
- **A leading `cd <path> &&` broke immunity** — `cd X && npx tsc --noEmit`: the navigation segment is non-diagnostic and denied immunity even though only the diagnostic can fail. Navigation (`cd`/`set-location`/`pushd`/`popd`) is now transparent. (`cd` alone still gates — a bare `cd` to a bad path is a real recurring mistake.)
- **`npm test` / `yarn test` / `pnpm test` were not recognized as diagnostics** — the test-runner list covered pytest/jest/vitest/etc. but not the npm/yarn/pnpm script runners, so their ordinary test failures gated. Added. (`npm run build` stays non-diagnostic — a build failure is a real error, not "the work".)

The `deploy --broken && grep done` hazard (a later diagnostic hiding a real failure) is unchanged and still denied.

### Systemic lesson
- An allowlist rule ("every segment must be diagnostic") is only as good as its segment model: segments that never produce the exit code (pipe formatters, `cd`) must be transparent to it, or the rule false-fires on the exact shapes agents use to trim noisy output (`… | Select-Object -Last 5`). Real production data was the only thing that surfaced this — the synthetic immunity tests all used bare or `&&`-chained commands.

## 2.16.0 — 2026-08-30

### Added (implementing the three deferred audit items)
- **Cross-channel double-count guard** — the same failure recorded by BOTH detection channels (after-hook exit/text AND the event-stream error part) within 2s for one (key, session) is now counted once. The guard keys on the WHOLE-CALL signature, not the segment-attributed key: the event channel signs the entire call, so a chained command (`x && gated`) double-firing across channels still dedups on one identity instead of slipping through on mismatched keys. The channels are disjoint by construction today (bash fails via exit/text, file tools via error-state parts), so the guard is inert until upstream ever double-fires — then it keeps counts and demotion math correct instead of inflating them. The doctor tripwire from 2.11.0 remains as the observable.
- **Promote→heal oscillation damping (`retireBaseline`)** — `count`/`sessions` are lifetime-cumulative, so a healed or taught-retired gate re-promoted on the VERY NEXT single failure (the FLAPPY loop the round-7 doctor report now measures). Retirement (heal or taught) now captures `retireBaseline.count`; re-promotion requires a full fresh bar (`count − retireBaseline.count ≥ threshold`), consumed on promotion. Feedback-demoted gates are untouched (they never re-promote mechanically). The invariant holds on EVERY mechanical re-promotion path: `migrate()`'s watching→reminding catch-up also exempts `retireBaseline` gates — without that, a healed diagnostic gate's lifetime count cleared the catch-up bar and re-promoted on every migrate (each version bump), re-opening the oscillation and spamming `healed` into the global log. This is the damping the audits deferred until data justified — shipped behind the same evidence model, observable via the FLAPPY report.
- **Deferred salient events reach the global log** — deferred events bypass `logAll`'s routing, so a project-store `demoted` (migrate) or `retired-healed` (expireAll) never reached the global forensics despite being in `GLOBAL_LOG_EVENTS`. The project store now carries `routeSalientTo` (wired by `Stores` to the global store); `log()`/`flushDeferred()` mirror the salient subset of the DRAINED deferred batch to the peer after their own log lock releases. Direct events are NOT mirrored (logAll already routes them — mirroring would double-write).

### Notes
- **`dejavu:learned` stays abandoned** — the audits' fourth deferred item is deliberately NOT implemented: a marker an agent (or injected content) could emit to silence gates mechanically is an adversarial vector; the proxy metrics (`REMINDERS IGNORED` / `TEACHING-WELL`) already cover the legitimate need.
- Re-promotion smoke tests updated to the damped semantics (a single post-heal failure no longer re-promotes; a full fresh bar does).

### Systemic lessons
- Two detection channels that are "disjoint by construction" still need a runtime dedup keyed on the shared identity (key, session) + channel-mismatch window — construction guarantees rot when the producer is upstream of you.
- Damping a lifecycle oscillation is best done with a baseline captured at the transition (like `feedbackBaseline`), not by resetting the lifetime evidence — the evidence stays truthful for display/eviction/merge while the decision is gated.
- Deferred-event routing and direct-event routing must stay distinct code paths: they look identical at the log lock, but only one is already routed.
- A mechanical-state invariant ("never re-promote without a fresh bar") is only as strong as its WEAPEST promotion path — `recordFailure` honored the baseline but `migrate`'s catch-up was a second promotion path that bypassed it. When adding a transition rule, enumerate EVERY path that performs that transition (here: recordFailure + migrate catch-up), and gate them all; a fresh-eyes audit caught the one the implementer's mental model omitted.

## 2.15.0 — 2026-08-30

### Fixed (subagent audit round 8)
- **`load(true)` outside the gates lock in `reconcileAll` (two sites)** — the escalation filter (project store, no lock held) and the index rebuild (holding the index lock, not the gates lock) both used the force path, which quarantines an unparseable `gates.json` — a WRITE — without the gates lock. That is exactly the write-without-lock class round 3 fixed in doctor. Both now use non-force `load()` (routing-hint reads per the project's own invariant); `reconcile()` healed both scopes a few lines earlier, so the peeks are fresh and the force path's only job (quarantine-on-corruption) already ran under the lock.

### Systemic lessons (round 8)
- `load()`'s two modes have different write semantics: non-force is a pure peek, force CAN WRITE (quarantine). The rule is therefore "force only under the gates lock" — not merely "prefer force under the lock". Any new read outside the gates lock must be non-force, or it silently reintroduces the write-without-lock window.

## 2.14.0 — 2026-08-30

### Fixed (subagent audit round 7)
- **`reconcile()` held the gates lock across the log lock (last nesting)** — `exciseCorruptLogLines()` was called inside `runLocked`, acquiring the log lock while holding the gates lock on every init. No deadlock (the log lock is a leaf), but it extended the gates critical section by a full log read+parse+rewrite exactly at init-storm time — the round-4 lesson leaking in one last place. Log hygiene now runs after the gates lock releases.

### Added
- **Doctor FLAPPY report** — per-key count of `promoted` vs resolved (`healed`/`retired-healed`/`retired-taught`) log transitions; flags keys promoted ≥2 AND resolved ≥2 times (promote→heal oscillation). Data-gathering only: `count`/`sessions` are lifetime-cumulative, so a healed/retired gate re-promotes on a single next failure — damping is deferred until this report shows it matters.
- **AGENTS.md CODE MAP is now symbol-only** — dropped the per-symbol line numbers (they rot every audit round and misled the round-7 doc check); references locate by symbol name. Header metadata refreshed.

### Systemic lessons (round 7)
- The log lock is a LEAF lock — it is always acquired alone or outermost, never while holding a gates/index lock. `reconcile()`'s nesting was the last survivor of the pre-`exciseCorruptLogLines` era; "nothing heavy runs under the gates lock" must be re-checked against every new log-touching helper.
- Doc line numbers rot on every change — a CODE MAP that carries them goes stale each round and misleads the next audit. Symbol-only references are the stable form; the map names WHAT and WHERE (file), never WHICH LINE.
- Measure oscillation before damping it — promote→heal→promote is a real risk, but damping changes promotion semantics; ship the FLAPPY tripwire first, act only on data.

## 2.13.0 — 2026-08-30

### Fixed (subagent audit round 6)
- **`recordFailure` flat lock phases (item A)** — the previous implementation held the project gates lock across the index lock + the global gates lock + two saves: the longest critical section in the system, and every other window's waiter degraded to unlocked after `LOCK_WAIT_MS` (the lost-update window the `degraded` event documents). Each phase now holds exactly one lock (project gates → index → [copy, global, remove-local] for escalation). Crash invariant preserved (global-first-then-remove-local; a crash between the two writes leaves a duplicate healed by migrate, never a hole).
- **`logAll` scoping (item B)** — the global log is shared by every window of every project (the most-contended lock) and was double-writing every event. High-volume events (`detected`/`reminded`/`blocked`/`retry-allowed`/`recurred-after-gate`) now stay in the project log; only machine-memory-salient events (`init`/`promoted`/`demoted`/`healed`/`retired-*`/`override`) reach the global log. ~90% fewer global log-lock acquisitions.
- **Deferred events drained before the log lock (N1)** — `log()`/`flushDeferred()` drained `deferredEvents` BEFORE acquiring the log lock, so an event deferred between the drain and the lock was dropped from that flush. The drain now happens inside the log lock.
- **Logging moved out of the index lock (N2)** — `reconcileAll` and doctor logged `repaired` events while holding the index lock, extending the index critical section at exactly init-storm time. Now logged after the lock releases.
- **TTL timer flushes deferred events (N3)** — `expireAll` defers `expired`/`retired-healed` events; a quiet long-lived process previously held them until the next hook log (lost on exit). The jittered TTL timer now calls `flushDeferredAll()`.

## 2.12.0 — 2026-08-30

### Fixed (subagent audit round 5)
- **Migration stamp was erased on every startup** — `reconcile()` parses `gates.json` directly (bypassing `load()`) and saved without the in-memory stamp, so the next `migrate()` re-ran its full per-gate scan on every startup. The init-storm killer from 2.11.0 was dead code. reconcile now preserves the stamp.
- **`recordSuccess` logged under the gates lock** — a heal on a hot gate while other windows waited cascaded contention. The `healed` event now logs after the lock releases.
- **Scripts lost deferred repair events** — doctor/migrate repair stores then exit without a subsequent `log()` call, so deferred repaired/quarantined/demoted/expired events were silently dropped ("every repair is logged" invariant). Added `GateStore.flushDeferred()`; doctor and migrate call it.
- **`pendingCalls` leaked entries for reminded/blocked calls** — aborted calls never reach the after-hook, so their entries leaked until FIFO eviction at the cap. Now deleted when the signal throws.
- **Paren sub-expressions blanket-immunized the outer verb** — `deploy (grep x)` flattened to one segment and the inner diagnostic immunized deploy's failure. Parens now flatten to segment separators (`;`), keeping command-level granularity.
- **`flagTokens` recomputed per pair** — the flood path re-split/sorted the same incoming signature on every gate under the gates lock. Now bounded-cached.
- **TTL timer had no jitter** — windows opened together all swept the shared global store at the same instant every interval. Now jittered (0.75–1.25× interval).

## 2.11.0 — 2026-08-30

### Added (subagent audit round 4 — verification + backlog triage)
- **Migration stamp** — `gates.json` now carries `migrated: <plugin version>`; the 2nd..Nth start of the same version skips the full per-gate `migrate()` scan. The biggest init-storm contributor removed on the common path (repairGate on load still heals hand-edits/policy violations).
- **Doctor capacity & corruption visibility** — per-scope gate count vs `MAX_GATES` (warning at ≥80%), flood-guard eviction count, quarantine artifact count+size, and a cross-channel double-count monitor (same failure recorded by two channels within 2s — the early-warning tripwire for the latent upstream double-count).
- **Stale-steal is pid-liveness-gated and visible** — a stale lock is stolen only if the recorded holder pid is dead (ESRCH); a live slow holder is waited out, and every steal is logged (`stale lock stolen`). A same-pid holder (another window/context in this process) is never stolen.

### Fixed
- **Escalation no longer rests on ghost dirs** — project dirs renamed/moved away (common on Windows dev machines) no longer count toward the 2-project escalation threshold (`recordFailure`, `reconcileAll`, doctor MISSED ESCALATION all filter `existsSync`). Evidence is preserved in the index; only the decision ignores ghosts.
- **`expireAll`/`migrate`/`reconcile`/quarantine/excise no longer log under the gates lock** — events are deferred (`deferEvent`) and flushed by the next `log()` call, batched under one log-lock acquisition. The round-3 invariant ("nothing heavy runs while holding the gates lock") was leaking in five places; all closed.
- **`reconcile()` reports steals/degrades** — it called `withLock` without the callbacks, so a stale-steal during init was invisible.
- **`fuzzySimilar` rejects cheap-first** — the O(1) length-band check now runs before the code-fingerprint regexes and `flagTokens` allocation; the flood path calls this per gate under the gates lock, and most pairs are rejected before any allocation.
- **Hook log flushes can no longer swallow enforcement** — the post-lock event flushes are wrapped: a logging failure is reported via `logHookError` and the GateSignal still throws.

### Systemic lessons (round 4)
- Lock staleness must be judged by holder LIVENESS, not lock age — a slow live holder and a dead one need opposite responses; and same-process lock holders are always "live".
- Deferred-event flushing must be the ONLY way to log from inside a store lock — every `await store.log(...)` inside `runLocked` is a contention cascade waiting to happen.
- Cross-project evidence must distinguish "dir existed" from "dir exists" at decision time; ghost evidence is kept (it may return) but never decides.
- Escalation of hot-path rejection order matters: free O(1) checks before any allocation.

## 2.10.0 — 2026-08-30

### Fixed (adversarial review round 3)
- **Paren-wrapped chains blanket-granted exit-1 immunity.** `splitChain` keeps `(deploy --broken && grep done log)` as ONE segment, so a diagnostic anywhere inside immunized the non-diagnostic part — hiding deploy's failure. `isIntendedNonzero` now flattens paren groups before splitting (immunity needs command-level granularity).
- **Re-promotion inherited stale session chains.** The lifecycle reset cleared counters but left `remindedSessions`/`failedSessions` — the session that triggered a taught-retirement could skip its reminder after re-promotion ("one retry allowed" on a stale entry). Promotion now clears session chains too.
- **Logging under the gates lock cascaded contention.** `reminded`/`blocked`/`retry-allowed`/`override`/`recurred-after-gate`/`demoted` events were logged while holding the gates lock — log-lock contention extended the critical section toward degrade storms. Hook events are queued and logged after the lock is released.
- **`recordSuccess` ran a wasted fuzzy scan** on every successful bash call while accepting exact matches only — now an exact-only lookup (also removes the fuzzy proxy-heal surface entirely). `recordFailure` routing uses the O(1) key index instead of a linear scan.
- **doctor repairs were unsafe against the live plugin.** `--repair`'s key collection used `load(true)`, which could quarantine an unparseable gates.json WITHOUT the store lock while OpenCode is running (the `/dejavu` command runs doctor in-session) — now non-force `load()`. Also: `--repair` now sweeps expired gates (reports no longer show gates that should be gone), and a missing init event after log rotation reports "version indeterminate" instead of a false VERSION DRIFT.
- Docs: review-flag semantics (blocked 10+ times, error persists — not "fired while error stopped"), re-enforcement wording (set `status` back AND clear `feedbackDemoted`), tunables list (`TAUGHT_REMINDERS`, `DEMOTE_REOFFENSE_SESSIONS`), blocking-only override counting.

### Fixed (adversarial review round 2 — holes found by subagent audit of 2.9.0)
- **Race-burst taught-retirement hole.** A parallel burst of identical calls within the reminder race window each incremented `remindedCount` — one burst of 5 could `retired-taught` a gate on its very first encounter, having taught nothing (raced calls never saw a reminder). Only true first encounters count now.
- **Retire↔re-promote oscillation.** Counters were lifetime-cumulative: a re-promoted gate (after heal/taught retirement) re-retired on its first reminder (stale `remindedCount ≥ 5`, stale zero recurrences), and one early recurrence locked out taught-retirement forever. Promotion now starts a fresh enforcement lifecycle (remindedCount/recurrences/overrides/heal-streak/baseline reset).
- **Demotion voted by failures the gate could not prevent.** `recurredAfterGate` counted first-encounter failures that never saw a reminder — 3 sessions failing once each demoted a gate that never spoke, and one bad session/model in a shared store could demote a gate for everyone. Recurrence demotion now additionally requires `DEMOTE_REOFFENSE_SESSIONS` (2) distinct sessions that reoffended AFTER a reminder (`reoffenseSessions`, capped, lifecycle-scoped).
- **`migrate()` re-promoted feedback-demoted gates.** The watching→reminding catch-up ignored `feedbackDemoted` — a demoted diagnostic gate silently re-enforced on every restart, directly violating "never re-promotes mechanically". The invariant now holds on EVERY mechanical path.
- **Proxy success healed the wrong gate.** `recordSuccess` used fuzzy matching: a success on a fuzzy-similar command grew another gate's heal streak and cleared its session chain. Healing and chain-clearing now require EXACT matches — fuzzy is attribution convenience, never a basis for state mutation.
- **Override marker smuggling.** The bypass check accepted an unquoted `dejavu:proceed` anywhere in actionable text — `echo dejavu:proceed && gated-cmd` or `tool --message dejavu:proceed` bypassed gates (and 5 smuggled overrides demoted them). The marker now requires comment syntax (`# dejavu:proceed`).
- **Chain immunity hole.** Exit-1 immunity was granted if ANY diagnostic verb appeared anywhere in the command — `deploy --broken && grep done log.txt` hid deploy's failure. Immunity now requires EVERY chain segment to be diagnostic.
- **Mid-session corruption → silent data loss.** `load()` conflated "file missing" with "file unparseable": a corrupted gates.json became an empty store in memory, and the next save overwrote the recoverable bytes. Parse errors now quarantine (bytes kept, fresh store started), like reconcile.
- **Lock ownership race.** After a stale-steal, the original holder's `unlink` deleted the STEALER's lockfile, opening the critical section to a third process. `withLock` now verifies ownership (pid in the lockfile) before releasing.
- **Env-prefixed one-liners escaped fingerprinting.** `PYTHONPATH=x python -c "..."` normalized to an over-generic watching shape; the interpreter regex anchor now allows leading env assignments.
- **`mergeGate` dropped the reminding tier** when merging a reminding source into a watching target (status merge is now rank-preserving: watching < reminding < blocking).
- Probe gates at count 3-4 no longer get the 60-day TTL (their promotion bar is 5); `coerceGateShape` round-trips `succeededAfterGate === 0`.

### Added
- **Retire-on-taught** — the positive twin of feedback demotion: a gate reminded `TAUGHT_REMINDERS` (5) times with zero in-session reoffense AND zero post-gate failures has taught its lesson — the agent changed behavior, so no success can ever heal it (the `wc -l` eternal-reminder loop). It retires softly to watching (logged `retired-taught`); re-promotion on new failures stays possible.
- **Flood guard prefers feedback-demoted victims** — proven-unteachable gates were the stickiest residents under the old lowest-count rule; they are evicted first now, and every eviction is logged (was invisible).
- **Lazy failure scan** — the full-output `detectFailure` scan is skipped on successful bash calls with exit metadata (hot-path cost).
- **doctor**: `REVIEW-FLAGGED` enforced-only (the flag never clears, healed gates would flag forever); `NOT TEACHING` baseline-relative (a human re-enforcement keeps its grace window); `GLOBAL_PROJECTS`/`DEMOTE_RECURRENCES` imported from store instead of hardcoded.

### Systemic lessons (how not to step on this class again)
- Every mechanical promotion/enforcement path must be audited against every demotion flag — a flag enforced in one path and ignored in another is a state-machine hole.
- Bypass markers must require unambiguous syntax (comment form); "strip quotes then regex" is not an annotation/data distinction.
- Policy checks over chains decide per-segment or all-segments — never "anywhere in the text".
- Fuzzy matching is for enforcement ATTRIBUTION; state mutations (heal, clear, consolidate) require exact identity.
- Locks are verified on release, not just acquired.
- Behavioral counters are lifecycle-scoped, not lifetime-cumulative: any retire/re-promote boundary resets them, or stale evidence from a previous lifecycle leaks into the next (oscillation, permanent lockouts). Lifecycle resets must clear ALL per-session enforcement state, not just counters — stale chains leak across lifecycle boundaries too.
- Feedback votes count only events the gate had a chance to influence (post-reminder failures, distinct sessions) — raw event counts let one bad session punish everyone.
- Chain-policy heuristics must treat paren groups as containers, not atoms — flatten whenever the decision needs command-level granularity.
- Nothing heavy (logging, nested locks) runs while holding the gates lock — lock hold time is contention cascade; diagnostics run outside the critical section.
- Diagnostic/report tooling must not mutate stores (quarantine) without the lock — it runs while the live plugin is open.

## 2.9.0 — 2026-08-30

### Added (the arms race, closed — negative-feedback loop completed)
- **Success clears the chain.** A success on an enforced gate now removes the succeeding session from its remind→block chain (`remindedSessions`/`failedSessions`). Before, a session that PROVED the fix (often via `dejavu:proceed`) stayed blocked forever and could only keep overriding — and the overrides then demoted the very gate the agent had just vindicated. Now: override once, succeed, the session is clean.
- **Iteration verbs remind-only.** `dart run`, `go run|build|test|vet`, `cargo run|build|test|clippy` join the diagnostic tier: their failures are the work itself (the agent is fixing the code they run). Blocking them produced the production arms races — dozens of overrides, zero teaching.
- **Doctor consumes the in-session metric.** New `REVIEW-FLAGGED` (mechanical `review: true`), `REMINDERS IGNORED` (`recurredAfterReminder >= 3` — the correction teaches nothing), and `TEACHING-WELL` notes; `recurredAfterReminder` is no longer a dead metric. `doctor --repair` now prunes TRUE-orphan index keys — safe only there, where every scope is visible at once.
- **analyze** shows reminding/feedback-demoted counts and discovers project stores from the global index (parity with doctor).

### Changed
- **Overrides count only against blocking gates.** On a reminding gate the marker merely skips one interrupting reminder — avoiding that is rational agent behavior, not friction with the teaching. The event is still logged.
- **Reminders are tier-truthful.** A reminding gate no longer promises to "harden into a block" (it never can) — teaching the agent a wrong model of enforcement.
- **Hook errors are visible.** Hook catches log rate-limited (1/min) client-log errors — a silently dead plugin was invisible before.
- The global index is no longer rewritten on the FIRST failure of a brand-new pattern (no escalation value) — machine-wide index churn drops while escalation evidence is preserved (anything indexed or recurring updates as before).
- Log rotation also runs on the TTL timer (multi-day sessions never rotated before).

### Fixed
- `exciseCorruptLogLines` reads the log INSIDE the log lock — the unlocked read + locked rewrite dropped every line another window appended between the two (concurrent OpenCode startups all reconcile at once).
- Unparseable `firstSeen`/`lastSeen` reset to now at parse time — a hand-edited garbage date made a gate immortal (`expire` compares `Date.parse < cutoff`; NaN never is).

### Release hygiene
- The npm package now ships `scripts/`, `command/`, `skills/` — doctor/analyze/migrate and the `/dejavu` command work on the recommended install path.

## 2.8.0 — 2026-08-30

### Added (roots, not symptoms — learned from 9 days of production data across 5 projects)
- **Behavioral feedback demotion.** Enforcement now has negative feedback (the twin of `healed`): an enforced gate that keeps failing after promotion (`DEMOTE_RECURRENCES` = 3) or keeps getting explicitly bypassed (`DEMOTE_OVERRIDES` = 5) is demoted to `watching` and marked `feedbackDemoted` — it never re-promotes mechanically; a human re-enforces by editing `gates.json`, and the gate gets a fresh grace window (`feedbackBaseline`) instead of re-demoting on the next failure. Overrides are now counted per gate (`overrideCount`), every demotion logs a `demoted` event, and `migrate()` catches up gates that already crossed the thresholds.
- **Residual-identity guard.** Signatures whose substance was entirely parameterized (`cmd <path> <str>`, `node <str> <n> >& <n>`, `& <str> -c @ <str> @`) can no longer enforce at any tier — they match whole command families. Generalizes the legacy bare-one-liner rule: any future normalization gap degrades to watching instead of blocking arbitrary calls.
- **PowerShell identity.** `cmd /c|/k "payload"` unwraps to the inner command — the wrapper no longer hides the real verb from the diagnostic policy, and `/c` no longer becomes `<path>`; interpreter one-liners recognize quoted exe paths and the call operator (`& "C:\...\python.exe" -c ...`) and here-string payloads (`@"..."@`) — code no longer leaks into signatures as raw tokens.
- **Control-character stripping.** ANSI/VT sequences and C0 junk are stripped before persistence (`stripControl`/`sanitizeForStore`) — PowerShell colored errors no longer corrupt snippets/corrections with raw `ESC[31;1m` garbage; historical gates are cleaned by `migrate()`.
- **mypy** joined the diagnostic verbs (remind-only tier; exit 1 is its normal "findings" outcome).
- **Noise filters**: grep_app "no results found" and the question tool's "user dismissed" are not failures.
- **doctor without arguments** discovers project stores from the global index's project list (before: cross-store checks ran global-only and reported hundreds of false INDEX ORPHANS).

### Changed
- `reconcileAll()` no longer prunes index orphans: one process sees ONE project store, so a key whose gate lives in another project is invisible, not dead — pruning destroyed cross-project escalation evidence. Rot is still bounded by the 60-day TTL sweep in `expireAll`; doctor reports true orphans (it now sees every scope).

### Fixed (adversarial review round)
- **`withLock` no longer deletes a foreign lock**: a waiter degrading to unlocked ran `unlink` unconditionally in `finally` — removing the lockfile the live holder owned and letting a third process enter the critical section concurrently. This is the root cause of the zero-byte corrupt log line seen in production.
- **Interpreter flag fragmentation**: regex alternatives run longest-first (`-command`/`-encodedcommand` before `-c`/`-e`) — before, `-command` matched as `-c` and swallowed `ommand` into the payload, fragmenting one call into different keys per spelling. Long flags converge to `-c` in the emitted signature.
- **Windows `py` launcher** one-liners are fingerprinted (before: `py - <n> -c <str>` — an enforceable over-generic shape).
- **Residual-identity guard bypasses closed**: `python -m <str>` (the module is the program, like `-c` — `-m`/`--module` are code-passing flags) and chains headed by `cd`/`pushd`/`popd`/`set-location`/`exit` (`cd <path> && python <path>` no longer borrows identity from the builtin).
- **Over-generic shapes never fuzzy-match**: an incoming signature without residual identity matches concrete gates exactly only — it no longer enforces via fuzzy or pollutes unrelated gates' evidence (`findGate` + `recordFailure` consolidation).
- **Chain bypass through `cmd /c`**: segment signatures recursively unfold the wrapper payload — a gate on the inner command fires even when the whole chain hides inside `cmd /c "a && gated"`; `dejavu:proceed` inside a LEADING `cmd /c "..."` payload is honored as an override (before, the wrapper quotes hid it like smuggled data).

### Data notes
- Production evidence (9 days, ~1000 gates, 5 projects): the global `wc -l` gate taught 10 sessions with zero recurrences — reminders work; script-runner gates (`dart run`, mypy behind wrappers, `cmd /c` gradle) produced arms races with dozens of `dejavu:proceed` overrides and zero teaching — feedback demotion ends that race mechanically.

## 2.7.0 — 2026-08-26

### Added (no more manual corrections)
- **Auto-corrections.** A promoted gate now always ships with a mechanical, overridable default correction (`suggestCorrection`), chosen by command family (stale `--check` artifacts, failing tests, type errors, network, installs) or from the captured error line — so a gate never sits "NOT TEACHING" awaiting a human. `migrate()` backfills existing enforced gates.
- **Richer snippets.** For exit-code failures whose output matched no signature, dejavu keeps the last non-empty output line (`failureSnippet`) instead of a bare "exit code N", giving corrections real context.

## 2.6.0 — 2026-08-26

### Added (only well-grounded triggers)
- **Gates heal.** dejavu previously only saw failures, so a gate kept reminding even after the underlying command was fixed (the `ruff check .` false positive). Now a SUCCESS matching an enforced gate increments `succeededAfterGate`; after `HEAL_SUCCESSES` (3) consecutive successes the gate retires to `watching` and logs `healed`, so fixed commands stop triggering. A failure resets the streak.

## 2.5.1 — 2026-08-26

### Fixed
- Cross-project index + forensic log now key on the gate's OWN key (post fuzzy-consolidation), not the raw failure key. Before, a failure that fuzzy-merged into an existing gate indexed a key with no gate — orphaning the entry and silently starving that gate's cross-project escalation (the "INDEX ORPHANS" you'd see in doctor).

## 2.5.0 — 2026-08-24

### Changed (the three known gaps, closed)
- **Diagnostics now signal.** Recurring test/lint/build-check failures (`tsc`, `pytest`, `curl`, ...) previously got zero enforcement. New gate tier `reminding`: they promote and REMIND like any gate, but NEVER block — a new status alongside `watching`/`blocking`, enforced everywhere (findGate, compaction, migrate/repair, doctor, TTL).
- **Repo-local verbs never escalate.** npm/yarn/pnpm/bun/npx, git, gradle/maven, cargo/go/pip/poetry/uv, docker, make/cmake/bazel failures are repo quirks, not agent habits — they stay project-scoped forever (`isRepoLocal`), so a broken `npm install` in one project can no longer block another. Doctor's MISSED-ESCALATION skips them.
- **Flag-aware fuzzy matching.** Commands with disjoint flag sets never merge (`train --lr` vs `train --epochs`); subset additions still do (`train` vs `train -v`), so enforcement doesn't fragment across harmless variants while different operations stay separate.

### Migration
- `migrate()` re-tiers legacy gates: over-blocking diagnostics → `reminding` (signal kept), and already-proven recurring diagnostics → `reminding` immediately (no waiting for the next failure).

## 2.4.0 — 2026-08-24

### Added
- Noise TTL: weak one-off patterns (below the promotion threshold, never enforced) expire after 7 days instead of 60 — memory is for recurring mistakes, not one-shot noise.
- Correction lifecycle signal: an expired gate that had a correction and zero recurrences after promotion logs `retired-healed` — the mechanical "the teaching worked"; doctor reports such gates as TEACHING.

### Notes
- V2 plugin API migration awaits upstream: `tool.execute.error` (opencode issue #27900) is drafted but unmerged — the event-stream scan remains the file-tool failure channel until then.

## 2.3.1 — 2026-08-24

### Fixed (adversarial + security review round)
- `mergeGate` now merges `remindedSessions`/`failedSessions` — escalation and dedupe no longer silently reset the remind→block chain.
- Fuzzy consolidation prefers the gate the session was already reminded about, keeping before/after hooks in sync when two blocking gates are near-duplicates; fuzzy merges no longer overwrite a gate's evidence snippet (a crafted near-duplicate cannot poison it).
- Quarantine resets the hot-path caches — no phantom gates served after a corrupt `gates.json` is quarantined.
- `failedSessions` became `sessionID -> timestamp` with the same 24h TTL as reminders — a stale block with no live session is a leak, not enforcement (legacy array shape coerces on load).

### Hardened
- Prompt-injection framing: snippets and corrections are labeled in remind/block/compaction messages as data/guidance, not instructions; corrections are truncated to 200 chars (context-pollution bound, enforced mechanically).
- Quarantined files and excised log lines are secret-scrubbed before being preserved.
- Overrides (`dejavu:proceed`) also emit a `warn`-level client log — mass-overriding must be noticeable.
- Store size bound: past 2000 gates the weakest watching gate is evicted (flood guard).
- `scrubSecrets` adds Hugging Face / DigitalOcean / Vercel / New Relic / SendGrid shapes and generic `key=<long value>` assignments (incl. lowercase keys).

## 2.3.0 — 2026-08-24

### Multi-process hardening (several OpenCode windows = several plugin processes on one store)
- Remind→block session state is persisted ON THE GATE (`remindedSessions`/`failedSessions`) instead of per-process memory: the escalation chain now survives process restarts and is visible to every window serving the session (before: two windows or a restart reset it to "remind forever, never block"). Enforcement reads fresh gate state under the store lock.
- Session state rots after 24h and is capped per gate; `session.deleted` cleans it from disk.

### Performance (hot path runs on every tool call)
- `fuzzySimilar`: O(1) length-band pre-filter (triangle inequality — zero false negatives) and a `FUZZY_MAX_LEN` cap — kills the Levenshtein explosion on long signatures (was 150-600ms/tool-call at scale).
- `GateStore`: O(1) key index + cached blocking subset for lookups; 1s TTL on the mtime cache so the hot path stops paying a `stat` per call (saves refresh the cache directly).
- Global log rotates at 2MB instead of 512KB — with several projects the aggregate forensics no longer vanish within a day.

### Fixed
- Init-storm TOCTOU: index orphan-pruning now keeps a 24h grace window, so a just-promoted gate's index entry cannot be pruned by a concurrent startup.
- After-hook escalation state is written under the store lock and follows the gate to the global store on escalation (previously lost in both cases).

### Added
- `doctor.ts` reports LOCK DEGRADATIONS (count of `degraded` log events) as an observability note — the evidence signal for whether the storage backend ever needs revisiting.

## 2.2.1 — 2026-08-24

### Fixed (adversarial-review round)
- Escalation order: the gate is written to the global store BEFORE being removed from the project store — a crash between the two writes leaves a duplicate (healed by migrate), never a hole.
- `dejavu:proceed` inside quoted strings no longer bypasses gates (`echo "dejavu:proceed" && gated-cmd` stays enforced); the marker is honored only outside quotes.
- Concurrent first-encounter race: calls dispatched in the same burst as a REMINDER (within 500ms) are reminded too instead of slipping through as a "retry".
- CRLF/CR commands normalize identically to LF; `splitChain` splits on CR — no more line-ending fragmentation.
- `normalizeCommand` is fully idempotent: quoted spans are parameterized BEFORE path rules (a `<str>` substitution inserts spaces that would expose an adjacent `/` to the path rule only on a second pass), fingerprint payloads are trimmed, and already-parameterized payloads are never re-fingerprinted.
- Interpreter flags glued to their payload (`node -e"code"`) fingerprint identically to the spaced form.
- Session state maps: inner key sets are capped — long sessions no longer grow unbounded.

### Added
- Lock degradation (contention > 3s) emits a `degraded` log event — the only window where concurrent writes can lose updates is now visible.
- `test/property.ts` — property-based tests for the normalization pipeline (idempotency, no nested tokens, output bound, one-liner distinctness, marker neutrality, splitChain atomicity).
- `test/fuzz.ts` — seeded mutation fuzzer with a metamorphic oracle and case shrinking; both harnesses run in CI. The harnesses caught the idempotency, marker-neutrality, glued-flag and nested-token-detector bugs above before production did.

## 2.2.0 — 2026-08-23

### Added
- Interpreter one-liner fingerprinting: `python -c` / `node -e` / `bun -e` and friends get their code payload hashed (`<code:sha1-8>`) instead of flattened to `<str>` — distinct scripts no longer share one gate, the same script failing repeatedly still converges.
- Global cross-project pattern index (`index.json`): counts distinct project dirs per failure key and now drives global escalation — a gate's own `projects` array only ever sees its own store, so escalation was dead code before.
- `mergeGate`: evidence merge for escalation and dedupe; never demotes a `blocking` gate.
- `isNoiseError()`: aborted/cancelled tool executions ("Tool execution aborted") are infrastructure noise and are no longer counted as failures.
- Self-healing stores (`src/validate.ts` invariant layer): every gate read from disk crosses strict parse + mechanical repair; `GateStore.reconcile()` quarantines unparseable gates.json (bytes preserved as `.corrupt-<ts>`), merges duplicate keys, excises unparseable log lines to `log.jsonl.corrupt`; `Stores.reconcileAll()` reconciles the index (prunes orphans, rebuilds missing entries, escalates gates proven in 2+ projects) — runs at every init.
- `doctor.ts [--repair]` now checks the full invariant set (shape, duplicates, temporal order, nested-token corruption, blocking without evidence, index consistency, stale project copies, missed escalation, log integrity) and heals on demand.

### Changed
- `canBlock()` rejects bare one-liner shapes (`-c <str>`); existing gates with them are auto-demoted by `migrate()`.
- Log appends and rotation run under their own lock with atomic writes — concurrent OpenCode windows no longer interleave broken JSONL lines.
- `migrate()` merges project-local copies of already-global keys into the global gate.
- `doctor.ts`: NOT-TEACHING/ANNOYING only flag gates that can actually block; non-blockable legacy gates no longer scream.

### Fixed
- All-digit `<code:...>` fingerprints are no longer re-parameterized by the number rule (~2.3% of payloads collapsed into one key).
- Signatures with different `<code:...>` fingerprints can no longer fuzzy-merge (random hashes differing in exactly 3 chars passed the distance rule and merged unrelated one-liners).
- `doctor.ts` no longer crashes on corrupt log lines; it now reports them as a CORRUPT LOG LINES pathology instead.
- Init failures (corrupt store, failed migrate) are logged instead of swallowed — a plugin starting on broken state is now visible.

## 2.1.0 — 2026-08-22

First public release.

### Added
- Gate enforcement state machine: remind on first same-session encounter, hard block after a reminded retry fails again; `dejavu:proceed` explicit escape hatch (logged as `override`).
- Two-scope store: project gates in `<repo>/.opencode/dejavu/`, escalation to global `~/.config/opencode/dejavu/` after 2+ distinct project dirs; lock order always project → global.
- Detection channels: `metadata.exit` (bash), line-by-line bash text scan, and `message.part.updated` event stream for tool-level errors; chain-segment matching so gates fire inside `a && gated` chains.
- Blocking policy: only non-diagnostic bash commands may block (`canBlock()`); probe tools use a higher promotion bar and never block.
- Secret scrubbing before any persistence (OpenAI/Anthropic/AWS/GitHub/Slack/Stripe/JWT/PEM/DB-conn/bearer/`root@host`, Google `AIza…`, full PEM blocks, `.env`-style `KEY=VALUE`).
- Near-duplicate consolidation via normalized Levenshtein ≤ 0.3 with an absolute floor of 3 edits.
- TTL expiry (60 days), log rotation, bounded in-memory session maps, `review: true` flagging, `recurredAfterGate` health metric.
- Observability: `log.jsonl` forensic events (`channel`, `via`, `exit`, `version`), `scripts/doctor.ts`, `scripts/analyze.ts`, `scripts/migrate.ts`.
- Companion agent skill (`skills/dejavu/`) and `/dejavu` status command (`command/dejavu.md`).
- `experimental.session.compacting` hook injecting active gates into compaction context.

### Fixed (post-review hardening, same release line)
- `pendingCalls` no longer leaks entries for aborted (reminded/blocked) calls; capped at 1000.
- Quoted-string parameterization regex rewritten as an unrolled loop (no catastrophic backtracking).
- `migrate()` now also secret-scrubs gate `correction` fields.
