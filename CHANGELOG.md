# Changelog

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
