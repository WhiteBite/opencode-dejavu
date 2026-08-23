# Changelog

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
