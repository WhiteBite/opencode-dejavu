# Changelog

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
