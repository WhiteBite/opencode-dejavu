<p align="center">
  <img src="logo/icon.svg" width="96" height="96" alt="dejavu logo — a lowercase d with two amber echo strokes">
</p>

<h3 align="center">dejavu — OpenCode error-gate plugin</h3>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/OpenCode-plugin-3178c6.svg" alt="OpenCode plugin">
  <img src="https://img.shields.io/badge/TypeScript-Bun-black.svg" alt="TypeScript + Bun">
  <img src="https://github.com/WhiteBite/opencode-dejavu/actions/workflows/ci.yml/badge.svg" alt="CI">
</p>

Cross-session **memory prosthesis with teeth** for [OpenCode](https://github.com/anomalyco/opencode). AI agents repeat the same mistakes because they forget between sessions — and markdown rules don't fix that. dejavu mechanically detects recurring tool-call failures (bash, read, edit, write, glob, grep) and promotes them into enforced gates: a reminder on the next attempt, a hard block on same-session repeat offense. TypeScript + Bun, ships as source, no build step.

## How it works

```
tool call fails  →  signature normalized (paths/numbers/hashes stripped)
                 →  pattern-key counted, sessions tracked
                 →  3 failures across 2 distinct sessions  →  gate promoted
next attempt     →  [dejavu] REMINDER thrown (call aborted, agent sees the correction)
retry fails again →  same-session repeat offense → hard BLOCK on further attempts
```

Design decisions (post-mortem of existing approaches):

- **Remind first, block on repeat.** Pure blocking starts an arms race — the agent routes around gates (`npm` blocked → uses `pnpm`). A reminder with the correction teaches; the block is reserved for ignored reminders.
- **Gate messages are teachers.** Every message carries `CORRECTION:` (what to do instead) and `EVIDENCE:` (N failures across M sessions), not just a prohibition.
- **Mechanical pattern-keys only.** No LLM-based error classification in the hot path — the unreliable component doesn't do reliability work.
- **Two scopes.** Repo-specific gotchas live in `<repo>/.opencode/dejavu/` (committable); patterns seen in 2+ project dirs are agent-level habits and move to `~/.config/opencode/dejavu/`.
- **Gates rot — so they expire.** 60 days without recurrence and a gate is dropped. A gate firing 10+ times while the error stopped gets `review: true` for manual inspection.
- **The metric is recurrence-after-gate.** Tracked per gate as `recurredAfterGate` — if gates don't reduce recurrence, the whole approach is wrong and you'll see it in the data.

## Install

```bash
git clone https://github.com/WhiteBite/opencode-dejavu ~/.config/opencode/vendor/dejavu
cd ~/.config/opencode/vendor/dejavu && bun install
```

```ts
// ~/.config/opencode/plugins/dejavu.ts
export { Dejavu } from "../vendor/dejavu/index.ts"
```

Companion skill (agent behavior protocol): copy `skills/dejavu/` to `~/.config/opencode/skills/dejavu/`.
Status command: copy `command/dejavu.md` to `~/.config/opencode/command/dejavu.md`.

Restart OpenCode. Gates appear automatically as failures recur — nothing to configure.

## Robustness & safety

- **Blocking policy** — only `bash` commands that are NOT diagnostics may ever become blocking gates. File probes (read/edit/write/glob/grep) and diagnostics (tsc/eslint/pytest/gradle-test/flutter/curl/grep...) stay `watching` forever: measured, visible in reports, but never interrupting the agent. `canBlock()` in `src/patterns.ts` is the single source of truth.
- **Secret scrubbing** — every signature and snippet passes `scrubSecrets()` (OpenAI/Anthropic/AWS/GitHub/Slack/Stripe/JWT/bearer/DB-conn-string/PEM patterns + `root@host`) before touching disk. Historical data is cleaned by `migrate()` at init or via `bun scripts/migrate.ts <dirs...>` (also scrubs logs).
- **Intended non-zero exits** — exit 1 from diagnostics is NOT a failure (that is their normal "found nothing / found issues" outcome). Exit ≥ 2 always counts.
- **File content is not command output** — text failure signatures are scanned for `bash` only; `read`/`edit`/`write` failures come exclusively from the event channel (a file containing "TypeError" is not a failure).
- **Concurrency** — gates.json mutations run under an exclusive lockfile; writes are tmp+rename with EPERM/EACCES/EBUSY retry (Windows AV/indexer). NT long paths get the `\\?\` prefix.
- **Near-duplicate consolidation** — new failures merge into existing patterns via normalized Levenshtein ≤ 0.3 with an absolute floor of 3 edits (replaces token Jaccard, which collapsed all `<str>` placeholders; the floor stops `git push` vs `git pull`-style merges).
- **Bounded memory** — per-session maps are capped (200 sessions) and freed on `session.deleted`; handled part IDs evict FIFO; TTL expiry re-runs every 6 h in long-lived processes.
- **Migration** — gates outside the blocking policy are demoted to `watching` automatically; nothing is deleted.

## Observability (debugging aids)

- Every `log.jsonl` gets an `init` event with `PLUGIN_VERSION`; `detected` events carry `channel` (`exit`/`text`/`event`) and the raw exit code; `reminded`/`blocked` carry `via` (`exact`/`fuzzy`/`segment`). Stale plugin sessions are therefore visible in the data.
- `bun scripts/doctor.ts [projectDirs...]` — one-command pathology report: blocking gates outside policy, not-teaching gates (recurredAfterGate ≥ 3), annoying gates (reminded ≥ 10), secrets on disk, version drift.
- `bun scripts/analyze.ts [projectDirs...]` — store summary: statuses, tools, top patterns.
- `/dejavu` command (installed globally) runs doctor first, then reports.

## Detection coverage

| Channel | Catches |
|---|---|
| `tool.execute.after` + `metadata.exit` | bash failures (non-zero exit, TS errors, test failures, stack traces) |
| `message.part.updated` event scan | tool-level failures (read of missing file, rejected edits) that never reach the after-hook; error text is Sentry-style parameterized (uuid/ip/url/hex/date → placeholders) |
| chain-segment matching | gates fire even when the gated command hides inside `x && gated-cmd` chains |
| companion skill | agent behavior protocol (how to react, when to annotate) |
| `/dejavu` command | status report: active gates, recurrence metric, review flags |

Not covered (by design, v1): semantically-equivalent-but-syntactically-different failures beyond fuzzy (Levenshtein ≤ 0.3, ≥ 3 edits) matching.

## Data files

| File | Contents |
|---|---|
| `~/.config/opencode/dejavu/gates.json` | global gates (agent habits) |
| `<repo>/.opencode/dejavu/gates.json` | project gates (repo gotchas) |
| `*/dejavu/log.jsonl` | every event: detected, promoted, reminded, blocked, override, expired, recurred-after-gate |

Both are human-editable. Removing a gate object disables it. Editing `correction` improves what the agent is told.

## Development

```bash
bun install
bun run typecheck        # tsc --noEmit (index.ts + src/**)
bun test/smoke.ts        # behavioral smoke test, no framework needed
```

Tunables are named constants at the top of `index.ts` and `src/store.ts`: `PROMOTE_COUNT` (3), `PROMOTE_COUNT_PROBE` (5), `PROMOTE_SESSIONS` (2), `GLOBAL_PROJECTS` (2), `TTL_DAYS` (60), `REVIEW_FIRES` (10).

## Roadmap

- v2: recurrence-after-gate reporting command; V2 plugin API error hooks when stable
- v3: auto-proposal of ast-grep rules for statically detectable patterns (repo-level CI gates)

## License

MIT
