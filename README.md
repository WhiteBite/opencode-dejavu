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
- **Two scopes.** Repo-specific gotchas live in `<repo>/.opencode/dejavu/` (committable); patterns seen in 2+ project dirs are agent-level habits and move to `~/.config/opencode/dejavu/`. No single store can see all projects, so a global pattern index (`index.json`) counts distinct project dirs per key and drives the escalation.
- **Gates rot — so they expire.** 60 days without recurrence and a gate is dropped. A gate firing 10+ times while the error stopped gets `review: true` for manual inspection.
- **The metric is recurrence-after-gate.** Tracked per gate as `recurredAfterGate` — if gates don't reduce recurrence, the whole approach is wrong and you'll see it in the data.

## Install

**npm (recommended)** — one line, OpenCode installs it automatically at startup:

```jsonc
// ~/.config/opencode/opencode.json (global) or opencode.json (project)
{ "plugin": ["opencode-dejavu"] }
```

**From source:**

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
- **One-liner identity** — for `python -c` / `node -e` / `bun -e` and friends the code payload IS the call, so it is fingerprinted (`<code:hash>`) instead of flattened to `<str>`: different scripts never share a gate, the same script failing repeatedly still converges. Legacy bare `-c <str>` shapes can never block.
- **Secret scrubbing** — every signature and snippet passes `scrubSecrets()` (OpenAI/Anthropic/AWS/GitHub/Slack/Stripe/JWT/bearer/DB-conn-string/PEM patterns + `root@host`) before touching disk. Historical data is cleaned by `migrate()` at init or via `bun scripts/migrate.ts <dirs...>` (also scrubs logs).
- **Intended non-zero exits** — exit 1 from diagnostics is NOT a failure (that is their normal "found nothing / found issues" outcome). Exit ≥ 2 always counts.
- **Aborted ≠ failed** — cancelled/aborted tool executions ("Tool execution aborted") are infrastructure noise and are never counted as failures.
- **File content is not command output** — text failure signatures are scanned for `bash` only; `read`/`edit`/`write` failures come exclusively from the event channel (a file containing "TypeError" is not a failure).
- **Concurrency** — gates.json mutations run under an exclusive lockfile; log appends and rotation take their own lock (every OpenCode window shares the global log); writes are tmp+rename with EPERM/EACCES/EBUSY retry (Windows AV/indexer). NT long paths get the `\\?\` prefix. If a lock cannot be acquired within 3s the critical section degrades to unlocked (the tool pipeline must never hang) and emits a `degraded` log event — the only window where updates can be lost is visible.
- **Multi-window safe** — the remind→block escalation chain is persisted on the gate itself (`remindedSessions`/`failedSessions`), not in process memory: several OpenCode windows on one store — and process restarts — all see the same chain. Enforcement always reads fresh gate state under the store lock.
- **Near-duplicate consolidation** — new failures merge into existing patterns via normalized Levenshtein ≤ 0.3 with an absolute floor of 3 edits (replaces token Jaccard, which collapsed all `<str>` placeholders; the floor stops `git push` vs `git pull`-style merges).
- **Bounded memory** — per-session maps are capped (200 sessions) and freed on `session.deleted`; handled part IDs evict FIFO; TTL expiry re-runs every 6 h in long-lived processes.
- **Migration** — gates outside the blocking policy are demoted to `watching` automatically; project copies of already-global gates are merged into the global gate (evidence is consolidated, never deleted).
- **Self-healing** — every init reconciles the stores: an unparseable `gates.json` is quarantined (bytes preserved as `gates.json.corrupt-<ts>`), gate records are strictly parsed and mechanically repaired (inverted dates swapped, duplicate keys merged, secrets re-scrubbed, stale blocking demoted), unparseable log lines are excised to `log.jsonl.corrupt`, and the cross-project index is reconciled. Every repair is logged as a `repaired`/`quarantined` event.

## Observability (debugging aids)

- Every `log.jsonl` gets an `init` event with `PLUGIN_VERSION`; `detected` events carry `channel` (`exit`/`text`/`event`) and the raw exit code; `reminded`/`blocked` carry `via` (`exact`/`fuzzy`/`segment`). Stale plugin sessions are therefore visible in the data.
- `bun scripts/doctor.ts [--repair] [projectDirs...]` — one-command report over every invariant the data model implies: gate shape, duplicate keys, temporal order, nested-token corruption, blocking without evidence, policy violations, index↔gates consistency, stale project copies, missed escalation, log integrity, secrets, version drift. `--repair` heals first (idempotent), then reports.
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
| `~/.config/opencode/dejavu/index.json` | cross-project pattern index: which project dirs each failure key was seen in (escalation evidence) |
| `<repo>/.opencode/dejavu/gates.json` | project gates (repo gotchas) |
| `*/dejavu/log.jsonl` | every event: detected, promoted, reminded, blocked, override, expired, recurred-after-gate, repaired, quarantined |
| `*/dejavu/*.corrupt*` | quarantined corruption (unparseable gates.json, excised log lines) — bytes preserved for forensics; safe to delete after inspection |

Both are human-editable. Removing a gate object disables it. Editing `correction` improves what the agent is told.

## Development

```bash
bun install
bun run typecheck        # tsc --noEmit (index.ts + src/**)
bun test/smoke.ts        # behavioral smoke test, no framework needed
```

Tunables are named constants at the top of `index.ts` and `src/store.ts`: `PROMOTE_COUNT` (3), `PROMOTE_COUNT_PROBE` (5), `PROMOTE_SESSIONS` (2), `GLOBAL_PROJECTS` (2), `TTL_DAYS` (60), `NOISE_TTL_DAYS` (7), `REVIEW_FIRES` (10), `MAX_GATES` (2000).

## Roadmap

- v2: recurrence-after-gate reporting command; V2 plugin API error hooks — `tool.execute.error` is drafted upstream (opencode issue #27900) but unmerged; the event-stream scan remains the file-tool failure channel until it lands
- v3: auto-proposal of ast-grep rules for statically detectable patterns (repo-level CI gates)

## License

MIT
