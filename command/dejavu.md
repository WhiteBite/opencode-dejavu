---
description: dejavu status report — pathologies first, then active gates, recurrence metrics, review flags
---

First run the pathology report (it surfaces every known defect class in one pass):

    bun ~/.config/opencode/vendor/dejavu/scripts/doctor.ts <current directory>

(If dejavu was cloned elsewhere, use that checkout's `scripts/doctor.ts`.)
Add `--repair` to heal first (idempotent): quarantines corrupt files, merges duplicates, excises broken log lines, reconciles the index.

Then read the state files for detail:

- Project gates: `.opencode/dejavu/gates.json` in the current directory (may not exist yet)
- Global gates: `~/.config/opencode/dejavu/gates.json` (plus `index.json` — cross-project evidence per key, machine-managed)
- Event logs: `log.jsonl` next to each gates.json (last ~30 lines; events carry `channel`, `via`, `exit`, `version` fields for forensics)

Report structure:

1. **Pathologies** — whatever doctor printed (stale blocking gates, not-teaching gates, annoying gates, secrets, version drift). For each, propose the minimal action (migrate / write correction / delete / restart OpenCode) but do NOT edit anything without explicit confirmation.
2. **Active gates** — table: signature, count, sessions, remindedCount, blockedCount, recurredAfterGate, correction (if set)
3. **Health** — any gate with `recurredAfterGate > 0` is NOT stopping its error: quote its evidence (last snippet) and propose a one-line `correction` text for it.
4. **Near promotion** — top-5 `watching` bash patterns by count (candidates for future gates)

Keep the report under 40 lines. Do not modify any files.
