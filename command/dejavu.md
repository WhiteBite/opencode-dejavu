---
description: dejavu status report — pathologies first, then active gates, recurrence metrics, review flags
---

First run the pathology report (it surfaces every known defect class in one pass):

    bun ~/.config/opencode/vendor/dejavu/scripts/doctor.ts

No arguments needed: doctor discovers every project store from the global index.
For npm installs the script lives in the plugin package instead (e.g. `node_modules/opencode-dejavu/scripts/doctor.ts`); if dejavu was cloned elsewhere, use that checkout's `scripts/doctor.ts`.
Add `--repair` to heal first (idempotent): quarantines corrupt files, merges duplicates, excises broken log lines, reconciles the index, prunes true-orphan index keys (safe in doctor — it sees every scope), applies feedback-demotion catch-up.

Then read the state files for detail:

- Project gates: `.opencode/dejavu/gates.json` in the current directory (may not exist yet)
- Global gates: `~/.config/opencode/dejavu/gates.json` (plus `index.json` — cross-project evidence per key, machine-managed)
- Event logs: `log.jsonl` next to each gates.json (last ~30 lines; events carry `channel`, `via`, `exit`, `version` fields for forensics)

Report structure:

1. **Pathologies** — whatever doctor printed (stale blocking/reminding gates, not-teaching gates, annoying gates, review-flagged, reminders-ignored, feedback-demoted, unsanitized data, version drift). For each, propose the minimal action (migrate / write correction / delete / restart OpenCode) but do NOT edit anything without explicit confirmation.
2. **Active gates** — table: signature, count, sessions, remindedCount, blockedCount, overrideCount, recurredAfterGate, correction (if set)
3. **Health** — any gate with `recurredAfterGate > 0` is NOT stopping its error: quote its evidence (last snippet) and propose a one-line `correction` text for it. Gates with `feedbackDemoted: true` surrendered to agent behavior — re-enforcing is a human decision (set `status` back to `blocking`/`reminding` AND clear `feedbackDemoted`).
4. **Near promotion** — top-5 `watching` bash patterns by count (candidates for future gates)

Keep the report under 40 lines. Do not modify any files.
