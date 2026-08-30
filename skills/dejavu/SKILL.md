---
name: dejavu
description: Protocol for working with the dejavu error-gate plugin. Use when a tool call is answered with a "[dejavu] REMINDER" or "[dejavu] BLOCKED" message, when the same tool call fails repeatedly, or when you discover the root cause of a gated failure. Covers how to react to reminders, what BLOCKED means, the dejavu:proceed escape hatch, and how to improve gate corrections in .opencode/dejavu/gates.json.
---

# dejavu — recurring-error gates

dejavu is an OpenCode plugin that watches tool calls fail, counts recurrences across sessions, and promotes frequent failures into **gates**. It is your external long-term memory for mistakes: what failed before will not silently fail again.

You do not manage dejavu's detection — it is mechanical. Your job is to react correctly and to improve gate quality when you learn something.

## When you get `[dejavu] REMINDER`

The call you were about to make has failed repeatedly in the past. The call was aborted before execution.

1. **Do not retry the identical call.** That is exactly the behavior the gate exists to prevent.
2. Read `Last failure:` and `Correction:` in the message.
3. Diagnose the root cause (read the relevant file, check the environment, run a diagnostic command).
4. Retry with a **changed** approach — a different command, fixed arguments, or a prerequisite step first.
5. If you are confident the situation changed (e.g. you just installed the missing dependency), retry as-is — a SUCCESS clears your session from the gate's chain. On a blocking gate, a repeated failure after a reminder escalates it to a hard block within this session; a reminding gate (diagnostics/iteration commands) never blocks, it only reminds.
6. `dejavu:proceed` (as a trailing COMMENT inside the call — `# dejavu:proceed`) bypasses the gate. Use it ONLY when the user explicitly asked you to force the operation, or you have concrete proof the gate is stale. Every override is logged; on blocking gates it is ALSO counted on the gate, and repeated overrides demote the gate (your bypasses are feedback: a gate everyone works around retires itself). If you override and the call SUCCEEDS, say so when improving the gate — that proves it stale.

## When you get `[dejavu] BLOCKED`

You were reminded, retried, and it failed again. The gate is now hard in this session.

- Do not attempt the same call again in any form that matches the pattern.
- Tell the user what is blocked and why (the message contains evidence and the gate file path).
- Choose a fundamentally different approach to reach the goal.

## Improving gates (your one write privilege)

Gates live in `.opencode/dejavu/gates.json` (project) and `~/.config/opencode/dejavu/gates.json` (global agent habits). The files are human- and agent-editable.

When you discover the **root cause** of a gated failure, update the gate's `correction` field with a one-line actionable instruction (what to do instead, not what to avoid). Example: `"correction": "Use 'npm install --legacy-peer-deps' — this repo has conflicting peer deps"`.

Do NOT:
- create gates manually (promotion is mechanical: 3 failures across 2 sessions),
- weaken or delete gates without telling the user,
- stuff prose into `correction` — one actionable line only.

## What dejavu tracks

- `bash` commands that exit non-zero or print error signatures (normalized: paths/numbers/hashes abstracted)
- `read`/`edit`/`write` failures on files (via tool-level error events)
- counts, distinct sessions, distinct projects; patterns seen in 2+ projects become global (they are your habits, not the repo's quirks)

Gates expire after 60 days without recurrence. Gates listen to behavior in both directions: a gate whose error keeps recurring under enforcement (3+ times) or that gets overridden repeatedly (5+ on blocking gates) demotes itself to `watching` + `feedbackDemoted` and stops enforcing — if you later learn it was right, a human re-enforces it by setting its `status` back to `blocking`/`reminding` AND clearing `feedbackDemoted` in gates.json (the gate gets a fresh grace window). A gate blocked 10+ times is flagged `review: true` in its file. A gate that taught its lesson (reminded 5+ times, never reoffended) retires softly too — if a retired gate starts failing again, it re-promotes on its own.
