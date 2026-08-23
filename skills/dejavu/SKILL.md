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
5. If you are confident the situation changed (e.g. you just installed the missing dependency), retry as-is. A repeated failure after a reminder escalates the gate to a hard block within this session.
6. `dejavu:proceed` (as a comment/argument inside the call) bypasses the gate. Use it ONLY when the user explicitly asked you to force the operation, or you have concrete proof the gate is stale. Every override is logged.

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

Gates expire after 60 days without recurrence. A gate that fires 10+ times without the error recurring is flagged `review: true` in its file.
