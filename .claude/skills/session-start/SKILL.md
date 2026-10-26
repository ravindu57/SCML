---
name: session-start
description: Start a work session on SCML — load current state, declare the session role, pick exactly one backlog item.
argument-hint: <role> [item-id]
disable-model-invocation: true
---

Session role: **$ARGUMENTS**

1. Read the current-state block and the latest log entry in `PROGRESS.md`.
2. Run `scripts/check_frozen.sh`. If it fails, stop and report; do not continue.
3. Run the test suite with the env prefix from `CLAUDE.md` and note the pass count. If it differs from `PROGRESS.md`, say so before anything else.
4. Read `feature_list.json`. If an item id was given, use it; otherwise propose the highest-priority item with `passes: false` that suits this role (see `docs/recovery/ROLE_PLAN.md` for which roles do what). Show its acceptance criteria.
5. Read the `.claude/rules/*.md` files that cover the paths the item touches, and the ADRs in `docs/DECISIONS.md` that mention it.
6. State, in under 10 lines: the role, the one item, its acceptance criteria, which frozen paths are nearby, and whether it costs money (paid LLM runs need a cost estimate and approval first).
7. For anything but a Conversationalist session, enter plan mode and wait for approval before changing files.

Stay in the declared role. If the work needs another role, say so and suggest ending the session.
