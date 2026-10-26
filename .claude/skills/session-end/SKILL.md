---
name: session-end
description: Close a work session — verify, record evidence, update PROGRESS.md / feature_list.json / ADRs, and commit.
disable-model-invocation: true
---

1. Run the full test suite (env prefix in `CLAUDE.md`) and `.venv/bin/python -m ruff check trust_mediator/ tests/`. Record the counts.
2. Run `scripts/check_frozen.sh`. If any hash fails, stop: report which file changed and how, and do not commit.
3. If `trust_mediator/` changed this session, run the `security-reviewer` agent on the diff. Run the `verifier` agent on the item worked on.
4. Update `feature_list.json` for that item: set `passes: true` **only** if the verifier confirms every acceptance criterion with evidence that reproduces (test names, result file paths, commit). Otherwise leave it false and write what is missing in `notes`.
5. Add an ADR to `docs/DECISIONS.md` for every decision made this session (next free number; status active). If a decision replaces an older one, mark the old one superseded and link both ways. Never delete an ADR.
6. Update `PROGRESS.md`: rewrite the current-state block (tests, HEAD, next item) and add a newest-first log entry with date, role, item, what changed, evidence and open questions.
7. Show the diff summary, then commit with a message that names the item and the evidence. Do not push.
