# Progress

<!-- current-state:start -->
## Current state (updated 2026-10-18)

- **Phase:** 1 harness set up; Phase 2 (one backlog item per session) next.
- **Tests:** 875 Python passed locally (2026-10-19). CI green on PR #1, TypeScript client tests included.
- **Frozen:** 47 files in FROZEN.md, all hashes match (`scripts/check_frozen.sh`).
- **Backlog** (`feature_list.json`): 11 verified (`passes: true`), 5 partial, 9 open.
- **Uncommitted:** `--offset` resume flag in `benchmarks/testbeds/agentdojo/runner.py` (for #11). Everything else is pushed on `debugger/audit-drain-probe` (draft PR #1), not merged into `main`.
- **Environment:** Linux. `.venv` was built at an old path, so use `.venv/bin/python -m <tool>`. `socat` missing for the sandbox.
- **Next:** review/merge PR #1 into `main`, then #11 AgentDojo re-baseline (paid; estimate first).
<!-- current-state:end -->

## Session log (newest first)

### 2026-10-19 — Shipper — confirm CI for #18
- Installed `gh` 2.102.0 to `~/.local/bin` (official release, checksum verified). Pushed `debugger/audit-drain-probe`, opened draft PR #1 (CI runs only on `main` pushes and PRs).
- First run failed on two leaks hidden locally: (1) `/metrics` tests needed `ALLOW_INSECURE_HTTP`, which only the local `.env` set; (2) services type-checked against a gitignored client `dist/`. Fixed in 5c9798f; the test env prefix in CLAUDE.md now pins `ALLOW_INSECURE_HTTP=false`.
- Run 39158432783: all 8 jobs green. #18 `passes: true`.

### 2026-10-18 — Verifier — sweep over the 11 implemented items
- Ran all cited evidence tests (245 passed) and read the key ones for what they assert; checked cited commits exist, `rescue/tls-by-default`, and the archive SHA256SUMS (all OK).
- `passes: true` for #0, #1, #2, #4, #5, #6, #7, #8, #9, #20. #7's [UNVERIFIED] note resolved: purge-status and release-race tests exist in `test_tenant_isolation.py`.
- #18 stays `implemented`: `ci.yml` covers every criterion, but no green run could be checked (`gh` not installed).
- Evidence: 875 tests passed; 47 frozen hashes match.

### 2026-10-18 — Debugger — 337k audit drops under the load harness
- Reproduced: ~311k `audit_logger.events_dropped` on `benchmarks.load --target pipeline`.
- Bug (harness only): the drain probe sent a 20k burst into the 10k queue, dropping 10k and counting them as drained. Reported 7,185 events/s against 3,851 actual. Fixed in `benchmarks/load/__main__.py`; regression test `TestAuditDrainProbe` (fails before, passes after).
- The rest is real overload (~8k–35k req/s in-process against a ~3.8k events/s writer), already recorded as `audit_gap` markers. No `trust_mediator/` change; noted on #19 (ADR-0008).
- Evidence: 875 tests passed; ruff clean; 47 frozen hashes match; `benchmarks/results/v2/load_2026-10-18.{md,json}`. Frozen `load.md` predates the queue bound and is unaffected.

### 2026-10-18 — Architect + Agentic builder — Phase 1 harness setup
- Added PROGRESS.md, feature_list.json, docs/DECISIONS.md (ADR-0001..0007), FROZEN.md, scripts/check_frozen.sh.
- CLAUDE.md 369 → 90 lines; module rules moved word for word into .claude/rules/*.md (ADR-0002).
- Hooks: PreToolUse frozen guard, SessionStart current-state print. Ruff hook switched to `python -m ruff` (the venv's console scripts are broken).
- Skills: /session-start, /session-end, /run-eval, /kpi-report. Agents: verifier, eval-analyst.
- Sandbox enabled (ADR-0003).
- Evidence: 874 tests passed; 47 frozen hashes match.
- Open: install socat; no Python LSP plugin installed.

### 2026-10-15 → 2026-10-16 — earlier sessions (reconstructed from git)
- Phase 0 analysis: `docs/recovery/`.
- Backlog #0–#9, #18, #20, #21 (partial), #23 (target chosen) committed; see feature_list.json evidence and ADR-0004..0007.
