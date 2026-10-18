# Architecture decision records

Status is one of **active**, **superseded** (link the replacement) or **rejected**. Never delete an ADR; supersede it.
ADR-0004 onwards up to ADR-0007 were recorded retroactively on 2026-10-18 from commits made on 2026-10-16; the commit is the evidence.

---

## ADR-0001: Committed benchmark results are frozen; new runs go to versioned files

- **Status:** active
- **Date:** 2026-10-18
- **Context:** `CLAUDE.md` told contributors to "update the committed result" after changing a scorer or detector. That
  overwrites the evidence the report and README quote, and the history of a claim is lost.
- **Decision:** The files in `FROZEN.md` (results, corpora, AgentDojo policies, PRD and addendum) are read-only. New runs
  write `benchmarks/results/v2/<testbed>_<YYYY-MM-DD>[_<variant>].{md,json}` plus a `.run.json` sidecar. Defects found in
  a frozen file are corrected in a new file, never in place. A PreToolUse hook enforces it; `scripts/check_frozen.sh`
  verifies the hashes. This supersedes the "update the committed result" line formerly in `CLAUDE.md`.
- **Consequences:** `docs/EVAL_RESULTS.md` (via `/kpi-report`) must show the newest result and the baseline side by side.
  Changing the frozen list requires the owner's approval and a new ADR.

## ADR-0002: CLAUDE.md slimmed; module rules moved to path-scoped `.claude/rules/`

- **Status:** active
- **Date:** 2026-10-18
- **Context:** `CLAUDE.md` had grown to 369 lines, so every session loaded every module's history.
- **Decision:** `CLAUDE.md` keeps the commands, global invariants (one line each), layout, known-gap list and measured
  headlines. Module detail moved word for word into `.claude/rules/{api-auth,audit,benchmarks,clients,infra,
  memory-integrity,output-sanitizer,policy,scanner}.md`, each with `paths:` front-matter. No rule text was dropped; the
  only wording change is ADR-0001's.
- **Consequences:** a rule loads when matching files are touched. A new module rule goes into the matching file, not
  `CLAUDE.md`.

## ADR-0003: Bash sandboxing on for this project

- **Status:** active
- **Date:** 2026-10-18
- **Context:** benchmarks replay real injection payloads, and the development machine is now Linux, where the sandbox
  is supported (bubblewrap).
- **Decision:** `sandbox.enabled: true` with `autoAllowBashIfSandboxed: true` in `.claude/settings.json`. Network access
  prompts per domain.
- **Consequences:** requires `socat` (not installed as of 2026-10-18). Commands that need Docker or unsandboxed access
  will prompt.

## ADR-0004: Deploy target is a single Docker host behind Caddy

- **Status:** active
- **Date:** 2026-10-16 (commit b508a58)
- **Decision:** `docker-compose.prod.yml` with Caddy terminating TLS on 80/443; the mediator's port is not published.
  Runbook `docs/DEPLOY_VPS.md`, smoke test `scripts/smoke.sh`.
- **Alternatives:** Render/Railway/Fly.io (configs exist but unmaintained), AWS ECS, the `k8s/` manifests (TLS and
  secret-volume gaps, see `.claude/rules/infra.md`).
- **Consequences:** no server provisioned yet (backlog #23).

## ADR-0005: Control-plane writes need a separate admin key set; shadow policies are never active

- **Status:** active
- **Date:** 2026-10-16 (commit 894399f)
- **Decision:** policy and quarantine writes resolve against `TRUST_MEDIATOR_ADMIN_API_KEYS`; data-plane keys never
  substitute, and no admin keys means the control plane is closed. A shadow version cannot be activated because nothing
  evaluates policy in shadow.

## ADR-0006: FR-OR-02 data-flow rules are per tenant and deny by default

- **Status:** active
- **Date:** 2026-10-16 (commit f4805d0)
- **Decision:** `_process_output` reads `protected_classes`/`data_flow_rules` from the tenant policy; PII and entropy
  settings stay built in so a tenant cannot disable redaction. Policy `memory`/`scanner` sections are not enforced.

## ADR-0007: Tool-affordance imperative detector — no-go for FR-SC-07

- **Status:** rejected (as a shipped detector)
- **Date:** 2026-10-16 (commit a1ae261)
- **Evidence:** `benchmarks/results/affordance_detector.md`: held-out InjecAgent AUC 0.779 (< 0.85), 7.6% FPR at the
  frozen threshold, 158 ms p95, 0% recall on memory poisoning. Tool similarity alone scores 0.834; the mood term lowers it.
- **Consequences:** §6.3 detection (backlog #17) stays open. Previously rejected: two TF-IDF approaches (AUC 0.660,
  0.506) and the token-level route gate.

## ADR-0008: The load drain probe stays inside the audit queue bound; harness overload drops are capacity, not a bug

- **Status:** active
- **Date:** 2026-10-18
- **Decision:** `_measure_audit_drain_rate` caps its burst at `AUDIT_QUEUE_MAXSIZE` and counts only persisted events.
  The 20k burst predated the 10k bound (eb36b03), so since then it dropped 10k events and counted them as drained
  (reported 7,185 events/s, actual 3,851). Regression test:
  `test_load_harness.py::TestAuditDrainProbe`.
- **Evidence:** `benchmarks/results/v2/load_2026-10-18.md`. The frozen `load.md` (2,809 events/s, 2026-08-05) predates
  the bound and is unaffected.
- **Consequences:** the 337k drops in `docs/recovery/ANALYSIS.md` were about 10k probe artifact plus real overload:
  the in-process pipeline scenarios run at ~8k–35k req/s against a ~3.8k events/s writer. No `AuditLogger` change;
  preventing the loss is spill-to-disk (backlog #19).
