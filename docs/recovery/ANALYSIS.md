# SCML / TrustMediator: Phase 0 recovery analysis

- **Session role:** Recoverer. **Date:** 2026-10-15. **HEAD:** `9d3fb69` (main = origin/main, 2026-09-05).
- **Method:** this is a read-only analysis. The project tree was not modified, except for this folder.
  - Reproduction ran in a `git archive` copy under the session scratchpad, with its own Python 3.12 venv.
  - No paid or LLM-backed run was made.
- **Evidence:** every number cites a committed file or a re-run from this session. Anything else is marked `[UNVERIFIED]`.

---

## 1. Executive summary (10 lines)

1. The code does what the repo says: **639/639 tests pass** (with the `grpc` extra), **25/25 TS client tests pass**, and lint is clean with the project's pinned ruff.
2. **Every free benchmark reproduces on HEAD**: memory poisoning 20.8%, harm 18.8%, InjecAgent 0.0% with `no_tool_policy` at 100%, load PASS, soak 100%. This includes the four results whose code changed after they were committed.
3. **"2 of 17" is confirmed by evidence.** AgentDojo registers 17 attacks, and 2 have been run (`important_instructions` on 4 suites, `ignore_previous` on banking + slack).
4. **PRD §14.2 acceptance is not met**:
   - AgentDojo ASR is 7.3% against a target below 5%, a 75% reduction against a ≥ 90% target.
   - Benign utility retained is 81% against ≥ 90%.
   - Memory storage ASR is 20.8% against a target below 10%.
   - The injection scanner detects 0 of 1054 InjecAgent attacks. Tool policy is the entire defence.
5. **The security review found one Critical and seven High findings in `trust_mediator/`.**
   - A policy document with `{"agents":{}}` passes validation and **allows every tool**.
   - Data-plane keys can rewrite their own policy.
   - Unknown trust labels are silently dropped, so the argument is treated as trusted.
   - The LangChain guard lets tools run when the mediator errors, even in `strict` mode.
   - Memory routes are not tenant-scoped.
   - `require_approval_for` is ignored.
   - `untrusted_arg_policy: allow` is accepted.
   - Memory writes may self-assert `trusted_instruction`.
6. Any of those fixes will change what the AgentDojo numbers mean. **Fix security first, then run the remaining attacks** (15 not run, 14 automatable), otherwise they have to be run twice.
7. **Docs overstate.** Six files still say memory ASR is 33.3%. The README and blog quote a full slack `--sanitize` run (33.3% → 0%) that has **no committed result**. CLAUDE.md still says AgentDojo covers "one suite of four".
8. **Uncommitted work exists only on disk.** A TLS-by-default change with a real handshake/mTLS test (5/5 handshake tests pass on HEAD) sits in `.claude/worktrees/scml-implementation-audit-12563a/`. The stash holds the demo video and the `demo_video/` docs.
9. Repo hygiene:
   - 9 prunable worktree registrations and 7 leftover worktree dirs (~153 MB)
   - a 24 MB zip in git history
   - hardcoded `tmpassword` / `change-me-in-production` in compose
   - an absolute path from the old machine in 3 files
10. Deployment is blocked by the security findings plus secret defaults, not by infrastructure. Docker, compose, k8s, Render and Railway configs all exist.

---

## 2. Timeline (from `git log --all`, 108 commits + 3 stash commits)

| Dates | Milestone | Key commits |
|---|---|---|
| 07-19 → 07-21 | Initial scaffold: 8 modules, Claude Code setup. Production hardening: Redis rate limit, gRPC, Kafka, k8s, CI, multi-worker audit chain, deploy.sh | 706f774, b22570e, 7cefdb4, 08fd226 |
| 08-04 → 08-05 | PRD §14 harness, OTel tracing, load NFRs, audit batching (~140 → ~2,800 ev/s), bounded audit queue, §9 fail-policy fixes | 1ad9941, ba8e7ea, 13f2002, 4c0a196, eb36b03, 817d5b4 |
| 08-08 → 08-09 | Stash (demo video), video and recording guides on `feat/p3-evaluation-harness`, demo wiring | 7c26bf5, 31ef452, 1f525b2 |
| 08-14 → 08-15 | **InjecAgent** testbed (scanner catches 0), ML-gate config, scanner async fix, soak (NFR-AVAIL-01), harm ASR, **PRD v1.1 addendum** | e63c94e, da05f33, 964b83a, 42e6f47, 9eeb72b |
| 08-16 → 08-21 | Demo era: SDK packaging, demo-agent, 4-agent orchestrator, dashboard templates, exhibition launcher, Output Redaction page | 9b44ecf, 27c9a86, f866181, c58c788 |
| 08-22 | Authenticated quarantine routes, `_FILE` secrets, LICENSE/SECURITY | 66a3146, 08bd83e, f63c1a7 |
| 08-23 → 08-25 | **AgentDojo**: workspace first, taint-by-value, then all 4 suites (ASR 29.0 → 7.3%), second attack `ignore_previous`, per-agent policy endpoints | a7cfc69 … 7f17ccb, 7d955e0, 43ef16e |
| 08-27 | Copilot "refactor" commits (screenshots only) | 4626af4, 4d74955 |
| 08-30 → 09-01 | LaTeX report, source zip (untracked); classifier LLM eval (run 09-01) | n/a |
| 09-04 | **FR-OR-03 sanitizer**, memory ASR 33.3 → 20.8%, README rewrite, blog, Railway/Render, INTEGRATION.md, MCP README section | 9812de2, e406e76, d4cd612 |
| 09-05 | **Key-bound tenant policy namespaces** (last commit) | 9d3fb69 |

The PRD `.docx` (07-19) and the addendum (08-15) have **not been changed since August**.

---

## 3. Architecture as built

### Request path

`SCMLClient` (SDK) / LangChain guard / TS client / MCP (local) → REST `/v1/*` (FastAPI, `AuthDep`/`CallerDep`) or gRPC → `MediationPipeline` (`core/pipeline.py`) → modules → `AuditLogger` (async queue, batched, SHA-256 chain in DB) → Kafka / SIEM fan-out.

### Modules

| Module | As built | Notes vs PRD |
|---|---|---|
| ingress | `wrap_*` builds `ContextEnvelope`s with fixed labels; LangChain adapters | Adapters return content even on BLOCK; `MediatedTool` sends no arg labels |
| trust_router | source→label, never-promote, `most_restrictive` taint | Arg labels on `/tool-call` are caller-asserted; the server derives nothing |
| injection_scanner | regex stage 1, gated ML stage 2 (`heuristic`/`llm`/`onnx`→heuristic), `scan_async` | Stage 2 is unreachable on `untrusted_data` (gate 0.20); classifier errors return 0.0 |
| tool_policy | allow-list → schema → constraints → rate limit → untrusted-arg → irreversible/high-impact | No validation of the policy doc; `require_approval_for` is ignored |
| memory_integrity | 5-stage write vetting, quarantine, rescan on read, FR-MI-06 control-conflict detector | Release/purge are unaudited; cross-tenant; label self-assertion |
| output_redaction | PII/secret/entropy redaction; FR-OR-03 sanitizer (inbound) | FR-OR-02 data-flow rules are never loaded |
| audit_log | bounded queue, batched hash chain, gap markers, Kafka/SIEM | Hash omits `agent_id`/`context_id`/provenance; a DB write failure leaves no gap marker |
| policy_store | versioned docs per tenant, per-agent upsert, rollback, YAML bootstrap | Shadow policies are enforced live; rollback breaks later upserts |

### Other components

- **Clients and demos:**
  - `clients/typescript` is current.
  - `demo-agent/`, `orchestrator/` and `frontend/` are current and launched by `run-demo.sh`.
  - Root `demo_agent.py` and `orchestrator.py` are leftovers; `exhibition.sh` still uses the latter.
  - `trust_mediator/mcp/` is local and gitignored.
- **Deploy targets present:** Dockerfile, compose (+dev, override), `k8s/` (gateway + sidecar), nginx (:80 only), systemd unit, `railway.json`, `render.yaml`, `deploy.sh`.

---

## 4. Requirement traceability

**Status key:**
- ✅ implemented + tested
- 🟡 implemented, but either no test cites the ID or there is a known defect
- 🔴 not implemented / defective in a way that defeats the requirement
- ❓ `[UNVERIFIED]`

"Sec #n" refers to §7.

### Functional (PRD v1.0 §7; M = Must, S = Should, C = Could)

| ID | Pri | Code | Test (cites ID) | Evidence / issue | Status |
|---|---|---|---|---|---|
| FR-IG-01 | M | ingress/, api/ | context_source_dispatch | No-bypass is up to the host; the adapters return BLOCKed content | 🟡 |
| FR-IG-02 | M | api/routers, api/grpc, integrations | grpc_api, api_auth, langchain_guard | REST + gRPC + LangChain | ✅ |
| FR-TR-01 | M | models/context_envelope.py | none | No immutability or provenance test | 🟡 |
| FR-TR-02 | M | trust_router/router.py | trust_router, langchain_guard | `most_restrictive`; server never derives arg labels | ✅/🟡 |
| FR-TR-03 | M | trust_router | (test_separate_channels, uncited) | Unknown labels dropped → trusted (Sec #3) | 🔴 |
| FR-SC-01 | M | injection_scanner/scanner.py | (uncited) | Runs on every item, but detects 0/1054 InjecAgent | 🟡 |
| FR-SC-02 | M | scanner.py | heuristic_sql_pattern | verdict + score + rationale | ✅ |
| FR-SC-03 | S | scanner TRANSFORM verdict | none | ❓ quality of the sanitised summary not assessed | ❓ |
| FR-SC-04 | M | config.py | (shadow test, uncited) | env thresholds + shadow mode | ✅ |
| FR-SC-05 | M | tool_policy independent | scanner_ml_gate | InjecAgent ablation shows policy alone holds | ✅ |
| FR-PE-01 | M | tool_policy/engine.py | client | Every call is evaluated, **but** a doc without `allowed_tools` = allow-all (Sec #1) | 🔴 |
| FR-PE-02 | M | engine.py, policy_store | langchain_guard, policy_per_agent | Schema/constraints are unvalidated (Sec E2) | 🟡 |
| FR-PE-03 | M | engine.py:131-143 | langchain_guard | `require_approval_for` ignored; only caller hints (Sec #7) | 🔴 |
| FR-PE-04 | M | engine.py:117-128 | agentdojo_taint, client, … | `untrusted_arg_policy: allow` accepted (Sec #8); label drop (Sec #3) | 🟡 |
| FR-PE-05 | S | rate_limiter.py | rate_limiter | Bucket not tenant-keyed (Sec #12) | 🟡 |
| FR-MI-01 | M | memory_integrity/layer.py | client | 5-stage vetting | ✅ |
| FR-MI-02 | M | consistency_checker.py | memory_integrity | **Storage ASR 20.8% vs < 10%: FAIL** | 🔴 (KPI) |
| FR-MI-03 | M | scorer.py | (uncited) | Self-asserted `trusted_instruction` → provenance 1.0 (Sec #5) | 🟡 |
| FR-MI-04 | M | layer.py:289-371 | memory_integrity | Hash check + rescan on read | ✅ |
| FR-MI-05 | S | routers/memory.py | api_auth | Authenticated; but unaudited, cross-tenant, no admin role, race (Sec #2, #6, #9, E5) | 🟡 |
| FR-OR-01 | M | redactor.py | redactor_secret_formats, client | Works | ✅ |
| FR-OR-02 | M | redactor.py | (uncited) | Data-flow rules never loaded (Sec #11) | 🔴 |
| FR-AL-01 | M | audit_log/logger.py | audit_* (4 files) | Chain works; admin actions unaudited; overflow drops (my load run dropped 337,000 events at 10k queue) | 🟡 |
| FR-AL-02 | S | routers/audit.py | none | Replay exists; not tenant-scoped | 🟡 |
| FR-AL-03 | S | kafka_forwarder.py | kafka_forwarder | Kafka + SIEM webhook | ✅ |
| FR-CP-01 | M | policy_store | policy_per_agent, tenant_policy | Versioning/rollback; rollback breaks later upserts (Sec E3) | 🟡 |
| FR-CP-02 | S | policy_repo.py | none | `shadow:true, activate:true` is enforced live (Sec E1) | 🔴 |
| FR-CP-03 | M | n/a | none | Same keys for control and data plane (Sec #2) | 🔴 |
| FR-CP-04 | C | frontend/ | none | Demo dashboard exists | 🟡 |

### Non-functional (v1.0 §8, all "required" except MAINT-01)

| ID | Evidence | Status |
|---|---|---|
| NFR-PERF-01 p50<120 / p95<400 ms | load re-run: HTTP fast path p95 21–27 ms | ✅ |
| NFR-PERF-02 LLM ≤1 inference | none | ❓ |
| NFR-PERF-03 policy p95<10 ms | load: 0.03 ms pipeline | ✅ |
| NFR-PERF-04 async audit | `put_nowait`; drops under overload | ✅ (with FR-AL-01 caveat) |
| NFR-SCAL-01 ≥100 rps | load re-run: ~510 rps HTTP fast path, single process | ✅ |
| NFR-SCAL-02/03, AVAIL-02/03, REL-01, COMP-01/02, PRIV-01 | no test, no measurement | ❓ |
| NFR-AVAIL-01 ≥99.9% | soak re-run 100.000% / 25,072 calls (in-process only) | ✅ (scoped) |
| NFR-SEC-01 mediator self-injection | security review: LLM classifier has no tools (clean); escalation webhook sends raw content (Sec #13) | 🟡 |
| NFR-SEC-02 policy/audit integrity | data-plane keys write policy (Sec #2); hash omits fields (Sec E4) | 🔴 |
| NFR-SEC-03 TLS | Supported; shipped configs opt out. The leftover test says the Dockerfile CMD and systemd unit bypass the TLS keypair wiring | 🟡 |
| NFR-SEC-04 secrets | `_FILE` sources; compose hardcodes `tmpassword` | 🟡 |
| NFR-OBS-01 OTel | observability tests | ✅ |
| NFR-MAINT-01 (S) plugins | none | ❓ |

### Addendum v1.1 (proposed, no priorities)

- **AC-14.2a:** storage < 10% FAIL (20.8%); harm gated 2.5% PASS; pessimistic 18.8%.
- **AC-14.2b:** coverage 100% per the addendum.
- **FR-SC-07:** not met (LLM AUC 0.72 < 0.85, p95 2.2 s).
- **AC-16.x:** 16.1 TLS is partial; 16.2 secrets is partial; 16.3 sandbox is missing; 16.4 spill-to-disk is missing; NFR-OPS-01 runbooks are missing.

**ID drift:**
- FR-OR-03 (the sanitizer) is used in code and docs but defined in neither spec.
- FR-MI-06 means "dual ASR reporting" in the addendum and "control-conflict detector" in the code.

Seven Musts have no test that cites their ID: TR-01, TR-03, SC-01, SC-04, MI-03, OR-02, CP-03. Most are exercised under other names.

---

## 5. Evaluation status

| Testbed / result | PRD § | Config | Headline (committed) | Commit | Code since? | Reproduced 2026-10-15 |
|---|---|---|---|---|---|---|
| AgentDojo `important_instructions`, 4 suites | §14.1/14.2 | gpt-4o-mini, v1.2.1, 949 attacked + 97 benign / arm | ASR 29.0 → **7.3%** (75%); benign util 74.2 → 59.8% (81%) | 7f17ccb | yes | not run (paid) |
| AgentDojo `ignore_previous`, banking + slack | §14.1 | same | banking 20.1 → 0.0; slack 17.1 → 10.5 | 7d955e0 | yes | not run (paid) |
| AgentDojo, other 15 attacks | §14.1 "strongest attacks" | n/a | **not run** | n/a | n/a | n/a |
| AgentDojo per-module ablation | §14.3 | n/a | **not run** (only defended vs undefended) | n/a | n/a | n/a |
| InjecAgent (1054) | §14.1 | heuristic, 5-config ablation | full 0.0%, `no_scanner` 0.0%, **`no_tool_policy` 100.0%** | da05f33 | yes | **identical** |
| Memory poisoning (48, in-house) | §14.2 | heuristic | full **20.8%** / no_scanner 29.2 / no_consistency 64.6; FPR 0; util 100 | 9812de2 | no | **identical** |
| Memory harm | add. §14.2a | n/a | gated 1/40 (2.5%); pessimistic 9/48 (18.8%) | 42e6f47 | yes | **identical** |
| Load | §8.1/8.2 | 5 s/scenario, conc 8, SQLite | all PASS; HTTP p95 29–42 ms; memory_write p95 1.1 s | 4c0a196 | yes | all PASS; HTTP p95 21–27 ms; memory_write p95 0.83 s |
| Soak | §8.3 | 7 fault phases | 100.000% / 10,666 calls | 964b83a | yes | 100.000% / 25,072 calls |
| Classifier LLM | add. §6.3a | gpt-4o-mini, ~USD 0.35 | AUC 0.72, p95 2237 ms, not shippable | 9812de2 | no | not run (paid) |
| Output sanitizer pilot | FR-OR-03 | slack `user_task_2` | ASR 60 → 0% | 9812de2 | no | not run (paid) |
| **Slack full `--sanitize`** | n/a | n/a | **quoted in README:239-244 & blog:59, no result file** | n/a | n/a | **unbacked** |

**What the PRD requires and what's missing:**
- AgentDojo + InjecAgent at the "strongest attacks", and a memory testbed. AgentDojo has 2 of 17 attacks run.
- A §14.3 ablation over 4 toggles. This exists for InjecAgent and memory, but not for AgentDojo.
- A shadow-mode FPR comparison. This is ❓, not found.

---

## 6. Reproduction: claimed vs measured

Measured in a `git archive HEAD` copy, Python 3.12.3, fresh venv. Env: `DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS=""`.

| Check | Claimed | Measured | Note |
|---|---|---|---|
| pytest, `.[dev]` only | 639 passed | 628 passed, 6 skipped | the skips need `grpc`, which is not in `[dev]` |
| pytest + `grpcio` | 639 passed | **639 passed** | ✅ |
| ruff (project pin, 0.15.22) | clean | **All checks passed** | ✅ |
| ruff (fresh install, 0.17.0) | n/a | **124 errors** | `ruff>=0.4.0` is unpinned: CI breaks on the next ruff release |
| TS client | 25 passed | **25 passed** | ✅ |
| memory_poisoning | 20.8% | 20.8% | exits 1 by design (KPI miss) |
| injecagent | 0.0 / 0.0 / 100.0 | identical | ✅ |
| harm | 1/40, 9/48 | identical | ✅ |
| load / soak | PASS / 100% | PASS / 100% | machine-dependent numbers |
| leftover `test_tls_handshake.py` (+`cryptography`) | n/a | 6 passed, **2 failed** | Handshake/mTLS pass on HEAD. The failures are the Dockerfile CMD and systemd ExecStart calling `uvicorn` directly (the worktree had the fix) |

**Side observations:**
- The committed settings tables show `memory_rescan_on_read=False`; the clean run shows `True`. A local `.env` probably leaked into the committed run. The numbers are unaffected.
- The load run logged `audit_logger.events_dropped dropped_total=337000`. Under the load harness the audit writer cannot keep up, so FR-AL-01 is "auditable under overload, not satisfied", as CLAUDE.md admits.
- The tracked `_heuristic_model.pkl` was pickled with sklearn 1.9.0; the fresh venv got 1.9.1, which produces an `InconsistentVersionWarning`.

---

## 7. Security findings (`security-reviewer` agent, read-only, HEAD 9d3fb69)

Of the 17 seeded claims, 16 are CONFIRMED and 1 is PARTIAL. 11 additional findings were found.

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | **Critical** | `PUT /v1/policy` validator checks only top-level keys. `{"agents":{}}` → no `default` → `{}` → missing `allowed_tools` = **allow every tool**. `allowed_tools` as a string becomes a substring match; as `null` it causes a 500 | `policy_store/store.py:240-250`, `tool_policy/engine.py:76-92` |
| 2 | High | No admin role: any data-plane key can rewrite or roll back its tenant's policy and release its own quarantined poison | `api/routers/policy.py:62-211`, `memory.py:137-153` |
| 3 | High | Unknown trust-label strings are dropped → arg treated as trusted (gRPC rejects them, REST drops them) | `api/routers/mediate.py:155-158` |
| 4 | High | LangChain guard `strict=True` does nothing on ERROR/ESCALATE: a revoked key or 500 = unmediated tool run | `integrations/langchain_guard.py:226-231` |
| 5 | High | Memory write accepts self-asserted `trusted_instruction` → scanner skipped, provenance 1.0 | `api/routers/memory.py:66-69`, `scorer.py:29` |
| 6 | High | Memory and audit routes are not tenant-scoped; gRPC always uses the `default` tenant | `memory.py`, `db/memory_repo.py`, `audit.py:17`, `grpc/server.py:89-97` |
| 7 | High | `require_approval_for` is ignored, so the shipped `send_email` / `initiate_transfer` are allowed without approval | `engine.py:131-143`, `policies/*.yaml` |
| 8 | High | `untrusted_arg_policy: allow` is accepted, which violates §5.2 by configuration | `store.py:219-220` |
| E1 | High | `shadow:true, activate:true` is enforced live (FR-CP-02) | `db/policy_repo.py:115-157` |
| 9 | Medium | Release, purge, policy changes and pipeline exceptions emit no AuditEvent; purge ignores status | `layer.py:379-398`, `pipeline.py:161-190` |
| 10 | Medium | Classifier error / missing key → 0.0 → "verified" ALLOW (unaudited fail-open) | `classifier.py:183-265` |
| 11 | Medium | FR-OR-02 data-flow rules never loaded; no rule = allowed | `api/dependencies.py:21`, `redactor.py:84-147` |
| 12 | Medium | Rate-limit key lacks tenant (cross-tenant DoS; `agent_id` rotation bypass) | `engine.py:109` |
| 13 | Medium | Escalation webhook sends raw attacker content into Slack mrkdwn | `mediate.py:132`, `escalation/webhook.py` |
| 14 | Medium | `/metrics` unauthenticated; raw-path labels leak ids and grow without bound | `api/app.py:147,188` |
| 15 | Medium | (local `mcp/`) `redact_output` returns unredacted text; the LLM picks its own labels | `mcp/server.py:224` |
| 16 | Medium | DB error on the default tenant silently falls back to YAML (may re-grant revoked tools) | `policy_loader.py:102-115` |
| E2 | Med-High | Policy fields untyped (TypeError → 500 → guard allows); ReDoS via `pattern`; `re.match` not `fullmatch` | `store.py`, `engine.py:199-217` |
| E3 | Medium | After a rollback, every later per-agent upsert hits IntegrityError, so emergency revocation fails | `policy_repo.py:51,305-311` |
| E4 | Medium | Audit hash omits `agent_id`/`context_id`/provenance; no head anchor; DB write failure leaves no gap marker | `models/audit_event.py:88-98`, `logger.py` |
| E5 | Medium | Release/purge race can resurrect a purged poison as ACTIVE | `layer.py:379-392` |
| E6 | Medium | `env` defaults to `development` → no keys = open API | `config.py:224` |
| E7 | Medium | Policy `memory`/`scanner`/`redaction` sections are dead config | `policy_store` |
| E8 | Low-Med | LLM classifier sees `text[:4000]` only; an out-of-range score → unaudited 500 | `classifier.py:247,262` |
| 17, E9–E11 | Low | Pickle load; compose password + unused `secret_key`; slowapi `swallow_errors`; whole-doc PUT race | various |

**Checked clean:** LLM classifier tool isolation (NFR-SEC-01), constant-time key comparison, every `/v1` route authenticated, atomic tool rate limiters, never-promote on `/context`, non-default tenants failing closed.

**Implication for the research claim:** the AgentDojo and InjecAgent numbers were measured with well-formed policies and correct labels, so they **remain valid as measured**. But a production deployment does not currently get that guarantee. #1, #3 and #4 each turn a misconfiguration or outage into an unmediated tool call.

---

## 8. Repo hygiene

| Item | Contents | Exists elsewhere? | Recommendation (**not executed**) |
|---|---|---|---|
| `4626af4`, `4d74955` (copilot branches) | 2 screenshots + `Terminal Commands/terminal start stop` | yes, as untracked ignored files in the working tree | delete branches after you confirm |
| `31ef452` (`feat/p3-evaluation-harness`) | DEMO_VIDEO_WORKFLOW.md, LIVE_DEMO_RECORDING_GUIDE.md | **yes, byte-identical on main** | delete branch |
| stash@{0} | untracked only: `demo_video/` (6 docs), `SCML Demo Video.mp4` (31 MB), "Complete Handbook" HTML, `.vscode/launch.json`, soak/ (identical on main) | **demo_video/, mp4 and Handbook exist only here** | export to `archive/` outside git (`git checkout stash@{0}^3 -- …` into a scratch dir), then drop |
| `.claude/worktrees/scml-implementation-audit-12563a` (31 MB) | **uncommitted TLS-by-default** (generate-dev-certs.sh, test_tls_handshake.py, edits to compose/Dockerfile/nginx/service/pyproject/CLAUDE.md/CHANGELOG), `INDUSTRY_READINESS_AND_IP_PLAN.md`, dev certs incl. private key | **no** | rescue into a branch `rescue/tls-by-default` (without the `certs/` key), review, then remove the dir. The IP plan was deliberately kept out of the repo (83bbf88), so move it outside the repo |
| `…/scml-cinematic-demo-f31050` | `scml_cinematic_demo{,_3min}.html` | no | archive outside the repo |
| `…/scml-presentation-video-d7e944` | `scml_intrusion_3d.html` | no | archive |
| `…/exhibition-narration-docx-650f23` | `SCML_Exhibition_Narration.docx` | no | archive |
| `…/competent-mccarthy-e83b0f` | old quarantine-auth fix + 62-line test | superseded on main (`memory.py:115,138`) | remove |
| `…/scml-autonomous-system-integration-a3a364` (103 MB), `…/scml-package-architecture-1a360f` | build artefacts, logs, `settings.local.json` | n/a | remove |
| 9 worktree registrations | point at `/home/ravindu/Desktop/project/...` (gone) | n/a | `git worktree prune`, only **after** the rescues above |
| Branches `claude/*`, `copilot/*` | all `claude/*` merged into main | n/a | delete local merged branches; `claude/scml-autonomous-system-integration-a3a364` is 1 ahead of origin (751c90a is already in main) |
| `SCML_Project_Source.zip` (24 MB) | in history at 9812de2 | n/a | purging needs a history rewrite + force push. **Ask first.** Probably not worth it |
| Old absolute path | `trust-mediator.service:11-13,30`, `benchmarks/testbeds/agentdojo/runner.py:245`, `LIVE_DEMO_RECORDING_GUIDE.md:140` | n/a | make relative/env-driven |
| Compose secrets | `docker-compose.yml:18,52` `tmpassword`; `:27` `change-me-in-production`; 5432/6379 published | n/a | `_FILE` secrets, no published DB ports |
| `render.yaml` | `ALLOW_INSECURE_HTTP=true` in production | n/a | fine only if Render terminates TLS (it does). Document it |
| CI | no TS build, no image build, ruff unpinned, `grpc` not in `[dev]` | n/a | add jobs; pin ruff; add grpc to `[dev]` |
| Leftovers | root `demo_agent.py` (no API key header), `orchestrator.py`, `NARRATION_SCRIPT.txt`, video guides (old ports and paths) | n/a | move to `archive/` or delete, after you confirm |

**Old Claude memory notes** (`~/.claude/projects/-home-ravindu-Desktop-project-…/memory/`):
- Still valid: the naming rule (title cards say SCML; code and architecture say TrustMediator) and the rules against claiming a sandbox or ONNX model.
- **Outdated:** "never claim any benchmark numbers". Benchmarks now exist, and the honesty rules in CLAUDE.md replace that one.
- Context only: HeyGen and Data Odyssey.
- No `~/.claude/plans` or `~/.claude/todos` existed. `history.jsonl` holds only this session.

**Doc drift to fix (not frozen):**

| Claim | Where it's wrong | Correct |
|---|---|---|
| memory 33.3% | README:242, SECURITY.md:58, CHANGELOG:91, PRD_v1.1_ADDENDUM:33/87/327/339, `SCML_Project_Report.tex`:160/196, benchmarks/README:205 | 20.8% |
| AgentDojo coverage | CLAUDE.md:112-114 ("one suite of four"), CLAUDE.md:259 ("important_instructions only"), benchmarks/README:224 ("unimplemented"), agentdojo.md CaMeL table ("1 of 17") | 4 suites, 2 of 17 |
| "cryptography not installed" | CLAUDE.md | it is in `.venv` (50.0.0) |
| Full slack `--sanitize` 33.3% → 0% | README:239-244, blog:59 | unbacked: no result file |
| "ran all shipped attack types" | blog:38 | 2 of 17 |

---

## 9. Ranked backlog

Tags:
- **D**: blocks deployment
- **R**: blocks the research claim
- **N**: nice to have

| Rank | Item | Tag | Evidence | Suggested role |
|---|---|---|---|---|
| 0 | **Rescue on-disk-only work**: TLS worktree → branch; stash media and films → archive (no deletions yet) | D | §8 | CLI vibe coder (with your approval) |
| 1 | Policy validation: strict schema for the whole doc; require `agents.default`; missing `allowed_tools` = deny; drop `untrusted_arg_policy: allow`; regex compile and `fullmatch` | D | Sec #1, #8, E2 | Architect → CLI vibe coder |
| 2 | Separate control-plane authority: admin role on policy write/rollback and quarantine release/purge; fix shadow enforcement | D | Sec #2, E1, FR-CP-02/03 | Architect → CLI vibe coder |
| 3 | Label integrity: reject unknown labels; unlabelled = untrusted; server-derived memory labels | D/R | Sec #3, #5 | CLI vibe coder |
| 4 | Fail-closed clients: guard `strict` raises on ERROR/ESCALATE/UNKNOWN; classifier errors → `_unscannable` | D | Sec #4, #10, §9 | CLI vibe coder |
| 5 | Honour `require_approval_for` (FR-PE-03) | D/R | Sec #7 | CLI vibe coder |
| 6 | Tenant isolation: memory, audit, gRPC, rate-limit bucket | D | Sec #6, #12 | Architect → CLI vibe coder |
| 7 | Audit completeness: admin events, pipeline exceptions, write-failure gap markers, hash all fields; purge status check + release race | D | Sec #9, E4, E5 | CLI vibe coder |
| 8 | Wire FR-OR-02 data-flow rules; decide on the dead policy sections | D | Sec #11, E7 | CLI vibe coder |
| 9 | Deploy defaults: compose secrets, `env` default production, Dockerfile/systemd TLS entrypoint, `/metrics` auth, webhook content, YAML fallback | D | §8, Sec #13, #14, #16, E6 | Shipper |
| 10 | **Doc honesty pass**: fix all of §8's drift; remove or back the slack `--sanitize` claim; define FR-OR-03; resolve the FR-MI-06 collision | R | §8 | PRD person → Shipper |
| 11 | Re-run the AgentDojo baseline (`important_instructions` × 4) **after 1–8**, into a versioned file | R | §5 | Agentic builder (paid) |
| 12 | Remaining 15 AgentDojo attacks (14 automatable; `manual` needs a human; DoS family reported separately) | R | PROGRESS_RECONCILIATION | Agentic builder (paid) |
| 13 | AgentDojo §14.3 per-module ablation | R | PRD §14.3 | Agentic builder (paid) |
| 14 | Full slack `--sanitize` suite | R | output_sanitizer.md | Agentic builder (paid) |
| 15 | AgentDojo targets: ASR < 5%, utility ≥ 90% (travel 64%, slack 52% reduction), with a held-out split | R | §5 | Architect → CLI vibe coder |
| 16 | Memory poisoning 20.8% → < 10%, no in-house tuning (needs an external or held-out corpus) | R | §5 | Architect |
| 17 | §6.3 detection (FR-SC-07..09): POS/dependency parser or fine-tuned model, off the request path | R | classifier_llm.md | Architect |
| 18 | CI: pin ruff, add grpc to `[dev]`, TS build+test job, image build | N | §6 | Shipper |
| 19 | Addendum production items: spill-to-disk (16.4), sandbox interface (16.3), runbooks (NFR-OPS), Postgres/Redis/Kafka TLS, k8s secret volume | N/D | CLAUDE.md "Known gaps" | Architect → CLI vibe coder |
| 20 | ID-citing tests for the 7 uncited Musts; measure the ❓ NFRs | N | §4 | CLI vibe coder |
| 21 | Hygiene clean-up (after #0): prune worktrees, drop stash, delete merged branches, old paths, leftovers | N | §8 | CLI vibe coder |
| 22 | Report, README, paper aligned with final numbers | R (for submission) | §8 | PRD person → Shipper |
| 23 | Deploy to the chosen target | D | open question | Architect → Shipper |
| 24 | `mcp/` server: fix or keep out of releases; pickle → safer format | N | Sec #15, #17 | CLI vibe coder |
