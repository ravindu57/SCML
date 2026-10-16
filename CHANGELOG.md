# Changelog

Notable changes to TrustMediator / SCML. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**On the version number.** `__version__` reads `1.0.0`, and that overstates
things: there are no releases, no tags, and no backports — only `main`. Treat
the project as pre-1.0 until a tagged release exists, as `SECURITY.md` says.
This file starts at the point one was first kept; earlier history is in the
commit log.

## [Unreleased]

### Deployment

- Single-host production setup (the chosen target): `docker-compose.prod.yml`
  adds Caddy for automatic TLS on 80/443 and stops publishing the mediator's
  port, so all traffic goes through TLS. It trusts `X-Forwarded-For` only
  because nothing but Caddy can reach the mediator, so per-client rate limits
  still work, and it sets the Host allow-list and HSTS. `docs/DEPLOY_VPS.md`
  is the runbook (configuration, policy load, upgrade notes, backups).
  `scripts/smoke.sh` checks a live deployment and passed against a
  production-configured mediator locally.

### CI

- Ruff is pinned (`0.15.22`) in the `[dev]` extra and the lint job, and the
  `[dev]` extra now includes `grpc`, so a plain dev install runs every test.
- New jobs: build, test and `npm pack` the TypeScript client; typecheck the
  orchestrator and demo-agent. None of them was built in CI before.
- The test-count floor rises from 390 to 860.
- The demo `load-policy` scripts send `SCML_ADMIN_API_KEY` (policy writes
  are control-plane).

### Security (deploy defaults)

- **HTTP rate limiting applied to no `/v1` route.** slowapi looks routes up in
  a flat `app.routes`, and FastAPI 0.139 nests included routers, so every
  mediation, policy and admin route was treated as exempt (8 calls under a
  5/minute limit: all 200). A replacement middleware walks nested routes.
  Limits are per principal for valid keys and per IP otherwise, which also
  throttles admin-key guessing.
- **`TRUST_MEDIATOR_ENV` defaults to `production`.** Development, where no
  keys means an open API, must now be set explicitly. **Behaviour change** for
  anyone relying on the old default.
- **A policy DB error fell back to the gateway YAML**, re-granting any tool
  revoked in the DB but still listed in the file. It now serves the last
  document the DB returned (for at most 5 minutes), else deny-all, and backs
  off the DB for 2 s after an error. YAML remains the bootstrap for an empty
  DB.
- **`/metrics` was public and labelled by raw path.** Production now needs
  `TRUST_MEDIATOR_METRICS_TOKEN` (bearer), or an explicit
  `TRUST_MEDIATOR_METRICS_PUBLIC=true` (set in the k8s configmap for
  in-cluster scraping). Latency is labelled by route template, so ids no
  longer leak or create one series each.
- **The escalation webhook put attacker text into Slack mrkdwn unescaped**
  (`<!channel>`, disguised links). All interpolated values are escaped.
- **docker-compose shipped `tmpassword` and published Postgres and Redis.** It
  now refuses to start without `POSTGRES_PASSWORD` and `REDIS_PASSWORD`, Redis
  requires its password, and neither datastore is published. **Upgrade note:**
  an existing Postgres volume keeps its old password. Run `ALTER USER tmuser
  PASSWORD '...'` once, or recreate the volume.
  `deploy.sh` generates both passwords (URL-safe) into `.env`; the dev
  compose binds datastores to loopback; demo scripts raise the rate limit,
  since every keyless dashboard tab shares one bucket; `/health` is exempt.

### Security (data-flow rules, FR-OR-02)

- **Data-flow rules were never loaded, and a missing rule meant allowed.** Each
  output call now reads the caller's tenant `redaction.data_flow_rules`. A
  protected class (always including pii, secret, credential) may flow only to
  destinations a rule names: deny by default (PRD §6.6). Labels and
  destinations are NFKC/casefold-normalised. A malformed section or an
  unreadable policy blocks labelled output. Only the flow rules are
  per-tenant; PII patterns and the entropy threshold stay built-in, so a
  tenant cannot switch redaction off. Shipped policies now permit pii -> user
  only. Labels are bounded (32 items x 64 chars). **Behaviour change:** output
  sent with a protected label and no permitting rule is blocked.
- Policy `memory` and `scanner` sections remain **not enforced**: the
  thresholds come from env settings, mediator-wide. This is now documented in
  the shipped policy.
- The soak `redactor_down` fault patched an instance the pipeline no longer
  used; it now patches the class.

### Security (audit completeness)

- **Admin actions left no audit record.** Policy writes, per-agent updates
  and deletes, rollbacks, and quarantine release and purge, successful or
  refused, now go into a per-tenant control-plane chain that no client
  session id can reach. Admins replay it at `GET /v1/audit/control-plane`.
- **The hash did not cover `agent_id`, `context_id` or `input_provenance`,** so
  they could be edited without breaking the chain. Events now carry
  `hash_version`; v2 hashes every field. Stored rows are migrated as v1 and
  still verify, and a v1 event after a v2 one is reported as a downgrade.
  **Upgrade note:** stop every old replica before new ones serve traffic
  against a shared database. An old replica's rows are stored as v1, and
  landing after a v2 event they read as a downgrade (`chain_valid: false`).
- **A failed audit write left no trace.** It now leaves an `audit_gap` marker
  (`cause: write_failed`) in the session's chain, as a queue overflow already
  did.
- **An unexpected exception in a mediation call was not audited.** It is now
  recorded as `pipeline_exception` in the session's chain before the error
  propagates.
- Gap counters are bounded at 10,000 sessions (the rest fold into one
  system marker), and a flush stops at the first failure, so a long outage
  cannot turn client-chosen session ids into unbounded memory or one failing
  write per session per batch.

### Security (tenant isolation)

- **Memory, audit replay, gRPC and rate limits were not tenant-scoped.** A
  tenant could read another's memory record by id, see and (through its admin)
  release or purge another's quarantine, and replay another's audit chain by
  reusing a session id. gRPC mediated every call as `default`, and two
  tenants' agents with the same id shared one rate-limit bucket. Memory records
  now carry `tenant_id` (migrated in place, existing rows `default`) and every
  query filters on it. Client session ids are namespaced per tenant at the API
  boundary, the default tenant keeping raw ids so existing chains replay. gRPC
  resolves the tenant from the key, and buckets are `tenant:agent:tool`.
  **Behaviour change:** a `session_id` containing `::`, or longer than 128
  characters, is now a 422. `session_id` columns widen from 36 to 200
  characters (migrated on PostgreSQL), because a scoped UUID session
  overflowed 36 and PostgreSQL would have dropped every such audit event.
  Startup migrations now run under the multi-worker advisory lock.
- **Purge accepted any record and always reported success.** It now purges
  only quarantined or rejected records and returns 404 otherwise. Release and
  purge are single conditional updates, so a release racing a purge or a second
  release cannot both succeed.

### Added

- **Research prototype: tool-affordance imperative detector**
  (`benchmarks/affordance_detector/`, optional `[detect]` extra). It flags
  untrusted text that tells the assistant to do something one of *this agent's*
  tools could do. Measured against the literature review's gates
  (`docs/research/DETECTION_LITERATURE_REVIEW.md`), with the threshold frozen on
  external data only (LLMail-Inject, NotInject; MIT). **Result: no-go.**
  Held-out InjecAgent AUC is 0.779 against a 0.85 target, FPR at the frozen
  threshold is 7.6%, and memory recall is 0%. The mood term lowers AUC relative
  to tool similarity alone (0.834). Not wired into the scanner. See
  `benchmarks/results/affordance_detector.md`.

### Security

- **Any data-plane key could administer the mediator (FR-CP-03).** The key an
  agent holds to mediate its own traffic could also rewrite or roll back its
  tenant's policy and release or purge quarantined memory. One injected
  instruction ("add `transfer_funds` to your allow-list", "release memory
  mem-…") needed only that key. Those six routes now require a key from a
  separate set, `TRUST_MEDIATOR_ADMIN_API_KEYS` (or `_FILE`, live-reloading),
  with the same syntax and tenant binding. The sets never substitute for each
  other. **Behaviour change:** a deployment with data-plane keys and no admin
  keys has a closed control plane (403). Keyless development stays open, so
  the demo scripts are unaffected. `PUT /v1/policy` now records the admin
  principal as `created_by`; the body field is accepted and ignored.
- **A "shadow" policy version was enforced live (FR-CP-02).** `shadow: true,
  activate: true` stored an active version flagged as shadow. Nothing
  evaluates policy in shadow, so the data plane enforced it while every
  listing called it shadow. That combination is now a 422. Stage with
  `activate: false` and promote with `POST /v1/policy/rollback/{id}`, which now
  clears the flag.

- **The LangChain guard let tools run when the mediator failed, even with
  `strict=True`.** A timeout, a 401/403 for a revoked key or a 500 arrived as
  `error` and was ignored; `escalate` only logged. A revoked key silently turned
  enforcement off. Under `strict` both now raise. Non-strict stays
  notify-only, as documented.
- **Unknown trust labels made an argument trusted.** `POST /v1/mediate/tool-call`
  dropped any label it did not recognise (`"untrusted"`, `"UNTRUSTED_DATA"`),
  and an unlabelled argument does not trigger FR-PE-04. Unknown labels are now
  a 422, matching gRPC.
- **A failed classifier reported a verified clean scan.** No API key, an HTTP
  error, an unparseable or out-of-range reply, or a missing model all returned
  0.0 and `is_verified=True`. Classifiers now raise `ClassifierUnavailable`, so
  the scanner's §9 path runs: `risky_external` escalates, other untrusted
  content proceeds tagged unverified and audited as `fail_open`.
- **A classifier exception discarded the regex verdict.** Stage 1 and stage 2
  shared one `try`, so when the classifier raised, content the regex had
  *blocked* came back as `allow` (unverified). Stage 2 only runs when the regex
  already scored high, and a hosted classifier can be made to fail, so this was
  attacker-reachable. The regex verdict is now kept and never weakened; a test
  that asserted the old behaviour was corrected.
- **Memory writes treated an unverified scan as clean.** A write whose scan
  could not be verified is now quarantined (§9: side effects fail closed); a
  re-verifying read withholds it without changing its status, so an outage
  does not empty memory. `trust_label` on `/memory/write` is typed (unknown
  values were coerced to `untrusted_data`, downgrading `"RISKY_EXTERNAL"`).
- The orchestrator demo's taint lattice used non-canonical labels (`trusted`,
  `user_input`) and ranked `risky_external` below `untrusted_data`, the reverse
  of the server. It now uses the server's labels and order.
- **Upgrade note:** a server installed without the `[ml]` extra (scikit-learn)
  has no stage-2 model. That used to read as a clean 0.0; it now fails the §9
  way — `risky_external` context escalates and gated memory writes quarantine —
  and logs `heuristic_classifier.no_model` at startup. The Dockerfile and
  `render.yaml` install `[ml]`; bare `pip install trust-mediator[server]` does not.
- `benchmarks.classifier_eval` excludes and counts samples whose classifier
  call failed (and aborts above 2%), instead of a failure either scoring 0.0
  or discarding a paid run.

- **A malformed policy document could authorise every tool.** `PUT /v1/policy`
  checked only that `agents` and `memory` existed, and the engine read an absent
  `allowed_tools` as "no restriction", so `{"agents": {}, "memory": {}}` allowed
  every tool for every agent in the tenant. A string `allowed_tools` became a
  substring match, `untrusted_arg_policy: allow` let untrusted data authorise
  calls (§5.2), and a malformed rate limit or constraint raised an unaudited
  500, which a fail-open client reads as permission. Now:
  - the whole document is validated (`tool_policy/validation.py`): a `default`
    agent is required, every agent is checked, `allow` is rejected, every
    constraint shape is typed, and patterns must compile;
  - the engine denies on any shape it does not recognise, never raises (an
    unexpected error is an audited `mediator_error`), resolves agents by key
    presence so an empty entry cannot inherit `default`, and matches patterns
    with `fullmatch`;
  - an invalid gateway YAML is served as deny-all, and rollback re-validates
    the target version (422 if it no longer passes).
- **`require_approval_for` ignored tool names.** The shipped policies gate
  `send_email` and `initiate_transfer` there, and those calls were allowed
  outright. A tool name on the agent's allow-list now requires approval
  (FR-PE-03).
- Demo policies (`demo-agent/`, `orchestrator/`) used `untrusted_arg_policy:
  allow` for three agents; changed to `require_approval`.

- **Quarantine review endpoints required no authentication.** `GET
  /v1/mediate/memory/quarantined`, `POST …/{id}/release` and `DELETE …/{id}`
  shipped open. Release is the highest-privilege call in the API — it promotes
  content the memory integrity layer quarantined to ACTIVE — so an attacker
  whose poison was caught could re-admit it and name the reviewer via a query
  parameter, and the hash chain would attest to a review that never happened.
- **API keys were compared with `in`**, which short-circuits and leaks the key
  to timing analysis. Now `hmac.compare_digest` over every candidate.
- **The raw API key was used as a rate-limit bucket name**, writing the
  credential into the Redis keyspace where `KEYS`, `MONITOR`, `SLOWLOG` and
  every snapshot expose it. Buckets now carry a principal.
- **gRPC served unauthenticated calls in production** whenever
  `TRUST_MEDIATOR_API_KEYS` was unset, while REST returned 401. Its docstring
  claimed parity that did not exist.

### Added

- **TLS and mTLS** on both listeners (NFR-SEC-03). Production refuses to start
  over plaintext unless `TRUST_MEDIATOR_ALLOW_INSECURE_HTTP` says an ingress is
  terminating it. The guard lives in `create_app()`, not `main()`, because the
  Dockerfile CMD and systemd unit invoke uvicorn directly.
- **API key rotation without a restart** via `TRUST_MEDIATOR_API_KEYS_FILE`
  (NFR-SEC-04). Revoke by *emptying* the file — deleting it is indistinguishable
  from a broken mount, so the last good key set is retained.
- **Any setting can be read from `<VAR>_FILE`**, the seam Docker Compose
  secrets, Kubernetes Secret volumes, Vault Agent and External Secrets all plug
  into. Read once at startup; only API keys reload live.
- **`LICENSE` (Apache-2.0)** — the repository previously advertised MIT in
  `pyproject.toml` while shipping no licence file, so it was legally
  all-rights-reserved. Apache over MIT for the express patent grant and
  defensive termination.
- **`SECURITY.md`** — a disclosure channel, scoped to the trust invariants, and
  listing the documented weak areas so a reporter is not credited with
  rediscovering something already published.
- **AgentDojo testbed** (`benchmarks/testbeds/agentdojo/`) — SCML as a pipeline
  defense, a workspace policy, and a runner. Includes a shim that round-trips
  Gemini's `thought_signature`, without which the tool loop dies on turn two.

### Changed

- **Per-agent policy endpoints** — `GET`/`PUT`/`DELETE /v1/policy/agents/{id}`.
  A mediator can now serve more than one team: previously `PUT /v1/policy`
  replaced the whole document, so the second team's write silently deny-alled
  the first via the `default` fallback. Concurrent updates to different agents
  are safe through optimistic concurrency on `base_version_id`.

- `AuthDep` resolves to a **principal**, never the raw key, so handlers cannot
  leak it into a log line or span and admin actions are attributable. The
  FR-MI-05 release reviewer is now the authenticated caller.
- Keys may be named (`alice:sk-abc123`) so audit records identify a keyholder.

### Fixed

- **The AgentDojo taint extractor read the wrong key.** Content blocks are
  `{"type": "text", "content": …}`; it read `text`, so the tool-output corpus
  was empty on every call and **FR-PE-04 never fired in a single run**. Silent,
  because an empty corpus is indistinguishable from a conversation containing
  nothing untrusted. Every published AgentDojo figure taken before this is
  invalid — see the notice in `benchmarks/results/agentdojo.md`.

### Known issues

- **AgentDojo covers all four suites but two attacks of seventeen**
  (`important_instructions` on all four; `ignore_previous` on banking and
  slack). ASR 29.0% -> 7.3% across 949 cases. Whether that generalises to the
  other fifteen attack types is untested and is the largest remaining unknown.
- **19% of benign task completion is lost** (74.2% -> 59.8%), concentrated in
  domains whose legitimate workflow is "fetch untrusted content and act on it".
  Quote the benign comparison, not the under-attack one: the latter reads as 97%
  retained only because the undefended baseline is already wrecked by hijacking.
- **Taint is inferred, not tracked.** An injection that has the model construct
  a value rather than copy one leaves no textual overlap and evades FR-PE-04.
- `PUT /v1/policy` still replaces the whole document; use
  `PUT /v1/policy/agents/{id}` for routine per-agent administration.
- The injection scanner detects 0 of 1054 InjecAgent attacks; enforcement, not
  detection, is what holds.
- Memory-poisoning ASR is 20.8% storage / 18.8% harm against a <10% target.
- TLS is supported but off in every shipped deployment; Postgres, Redis and
  Kafka connections remain plaintext.
