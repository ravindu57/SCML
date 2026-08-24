# Changelog

Notable changes to TrustMediator / SCML. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**On the version number.** `__version__` reads `1.0.0`, and that overstates
things: there are no releases, no tags, and no backports — only `main`. Treat
the project as pre-1.0 until a tagged release exists, as `SECURITY.md` says.
This file starts at the point one was first kept; earlier history is in the
commit log.

## [Unreleased]

### Security

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

- **AgentDojo covers all four suites but one attack of seventeen.** ASR
  29.0% -> 7.3% across 949 cases. Whether that generalises to the other sixteen
  attack types is untested and is the largest remaining unknown.
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
- Memory-poisoning ASR is 33.3% storage / 18.8% harm against a <10% target.
- TLS is supported but off in every shipped deployment; Postgres, Redis and
  Kafka connections remain plaintext.
