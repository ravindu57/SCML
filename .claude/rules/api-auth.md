---
paths:
  - "trust_mediator/api/**"
  - "trust_mediator/config.py"
  - "trust_mediator/core/tenancy.py"
  - "trust_mediator/modules/tool_policy/rate_limiter.py"
---

# API auth, control-plane authority, tenancy, transport (FR-CP-03, NFR-SEC-03, Sec #6)

- **Every `/v1` route takes `AuthDep`, `CallerDep` or `AdminDep`; each yields a *principal*, never the key.**
  Three FR-MI-05 quarantine routes shipped unauthenticated because they declared
  `pipeline: PipelineDep = None` and a non-defaulted `_: AuthDep` cannot follow a
  defaulted parameter — so auth was dropped instead of the parameters reordered.
  Put dependencies before defaulted parameters.
  `test_api_auth.py::test_all_v1_routes_require_a_key` walks the route tree and
  fails on any `/v1` route that does not resolve `_validate_api_key`; its
  companion `test_at_least_one_route_was_discovered` exists because the first
  version of that walk found nothing and passed vacuously (FastAPI 0.139 nests
  included routers under `_IncludedRouter` rather than flattening them into
  `app.routes`). Auth returns the principal so handlers cannot leak the secret
  into a log line or span, and so admin actions are attributable: the FR-MI-05
  release reviewer is the authenticated caller, not a query parameter. Compare
  keys only with `hmac.compare_digest` over every candidate with no early exit —
  `key in keys` short-circuits and leaks the key to timing analysis. Never put a
  raw key in a rate-limit bucket, log field or audit record; use
  `key_fingerprint`.
- **Control-plane writes take `AdminDep`, never `AuthDep`/`CallerDep` (FR-CP-03).**
  Policy PUT/upsert/delete/rollback and quarantine release/purge resolve
  `_validate_admin` against `TRUST_MEDIATOR_ADMIN_API_KEYS[_FILE]`, a set
  separate from the data-plane keys. Neither set substitutes for the other,
  and data-plane keys with no admin keys means the control plane is *closed*:
  falling back to data-plane keys is the escalation this exists to prevent.
  `test_control_plane_authority.py` pins the exact admin route set; a new
  control-plane write must be added there. A shadow policy version is never
  active (FR-CP-02): nothing evaluates policy in shadow, so an active shadow
  version would be enforced.
- **HTTP rate limiting uses `rate_limit.build_rate_limit_middleware`, not `SlowAPIMiddleware`.** slowapi's
  flat route lookup misses included routers (FastAPI 0.139) and exempted every `/v1` route;
  `test_deploy_defaults.py` fails if any guarded route becomes invisible to the limiter again.
  `env` defaults to production; a policy DB error never falls back to the gateway YAML.
- **Configuring a key file means this deployment authenticates.**
  `TRUST_MEDIATOR_API_KEYS_FILE` is re-read while running so keys rotate without
  a restart (`key_store.py`). Two rules that look like bugs and are not:
  an unreadable file **retains the last good key set** (a transient mount glitch
  must not be a total auth outage — revoke by *emptying* the file, never
  deleting it), and setting the file **suppresses development open-access**
  entirely, or emptying it to revoke everything would instead open the API to
  everyone. Last-good is per *source*: if the configured path changes, the old
  keys are dropped.
- **Production refuses to serve plaintext unless told to.**
  `require_secure_transport()` runs in `create_app()` and `create_grpc_server()`
  — not in `main()`, because the Dockerfile CMD and the systemd unit both invoke
  `uvicorn trust_mediator.api.app:app` directly and never call it. Terminating
  TLS at an ingress is legitimate, so it is an opt-out
  (`TRUST_MEDIATOR_ALLOW_INSECURE_HTTP`), but it must stay an explicit, greppable
  choice rather than the silent default it was. Both listeners honour a keypair;
  set `_TLS_CA_FILE` + `_TLS_REQUIRE_CLIENT_CERT` for mTLS.

- **Tenant is key-bound, never client-supplied.** A key like `acme@ops:sk-...`
  binds the caller to tenant `acme` (see `KeyEntry` / `parse_key_entries_with_tenant`
  in `config.py`); an unqualified key resolves to `TRUST_MEDIATOR_DEFAULT_TENANT`,
  so pre-tenancy deployments behave exactly as before. `CallerDep` yields a
  `Caller(tenant, principal)` and the handler scopes every policy read/write and
  every tool-call mediation by `caller.tenant`. **No request model accepts a
  `tenant_id`/`tenant` field** — the router sets `tenant_id=caller.tenant` on the
  `ToolCallRequest` (`mediate.py`), so a caller cannot claim another company's
  namespace by shaping the body. A tenant with no policy document is **deny-all**
  (`_TENANT_DENY_ALL` in `policy_loader.py`, with an explicit `allowed_tools:
  []` so it is a valid document in its own right), and only the `default`
  tenant falls back to the gateway YAML. `bootstrap_from_yaml` seeds `default`
  only; a per-agent upsert needs an existing tenant document.
  **The same binding covers memory, audit, gRPC and rate limits (Sec #6).**
  Every `MemoryRepository` query filters on `tenant_id`, which routers set from
  `caller.tenant` (never the body), and release/purge use the *admin* key's
  tenant. Session ids pass through `session_for(caller, sid)` /
  `core/tenancy.scoped_session` before reaching the pipeline: the default
  tenant keeps raw ids (old chains replay), others become `tenant::sid`, and a
  client id containing `::` is a 422, or a default caller could write into
  another tenant's audit chain. gRPC resolves the tenant from `x-api-key`
  per call. Rate-limit buckets are `tenant:agent:tool`.
  `test_tenant_isolation.py` pins all of it.

- gRPC transport: `trust_mediator/api/grpc/` (proto + generated stubs + grpc.aio server); enable via `TRUST_MEDIATOR_GRPC_ENABLED`. Regeneration instructions in that package's `__init__.py`. Generated `mediation_pb2*.py` are ruff-excluded — never hand-edit them.
- Rate limiting: Redis-backed cluster-wide when `REDIS_URL` set (`modules/tool_policy/rate_limiter.py`), per-process in-memory otherwise.
