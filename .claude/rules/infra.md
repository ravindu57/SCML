---
paths:
  - "Dockerfile"
  - "docker-compose*.yml"
  - "k8s/**"
  - "nginx/**"
  - "deploy/**"
  - "*.sh"
  - "scripts/**"
  - "trust-mediator.service"
  - ".github/**"
  - "docs/DEPLOY_VPS.md"
  - "trust_mediator/config.py"
---

# Deployment, TLS, secrets, availability (NFR-SEC-03/04, NFR-AVAIL-01)

- Deploy: `k8s/` (gateway + sidecar), `.github/workflows/ci.yml` (lint, 3.11/3.12 tests, docker smoke).

- **TLS (NFR-SEC-03) is now supported but not on by default, and not everywhere.**
  Both listeners accept a keypair and optional client-cert verification, and
  production refuses plaintext without an explicit opt-out. But every shipped
  deployment (`docker-compose.yml`, `k8s/`) still sets
  `TRUST_MEDIATOR_ALLOW_INSECURE_HTTP=true` and terminates at nginx/Ingress —
  nginx itself listens on :80 with no certificate configured. Connections to
  **Postgres, Redis and Kafka are still plaintext** and have no TLS settings at
  all. So "SCML supports TLS" is true; "SCML is deployed over TLS" is not.
  There is no test on `main` against a real certificate — `test_tls.py` asserts
  configuration and wiring, not a completed handshake. A real handshake/mTLS
  test exists, unmerged, on branch `rescue/tls-by-default`; it needs
  `cryptography`, which is not a declared dependency.
- **Secrets management (NFR-SEC-04): file sources exist, rotation only for API
  keys.** Any setting can be read from `<VAR>_FILE` (`FileSecretSource` in
  `config.py`), which is the seam Docker Compose secrets, Kubernetes Secret
  volumes, Vault Agent and External Secrets all plug into. That is **read once
  at startup** — DB and Redis pools are built from those values, so rotating
  `DATABASE_URL_FILE` on disk does nothing until restart. Only
  `TRUST_MEDIATOR_API_KEYS_FILE` reloads live, and it is deliberately excluded
  from the generic mechanism (`_NO_FILE_SOURCE`) so one path is not read by two
  sources with different lifetimes. Still missing: no rotation for anything but
  API keys, no integration with a secrets *API* (only files), and the k8s
  manifests still pass keys via `envFrom: secretRef`, which cannot rotate —
  env vars from a Secret are snapshotted at pod start, and only a
  volume-mounted Secret refreshes in place. That volume is written into
  `k8s/gateway/deployment.yaml` but left commented out, because enabling it
  switches the auth source and needs three coordinated edits.
- ~~NFR-AVAIL-01 unmeasured~~ — **measured**: `benchmarks/soak/` injects six
  dependency failures into a live pipeline; committed result
  `benchmarks/results/soak.md` shows 100.000% over 10,666 calls (target 99.9%).
  Availability there means *a decision was rendered*, denials included — §9
  makes a deny during an outage correct behaviour, and scoring it as downtime
  would reward failing open. In-process only: no load balancer, network
  partition, disk-exhaustion or OOM coverage, so it is **not** a production
  uptime SLO. Re-run it after touching any fail-open/fail-closed path; its
  first run found a §9 escape the unit tests missed.
