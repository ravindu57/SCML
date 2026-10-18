# Deploying SCML on a single Docker host

This is the chosen deployment target (backlog #23): one Linux server running
`docker compose`, with Caddy terminating TLS in front of the mediator.

```
internet ──443/80──> caddy ──(compose network)──> trust-mediator:8000 ──> postgres, redis
```

Only Caddy publishes ports. The mediator, Postgres and Redis are reachable on
the compose network only.

## What it does not cover

- **Postgres, Redis and Kafka connections are plaintext** on the compose
  network. That is acceptable on one host. It is not acceptable once they move
  to separate machines (see CLAUDE.md, "Known gaps").
- **Single host, so no high availability.** `restart: unless-stopped` covers
  crashes, not host loss. Back up Postgres (below).
- **Some tests have only run on SQLite.** The PostgreSQL-only migrations
  (session-id widening, `IF NOT EXISTS` guards) have not run against a real
  PostgreSQL in this repository's tests yet. Run the test suite against the
  compose Postgres once before relying on them (see step 6).

## 1. Server prerequisites

- Ubuntu 22.04/24.04 (or similar) with Docker Engine and the compose plugin
  (v2.24 or later, for `!reset`).
- A DNS A/AAAA record for your domain (e.g. `scml.example.com`) pointing at
  the server.
- A firewall allowing only 22, 80 and 443:

  ```bash
  sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443
  sudo ufw enable
  ```

  Docker writes its own iptables rules for published ports. That is why the
  mediator's port is unpublished in `docker-compose.prod.yml` rather than
  merely firewalled.

## 2. Configuration (`.env` on the server)

Copy `.env.example` to `.env`, then set at least the following. Generate every
secret with `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.
The values are interpolated into URLs, so use URL-safe values only.

| Variable | Value |
|---|---|
| `SCML_DOMAIN` | `scml.example.com` |
| `TRUST_MEDIATOR_ENV` | `production` |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD` | generated (compose refuses to start without them) |
| `TRUST_MEDIATOR_API_KEYS` | data-plane keys, one per agent or workflow: `acme@ops:sk-...` |
| `TRUST_MEDIATOR_ADMIN_API_KEYS` | separate admin keys for policy and quarantine: `acme@secops:sk-...` |
| `TRUST_MEDIATOR_ALLOW_INSECURE_HTTP` | `true` (already set in compose): TLS ends at Caddy |
| `TRUST_MEDIATOR_METRICS_TOKEN` | generated, if anything scrapes `/metrics` |
| `TRUST_MEDIATOR_CORS_ORIGINS` | only if a browser front-end calls the API |

Notes:
- With no admin keys, the control plane is closed. Policy writes return 403.
- `deploy.sh` generates the two datastore passwords if they are missing. It
  targets a bare host and also installs Docker. Read it before running it.
- **Keep `.env` mode 600.** For rotation without restarts, point
  `TRUST_MEDIATOR_API_KEYS_FILE` / `TRUST_MEDIATOR_ADMIN_API_KEYS_FILE` at
  files instead (see `.env.example`).

## 3. Start

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Caddy fetches a certificate on first start, which needs DNS and port 80 to be
working. `docker logs trust-mediator-caddy` shows the ACME exchange.

## 4. Load policy

Policy writes need an admin key. Every agent you have not configured falls
back to `default`, which is deny-all.

```bash
curl -fsS -X PUT "https://$SCML_DOMAIN/v1/policy" \
  -H "X-API-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d "{\"policy_data\": $(python3 -c 'import json,yaml;print(json.dumps(yaml.safe_load(open("policies/default_policy.yaml"))))')}"
```

After that, use `PUT /v1/policy/agents/{id}` for routine per-agent changes.
Every change is recorded in the control-plane audit chain:
`GET /v1/audit/control-plane` with an admin key.

## 5. Smoke test

```bash
SCML_URL="https://$SCML_DOMAIN" SCML_API_KEY="$DATA_KEY" ./scripts/smoke.sh
```

It checks:
- `/health`
- a `/v1` call without a key returns 401
- a data-plane key can mediate
- a data-plane key cannot write policy (403)
- `/metrics` is not public
- the HSTS header is present

It writes no policy. It was verified against a production-configured mediator
locally (plain HTTP, so the HSTS check was skipped there).

## 6. Before the first real traffic: run the tests against PostgreSQL

On the server, or on any machine with Docker:

```bash
docker compose up -d postgres redis
DATABASE_URL="postgresql+asyncpg://tmuser:$POSTGRES_PASSWORD@localhost:5432/trust_mediator" \
  TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  TRUST_MEDIATOR_ADMIN_API_KEYS="" .venv/bin/pytest tests/ -q
```

This needs the dev compose file's loopback port, or a temporary
`127.0.0.1:5432:5432` mapping. Without it the PostgreSQL-only code paths are
still unverified.

## Upgrading an existing deployment

- **Datastore passwords.** An existing Postgres volume keeps the password it
  was created with. Before switching to a generated one, run
  `ALTER USER tmuser PASSWORD '<new>'`.
- **Audit `hash_version`.** Stop every old mediator replica before new ones
  write events. Old replicas' rows after v2 events read as a downgrade
  (`chain_valid: false`).
- **Admin keys.** Deployments with data-plane keys must add admin keys before
  writing policy.
- **Session ids** containing `::` or longer than 128 characters are now
  rejected with 422.
- **Rate limits** now actually apply (they never did, see CHANGELOG). Size
  `TRUST_MEDIATOR_RATE_LIMIT` (default `200/minute` per key, or per client IP
  without one) for your agents.

## Backups

```bash
docker exec trust-mediator-postgres pg_dump -U tmuser -Fc trust_mediator > scml-$(date +%F).dump
```

The database holds policy versions, memory records and the audit hash chain.
Restoring an older dump rolls all three back together, which keeps them
consistent, but loses the audit events written since the dump.
