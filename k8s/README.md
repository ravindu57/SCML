# Kubernetes deployment (PRD §5.4)

Two interchangeable topologies over the same image:

- **Gateway mode** (`gateway/`): a horizontally scaled mediation cluster behind a
  Service, shared by many agent services. Centralised policy, HPA-scaled.
- **Sidecar mode** (`sidecar-example.yaml`): the mediator container co-located in
  each agent Pod; the agent calls `http://localhost:8000`. Lowest latency,
  per-tenant isolation.

## Deploy (gateway)

```bash
kubectl apply -f namespace.yaml
# Create the secret first — never commit real values:
kubectl -n trust-mediator create secret generic trust-mediator-secrets \
  --from-literal=TRUST_MEDIATOR_API_KEYS="sk-$(openssl rand -hex 16)" \
  --from-literal=TRUST_MEDIATOR_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=DATABASE_URL="postgresql+asyncpg://USER:PASS@postgres:5432/trust_mediator"
kubectl apply -f gateway/
```

Prerequisites assumed cluster-side: PostgreSQL, Redis, and (optionally) Kafka
reachable at the addresses in `gateway/configmap.yaml`; a TLS-terminating
ingress in front (set `TRUST_MEDIATOR_HSTS_ENABLED=true` once it is).

## Production notes

- `REDIS_URL` is required in gateway mode — rate limiting is only
  cluster-correct with the Redis backend.
- The Deployment runs non-root, read-only root filesystem, no privilege
  escalation, and has liveness/readiness probes on `/health`.
- PodDisruptionBudget keeps ≥1 replica during node drains (NFR-AVAIL-02).
- Resource requests are sized for the heuristic scanner; raise CPU/memory and
  add a GPU node selector if you serve an ONNX scanner in-pod (PRD §11 suggests
  a separate model-serving tier instead).
