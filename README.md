# SCML — Securing Agentic AI at the Middleware Layer

[![CI](https://github.com/ravindu57/SCML/actions/workflows/ci.yml/badge.svg)](https://github.com/ravindu57/SCML/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-614%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![TypeScript](https://img.shields.io/badge/TS_client-25%20passed-blue)](clients/typescript/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

---

## The problem

LLM agents call external tools, read untrusted documents, and make decisions with real-world consequences. Every integration is a new attack surface: a poisoned memory record can escalate privileges, a malicious tool output can hijack an agent into exfiltrating data, and a prompt injection in a fetched webpage can override the agent's instructions. Existing guardrails focus on the model layer. SCML sits one layer lower — the middleware between the agent and the world — where policy is enforced before any tool call is authorised, before any memory write is persisted, and before any outbound response leaves the process.

## What SCML does

SCML is a **trust-aware context mediation middleware**. Every data path — context, tool call, memory write, outbound output — passes through a pipeline that labels data, scans for injection, enforces a declarative per-agent policy, redacts sensitive content, and logs every decision to a tamper-evident SHA-256 hash chain. Side-effect operations fail closed: an unreachable mediator denies by default, never permits by silence.

```
Data in ──► Trust Label ──► Injection Scan ──► Policy Gate ──► Memory Check ──► Output Redact ──► Audit Log ──► Data out
```

Install the client SDK (14 packages, ~32 MB) and talk to a running mediator, or install the server extras to self-host:

```bash
pip install trust-mediator        # client SDK — talks to the mediator
pip install "trust-mediator[server]"  # run the mediator yourself
```

```python
from scml import SCMLClient

scml = SCMLClient("http://localhost:8000", api_key="sk-...")

# Label and scan untrusted content
ctx = scml.mediate_context(session_id="s1", content=untrusted_document)

# Gate a tool call — untrusted arguments are denied, trusted ones pass
decision = scml.mediate_tool_call(
    session_id="s1",
    tool_name="send_email",
    arguments={"to": ctx.parsed["recipient"]},
    argument_trust_labels={"to": ctx.trust_label},
)
if not decision.allowed:
    raise RuntimeError(decision.reason)  # fail closed
```

TypeScript mirror (zero runtime deps):

```js
const { SCML } = require('scml-client');
const scml = new SCML({ url: process.env.SCML_URL });
const ctx = await scml.mediateContext({ sessionId, content: untrustedDoc });
const d = await scml.mediateToolCall({
  sessionId, tool: 'send_email',
  arguments: { to: ctx.parsed?.recipient },
  argumentTrustLabels: { to: ctx.trustLabel ?? 'untrusted_data' },
});
if (!d.allowed) throw new Error(d.reason);
```

---

## Measured results — benchmarks against external testbeds

SCML is evaluated against **four published attack corpora** with a total of **2,100+ attack cases**. Every number below is reproducible from a committed result file.

### InjecAgent (1,054 cases — ACL Findings 2024, third-party)

| KPI | Measured | Target |
|---|---:|---:|
| Injection ASR | **0.0%** | < 5% |
| ASR reduction vs undefended | **100.0%** | ≥ 90% |
| False-positive rate | **0.0%** | < 3% |
| Utility | **100.0%** | ≥ 90% |
| Latency (p95) | **0.4 ms** | < 400 ms |

Ablation: removing the scanner → 0.0% ASR. Removing tool policy → 100.0% ASR.
**Tool policy is the entire defence.** The scanner detects 0 of 1,054 attacks.

### AgentDojo — all four suites (949 attacked cases)

| Metric | Undefended | SCML | Change |
|---|---:|---:|---:|
| ASR | 29.0% | **7.3%** | 75% reduction |
| Benign utility | 74.2% | 59.8% | 81% retained |

By suite:

| Suite | Undefended ASR | SCML ASR | Benign retained |
|---|---:|---:|---:|
| banking | 49.3% | **0.0%** | 75% |
| workspace | 16.8% | **4.8%** | 94% |
| travel | 30.7% | **7.1%** | 64% |
| slack | 63.8% | **30.5%** | 71% |

### Tool-output sanitizer — closing the slack gap (FR-OR-03)

The slack gap (30.5% ASR) is caused by attacks delivered inside tool results that the model rewrites rather than copies. The deterministic `ToolOutputSanitizer` strips instruction framing from tool outputs before the agent reads them — no LLM call, no new dependencies.

| Arm | ASR | Benign utility |
|---|---:|---:|
| SCML | 33.3% | 52.4% |
| SCML + `--sanitize` | **0.0%** | 52.4% |

105 attacked cases (21 tasks × 5 injections), 122 injected spans stripped, zero benign utility cost. The sanitizer is core-install-safe (structlog optional, no server deps).

### Memory poisoning (48 in-house cases)

| Harm vector | Cases | Harmful after defence |
|---|---:|---:|
| tool | 13 | **0** |
| control-bypass | 22 | **0** |
| output | 5 | 1 |
| informational | 8 | no mediator gate |

Pessimistic harm total: **18.8%** (9/48). The 22 control-bypass cases are inert because the mediator never reads agent memory to decide authorisation (§5.2 invariant).

---

## In 60 seconds

```bash
git clone https://github.com/ravindu57/SCML.git && cd SCML
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
DATABASE_URL="" REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  .venv/bin/uvicorn trust_mediator.api.app:app --port 8000 &
sleep 2

# Run the demo
bash demo.sh
# Or run the full test suite
.venv/bin/pytest tests/ -q          # 614 passed
cd clients/typescript && npm test   # 25 passed
```

Interactive docs appear at **http://localhost:8000/docs**.

### Docker Compose (full stack)

```bash
bash deploy.sh   # builds image, starts Postgres + Redis + mediator
```

### Dashboard

```bash
bash run-demo.sh          # mediator :8000, dashboard :3100, agents :4000/:4100
bash run-demo.sh --stop   # tear down
```

| Dashboard page | URL | Shows |
|---|---|---|
| Command Center | localhost:3100/index.html | Decisions, latency, audit trail |
| Live Agent Demo | localhost:3100/demo.html | Every decision as it lands |
| Tool Policies | localhost:3100/policy.html | Per-agent allow-lists, version history |
| Memory Integrity | localhost:3100/memory.html | Quarantined writes, integrity scores |
| Audit Logs | localhost:3100/audit.html | Full replay with hash-chain verification |

---

## Architecture

| Layer | What it does | PRD ref |
|---|---|---|
| IngressInterceptor | Classifies input provenance | §5.1 |
| TrustRouter | Labels data, propagates taint | §5.2 |
| InjectionScanner | Heuristic + pluggable ML classifier | §6.3 |
| ToolPolicyEngine | Declarative allow-list, rate limits, approval gates | §7 |
| MemoryIntegrityLayer | Quarantine → score → persist/reject | §8 |
| OutputRedactor | PII, secrets, entropy detection | §9 |
| AuditLogger | SHA-256 tamper-evident hash chain, Kafka fan-out | §10 |
| PolicyStore | Versioned YAML policy, hot-reload | §11 |

All config is via `TRUST_MEDIATOR_*` env vars — nothing hardcoded.
Every mediation decision emits an `AuditEvent`. Fail-closed on error for all side effects.

## API surface

| Endpoint | Description |
|---|---|
| `POST /v1/mediate/context` | Label + scan retrieved content |
| `POST /v1/mediate/tool-call` | Authorise a proposed tool call |
| `POST /v1/mediate/memory/write` | Vet a memory write |
| `POST /v1/mediate/memory/read` | Verify a memory read |
| `POST /v1/mediate/output` | Redact + authorise outbound response |
| `GET /v1/audit/replay/{sessionId}` | Full session decision trail |
| `GET /v1/policy` | Read active policy |
| `PUT /v1/policy` | Update policy |

## Production deployment

| Concern | Mechanism |
|---|---|
| Kubernetes | `k8s/` — gateway + sidecar, HPA, PDB |
| Rate limiting | Redis-backed cluster-wide (`REDIS_URL`) or in-process |
| gRPC | `TRUST_MEDIATOR_GRPC_ENABLED=true` (port 50051) |
| Audit pipeline | Kafka fan-out + SIEM webhook; DB chain authoritative |
| TLS / mTLS | `TRUST_MEDIATOR_TLS_*` env vars, production refuses plaintext by default |
| Auth | `TRUST_MEDIATOR_API_KEYS` / `_FILE`, HMAC-compared, live-rotatable |
| CI | ruff + pytest 3.11/3.12 with test-count floor + Docker build smoke |

## Running tests

```bash
DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  .venv/bin/pytest tests/ -q
# Expected: 614 passed

cd clients/typescript && npm test
# Expected: 25 passed
```

## License

[Apache License 2.0](LICENSE) — includes patent grant and defensive termination.
