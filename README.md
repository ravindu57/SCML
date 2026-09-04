<img width="1672" height="940" alt="image" src="https://github.com/user-attachments/assets/967bb837-b8e1-4eaa-a9aa-811d73cef54c" /><div align="center">

```
█▀▀ █▀▀ █▀█▀█ █  
▀▀▓ ▓░  █   ▓ ▓░ 
▀▀▀ ▀▀▀ ▀   ▀ ▀▀▀
```

# SCML — Securing Agentic AI at the Middleware Layer

```
<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/5d98eb78-b71f-427c-ba7d-db240fd13e82" />



```

**Trust-aware context mediation for LLM agents, RAG pipelines, and tool-calling systems.**

[![CI](https://github.com/ravindu57/SCML/actions/workflows/ci.yml/badge.svg)](https://github.com/ravindu57/SCML/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-614%20passed-brightgreen?style=flat-square)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![TypeScript](https://img.shields.io/badge/TS_client-25%20passed-3178C6?style=flat-square&logo=typescript&logoColor=white)](clients/typescript/)
[![License](https://img.shields.io/badge/license-Apache%202.0-orange?style=flat-square)](LICENSE)

</div>

---

## The Problem

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  LLM agents call tools, read documents, store memories.             │
  │  Every integration is a new attack surface.                         │
  │                                                                     │
  │  • Poisoned memory     → privilege escalation                       │
  │  • Malicious tool out  → agent hijacked, data exfiltrated           │
  │  • Prompt injection    → agent instructions overridden              │
  │                                                                     │
  │  Existing guardrails secure the MODEL.                              │
  │  SCML secures the MIDDLEWARE.                                       │
  └─────────────────────────────────────────────────────────────────────┘
```

LLM agents call external tools, read untrusted documents, and make decisions with real-world consequences. Every integration is a new attack surface. Existing guardrails focus on the model layer. **SCML sits one layer lower** — the middleware between the agent and the world — where policy is enforced before any tool call is authorised, before any memory write is persisted, and before any outbound response leaves the process.

---

## What SCML Does

SCML is a **trust-aware context mediation middleware**. Every data path passes through a pipeline that labels data, scans for injection, enforces declarative per-agent policy, redacts sensitive content, and logs every decision to a tamper-evident SHA-256 hash chain.

```
                          SCML Mediation Pipeline
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  Trust   │──▶│ Injection│──▶│  Policy  │──▶│  Memory  │──▶│  Output  │──▶│  Audit   │
  │  Label   │   │  Scan    │   │   Gate   │   │  Check   │   │  Redact  │   │   Log    │
  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
       │              │              │              │              │              │
       ▼              ▼              ▼              ▼              ▼              ▼
   Propagate      Detect &       Allow / Deny   Quarantine    Strip PII    SHA-256
    taint         block inject   per-agent       & score       & secrets    hash chain
```

Side-effect operations **fail closed**: an unreachable mediator denies by default, never permits by silence.

### Install

```bash
pip install trust-mediator            # client SDK — 14 packages, ~32 MB
pip install "trust-mediator[server]"  # run the mediator yourself
```

### Python SDK

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

### TypeScript SDK (zero runtime deps)

```typescript
const { SCML } = require('scml-client');
const scml = new SCML({ url: process.env.SCML_URL });

const ctx = await scml.mediateContext({ sessionId, content: untrustedDoc });
const d   = await scml.mediateToolCall({
  sessionId, tool: 'send_email',
  arguments: { to: ctx.parsed?.recipient },
  argumentTrustLabels: { to: ctx.trustLabel ?? 'untrusted_data' },
});
if (!d.allowed) throw new Error(d.reason);
```

---

## MCP Server (Claude Desktop / Cursor / Windsurf)

![MCP Server](https://img.shields.io/badge/MCP-Server-8B5CF6?style=flat-square&logo=modelcontextprotocol&logoColor=white)

SCML exposes its full security pipeline as **MCP tools** — any MCP-compatible client gets tool-call authorization, injection scanning, memory quarantine, and PII redaction with zero code changes.

```
  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
  │  LLM Client  │──────▶│  SCML MCP    │──────▶│  Your Tool   │
  │  (Claude,    │       │  Server      │       │  (API, DB,   │
  │   Cursor)    │◀──────│              │◀──────│   file, etc) │
  └──────────────┘       │  • authorize │       └──────────────┘
                         │  • scan      │
                         │  • quarantine│
                         │  • redact    │
                         └──────────────┘
```

### Install

```bash
pip install trust-mediator mcp
```

### Run

```bash
SCML_URL=http://localhost:8000 SCML_API_KEY=sk-your-key \
  python -m trust_mediator.mcp.server
```

### Claude Desktop config

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scml": {
      "command": "python",
      "args": ["-m", "trust_mediator.mcp.server"],
      "env": {
        "SCML_URL": "http://localhost:8000",
        "SCML_API_KEY": ""
      }
    }
  }
}
```

### Available MCP tools

| Tool | What it does |
|---|---|
| `authorize_tool_call` | Check if a tool call is allowed by policy |
| `scan_content` | Detect prompt injection in external content |
| `check_memory_write` | Score a memory write for integrity |
| `redact_output` | Strip PII and secrets from responses |
| `get_audit_trail` | Replay session decisions with hash chain |
| `get_policy` | Show active security policy |
| `health_check` | Verify SCML is running |

---

## Benchmarks

SCML is evaluated against **four published attack corpora** with **2,100+ attack cases**. Every number is reproducible from a committed result file.

### InjecAgent — 1,054 third-party cases (ACL Findings 2024)

<table>
<tr><th>KPI</th><th align="right">Measured</th><th align="right">Target</th><th></th></tr>
<tr><td>Injection ASR</td><td align="right"><b>0.0%</b></td><td align="right">&lt; 5%</td><td>✅</td></tr>
<tr><td>ASR reduction vs undefended</td><td align="right"><b>100.0%</b></td><td align="right">≥ 90%</td><td>✅</td></tr>
<tr><td>False-positive rate</td><td align="right"><b>0.0%</b></td><td align="right">&lt; 3%</td><td>✅</td></tr>
<tr><td>Utility</td><td align="right"><b>100.0%</b></td><td align="right">≥ 90%</td><td>✅</td></tr>
<tr><td>Latency (p95)</td><td align="right"><b>0.4 ms</b></td><td align="right">&lt; 400 ms</td><td>✅</td></tr>
</table>

> **Ablation truth:** Removing the scanner → 0.0% ASR. Removing tool policy → 100.0% ASR.
> **Tool policy is the entire defence.** The scanner detects 0 of 1,054 attacks.

### AgentDojo — All Four Suites (949 attacked cases)

<table>
<tr><th>Metric</th><th align="right">Undefended</th><th align="right">SCML</th><th align="right">Change</th></tr>
<tr><td>Attack Success Rate</td><td align="right">29.0%</td><td align="right"><b>7.3%</b></td><td align="right">75% reduction</td></tr>
<tr><td>Benign Utility</td><td align="right">74.2%</td><td align="right"><b>59.8%</b></td><td align="right">81% retained</td></tr>
</table>

<table>
<tr><th>Suite</th><th align="right">Undefended</th><th align="right">SCML</th><th align="right">Benign Retained</th></tr>
<tr><td><code>banking</code></td><td align="right">49.3%</td><td align="right"><b>0.0%</b></td><td align="right">75%</td></tr>
<tr><td><code>workspace</code></td><td align="right">16.8%</td><td align="right"><b>4.8%</b></td><td align="right">94%</td></tr>
<tr><td><code>travel</code></td><td align="right">30.7%</td><td align="right"><b>7.1%</b></td><td align="right">64%</td></tr>
<tr><td><code>slack</code></td><td align="right">63.8%</td><td align="right"><b>30.5%</b></td><td align="right">71%</td></tr>
</table>

### Tool-Output Sanitizer — Closing the Slack Gap (FR-OR-03)

The slack gap (30.5% ASR) is caused by attacks delivered inside tool results that the model rewrites rather than copies. The deterministic `ToolOutputSanitizer` strips instruction framing before the agent reads them — no LLM call, no new dependencies.

<table>
<tr><th>Arm</th><th align="right">ASR</th><th align="right">Benign Utility</th></tr>
<tr><td>SCML</td><td align="right">33.3%</td><td align="right">52.4%</td></tr>
<tr><td>SCML + <code>--sanitize</code></td><td align="right"><b>0.0%</b></td><td align="right">52.4%</td></tr>
</table>

> 105 attacked cases (21 tasks × 5 injections), **122 injected spans stripped**, zero benign utility cost.

### Memory Poisoning (48 in-house cases)

<table>
<tr><th>Harm Vector</th><th align="right">Cases</th><th align="right">Harmful After Defence</th></tr>
<tr><td><code>tool</code></td><td align="right">13</td><td align="right"><b>0</b></td></tr>
<tr><td><code>control-bypass</code></td><td align="right">22</td><td align="right"><b>0</b></td></tr>
<tr><td><code>output</code></td><td align="right">5</td><td align="right">1</td></tr>
<tr><td><code>informational</code></td><td align="right">8</td><td align="right">no mediator gate</td></tr>
</table>

> Pessimistic harm total: **18.8%** (9/48). The 22 control-bypass cases are inert because the mediator never reads agent memory to decide authorisation.

---

## Quick Start

```bash
git clone https://github.com/ravindu57/SCML.git && cd SCML
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
DATABASE_URL="" REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  .venv/bin/uvicorn trust_mediator.api.app:app --port 8000 &
sleep 2
bash demo.sh                                        # run the demo
.venv/bin/pytest tests/ -q                           # 614 passed
cd clients/typescript && npm test                    # 25 passed
```

Interactive docs: **http://localhost:8000/docs**

### Docker Compose

```bash
bash deploy.sh    # builds image, starts Postgres + Redis + mediator
```

### Dashboard

```bash
bash run-demo.sh          # mediator :8000, dashboard :3100, agents :4000/:4100
bash run-demo.sh --stop   # tear down
```

<table>
<tr><th>Page</th><th>URL</th><th>Shows</th></tr>
<tr><td>Command Center</td><td><code>localhost:3100/index.html</code></td><td>Decisions, latency, audit trail</td></tr>
<tr><td>Live Agent Demo</td><td><code>localhost:3100/demo.html</code></td><td>Every decision as it lands</td></tr>
<tr><td>Tool Policies</td><td><code>localhost:3100/policy.html</code></td><td>Per-agent allow-lists, version history</td></tr>
<tr><td>Memory Integrity</td><td><code>localhost:3100/memory.html</code></td><td>Quarantined writes, integrity scores</td></tr>
<tr><td>Audit Logs</td><td><code>localhost:3100/audit.html</code></td><td>Full replay with hash-chain verification</td></tr>
</table>

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                        SCML System Architecture                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
  │   │   Python    │     │  TypeScript  │     │    gRPC     │              │
  │   │    SDK      │     │     SDK      │     │   Client    │              │
  │   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘               │
  │          │                    │                    │                    │
  │          └────────────────────┼────────────────────┘                    │
  │                               │                                         │
  │                        ┌──────▼──────┐                                  │
  │                        │   FastAPI   │  /v1/mediate/*                   │
  │                        │   + gRPC    │  /v1/audit/*                     │
  │                        └──────┬──────┘                                  │
  │                               │                                         │
  │   ┌───────────────────────────▼───────────────────────────┐             │
  │   │              Mediation Pipeline                       │             │
  │   │                                                       │             │
  │   │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐          │             │
  │   │  │ Trust  │→│Inject. │→│ Policy │→│Memory  │          │             │
  │   │  │ Router │ │Scanner │ │ Engine │ │Integrity│         │             │
  │   │  └────────┘ └────────┘ └────────┘ └────────┘          │             │
  │   │       │                            │                  │             │
  │   │       └────────────┬───────────────┘                  │             │
  │   │                    ▼                                  │             │
  │   │            ┌──────────────┐     ┌──────────────┐      │             │
  │   │            │   Output     │     │    Audit     │      │             │
  │   │            │   Redactor   │     │    Logger    │      │             │
  │   │            └──────────────┘     └──────────────┘      │             │
  │   └───────────────────────────────────────────────────────┘             │
  │                               │                                         │
  │                    ┌──────────▼──────────┐                              │
  │                    │   PostgreSQL / SQLite│                             │
  │                    │   + Redis (optional) │                             │
  │                    └─────────────────────┘                              │
  └─────────────────────────────────────────────────────────────────────────┘
```

<table>
<tr><th>Layer</th><th>What It Does</th><th>PRD</th></tr>
<tr><td><code>IngressInterceptor</code></td><td>Classifies input provenance</td><td>§5.1</td></tr>
<tr><td><code>TrustRouter</code></td><td>Labels data, propagates taint</td><td>§5.2</td></tr>
<tr><td><code>InjectionScanner</code></td><td>Heuristic + pluggable ML classifier</td><td>§6.3</td></tr>
<tr><td><code>ToolPolicyEngine</code></td><td>Declarative allow-list, rate limits, approval gates</td><td>§7</td></tr>
<tr><td><code>MemoryIntegrityLayer</code></td><td>Quarantine → score → persist/reject</td><td>§8</td></tr>
<tr><td><code>OutputRedactor</code></td><td>PII, secrets, entropy detection</td><td>§9</td></tr>
<tr><td><code>AuditLogger</code></td><td>SHA-256 tamper-evident hash chain, Kafka fan-out</td><td>§10</td></tr>
<tr><td><code>PolicyStore</code></td><td>Versioned YAML policy, hot-reload</td><td>§11</td></tr>
</table>

All config via `TRUST_MEDIATOR_*` env vars — nothing hardcoded. Every decision emits an `AuditEvent`.

---

## API Surface

<table>
<tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
<tr><td><code>POST</code></td><td><code>/v1/mediate/context</code></td><td>Label + scan retrieved content</td></tr>
<tr><td><code>POST</code></td><td><code>/v1/mediate/tool-call</code></td><td>Authorise a proposed tool call</td></tr>
<tr><td><code>POST</code></td><td><code>/v1/mediate/memory/write</code></td><td>Vet a memory write</td></tr>
<tr><td><code>POST</code></td><td><code>/v1/mediate/memory/read</code></td><td>Verify a memory read</td></tr>
<tr><td><code>POST</code></td><td><code>/v1/mediate/output</code></td><td>Redact + authorise outbound response</td></tr>
<tr><td><code>GET</code></td><td><code>/v1/audit/replay/{sessionId}</code></td><td>Full session decision trail</td></tr>
<tr><td><code>GET</code></td><td><code>/v1/policy</code></td><td>Read active policy</td></tr>
<tr><td><code>PUT</code></td><td><code>/v1/policy</code></td><td>Update policy</td></tr>
</table>

---

## Production Deployment

> **Full integration guide:** [`INTEGRATION.md`](INTEGRATION.md) — Python SDK, TypeScript SDK, LangChain guard, HTTP API, embedded mode, and examples for CrewAI, LangGraph, and OpenAI function calling.

<table>
<tr><th>Concern</th><th>Mechanism</th></tr>
<tr><td>Kubernetes</td><td><code>k8s/</code> — gateway + sidecar, HPA, PDB</td></tr>
<tr><td>Rate Limiting</td><td>Redis-backed cluster-wide (<code>REDIS_URL</code>) or in-process</td></tr>
<tr><td>gRPC</td><td><code>TRUST_MEDIATOR_GRPC_ENABLED=true</code> (port 50051)</td></tr>
<tr><td>Audit Pipeline</td><td>Kafka fan-out + SIEM webhook; DB chain authoritative</td></tr>
<tr><td>TLS / mTLS</td><td><code>TRUST_MEDIATOR_TLS_*</code> env vars, production refuses plaintext</td></tr>
<tr><td>Auth</td><td><code>TRUST_MEDIATOR_API_KEYS</code> / <code>_FILE</code>, HMAC-compared, live-rotatable</td></tr>
<tr><td>CI</td><td>ruff + pytest 3.11/3.12 with test-count floor + Docker build smoke</td></tr>
</table>

---

## Tests

```bash
DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  .venv/bin/pytest tests/ -q            # 614 passed

cd clients/typescript && npm test       # 25 passed
```

---

<div align="center">

**Apache License 2.0** — includes patent grant and defensive termination.

[<img src="https://img.shields.io/badge/GitHub-ravindu57%2FSCML-181717?style=for-the-badge&logo=github" alt="GitHub" />](https://github.com/ravindu57/SCML)

</div>
