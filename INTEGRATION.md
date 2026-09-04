# Integrating SCML into Your System

SCML protects any LLM agent by sitting between the agent and the world. Five integration paths, from simplest to most control.

---

## 1. Python SDK (recommended)

**Install:**
```bash
pip install trust-mediator
```

**Basic usage — 4 lines of code:**
```python
from scml import SCMLClient

scml = SCMLClient("http://localhost:8000", api_key="sk-...")

# Before any tool call
decision = scml.mediate_tool_call(
    session_id="user-123",
    tool_name="send_email",
    arguments={"to": recipient_email, "body": email_body},
    argument_trust_labels={
        "to": "untrusted_data",   # came from user input
        "body": "trusted",         # you generated this
    },
)
if not decision.allowed:
    raise RuntimeError(decision.reason)  # fail closed
```

**Before processing untrusted content:**
```python
ctx = scml.mediate_context(
    session_id="user-123",
    content=webpage_text,  # from a tool result, fetched document, etc.
)
if ctx.decision == "block":
    print(f"Blocked: {ctx.rationale}")
# ctx.trust_label is now "untrusted_data" — pass it to downstream calls
```

**Before sending a response to the user:**
```python
result = scml.mediate_output(
    session_id="user-123",
    content=agent_response,
)
if not result.allowed:
    # Redact or replace the response
    agent_response = result.redacted_content
```

**Async variant:**
```python
async_scml = AsyncSCMLClient("http://localhost:8000", api_key="sk-...")
decision = await async_scml.mediate_tool_call(...)
```

---

## 2. TypeScript / Node.js SDK

**Install:**
```bash
npm install scml-client
# or from local tarball:
npm pack && npm install ./scml-client-1.0.0.tgz
```

**Usage:**
```javascript
const { SCML } = require('scml-client');
const scml = new SCML({ url: process.env.SCML_URL });

// Before a tool call
const d = await scml.mediateToolCall({
  sessionId: 'user-123',
  tool: 'send_email',
  arguments: { to: recipientEmail, body: emailBody },
  argumentTrustLabels: { to: 'untrusted_data', body: 'trusted' },
});
if (!d.allowed) throw new Error(d.reason);

// Before processing fetched content
const ctx = await scml.mediateContext({
  sessionId: 'user-123',
  content: webpageText,
});
```

---

## 3. LangChain Guard (drop-in callback)

**Install:**
```bash
pip install trust-mediator[langchain]
```

**Usage — wraps any LangChain agent:**
```python
from trust_mediator.integrations.langchain_guard import TrustMediatorGuard

guard = TrustMediatorGuard(
    api_url="http://localhost:8000",
    api_key="sk-...",
    agent_id="my-agent",
    session_id="current-session",
)

# Wrap your agent — all tool calls and outputs are now protected
agent = initialize_agent(tools, llm, callbacks=[guard])

# Run as normal — SCML blocks injection in tool results,
# authorises tool calls, and redacts outbound responses
result = agent.run("Search for recent news and summarise it")
```

**What it intercepts:**
| LangChain event | SCML endpoint | Action |
|---|---|---|
| `on_tool_start` | `/v1/mediate/tool-call` | Authorise or deny the call |
| `on_tool_end` | `/v1/mediate/context` | Scan tool output for injection |
| `on_llm_start` | `/v1/mediate/context` | Scan prompts before LLM sees them |
| `on_chain_end` | `/v1/mediate/output` | Audit the final response |

**Strict mode** (raises on block instead of silently redacting):
```python
guard = TrustMediatorGuard(..., strict=True)
```

---

## 4. HTTP API (any language)

SCML is a REST API. Any language that can make HTTP requests can integrate.

```bash
# Tool call authorization
curl -X POST http://localhost:8000/v1/mediate/tool-call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sk-your-key" \
  -d '{
    "session_id": "user-123",
    "tool_name": "web_search",
    "arguments": {"query": "latest news"},
    "argument_trust_labels": {"query": "trusted"}
  }'
```

**Response:**
```json
{
  "decision": "allow",
  "reason": "Tool 'web_search' authorised by policy",
  "reason_code": "allow"
}
```

**All endpoints:**

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/mediate/context` | POST | Label + scan content |
| `/v1/mediate/tool-call` | POST | Authorise a tool call |
| `/v1/mediate/output` | POST | Redact outbound response |
| `/v1/mediate/memory/write` | POST | Vet a memory write |
| `/v1/mediate/memory/read` | POST | Verify a memory read |
| `/v1/audit/replay/{sessionId}` | GET | Session audit trail |
| `/v1/policy` | GET | Read active policy |
| `/health` | GET | Health check |

Interactive docs: `http://localhost:8000/docs` (Swagger UI)

---

## 5. Embedded (in-process, no HTTP)

Run the pipeline inside your Python process — no network hop.

```bash
pip install "trust-mediator[embedded]"
```

```python
from trust_mediator.core.pipeline import MediationPipeline

pipeline = MediationPipeline()

# Synchronous
result = pipeline.mediate_tool_call(
    session_id="user-123",
    tool_name="send_email",
    arguments={"to": email},
    argument_trust_labels={"to": "untrusted_data"},
)
```

Use this when latency matters and you trust the pipeline to run in the same process. The trade-off: audit logs stay in-process (no shared database, no hash chain across instances).

---

## Configuration

All configuration is via environment variables. No config files required for basic use.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | SQLite | PostgreSQL for production |
| `REDIS_URL` | in-memory | Distributed rate limiting |
| `TRUST_MEDIATOR_API_KEYS` | open | Comma-separated API keys |
| `TRUST_MEDIATOR_API_KEYS_FILE` | — | Path to key file (live-reloadable) |
| `SCANNER_BLOCK_THRESHOLD` | 0.85 | Score above which content is blocked |
| `SCANNER_BACKEND` | heuristic | `heuristic` / `onnx` / `llm` |
| `MEMORY_INTEGRITY_THRESHOLD` | 0.65 | Below this, writes are quarantined |

---

## Integration patterns by agent framework

### CrewAI / AutoGen / Custom agent

```python
from scml import SCMLClient

scml = SCMLClient("http://localhost:8000", api_key="sk-...")

def safe_tool_call(tool_name, arguments, trust_labels, session_id):
    """Wrap every tool call with SCML authorization."""
    decision = scml.mediate_tool_call(
        session_id=session_id,
        tool_name=tool_name,
        arguments=arguments,
        argument_trust_labels=trust_labels,
    )
    if not decision.allowed:
        raise PermissionError(f"SCML denied: {decision.reason}")
    return execute_tool(tool_name, arguments)
```

### LangGraph

```python
from scml import SCMLClient

scml = SCMLClient(...)

def tool_node(state):
    """LangGraph tool node with SCML gating."""
    for tool_call in state["tool_calls"]:
        decision = scml.mediate_tool_call(
            session_id=state["session_id"],
            tool_name=tool_call["name"],
            arguments=tool_call["args"],
            argument_trust_labels=derive_labels(tool_call["args"], state),
        )
        if not decision.allowed:
            return {"error": decision.reason}
    # ... execute tools ...
```

### OpenAI function calling

```python
from scml import SCMLClient
import openai

scml = SCMLClient(...)

def run_agent(user_message, session_id):
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_message}],
        tools=TOOLS,
    )

    for tool_call in response.choices[0].message.tool_calls:
        # Gate before execution
        decision = scml.mediate_tool_call(
            session_id=session_id,
            tool_name=tool_call.function.name,
            arguments=json.loads(tool_call.function.arguments),
            argument_trust_labels=derive_labels(tool_call.function.arguments),
        )
        if decision.allowed:
            result = execute_tool(tool_call)
        else:
            result = f"Blocked by SCML: {decision.reason}"

        # Scan tool output for injection before feeding back to LLM
        ctx = scml.mediate_context(
            session_id=session_id,
            content=str(result),
        )
        # Use ctx.content (potentially redacted) in next LLM call
```

---

## What SCML checks (and what it doesn't)

| SCML checks | SCML does NOT check |
|---|---|
| Is this tool on the agent's allow-list? | Whether the LLM's reasoning is correct |
| Do arguments come from trusted or untrusted sources? | Whether the user's intent is legitimate |
| Does the tool output contain injection patterns? | Whether the output is factually accurate |
| Does a memory write conflict with known controls? | Whether the memory content is useful |
| Does the outbound response leak PII/secrets? | Whether the response is creative enough |

SCML enforces **policy**, not **judgment**. The agent decides what to do; SCML decides whether it's authorised.
