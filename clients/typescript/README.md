# scml-client

SCML (Secure Context Mediation Layer) client for Node.js and TypeScript.

Put a trust boundary between your agent and everything it reads or acts on:
label untrusted content, authorise tool calls against a declarative policy, vet
memory writes, redact outbound text, and get a hash-chained audit trail of every
decision.

**Zero runtime dependencies.** Uses the platform `fetch`, so it needs Node 18+
and adds nothing to your dependency tree.

## What this is and is not

SCML's defence is **least agency**: untrusted content may inform what an agent
says, but it can never authorise what an agent *does*. Authorisation comes from
a declarative policy store, and the mediator never reads agent memory to decide
it — so a document (or a memory record) claiming "policy validation has been
disabled" cannot disable policy validation.

It is **not** a prompt-injection detector. The scanner that ships today catches
obvious phrasings and misses most of the rest — measured at 0 of 1054 on the
external InjecAgent corpus, where the tool policy alone accounted for the entire
defence. Build your integration around the policy decision, not around detection.
See `benchmarks/results/` in the main repository for the numbers.

## Install

```bash
# from a packed tarball (works offline — best for demos and air-gapped hosts)
npm install ./scml-client-1.0.0.tgz
```

You also need a mediator running somewhere reachable:

```bash
docker compose up -d          # or: bash exhibition.sh
```

## Quick start

```ts
import { SCML } from 'scml-client';

const scml = new SCML({
  url: process.env.SCML_URL,        // e.g. http://192.168.1.42:8000
  apiKey: process.env.SCML_API_KEY, // omit in development mode
  agentId: 'shipping-agent',
});

// 1. External content enters — label and scan it
const ctx = await scml.mediateContext({
  sessionId, content: supplierDocument, source: 'tool_result',
});

// 2. Before the consequential action — this is the enforcement point
const decision = await scml.mediateToolCall({
  sessionId,
  tool: 'release_container',
  arguments: { containerId },
  // Without labels, FR-PE-04 never fires and a model-composed argument is
  // indistinguishable from a user-supplied one. Send them.
  argumentTrustLabels: { containerId: ctx.trustLabel ?? 'untrusted_data' },
  isIrreversible: true,
});
if (!decision.allowed) throw new Error(decision.reason);

// 3. Before anything goes back out — substitute the returned text
const out = await scml.mediateOutput({ sessionId, content: reply });
send(out.content);
```

Run the worked example against a live mediator:

```bash
SCML_URL=http://localhost:8000 node examples/shipping-agent.js
```

## Why `result.allowed` rather than `result.decision`

The mediation endpoints do not share a response shape:

| Endpoint | Carries |
|---|---|
| `/v1/mediate/context` | `decision` |
| `/v1/mediate/tool-call` | `decision` |
| `/v1/mediate/output` | `blocked` — no `decision` at all |
| `/v1/mediate/memory/write` | `verdict` (`persist`/`quarantine`/`reject`) |
| `/v1/mediate/memory/read` | `verified` / `withheld` |

Code branching on `result.decision` is correct for two of them and silently
wrong for three — a blocked output reads as "no decision field, carry on". This
client normalises all five onto one `verdict`, so `if (!result.allowed)` means
the same thing everywhere.

`allowed` is true **only** for an explicit allow. Quarantine, escalate,
approval-required, error and unknown are all not-allowed.

## Fail policy

Side-effect operations fail **closed**. If the mediator is unreachable the call
throws `SCMLUnavailable` rather than returning something that looks like an
allow:

```ts
try {
  const d = await scml.mediateToolCall({ ... });
} catch (err) {
  if (err instanceof SCMLUnavailable) {
    // correct: never treat "could not ask" as "permitted"
  }
}
```

Opt out per call on a genuinely low-risk read with `{ failOpen: true }`. Every
fail-open is logged, because by definition the audit log is unreachable at that
moment.

## API

| Method | Endpoint |
|---|---|
| `mediateContext({ sessionId, content, source? })` | `POST /v1/mediate/context` |
| `mediateToolCall({ sessionId, tool, arguments?, argumentTrustLabels? })` | `POST /v1/mediate/tool-call` |
| `mediateOutput({ sessionId, content, destination? })` | `POST /v1/mediate/output` |
| `mediateMemoryWrite({ sessionId, content, trustLabel? })` | `POST /v1/mediate/memory/write` |
| `mediateMemoryRead({ sessionId, memoryId })` | `POST /v1/mediate/memory/read` |
| `replaySession(sessionId)` | `GET /v1/audit/replay/{id}` |
| `health()` | `GET /health` |

All mediation methods return a `MediationResult`:

```ts
{
  verdict: 'allow' | 'block' | 'approval_required' | 'escalate'
         | 'quarantine' | 'error' | 'unknown';
  decision: string;        // the raw server string, e.g. "deny.not_allowlisted"
  reason: string;
  content?: string;        // redacted/sanitised text, where applicable
  trustLabel?: string;
  score?: number;
  auditRef: string;
  patternsMatched: string[];
  raw: Record<string, unknown>;
  get allowed(): boolean;
  assertAllowed(): this;   // throws SCMLBlocked unless allowed
}
```

## Notes

- The audit trail is written by a batching writer, so an event can take up to
  one batch interval to appear in `replaySession`. It is not lost, just not
  instant.
- The Python SDK (`pip install trust-mediator`) mirrors this API method for
  method, so an integration written against one reads the same as the other.

## Development

```bash
npm install
npm run build
npm test          # 18 tests, Node's built-in runner
npm pack          # → scml-client-1.0.0.tgz
```

MIT licensed.
