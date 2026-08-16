# SCML Demo Agent

A small autonomous freight-operations agent with SCML trust mediation on every
edge. Type a prompt injection into the chat and watch the action get stopped.

Built to run on a laptop that has nothing installed: **no database, no Docker,
no API key required.** Node 18+ and the mediator, that's it.

```
┌──────────────┐   1. mediate context    ┌─────────────┐
│  chat (you)  │ ──────────────────────▶ │             │
└──────────────┘                         │             │
       │                                 │    SCML     │
       ▼  agent picks a tool             │  mediator   │
┌──────────────┐   2. authorise call     │             │
│    agent     │ ──────────────────────▶ │  (policy +  │
└──────────────┘                         │   audit)    │
       │  runs only if allowed           │             │
       ▼                                 │             │
┌──────────────┐   3. mediate output     │             │
│    reply     │ ──────────────────────▶ │             │
└──────────────┘                         └─────────────┘
```

## What it demonstrates

**Least agency, not detection.** The injection is read, believed, and acted on.
The agent genuinely tries to call `dispatch_container`. What stops it is step 2,
where authority comes from a policy store that never reads your message.

Run the three attack scenarios and watch the `ingress` row: the scanner catches
the blatant "ignore previous instructions" phrasing and **misses the other two
entirely** — and all three actions are still stopped. That gap is the honest
argument for why enforcement cannot depend on detection.

The tools are real. `dispatch_container` will happily print "CONTAINER
RELEASED" if it is ever reached. Nothing in the tool layer second-guesses
policy, because a demo whose tools refuse dangerous actions proves nothing
about the mediator.

## Run it

```bash
# 1. start the mediator (from the repo root)
bash exhibition.sh                  # or: docker compose up -d

# 2. this agent
cd demo-agent
npm install
npm run build
npm run policy                      # push the agent's policy into the mediator
npm start
```

Open **http://localhost:4000**.

## Run it on a second laptop

The agent and the mediator do not have to be on the same machine.

```bash
# on the machine running the mediator — confirm it is reachable
curl http://<mediator-ip>:8000/health

# on the second laptop
export SCML_URL=http://<mediator-ip>:8000
npm install && npm run build && npm run policy && npm start
```

The mediator already binds `0.0.0.0`, so no server change is needed. If the
health check hangs, the network has client isolation — use a phone hotspot or
an ethernet cable.

To watch the decisions arrive on the mediator's dashboard:

```
audit.html?api=http://<mediator-ip>:8000&session=agent-live
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SCML_URL` | `http://localhost:8000` | Where the mediator lives |
| `SCML_API_KEY` | — | Sent as `X-API-Key`; omit in development mode |
| `SCML_SESSION` | `agent-live` | Groups decisions in the audit trail |
| `SCML_TIMEOUT_MS` | `5000` | Per-request timeout |
| `PORT` | `4000` | This agent's HTTP port |
| `ANTHROPIC_API_KEY` | — | Optional; see below |
| `DEMO_AGENT_MODEL` | `claude-sonnet-4-6` | Model, when a key is set |

### Intent selection: two modes

- **deterministic** (no API key) — keyword intent matching picks the tool.
- **llm** (`ANTHROPIC_API_KEY` set) — a real model picks the tool.

The header shows which is active. Deterministic mode is not a shortcut: what is
being demonstrated is the mediation boundary, not the model's cleverness, and a
demo that dies because a key expired mid-exhibition is worse than one that
cannot die that way. If the model call fails, it falls back automatically.

## The policy is the interesting file

[`policies/policy.json`](policies/policy.json) grants two identities:

| Agent id | Tools |
|---|---|
| `demo-agent-quoting` | `quote_shipment`, `track_container`, `lookup_customer` |
| `demo-agent-billing` | `issue_invoice` — allow-listed but gated as irreversible |

`dispatch_container`, `export_customer_data` and `wipe_shipment_records` are on
**no** allow-list. They resolve to `demo-agent-dispatch`, which is not in the
document, so it falls back to `default` — deny-all. **The absence is the
control.** There is no rule to misconfigure and no toggle to get wrong.

Splitting quoting from billing matters too: a single shared identity would make
the allow-list the union of everything the agent ever needs, so an injection
that reached the quoting path could reach invoicing. Separate identities make
that structurally impossible rather than merely unlikely.

`npm run policy` replaces the mediator's **whole** policy document — it is not a
merge. On a mediator shared with another system it will overwrite that system's
agents. Run your own mediator for the demo.

## Fail policy

Authorisation fails **closed**. Stop the mediator and try a scenario: the action
does not run, and the reply says why. "Could not ask" is never "permitted"
(PRD §9). Ingress and egress fail open with a loud banner, since neither is an
authorisation step.

## What this is not

It is not a prompt-injection detector, and the UI says so. The scanner in this
build measures **0 of 1054** on the external InjecAgent corpus; tool policy
accounted for the entire defence in that ablation. See `benchmarks/results/` in
the repo root. Build your integration around the policy decision.
