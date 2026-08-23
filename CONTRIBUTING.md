# Contributing

This is security infrastructure: it decides whether an agent may act, and it
produces the record of that decision. A change that weakens either is worse than
no change, because whatever was relying on it will not notice.

Found a vulnerability? Do not open an issue — see [SECURITY.md](SECURITY.md).

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,grpc]"     # [dev] pulls in [server] and [ml]
```

## Before you open a PR

```bash
.venv/bin/ruff check trust_mediator/ tests/ benchmarks/
DATABASE_URL="" TRUST_MEDIATOR_ENV=development REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
    .venv/bin/pytest tests/ -q                    # expect 497 passed

cd clients/typescript && npm install && npm run build && npm test   # expect 18
```

Those env overrides are not optional. The local `.env` sets production mode,
docker-only hostnames and a real API key, all of which break a bare `pytest`.

## The rules that matter

`CLAUDE.md` holds the full set, each with the incident that motivated it. The
ones most often broken by accident:

- **Untrusted data must never enter the control path** (PRD §5.2). Data labelled
  `untrusted_data` or `risky_external` can inform content; it can never
  authorise a tool call or influence a policy decision.
- **Side-effect operations fail closed** (PRD §9). Tool execution, memory writes
  and outbound responses deny on mediator error. Only low-risk reads may fail
  open, and every fail-open is audited.
- **Every `/v1` route takes `AuthDep`,** and dependencies go *before* defaulted
  parameters. Three endpoints shipped unauthenticated because a non-defaulted
  `_: AuthDep` cannot follow `pipeline: PipelineDep = None`, and auth was
  dropped rather than the parameters reordered.
- **Config goes through `TRUST_MEDIATOR_*` in `config.py`.** No hardcoded
  thresholds, URLs or keys.
- **Every decision point emits an `AuditEvent`.**
- **Cite PRD requirement IDs** (`FR-*`, `NFR-*`) in module docstrings and test
  names, as the existing code does.

## Tests

A test should fail for one reason, and the reason should be in its name. Two
habits this project has learned the hard way:

- **Check your test can fail.** A structural auth test once walked the route
  tree, found nothing, and passed vacuously — FastAPI nests included routers
  rather than flattening them. It now asserts it discovered routes at all.
- **Build fixtures from the real shape, not the shape you assume.** The
  AgentDojo taint extractor read `text` from content blocks that use `content`.
  Tests built from the assumed shape passed while the code never worked in a
  single real run.

When you fix a bug, add the test that would have caught it, and say in the
commit what it was.

## Benchmarks

Numbers in `benchmarks/results/` are committed records. If you change a scorer,
threshold or detector, re-run the benchmark and update the result in the same
change.

**Do not tune against the in-house corpus.** It was written here, so fitting to
it measures the fitting. Classifier work trains on external data and evaluates
against the in-house corpus as a held-out set, never the reverse.

Report what the number does not show. `benchmarks/README.md` and the result
files are written that way on purpose — an ablation that reveals a component
contributes nothing belongs in the headline, not a footnote.

## Commits

Explain *why*, and what breaks without the change. Prefer one coherent commit
over several that leave the tree failing in between.

If you are correcting an earlier claim, say so plainly and leave the error
visible rather than quietly rewriting it. A record that edits away its mistakes
is not a record.
