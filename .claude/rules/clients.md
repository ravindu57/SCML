---
paths:
  - "trust_mediator/client.py"
  - "trust_mediator/__init__.py"
  - "trust_mediator/integrations/**"
  - "clients/**"
  - "scml/**"
  - "pyproject.toml"
  - "demo-agent/**"
  - "examples/**"
---

# Client SDKs, public API, packaging, LangChain guard

- **The core install is the client SDK; the server stack lives in extras.** `pip install trust-mediator` must stay ~14 packages (`httpx`, `pydantic`, `pydantic-settings`). Everything else is `[server]`, `[ml]` (scikit-learn only, imported lazily in `HeuristicClassifier.train`), `[embedded]`. `[dev]` self-references `[server,ml]` so `pip install -e ".[dev]"` still gives a full stack. The `client-install` CI job fails if a server dependency leaks back into core — if you add a core dependency, that job is the thing telling you not to.
- **`__all__` in `trust_mediator/__init__.py` is the public API contract.** Adding to it is a minor version; removing or renaming is a major one. Everything under `modules/`, `db/`, `api/` is internal and free to change. `MediationPipeline` and `settings` resolve lazily via module `__getattr__` so a client-only install can import the package without the server stack — do not make them eager. `test_public_api.py` pins all of this.

- **Never classify a mediation verdict inline.** `client.classify_decision` is the single implementation, shared by the SDK and the LangChain guard. `require_approval` and `deny` both arrive *suffixed* (`.irreversible`, `.schema_violation`), and an unrecognised verdict must map to `unknown`, never `allow` — matching `require_approval` exactly once let gated irreversible actions through (FR-PE-03). The TypeScript client mirrors the same branch order and must stay in sync.

- `trust_mediator/client.py` — the client SDK (`SCMLClient`/`AsyncSCMLClient`). Normalises the five mediation endpoints, which return three different shapes: `/context` and `/tool-call` carry `decision`, `/output` carries `blocked` and **no `decision` at all**, `/memory/write` carries `verdict`. Callers branch on `result.allowed`, never on a raw field.

- LangChain guard (`integrations/langchain_guard.py`): callbacks are notification-only, so the hooks scan and audit but cannot alter data in flight. The only enforcement points are `strict=True` (raises, aborting the run) and `guard.redact(text)` (returns safe text for the caller to substitute). It sends `argument_trust_labels` by default — without them FR-PE-04 never fires and a model-composed argument sails through as `allow`. It also prefers LangChain's structured `inputs` dict over the flat string, or declared `argument_schema`s can never match. Don't "simplify" either back.
