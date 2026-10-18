---
paths:
  - "trust_mediator/modules/injection_scanner/**"
  - "benchmarks/classifier_eval/**"
  - "benchmarks/affordance_detector/**"
---

# Injection scanner and classifiers (PRD §6.3, FR-SC-*). Measured detection results: rules/benchmarks.md

- **A classifier that cannot score raises `ClassifierUnavailable`; it never returns 0.0.**
  0.0 means "definitely benign", so returning it on failure (no API key, HTTP
  error, bad reply, no model) marked unscanned content verified and bypassed
  the scanner's `_unscannable` §9 path. The same goes for clients:
  `strict=True` in the LangChain guard raises on `error` and `escalate`, and
  `/tool-call` rejects unknown trust labels (422) rather than dropping them.
  `test_fail_closed_clients.py` pins all three.
- **Async callers use `InjectionScanner.scan_async`, never `scan`.** `scan` runs stage 2 inline, and `LLMClassifier.predict` bridges to async by blocking on `Future.result()` — a 1s classifier call measured 4 event-loop iterations instead of ~100, stalling every concurrent request, not just its own. A backend that performs I/O must override `predict_async`; the base class default delegates to `predict`, which is correct only for CPU-bound backends. `test_scanner_async_path.py` asserts both call sites.
