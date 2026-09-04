"""
Classifier evaluation harness (FR-SC-06/07/08, §6.3a).

Verifiable wiring for the injection-classifier protocol. It does not ship a
trained model — the two permitted directions (an LLM backend or a syntactic
imperative detector) are scaffolded here with the exact evaluation they must
pass before shipping, so the number is produced by the same harness that will
gate them.

Run the harness self-test (no API key, no model):

    python -m benchmarks.classifier_eval.evaluate --oracle

Evaluate a backend against the external held-out InjecAgent corpus:

    python -m benchmarks.classifier_eval.evaluate

For the I/O-bound LLM backend, score concurrently (latency only, never the
metrics) — measured result committed in ``benchmarks/results/classifier_llm.md``:

    LLM_SCANNER_API_KEY=$KEY python -m benchmarks.classifier_eval.evaluate \
        --backend llm --gate 0.20 --workers 12
"""
