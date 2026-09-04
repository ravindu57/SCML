# Benchmark report — classifier protocol (FR-SC-06/07/08)

- Backend: `llm` (`LLMClassifier`, `gpt-4o-mini` via OpenAI-compatible
  `api.openai.com/v1`, temperature 0)
- Held-out corpus: InjecAgent (external, vendored) — 1054 attacks, 17 benign
- Harness: `python -m benchmarks.classifier_eval.evaluate --backend llm --gate 0.20 --workers 12`
- Run date: 2026-09-01
- Executed concurrently (12 workers); the LLM path is I/O-bound, so wall-clock
  is not a per-payload latency. The FR-SC-07 latency figure below is the
  per-payload p95, measured inside the harness.
- Cost: ~1071 hosted-LLM calls on `gpt-4o-mini` (~USD 0.35); no 429/quota errors.

## FR-SC-07 held-out metrics — `llm` backend

| Metric | Measured | FR-SC-07 target | Result |
|---|---:|---:|---|
| ROC-AUC | 0.7206 | ≥ 0.85 | NO |
| Attack recall @ operating threshold | 1.0000 | ≥ 0.50 | at threshold 0.0 |
| FPR @ that threshold | 1.0000 | ≤ 0.03 | NO |
| Added p95 latency | 2237 ms | ≤ 400 ms (NFR-PERF-01) | NO |

**FR-SC-07 shippable? NO.**

## Reading the number

This is the first live measurement of the `SCANNER_BACKEND=llm` direction against
the external held-out corpus, which the README had flagged as "untested; the
obvious next measurement". It retires that unknown and pins three facts:

1. **The LLM is genuinely discriminative, unlike the shipped heuristic.** ROC-AUC
   0.72 ranks attacks above benign — where the heuristic (`HeuristicClassifier`)
   measured 0.35 (anti-discriminative: benign higher) and both rejected TF-IDF
   approaches (0.66 / 0.51). The direction is correct.
2. **It is not shippable at these targets.** AUC 0.72 < 0.85, and the only
   operating point with recall ≥ 0.5 is threshold 0.0, which admits every benign
   (FPR 1.0). No threshold clears both bounds. It cannot be wired in as the
   stage-2 classifier today.
3. **Latency is disqualifying for the request path regardless of accuracy.**
   p95 ≈ 2.2 s against a 400 ms target. A hosted per-payload LLM call is a
   synchronous network round trip on the mediation path (NFR-PERF-04 forbids
   holding it). Even if it met the AUC bar, it would still fail latency.

## FR-SC-08 — the paired gate is the real blocker

At the default `SCANNER_ML_GATE_THRESHOLD` (0.20) the stage-2 classifier is
consulted on **0 of 1054** external attacks (the regex pre-filter scores them
exactly 0.0 on the `untrusted_data` path). So this standalone 0.72 AUC is moot
on that path until the gate is opened — and opening it is only justified by a
classifier that clears FR-SC-07 and is fast enough for the request path.

## Implication for the classifier protocol

The LLM is the only measured backend that separates the classes, but it fails
on latency and margin. A *fast, CPU-bound pre-filter* that routes only genuinely
ambiguous payloads to the LLM (never the request path) is the seam to build on:
it must be designed from the syntactic concept (FR-SC-06), evaluated with the
gate it will ship with (FR-SC-08), and kept off the synchronous path
(NFR-PERF-04). Neither the LLM alone nor the heuristic alone satisfies FR-SC-07;
a syntactic gate that most attacks pass through fast, with the LLM only on the
rare ambiguous remainder, is the untested combination.

## The routing gate was then built and measured — token-level syntax is a dead end

The "untested combination" above was implemented (`SyntacticRouteGate`, concept-
based, CPU-bound) and measured over the same held-out corpus
(`python -m benchmarks.classifier_eval.evaluate --route`). The result is a
negative one, and it is load-bearing because it was measured rather than assumed.

| Gate variant | Attacks preserved | Benign routed away | LLM call fraction | Avg latency |
|---|---:|---:|---:|---:|
| strips quoted values | 51/1054 (4.8%) | 17/17 | 4.8% | 107 ms |
| searches full tool output | 1007/1054 (95.5%) | 17/17 | 94.0% | 2103 ms |

The first variant reveals why the second had to be tried: an injected instruction
in tool output sits *inside a quoted JSON value*, so stripping quotes (the naive
"quoted text is content" rule from the scaffold) deletes the very signal the gate
is hunting — it dropped 95% of attacks. The second variant searches the whole
payload and preserves 95.5% of attacks with zero benign routed to the LLM, but in
doing so it routes *almost everything* to the LLM (94%), because benign data
shares the same closed-class command vocabulary ("create", "add", "send", "share"
all appear in harmless tool output). It saves essentially no latency
(≈2.1 s, back to the raw LLM figure).

**Conclusion:** at the token level the gate cannot separate "command addressed
to an assistant" from "command-word used as data" — the same verb is a tool
action in the attack and a noun phrase in the benign contention (e.g. "who
*created* the order"). That is precisely the discriminator the addendum said is
syntactic-clause-level, not lexical. So a routing gate is only viable with a
real dependency/POS parser that recognises imperative *mood* as distinct from
declarative usage of the identical verb — which is the spacy/POS seam the
scaffold's `_syntactic_score` was built for, and the resource this environment
does not install in the core install. No further token-level work is
warranted; the next step is parser-backed clause features or a fine-tuned
transformer (deployment/GPU question per `benchmarks/README.md`).

