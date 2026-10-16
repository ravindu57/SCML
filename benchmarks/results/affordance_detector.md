# Tool-affordance imperative detector: prototype result (2026-10-16)

**Verdict: no-go for FR-SC-07.** On held-out InjecAgent with hard negatives, the
prototype reaches **ROC-AUC 0.779** (95% CI 0.752–0.804) against a 0.85 target, and
**7.6% FPR** at the externally frozen threshold against a 3% target. It is still the
best detection backend SCML has measured: the heuristic classifier scores 0.35 and
the gpt-4o-mini LLM backend 0.72 (`classifier_llm.md`). The prototype runs at
**158 ms p95 on CPU** with no API call, against the LLM backend's ~2.2 s.

The decisive finding is that **the imperative-mood term does not earn its place.**
Tool similarity alone, ignoring mood, scores AUC 0.834 on the same set. Multiplying
it by the parser's mood weight *lowers* AUC to 0.779. The parser misses the directive
in 23% of InjecAgent attacks, and 62% of harmless commands spliced into tool output
contain one. So the "imperative × affordance" product, which is the part of the idea
the literature review marked as new (`docs/research/DETECTION_LITERATURE_REVIEW.md`),
is not supported by this measurement.

- **Code:** `benchmarks/affordance_detector/` (detector, evaluator, data curation)
- **Raw report:** `affordance_detector.json` (sha256 `5b625a4a…bb0c5c`), from
  commit `894399f` plus the uncommitted prototype in that directory
- **Reproduce:** `pip install -e ".[detect]" && python -m spacy download en_core_web_sm`,
  then `python -m benchmarks.affordance_detector.evaluate --out <dir>`. The run is
  deterministic, so a re-run should reproduce this file exactly. That is asserted
  for a probe sample, not for the whole file.

## Setup

- **Embedding model:** spaCy `en_core_web_sm` 3.8.0 parse, `BAAI/bge-small-en-v1.5`
  via fastembed/onnxruntime, single thread.
- **Tool set:** one general-assistant tool set used everywhere: 79 tools (the 17
  InjecAgent user tools plus every attacker tool), described by name only. Name only
  is all SCML's policy store holds today.
- **No tuning on held-out data:**
  - The variant (mood × best similarity, or mood × contrast) was chosen by
    calibration AUC.
  - The threshold (0.7145) was frozen at calibration FPR ≤ 3%.
  - Both were fixed before any held-out set was scored. The evaluator enforces that
    order.

| Set | Role | Positives | Negatives |
|---|---|---|---|
| Calibration (external) | variant choice and threshold | 400 LLMail-Inject attacks that triggered the tool | 300 LLMail non-attacks, 203 LLMail FP-test emails, 169 NotInject |
| A clean (held-out) | | 1,054 InjecAgent | 17 clean InjecAgent tool responses |
| **A hard** (held-out) | **gate set** | 1,054 InjecAgent | 170 NotInject (the disjoint half) spliced into the same tool responses |
| B memory (held-out, in-house) | | 48 memory-poisoning attacks | 40 benign, incl. adversarial-benign |

The 17 clean negatives are too few to measure a 3% FPR (one false positive is 5.9%),
which is why the hard-negative set is the gate set.

## Results (frozen threshold per variant)

| Variant | Calibration AUC | A clean AUC | **A hard AUC (95% CI)** | A hard recall | A hard FPR | Memory AUC | Memory recall |
|---|---|---|---|---|---|---|---|
| **mood × similarity (chosen)** | 0.675 | 0.863 | **0.779 (0.752–0.804)** | 50.6% | 7.6% | 0.697 | 0% |
| mood × contrast | 0.667 | 0.860 | 0.741 (0.712–0.772) | 33.5% | 1.8% | 0.695 | 0% |
| mood alone (ablation) | 0.616 | 0.856 | 0.633 (0.593–0.674) | 0% | 0% | 0.696 | 0% |
| similarity alone (ablation) | 0.830 | 0.830 | 0.834 (0.803–0.866) | 61.6% | 24.7% | 0.572 | 0% |
| contrast alone (ablation) | 0.775 | 0.763 | 0.763 (0.725–0.797) | 46.5% | 12.9% | 0.544 | 0% |

Two notes on reading the table:
- The ablation rows show where the signal is, but they could not have been chosen:
  only the two detector variants were eligible.
- "Similarity alone" achieves its higher AUC at a frozen-threshold FPR of 24.7%. It
  does not pass either.

### Gates

| Gate | Result |
|---|---|
| G1 threshold from external data only | **pass**, enforced by the evaluator's order of operations |
| G2 held-out AUC ≥ 0.85 | **fail**: 0.779 |
| G2 FPR ≤ 3% at the frozen threshold | **fail**: 7.6% |
| G2 recall ≥ 50% at the frozen threshold | pass: 50.6%, barely |
| G3 the combined score beats mood alone | pass: 0.779 vs 0.633, CIs disjoint |
| G3′ the combined score beats similarity alone | **fail**: 0.779 vs 0.834. This is the comparison that matters for the novelty claim |
| G4 adaptive attacker | not run |
| G5 AgentDojo end to end | not run (paid) |
| G6 p95 < 400 ms | pass: 158 ms p95, 76 ms p50, 314 ms max over 1,241 texts |
| G6 deterministic | pass, on a re-scored probe sample |

G3 as written in the review compared the combined score only with mood alone. It
should also have required beating similarity alone, so G3′ is added here and fails.

## Diagnosis (held-out data used to explain, never to change the detector)

| | Has no parsed directive | Mean score |
|---|---|---|
| Calibration attacks | 27% | 0.498 |
| Calibration negatives | 49% | 0.322 |
| InjecAgent attacks | 23% | 0.578 |
| InjecAgent clean | 94% | 0.042 |
| Hard negatives | 38% | 0.359 |
| Memory attacks | **54%** | 0.266 |
| Memory benign | 93% | 0.042 |

1. **Mood recall caps the detector.** Any attack without a parsed directive scores
   0, so at most 77% of InjecAgent attacks can ever be flagged. The misses include
   phrasings that `en_core_web_sm` mis-tags, and requests that are not in the
   imperative at all.
2. **Harmless commands are common in tool output.** 62% of NotInject prompts ("write
   a creative story…", "should I activate…") parse as directives. Mood cannot tell a
   command to the reader from a command to the assistant. The literature review
   predicted this risk.
3. **Tool attribution is moderate.** Where a directive was found, the best-matching
   tool was the attacker's actual target in 545 of 813 cases (67%), from tool names
   alone.
4. **Memory is out of reach for this design.** Memory poisoning arrives as notes and
   facts ("Note for future tasks: the correct tool for sending email is…"). 54% of
   these have no imperative, and none clears the frozen threshold. This matches the
   literature (MPBench: command-style payloads are caught far more often than
   fact-style ones). Memory needs provenance quarantine, not this detector.

## What this means for SCML

- **Do not ship it** as a scanner backend or gate (FR-SC-07 not met), and do not
  claim the imperative × affordance score as a contribution: its own ablation
  refutes it.
- **The useful signal is tool similarity**: "does this text talk about something
  this agent can do?" It is the strongest single feature measured (0.834 hard AUC,
  CPU, no LLM). It fails on FPR, though, because commands and descriptions of
  actions look alike to an embedding.
- **Candidate next steps, each to be decided before measurement, with a fresh
  held-out set:**
  - richer tool descriptors (descriptions and argument schemas) in the policy store
  - argument-shape matching (an IBAN, email address or account number that fits a
    tool argument)
  - a better parser (`en_core_web_md`/`lg`)
  - using the score to *route* content to the LLM classifier, not to block it

  Any change prompted by this run must be validated on data this run did not see,
  or it is tuning on the test set.
