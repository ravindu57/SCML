"""
Evaluator and CLI for the classifier protocol (FR-SC-06/07/08).

Runs any `BaseClassifier` over the external held-out InjecAgent corpus and
reports the FR-SC-07 table (ROC-AUC, attack recall and FPR at the operating
threshold) alongside the stage-2 gate it is paired with (FR-SC-08: reporting
classifier quality without the gate is invalid, because at the default gate the
classifier is consulted on 0 of 1054 external attacks).

`--oracle` runs a deterministic, perfectly-separating classifier as a harness
self-test: because it scores every attack above every benign, the harness must
report ROC-AUC 1.0, recall 1.0 and FPR 0.0. If it does not, the harness itself
is wrong, not the classifier.
"""

from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from benchmarks.classifier_eval.corpus import (
    assert_external_training,
    held_out_samples,
)
from benchmarks.classifier_eval.metrics import (
    FR_SC07_TARGETS,
    ScoredSample,
    find_operating_threshold,
    metric_at_threshold,
    roc_auc,
)
from benchmarks.classifier_eval.route_gate import SyntacticRouteGate


class Scorer(Protocol):
    """Anything with a `predict(text) -> float` and `name` attribute."""

    name: str
    def predict(self, text: str) -> float: ...


class OracleClassifier:
    """Deterministic self-test of the *metrics*, not of a real detector.

    The harness's own numbers must be provably correct before they are trusted,
    so the oracle scores perfectly-separable *synthetic* inputs: every attack
    higher than every benign. The metrics code must therefore report ROC-AUC
    1.0, recall 1.0 and FPR 0.0 — a failure means the harness is wrong, not the
    classifier. It runs on synthetic data, not the real corpus, because the
    real attack strings are varied text with no stable marker to separate on.
    """

    name = "oracle"

    def synthetic_samples(self, n_per_class: int = 50) -> list[ScoredSample]:
        return [
            ScoredSample(text=f"attack-{i}", score=1.0 - i * 1e-3, is_attack=True)
            for i in range(n_per_class)
        ] + [
            ScoredSample(text=f"benign-{i}", score=i * 1e-3, is_attack=False)
            for i in range(n_per_class)
        ]

    def predict(self, text: str) -> float:  # pragma: no cover - not used on real text
        return 0.0


def _oracle_self_test() -> dict:
    """Prove the metric code by running it on perfectly-separable synthetic data."""
    oracle = OracleClassifier()
    samples = oracle.synthetic_samples()
    auc = roc_auc(samples)
    ops = find_operating_threshold(samples)
    return {
        "classifier": "oracle (metrics self-test)",
        "n_attacks": sum(1 for s in samples if s.is_attack),
        "n_benign": sum(1 for s in samples if not s.is_attack),
        "roc_auc": round(auc, 4),
        "operating_threshold": round(ops.threshold, 4) if ops else 0.0,
        "attack_recall": round(ops.attack_recall, 4) if ops else 0.0,
        "false_positive_rate": round(ops.false_positive_rate, 4) if ops else 0.0,
        "gate_threshold": "n/a (self-test)",
        "added_p95_latency_ms": 0.0,
        "threshold_meets_fr_sc07": bool(
            ops
            and ops.attack_recall >= FR_SC07_TARGETS["attack_recall"]
            and ops.false_positive_rate <= FR_SC07_TARGETS["false_positive_rate"]
        ),
        "self_test": True,
    }


def evaluate(scorer: Scorer, gate_threshold: float, workers: int = 1) -> dict:
    """Score the held-out corpus and assemble the FR-SC-07/08 report dict.

    `workers > 1` scores concurrently through a bounded thread pool. This is
    intended for I/O-bound backends (the LLM classifier) where serial scoring
    would spend the wall clock waiting on the network; the metric computation is
    order-independent, so concurrency changes only latency, never the result.
    Deterministic CPU-bound backends should stay at the default of 1.
    """
    samples = held_out_samples()
    scored: list[ScoredSample] = []

    def _score_one(sample) -> tuple:
        t0 = time.perf_counter()
        score = float(scorer.predict(sample.text))
        return (sample, score, (time.perf_counter() - t0) * 1000.0)

    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_score_one, samples))
    else:
        results = [_score_one(s) for s in samples]

    scored = [
        ScoredSample(text=s.text, score=score, is_attack=s.is_attack)
        for (s, score, _lat) in results
    ]
    latencies = [lat for (_s, _score, lat) in results]

    auc = roc_auc(scored)
    ops = find_operating_threshold(scored)
    if ops is not None:
        at_op = ops
    else:
        # No threshold satisfies both FR-SC-07 bounds; report the best-recall
        # threshold and let the KPI table show which bound failed.
        at_op = max(
            (metric_at_threshold(scored, t) for t in {s.score for s in scored}),
            key=lambda m: m.attack_recall,
        )
    p95 = sorted(latencies)[int(0.95 * (len(latencies) - 1))]

    return {
        "classifier": scorer.name,
        "n_attacks": sum(1 for s in scored if s.is_attack),
        "n_benign": sum(1 for s in scored if not s.is_attack),
        "roc_auc": round(auc, 4),
        "operating_threshold": round(at_op.threshold, 4),
        "attack_recall": round(at_op.attack_recall, 4),
        "false_positive_rate": round(at_op.false_positive_rate, 4),
        # FR-SC-08: the gate the classifier is paired with.
        "gate_threshold": gate_threshold,
        "added_p95_latency_ms": round(p95, 3),
        "threshold_meets_fr_sc07": (
            at_op.attack_recall >= FR_SC07_TARGETS["attack_recall"]
            and at_op.false_positive_rate <= FR_SC07_TARGETS["false_positive_rate"]
        ),
    }


def report_text(result: dict) -> str:
    line = "─" * 62
    lines = [
        line,
        f"Classifier protocol (FR-SC-06/07/08) — {result['classifier']}",
        line,
        f"  Held-out attacks            {result['n_attacks']}",
        f"  Held-out benign             {result['n_benign']}",
        "",
        "  FR-SC-07 held-out metrics:",
        f"    ROC-AUC                {result['roc_auc']:>7.4f}   target ≥ {FR_SC07_TARGETS['roc_auc']}",
        f"    Attack recall @ {result['operating_threshold']:<5} {result['attack_recall']:>7.4f}   target ≥ {FR_SC07_TARGETS['attack_recall']}",
        f"    FPR @ threshold        {result['false_positive_rate']:>7.4f}   target ≤ {FR_SC07_TARGETS['false_positive_rate']}",
        f"    Added p95 latency      {result['added_p95_latency_ms']:>7.3f} ms   target ≤ 400 ms (NFR-PERF-01)",
        "",
        f"  FR-SC-07 shippable?          {'YES' if result['threshold_meets_fr_sc07'] else 'NO'}",
        f"  FR-SC-08 paired gate (SCANNER_ML_GATE_THRESHOLD) = {result['gate_threshold']}",
        "    Note: at the default gate (0.20) the classifier is consulted on 0/1054.",
        "    A shippable classifier must be evaluated with the gate it will ship with.",
        line,
    ]
    return "\n".join(lines)


def route_gate_report(llm_p95_ms: float = 2237.0) -> dict:
    """Measure the routing gate over the held-out corpus (FR-SC-08, NFR-PERF-01).

    This is the architecture from the committed result: a fast syntactic gate
    that frees the request path from the LLM by routing only ambiguous payloads
    to it. The honest numbers are:
      - attack_routed / attack_routed_away : does the gate drop attacks before
        the LLM (undermining recall)?
      - benign_routed_away: how many benign payloads never hit the LLM, so the
        LLM's FPR risk and its ~2.2 s latency are both spared?
      - llama_call_fraction: the effective load on the LLM after gating.
    """
    gate = SyntacticRouteGate()
    samples = held_out_samples()
    attacks = [s for s in samples if s.is_attack]
    ben = [s for s in samples if not s.is_attack]

    def _count(group):
        to_llm = 0
        for s in group:
            if gate.route(s.text).route_to_llm:
                to_llm += 1
        return to_llm, len(group) - to_llm

    att_to_llm, att_away = _count(attacks)
    ben_to_llm, ben_away = _count(ben)
    total = len(samples)
    llm_calls = att_to_llm + ben_to_llm

    # Fast-path latency is the gate itself (microseconds); only routed payloads
    # pay the LLM's measured p95. The gate scan is local and cheap.
    return {
        "gate": "syntactic_route",
        "n_attacks": len(attacks),
        "n_benign": len(ben),
        "attack_routed_to_llm": att_to_llm,
        "attack_routed_away": att_away,
        "attack_preserved_ratio": att_to_llm / len(attacks) if attacks else 0.0,
        "benign_routed_away": ben_away,
        "benign_routed_to_llm": ben_to_llm,
        "llm_call_fraction": llm_calls / total if total else 0.0,
        "llm_p95_ms": llm_p95_ms,
        "avg_latency_ms": llm_p95_ms * (llm_calls / total if total else 0.0),
    }


def route_report_text(r: dict) -> str:
    line = "─" * 62
    return "\n".join(
        [
            line,
            f"Routing gate (FR-SC-08 / NFR-PERF-01) — {r['gate']}",
            line,
            f"  Held-out attacks            {r['n_attacks']}",
            f"  Held-out benign             {r['n_benign']}",
            "",
            f"  Attacks routed to LLM       {r['attack_routed_to_llm']}  "
            f"({r['attack_preserved_ratio'] * 100:.1f}% preserved)",
            f"  Attacks routed away (lost   {r['attack_routed_away']}",
            "      before the LLM)",
            f"  Benign routed away          {r['benign_routed_away']} "
            f"(spares latency + FPR risk)",
            f"  Benign still to LLM         {r['benign_routed_to_llm']}",
            "",
            f"  LLM call fraction           {r['llm_call_fraction'] * 100:.1f}% "
            f"of payloads",
            f"  Assumed LLM p95             {r['llm_p95_ms']:.0f} ms "
            "(measured)",
            f"  Avg latency after gate      {r['avg_latency_ms']:.1f} ms",
            line,
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", action="store_true", help="harness self-test")
    parser.add_argument(
        "--route", action="store_true", help="measure the syntactic routing gate"
    )
    parser.add_argument(
        "--llm-p95-ms",
        type=float,
        default=2237.0,
        help="assumed LLM per-call p95 latency when --route (measured default)",
    )
    parser.add_argument(
        "--backend",
        choices=["syntactic", "llm", "heuristic"],
        default="syntactic",
        help="classifier backend to evaluate against the held-out corpus",
    )
    parser.add_argument(
        "--gate",
        type=float,
        default=0.20,
        help="SCANNER_ML_GATE_THRESHOLD the classifier is paired with (FR-SC-08)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="concurrent scoring threads (use >1 for the I/O-bound LLM backend)",
    )
    parser.add_argument(
        "--training-source",
        default="",
        help="origin of the training data; refused if it is the in-house corpus (FR-SC-06)",
    )
    args = parser.parse_args(argv)

    if args.training_source:
        try:
            assert_external_training(args.training_source)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    if args.oracle:
        result = _oracle_self_test()
    elif args.route:
        r = route_gate_report(llm_p95_ms=args.llm_p95_ms)
        print(route_report_text(r))
        return 0
    else:
        from benchmarks.classifier_eval.classifiers import SyntacticImperativeClassifier

        if args.backend == "syntactic":
            scorer = SyntacticImperativeClassifier()
            scorer.name = "syntactic_imperative_scaffold"
        elif args.backend == "llm":
            # Phase 4 wiring, verifiable without a key: LLMClassifier.predict
            # returns 0.0 (with a logged warning) when no API key is set, so the
            # harness still runs and correctly reports NOT shippable. With
            # LLM_SCANNER_API_KEY set it scores for real.
            from trust_mediator.modules.injection_scanner.classifier import LLMClassifier

            scorer = LLMClassifier()
            scorer.name = "llm_scanner"
        else:
            # The shipped heuristic backend, measured for contrast and as the
            # FR-SC-07 baseline that must be beaten.
            from trust_mediator.modules.injection_scanner.classifier import HeuristicClassifier

            scorer = HeuristicClassifier()
            scorer.name = "heuristic_current"
        result = evaluate(scorer, gate_threshold=args.gate, workers=args.workers)

    if result.get("self_test"):
        ok = result["threshold_meets_fr_sc07"] and abs(result["roc_auc"] - 1.0) < 1e-6
        print(
            f"Metrics self-test: {'PASS' if ok else 'FAIL'} "
            f"(ROC-AUC {result['roc_auc']}, recall {result['attack_recall']}, "
            f"FPR {result['false_positive_rate']})"
        )
        return 0 if ok else 1

    print(report_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
