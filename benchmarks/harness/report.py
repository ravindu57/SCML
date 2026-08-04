"""
Report rendering for benchmark runs (PRD §14.2 / §14.3).

Two outputs:
  - Markdown, for the dissertation / release notes
  - JSON, for machine comparison across commits

Both are derived from the same `BenchmarkReport`, so a rendered table can
never drift from the raw outcomes behind it.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from benchmarks.harness.ablation import ALL_AXES
from benchmarks.harness.metrics import SuiteMetrics
from benchmarks.harness.runner import BenchmarkReport


def render_markdown(report: BenchmarkReport) -> str:
    lines: list[str] = []
    baseline = report.baseline

    lines.append(f"# Benchmark report — {report.testbed}")
    lines.append("")
    lines.append(f"- Run started: `{report.started_at}`")
    lines.append(f"- Duration: {report.duration_s:.2f}s")
    lines.append(f"- Python {report.environment['python']} on {report.environment['platform']}")
    lines.append("")

    lines.append("## Mediator settings (reproducibility)")
    lines.append("")
    lines.append("| Setting | Value |")
    lines.append("|---|---|")
    for key, value in report.mediator_settings.items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.append("")

    lines.append("## Ablation grid (PRD §14.3)")
    lines.append("")
    lines.append("| Configuration | ASR | Blocked | FPR | Utility | p50 ms | p95 ms |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for m in report.metrics:
        lines.append(
            f"| `{m.config_name}` | {m.asr:.1%} | {m.blocked_rate:.1%} | "
            f"{m.false_positive_rate:.1%} | {m.utility:.1%} | "
            f"{m.latency_p50_ms:.2f} | {m.latency_p95_ms:.2f} |"
        )
    lines.append("")

    headline = report.headline
    if headline is not None:
        lines.append("## KPI acceptance (PRD §14.2) — `full_defence`")
        lines.append("")
        lines.append("| KPI | Measured | Target | Result |")
        lines.append("|---|---:|---:|---|")
        for check in headline.kpi_checks(baseline=baseline, asr_kpi=report.asr_kpi):
            measured = (
                f"{check.value:.2f} ms"
                if check.kpi.endswith("_ms")
                else f"{check.value:.1%}"
            )
            target = (
                f"< {check.target:.0f} ms"
                if check.kpi.endswith("_ms")
                else (
                    f"< {check.target:.0%}"
                    if check.lower_is_better
                    else f"≥ {check.target:.0%}"
                )
            )
            note = f" — {check.note}" if check.note else ""
            lines.append(f"| {check.kpi} | {measured} | {target} | {check.status}{note} |")
        lines.append("")

    lines.append("## Attack family breakdown (ASR per family)")
    lines.append("")
    families = sorted({f for m in report.metrics for f in m.by_family})
    header = "| Family | " + " | ".join(f"`{m.config_name}`" for m in report.metrics) + " |"
    lines.append(header)
    lines.append("|---" * (len(report.metrics) + 1) + "|")
    for family in families:
        cells = []
        for m in report.metrics:
            fm = m.by_family.get(family)
            cells.append(f"{fm.asr:.0%} ({fm.succeeded}/{fm.total})" if fm else "—")
        lines.append(f"| {family} | " + " | ".join(cells) + " |")
    lines.append("")

    lines.append("## Attack path breakdown")
    lines.append("")
    paths = sorted({p for m in report.metrics for p in m.by_path})
    lines.append("| Path | " + " | ".join(f"`{m.config_name}`" for m in report.metrics) + " |")
    lines.append("|---" * (len(report.metrics) + 1) + "|")
    for path in paths:
        cells = []
        for m in report.metrics:
            pm = m.by_path.get(path)
            cells.append(f"{pm.asr:.0%} ({pm.succeeded}/{pm.total})" if pm else "—")
        lines.append(f"| {path} | " + " | ".join(cells) + " |")
    lines.append("")

    unsupported = report.metrics[0].unsupported_axes if report.metrics else ()
    if unsupported:
        lines.append("## Axes not exercised by this testbed")
        lines.append("")
        lines.append(
            "These layers do not sit on this testbed's decision path and were "
            "**not** varied. They are reported N/A rather than measured:"
        )
        lines.append("")
        for axis in unsupported:
            lines.append(f"- `{axis}`")
        lines.append("")

    return "\n".join(lines)


def render_json(report: BenchmarkReport) -> str:
    payload = {
        "testbed": report.testbed,
        "asr_kpi": report.asr_kpi,
        "started_at": report.started_at,
        "duration_s": report.duration_s,
        "environment": report.environment,
        "mediator_settings": report.mediator_settings,
        "configurations": [
            _metrics_payload(m, report) for m in report.metrics
        ],
        "raw_outcomes": [
            {
                "config": r.config_name,
                "outcomes": [asdict(o) for o in r.outcomes],
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2)


def _metrics_payload(m: SuiteMetrics, report: BenchmarkReport) -> dict:
    checks = m.kpi_checks(baseline=report.baseline, asr_kpi=report.asr_kpi)
    return {
        "name": m.config_name,
        "asr": m.asr,
        "blocked_rate": m.blocked_rate,
        "false_positive_rate": m.false_positive_rate,
        "utility": m.utility,
        "total_attacks": m.total_attacks,
        "attacks_succeeded": m.attacks_succeeded,
        "total_benign": m.total_benign,
        "benign_blocked": m.benign_blocked,
        "latency_p50_ms": m.latency_p50_ms,
        "latency_p95_ms": m.latency_p95_ms,
        "latency_mean_ms": m.latency_mean_ms,
        "by_family": {k: {"total": v.total, "succeeded": v.succeeded, "asr": v.asr} for k, v in m.by_family.items()},
        "by_path": {k: {"total": v.total, "succeeded": v.succeeded, "asr": v.asr} for k, v in m.by_path.items()},
        "kpi_checks": [
            {
                "kpi": c.kpi,
                "value": c.value,
                "target": c.target,
                "status": c.status,
                "note": c.note,
            }
            for c in checks
        ],
        "unsupported_axes": [a for a in ALL_AXES if a in m.unsupported_axes],
    }
