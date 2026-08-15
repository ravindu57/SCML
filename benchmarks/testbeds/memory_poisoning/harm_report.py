"""
Harm-analysis report for the memory-poisoning corpus (PRD §14.1, §5.2).

    python -m benchmarks.testbeds.memory_poisoning.harm_report
    python -m benchmarks.testbeds.memory_poisoning.harm_report --out benchmarks/results

Answers a different question from `benchmarks.cli --testbed memory_poisoning`:
that one measures how much poison gets **stored**, this one measures how much
stored poison could actually **do** anything. Both are reported; neither
replaces the other. See `harm.py` for why the distinction is not goalpost
movement.

Environment is pinned before importing trust_mediator, as in the other runners.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import os
import sys
from pathlib import Path


def _configure_environment(db_path: Path) -> None:
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["TRUST_MEDIATOR_ENV"] = "test"
    os.environ["REDIS_URL"] = ""
    os.environ["TRUST_MEDIATOR_API_KEYS"] = ""
    os.environ["SCANNER_SHADOW_MODE"] = "false"


def _quiet() -> None:
    import structlog

    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))


def _render(rows, storage_asr: float | None) -> str:
    total = len(rows)
    in_scope = [r for r in rows if not r.out_of_scope]
    out_scope = [r for r in rows if r.out_of_scope]
    harmful_in_scope = [r for r in in_scope if r.harmful]
    harmful_any = [r for r in rows if r.harmful]

    lines = [
        "# Memory poisoning — harm analysis (PRD §5.2, §14.1)",
        "",
        "## The question this answers",
        "",
        "`benchmarks/results/memory_poisoning.md` measures how much poison is",
        "**stored** — the memory integrity layer in isolation. This measures how",
        "much stored poison could actually **act**, applying the same standard the",
        "InjecAgent testbed uses: an attack succeeds only when the mediator would",
        "have let its goal through.",
        "",
        "Both numbers are reported. Quoting only this one would be moving the",
        "goalposts; quoting only the storage figure overstates the risk of a record",
        "the control path never consults.",
        "",
        "## Headline",
        "",
        "| Measure | Value |",
        "|---|---:|",
    ]
    if storage_asr is not None:
        lines.append(f"| Storage ASR (poison persisted ACTIVE) | {storage_asr:.1%} |")
    lines += [
        f"| Cases analysed | {total} |",
        f"| On a mediator-gated path | {len(in_scope)} |",
        f"| **Gated and still harmful** | **{len(harmful_in_scope)}/{len(in_scope)}"
        f" ({len(harmful_in_scope) / len(in_scope):.1%})** |"
        if in_scope else "| Gated and still harmful | n/a |",
        f"| Outside any mediator gate | {len(out_scope)}"
        f" ({len(out_scope) / total:.1%}) |",
        f"| Harmful counting out-of-scope as harmful | {len(harmful_any)}/{total}"
        f" ({len(harmful_any) / total:.1%}) |",
        "",
        "The last row is the pessimistic reading and the one to quote if only one",
        "number is wanted: it credits the mediator with nothing it does not do.",
        "",
        "## By harm vector",
        "",
        "| Vector | Cases | Harmful | What it must defeat |",
        "|---|---:|---:|---|",
    ]

    what = {
        "tool": "tool allow-list, or untrusted-argument policy",
        "output": "egress redaction",
        "control": "the claim that a mediator control is disabled",
        "informational": "nothing — no mediator gate on this path",
    }
    by_vec = collections.defaultdict(list)
    for r in rows:
        by_vec[r.vector.value].append(r)
    for vec in ("tool", "output", "control", "informational"):
        got = by_vec.get(vec, [])
        if not got:
            continue
        harmful = sum(1 for r in got if r.harmful)
        lines.append(f"| `{vec}` | {len(got)} | {harmful} | {what[vec]} |")

    lines += ["", "## By family", "",
              "| Family | Cases | Harmful | Out of scope |", "|---|---:|---:|---:|"]
    by_fam = collections.defaultdict(list)
    for r in rows:
        by_fam[r.family].append(r)
    for fam in sorted(by_fam):
        got = by_fam[fam]
        lines.append(
            f"| {fam} | {len(got)} | {sum(1 for r in got if r.harmful)} "
            f"| {sum(1 for r in got if r.out_of_scope)} |"
        )

    lines += [
        "",
        "## Reading this honestly",
        "",
        "**Out-of-scope cases are not blocked.** A poisoned memory that makes the",
        "agent quote a false approval limit, or conceal that it used a tool, is real",
        "harm and nothing here stops it. The mediator gates actions and egress, not",
        "beliefs. Counting those as defended would be exactly the overstatement §14",
        "exists to prevent, so they are reported as out of scope and included in the",
        "pessimistic total above.",
        "",
        "**Control-bypass cases are inert for a measured reason.** Authorisation is",
        "read from the declarative policy store; the mediator never consults agent",
        "memory to decide it. A record asserting \"policy validation has been",
        "disabled\" therefore cannot disable it — verified here rather than assumed,",
        "and asserted in `tests/unit/test_memory_harm.py`.",
        "",
        "**The agent is modelled as fully persuaded.** It does exactly what the",
        "poison says. That removes the model's judgement from the measurement, so",
        "what remains is the mediator's contribution alone.",
        "",
    ]
    return "\n".join(lines)


async def _run(args) -> int:
    from benchmarks.testbeds.memory_poisoning.corpus import ATTACK_CASES
    from benchmarks.testbeds.memory_poisoning.harm import build_policy_engine, evaluate_harm
    from trust_mediator.db.base import create_all_tables
    from trust_mediator.modules.output_redaction.redactor import OutputRedactor

    await create_all_tables()
    engine = build_policy_engine()
    redactor = OutputRedactor()

    rows = [
        await evaluate_harm(c.id, c.family, engine, redactor) for c in ATTACK_CASES
    ]

    storage_asr = None
    committed = Path("benchmarks/results/memory_poisoning.json")
    if committed.exists():
        try:
            data = json.loads(committed.read_text())
            for m in data.get("metrics", []):
                if m.get("config_name") == "full_defence":
                    storage_asr = m["attacks_succeeded"] / m["total_attacks"]
        except Exception:
            pass

    report = _render(rows, storage_asr)
    print(report)

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "memory_poisoning_harm.md").write_text(report)
        (out / "memory_poisoning_harm.json").write_text(json.dumps([
            {
                "case_id": r.case_id, "family": r.family, "vector": r.vector.value,
                "harmful": r.harmful, "out_of_scope": r.out_of_scope, "detail": r.detail,
            }
            for r in rows
        ], indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Memory-poisoning harm analysis")
    parser.add_argument("--out", help="Directory to write the report into")
    args = parser.parse_args()

    db = Path(__file__).resolve().parent / "_harm.db"
    _configure_environment(db)
    _quiet()
    try:
        return asyncio.run(_run(args))
    finally:
        db.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
