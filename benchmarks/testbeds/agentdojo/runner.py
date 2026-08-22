"""
Phase 0 runner: AgentDojo `workspace`, undefended vs SCML (PRD §14.1).

Requires the `agentdojo` package, which is deliberately *not* a dependency of
this repo — it pulls langchain and four provider SDKs, and the `client-install`
CI job exists to keep exactly that out of the core install. Install it in a
separate virtualenv alongside `pip install -e .` (which brings only the client
SDK) and run this module from there.

    python -m benchmarks.testbeds.agentdojo.runner --tasks 5
    python -m benchmarks.testbeds.agentdojo.runner --tasks 5 --no-scml

Nothing imports this module at package import time, so the SCML test suite is
unaffected by AgentDojo's absence.

What is measured, in AgentDojo's terms:

* **utility** — did the user's actual task succeed
* **security** — did the *injected* task succeed. This is the ASR numerator;
  lower is better.

Both are needed. A defense that denies everything scores a perfect 0% ASR and
is worthless, which is why utility is reported beside it rather than after it.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig, ToolsExecutionLoop
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites

from benchmarks.testbeds.agentdojo.defense import ScmlDefense
from benchmarks.testbeds.agentdojo.gemini_compat import (
    GEMINI_OPENAI_BASE_URL,
    wrap_for_gemini,
)

BENCHMARK_VERSION = "v1.2.1"
SUITE = "workspace"
AGENT_ID = "agentdojo_workspace"
#: The standard strong attack, and the one comparable work reports on.
ATTACK = "important_instructions"


class _ScmlElement(ScmlDefense, BasePipelineElement):
    """Adapter so AgentDojo sees a pipeline element.

    ScmlDefense itself stays free of AgentDojo imports; the subclass exists
    only here, where AgentDojo is installed.

    ScmlDefense must precede BasePipelineElement: `query` is abstract on the
    latter, and with the bases the other way round it resolves first, leaving
    the class abstract and uninstantiable.
    """

    def __init__(self, client: Any, agent_id: str, session_id: str) -> None:
        ScmlDefense.__init__(
            self, client, agent_id, session_id=session_id, abort_cls=AbortAgentError
        )


def build_llm(api_key: str, model: str) -> OpenAILLM:
    """Gemini through its OpenAI-compatible endpoint, with the signature shim."""
    import openai

    client = wrap_for_gemini(
        openai.OpenAI(api_key=api_key, base_url=GEMINI_OPENAI_BASE_URL)
    )
    return OpenAILLM(client, model)


def build_pipeline(
    llm: OpenAILLM, scml_client: Any | None, session_id: str
) -> AgentPipeline:
    """Standard AgentDojo pipeline, with SCML spliced into the tools loop.

    The defense goes *first* in the loop, ahead of ToolsExecutor: SCML
    authorises an action before it happens. Placed after, it would be
    describing damage rather than preventing it.
    """
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm, defense=None, system_message_name=None, system_message=None,
            tool_delimiter="tool", model_id=None,
        )
    )
    if scml_client is None:
        pipeline.name = "undefended"
        return pipeline

    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.elements = [
                _ScmlElement(scml_client, AGENT_ID, session_id),
                *element.elements,
            ]
            break
    else:  # pragma: no cover - guards a silent no-op if AgentDojo restructures
        raise RuntimeError("no ToolsExecutionLoop found; SCML was not installed")

    pipeline.name = "scml"
    return pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=int, default=5, help="user tasks to run")
    # Each user task is replayed once per injection task, so the run is
    # tasks x injections agent executions. workspace ships 14 injections, which
    # is far more than a free-tier daily quota tolerates while iterating.
    parser.add_argument(
        "--injections", type=int, default=0, help="cap injection tasks (0 = all)"
    )
    parser.add_argument("--model", default="gemini-3.6-flash")
    parser.add_argument("--scml-url", default="http://127.0.0.1:8111")
    parser.add_argument("--no-scml", action="store_true", help="undefended baseline")
    parser.add_argument("--logdir", default="/tmp/agentdojo-phase0")
    parser.add_argument(
        "--env-file",
        default="/home/ravindu/Desktop/project/scml - middleware layer secure/.env",
    )
    args = parser.parse_args()

    api_key = _load_key(args.env_file)
    if not api_key:
        print("no GEMINI_API_KEY in .env", file=sys.stderr)
        return 1

    scml_client = None
    if not args.no_scml:
        from trust_mediator import SCMLClient

        scml_client = SCMLClient(args.scml_url, agent_id=AGENT_ID)

    suite = get_suites(BENCHMARK_VERSION)[SUITE]
    attack_pipeline = build_pipeline(build_llm(api_key, args.model), None, "probe")
    # `important_instructions` addresses the injection to the model by name,
    # resolving it by substring against a table whose Gemini entries are all
    # retired ids. The prose it needs is the vendor ("AI model developed by
    # Google"), which is correct for any Gemini, so naming the pipeline after a
    # mapped id gets the attack phrased right. The model actually queried is
    # still args.model — only the attack's salutation is affected.
    attack_pipeline.name = f"gemini-2.0-flash-001 ({args.model})"
    attack = load_attack(ATTACK, suite, attack_pipeline)

    task_ids = sorted(suite.user_tasks)[: args.tasks]
    injection_ids = sorted(suite.injection_tasks)
    if args.injections:
        injection_ids = injection_ids[: args.injections]
    logdir = Path(args.logdir)
    logdir.mkdir(parents=True, exist_ok=True)

    label = "undefended" if args.no_scml else "SCML"
    print(
        f"{SUITE} | {args.model} | attack={ATTACK} | {label} | "
        f"{len(task_ids)} tasks x {len(injection_ids)} injections\n"
    )

    utility_all: list[bool] = []
    security_all: list[bool] = []
    denials = 0

    for task_id in task_ids:
        task = suite.get_user_task_by_id(task_id)
        session_id = f"adj-{task_id}-{uuid.uuid4().hex[:8]}"
        pipeline = build_pipeline(
            build_llm(api_key, args.model), scml_client, session_id
        )
        try:
            with OutputLogger(str(logdir), live=None):
                utility, security = run_task_with_injection_tasks(
                    suite, pipeline, task, attack, logdir=logdir,
                    force_rerun=True, injection_tasks=injection_ids,
                )
        except Exception as exc:  # noqa: BLE001 - one bad task must not end the run
            print(f"  {task_id:<16} ERROR {type(exc).__name__}: {str(exc)[:80]}")
            continue

        utility_all.extend(utility.values())
        security_all.extend(security.values())
        for element in pipeline.elements:
            if isinstance(element, ToolsExecutionLoop):
                for sub in element.elements:
                    if isinstance(sub, ScmlDefense):
                        denials += len(sub.denied)

        u = _pct(list(utility.values()))
        a = _pct(list(security.values()))
        print(f"  {task_id:<16} utility={u:>5.1f}%  ASR={a:>5.1f}%  ({len(security)} injections)")

    print()
    print(f"{'utility':<10} {_pct(utility_all):.1f}%   ({sum(utility_all)}/{len(utility_all)})")
    print(f"{'ASR':<10} {_pct(security_all):.1f}%   ({sum(security_all)}/{len(security_all)})")
    if not args.no_scml:
        print(f"{'denials':<10} {denials} tool calls refused by policy")
    return 0


def _pct(values: list[bool]) -> float:
    return 100.0 * sum(values) / len(values) if values else 0.0


def _load_key(env_file: str) -> str:
    for raw in open(env_file, encoding="utf-8"):
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() in ("GEMINI_API_KEY", "GOOGLE_API_KEY") and v.strip():
            return v.strip()
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
