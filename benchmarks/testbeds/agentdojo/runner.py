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

from agentdojo.agent_pipeline import (
    AgentPipeline,
    PipelineConfig,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import (
    run_task_with_injection_tasks,
    run_task_without_injection_tasks,
)
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

from benchmarks.testbeds.agentdojo.defense import ScmlDefense
from benchmarks.testbeds.agentdojo.gemini_compat import (
    GEMINI_OPENAI_BASE_URL,
    wrap_for_gemini,
)

BENCHMARK_VERSION = "v1.2.1"
#: One agent_id per suite, and one policy per agent_id. A shared id would
#: make the allow-list the union of everything any suite needs, which is the
#: opposite of least agency.
DEFAULT_SUITE = "workspace"
#: The standard strong attack, and the one comparable work reports on.
ATTACK = "important_instructions"


class _ScmlToolsExecutor(ToolsExecutor):
    """Executes the tool calls SCML authorises, and answers the ones it refuses.

    Replaces AgentDojo's ToolsExecutor rather than sitting in front of it. An
    element placed *before* the executor can only wave a batch through or abort
    the run, and aborting is what drove utility to 0% in the first pilot:
    refusing an injected `send_email` killed the user's unfinished task too.

    A refused call gets a tool result carrying the reason — the same shape
    AgentDojo already uses for an unknown tool. The agent sees the refusal,
    keeps its context, and can continue with the rest of the user's work. Only
    the action is blocked, not the agent.
    """

    def __init__(self, defense: ScmlDefense) -> None:
        super().__init__()
        self._defense = defense

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Any = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Any, dict[str, Any]]:
        messages = list(messages)
        extra_args = extra_args or {}

        verdicts = self._defense.evaluate(messages)
        refused = [(c, d) for c, d in verdicts if not d.allowed]
        if not verdicts or not refused:
            return super().query(query, runtime, env, messages, extra_args)

        proposed = messages[-1]
        allowed = [c for c, d in verdicts if d.allowed]

        # Run the real executor over the allowed calls only.
        trimmed = dict(proposed)
        trimmed["tool_calls"] = allowed
        q, rt, e, out, ex = super().query(
            query, runtime, env, [*messages[:-1], trimmed], extra_args
        )

        # Restore the model's original message: the transcript should show what
        # it proposed, not a version edited to look compliant. Every tool_call
        # then needs a matching result, so answer the refused ones.
        out = list(out)
        out[len(messages) - 1] = proposed
        for call, decision in refused:
            out.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string("")],
                    tool_call_id=call.id,
                    tool_call=call,
                    error=self._defense.refusal_text(decision),
                )
            )
        return q, rt, e, out, ex


def is_openai(model: str) -> bool:
    return model.startswith(("gpt-", "o1-", "o3-", "o4-"))


def build_llm(api_key: str, model: str) -> OpenAILLM:
    """An LLM element for `model`.

    OpenAI models go straight to the native endpoint. Gemini needs its
    OpenAI-compatible URL plus the thought-signature shim, without which the
    tool loop dies on turn two — see gemini_compat.
    """
    import openai

    if is_openai(model):
        # The SDK retries twice by default, which a 560-case run outlasts: one
        # throttled call becomes a failed task, and a failed task is a hole in
        # the result rather than a slow one. The Gemini path has its own backoff
        # in the shim; this is the equivalent for the native path.
        return OpenAILLM(openai.OpenAI(api_key=api_key, max_retries=8), model)

    client = wrap_for_gemini(
        openai.OpenAI(api_key=api_key, base_url=GEMINI_OPENAI_BASE_URL)
    )
    return OpenAILLM(client, model)


def build_pipeline(
    llm: OpenAILLM,
    scml_client: Any | None,
    session_id: str,
    *,
    agent_id: str = "agentdojo_workspace",
    auto_approve: bool = False,
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

    defense = ScmlDefense(
        scml_client, agent_id, session_id=session_id, auto_approve=auto_approve
    )
    replaced = False
    for element in pipeline.elements:
        if isinstance(element, ToolsExecutionLoop):
            element.elements = [
                _ScmlToolsExecutor(defense) if isinstance(sub, ToolsExecutor) else sub
                for sub in element.elements
            ]
            replaced = any(
                isinstance(sub, _ScmlToolsExecutor) for sub in element.elements
            )
            break
    if not replaced:  # pragma: no cover - AgentDojo restructured its loop
        raise RuntimeError("no ToolsExecutor found; SCML was not installed")

    pipeline.name = "scml"
    # Carried on the pipeline so the caller can read what was refused without
    # walking the element tree again.
    pipeline.scml_defense = defense
    return pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default=DEFAULT_SUITE,
                        choices=["workspace", "travel", "banking", "slack"])
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
    # Utility with no attack at all. This is the ceiling: without it there is no
    # way to tell whether a low defended score is the mediator refusing work or
    # simply the model failing the task.
    parser.add_argument(
        "--no-attack", action="store_true", help="benign utility, no injections"
    )
    # Stand in for a human reviewer. `require_approval` is otherwise counted as
    # a refusal, which makes the measured utility a floor rather than an
    # estimate of a deployment that has someone to ask.
    parser.add_argument(
        "--auto-approve", action="store_true", help="treat require_approval as allowed"
    )
    parser.add_argument("--logdir", default="/tmp/agentdojo-phase0")
    parser.add_argument(
        "--env-file",
        default="/home/ravindu/Desktop/project/scml - middleware layer secure/.env",
    )
    args = parser.parse_args()

    api_key = _load_key(args.env_file, args.model)
    if not api_key:
        needed = "OPENAI_API_KEY" if is_openai(args.model) else "GEMINI_API_KEY"
        print(f"no {needed} in {args.env_file}", file=sys.stderr)
        return 1

    agent_id = f"agentdojo_{args.suite}"
    scml_client = None
    if not args.no_scml:
        from trust_mediator import SCMLClient

        scml_client = SCMLClient(args.scml_url, agent_id=agent_id)

    suite = get_suites(BENCHMARK_VERSION)[args.suite]
    attack_pipeline = build_pipeline(build_llm(api_key, args.model), None, "probe")
    # `important_instructions` addresses the injection to the model by name,
    # resolving it by substring against a table of pinned ids. Naming the
    # attack pipeline after a mapped id gets the salutation right; the model
    # actually queried is args.model and is unaffected. For Gemini every mapped
    # id is retired, but they all resolve to the same vendor prose, so any of
    # them is correct.
    mapped = "gpt-4o-mini-2024-07-18" if is_openai(args.model) else "gemini-2.0-flash-001"
    attack_pipeline.name = f"{mapped} ({args.model})"
    attack = None if args.no_attack else load_attack(args.attack, suite, attack_pipeline)

    task_ids = sorted(suite.user_tasks)[: args.tasks]
    injection_ids = sorted(suite.injection_tasks)
    if args.injections:
        injection_ids = injection_ids[: args.injections]
    logdir = Path(args.logdir)
    logdir.mkdir(parents=True, exist_ok=True)

    label = "undefended" if args.no_scml else "SCML"
    if args.auto_approve:
        label += " +approver"
    if args.no_attack:
        print(f"{args.suite} | {args.model} | NO ATTACK | {label} | {len(task_ids)} tasks\n")
    else:
        print(
            f"{args.suite} | {args.model} | attack={args.attack} | {label} | "
            f"{len(task_ids)} tasks x {len(injection_ids)} injections\n"
        )

    utility_all: list[bool] = []
    security_all: list[bool] = []
    denials = 0
    approvals = 0

    for task_id in task_ids:
        task = suite.get_user_task_by_id(task_id)
        session_id = f"adj-{args.suite}-{task_id}-{uuid.uuid4().hex[:8]}"
        pipeline = build_pipeline(
            build_llm(api_key, args.model), scml_client, session_id,
            agent_id=agent_id, auto_approve=args.auto_approve,
        )
        try:
            with OutputLogger(str(logdir), live=None):
                if args.no_attack:
                    # One run, no injection: what the agent manages unopposed.
                    util_bool, _ = run_task_without_injection_tasks(
                        suite, pipeline, task, logdir=logdir, force_rerun=True
                    )
                    utility, security = {task_id: util_bool}, {}
                else:
                    utility, security = run_task_with_injection_tasks(
                        suite, pipeline, task, attack, logdir=logdir,
                        force_rerun=True, injection_tasks=injection_ids,
                    )
        except Exception as exc:  # noqa: BLE001 - one bad task must not end the run
            print(f"  {task_id:<16} ERROR {type(exc).__name__}: {str(exc)[:80]}")
            continue

        utility_all.extend(utility.values())
        security_all.extend(security.values())
        defense = getattr(pipeline, "scml_defense", None)
        refused: list[Any] = list(defense.denied) if defense else []
        gated = [d for d in (defense.decisions if defense else []) if d.needs_approval]
        denials += len(refused)
        approvals += len(gated)

        u = _pct(list(utility.values()))
        note = ""
        if refused:
            # Which tool was refused decides how to read a utility drop: an
            # exfiltration tool means least agency worked, a read tool means
            # the taint approximation is over-blocking.
            note = "  denied: " + ", ".join(sorted({d.tool for d in refused}))
        if gated:
            note += "  gated: " + ", ".join(sorted({d.tool for d in gated}))
        if args.no_attack:
            print(f"  {task_id:<16} utility={u:>5.1f}%{note}")
        else:
            a = _pct(list(security.values()))
            print(
                f"  {task_id:<16} utility={u:>5.1f}%  ASR={a:>5.1f}%  "
                f"({len(security)} injections){note}"
            )

    print()
    print(f"{'utility':<10} {_pct(utility_all):.1f}%   ({sum(utility_all)}/{len(utility_all)})")
    if not args.no_attack:
        print(
            f"{'ASR':<10} {_pct(security_all):.1f}%   "
            f"({sum(security_all)}/{len(security_all)})"
        )
    if not args.no_scml:
        hard = denials - (0 if args.auto_approve else approvals)
        print(f"{'denials':<10} {denials} tool calls refused by policy")
        # Split out because the two are not the same kind of loss. A hard deny
        # is work the policy will never permit; a gated call is work waiting on
        # a reviewer who does not exist in a benchmark but does in a deployment.
        print(f"{'  hard':<10} {hard} denied outright")
        print(
            f"{'  gated':<10} {approvals} needed human approval"
            + (" (auto-approved)" if args.auto_approve else " (counted as refused)")
        )
    return 0


def _pct(values: list[bool]) -> float:
    return 100.0 * sum(values) / len(values) if values else 0.0


def _load_key(env_file: str, model: str) -> str:
    wanted = (
        ("OPENAI_API_KEY",)
        if is_openai(model)
        else ("GEMINI_API_KEY", "GOOGLE_API_KEY")
    )
    for raw in open(env_file, encoding="utf-8"):
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() in wanted and v.strip():
            return v.strip()
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
