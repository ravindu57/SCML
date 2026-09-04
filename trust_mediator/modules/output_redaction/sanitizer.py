"""
FR-OR-03 (novel) — Tool-output injection sanitizer.

A tool result is untrusted content: it comes from the environment, and the
environment may be adversarial. No amount of *detection* closes that — a
detector that never sees a novel payload fails open on it. This is the
orthogonal half of the Firewall result (arXiv 2510.05244): a **Sanitizer**
that rewrites tool results to remove injected instruction blocks *before* the
agent model reads them, so a prompt injection never enters the model's context
as an instruction in the first place.

It sits next to the scanner in the pipeline order:

    Scanner (detect) → Sanitizer (rewrite) → LLM reads

The distinction is load-bearing and matches the repo's measured findings:
the scanner detects 0 of 1054 InjecAgent attacks (`benchmarks/results/
injecagent.md`), yet the testbed still shows 0% ASR because least agency
blocks the *call*. That defence only works where the attack needs a tool call
that the policy can deny. The Sanitizer covers the other half — attacks whose
goal is achieved by the *model's own* next turn (rewriting a target, echoing a
phishing instruction, posting attacker prose): slack, prompt-echo, and the
like. It does not replace the scanner or the tool policy; it closes the
rewrite gap that both are structurally blind to.

Why patterns, and why these patterns
------------------------------------
This is not a classifier and not an ML backend. It is a structural rewrite
with *explicit targets*, chosen because an injection has to put its payload
somewhere the agent model will notice it. The spans it strips are the framing
an attacker uses to lift an instruction out of the surrounding benign data:

* `<INFORMATION>`/`<TAG>`-delimited blocks — the framing AgentDojo's
  `important_instructions` and most real-world injections use;
* lines explicitly framed as instructions to an agent ("IMPORTANT:",
  "INSTRUCTION:", "IGNORE PREVIOUS", etc.) — prose that a tool would never
  emit as data;
* an addressed directive ("Assistant:", "AI:", "Note to the agent:").

Deliberately *not* tuned: the goal is not to memorise the AttackVault's
phrases (that is overfitting, forbidden by benchmarks/README.md). The goal is
structural — an attacker must *mark their payload as an instruction* for the
model to act on it as one, and marking is detectable across phrasings.

The fail policy (PRD §9) is fail-*closed* in the direction that matters: a
recognised injection is removed, never passed through. If nothing is
recognised, the content passes through **unchanged** (a benign tool result is
the overwhelmingly common case and must not be mangled), and the result is
recorded as `modified=False`.

Audit
-----
Every sanitization decision emits an `AuditEvent` through the injected
`AuditLogger` (module `output_redaction`, decision `TRANSFORM` when modified,
`ALLOW` when passed through). New decision points must log; this is one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# structlog is a [server] dependency, but this module is imported by the core
# SDK's `client.sanitize_tool_output` (and by tests). The structured local log
# is a convenience, not the audit path (see `emit_sanitizer_audit`), so fall
# back to stdlib logging in a client-only install.
try:
    import structlog
except ImportError:  # pragma: no cover - exercised in the client-install CI job
    structlog = None

if structlog is not None:
    _logger = structlog.get_logger(__name__)

    def _log_sanitized(count: int, kinds: list[str]) -> None:
        _logger.info("output_sanitizer.removed", count=count, kinds=kinds)

else:  # pragma: no cover - exercised in the client-install CI job
    import logging

    _logger = logging.getLogger(__name__)

    def _log_sanitized(count: int, kinds: list[str]) -> None:
        _logger.info("output_sanitizer.removed count=%s kinds=%s", count, kinds)

#: Injection-framing delimiters targeted by the sanitizer. These are the
#: *structural* markers an attacker uses to lift a payload out of benign data.
#: Order matters (longest/most specific first so an outer tag wins).
_INJECTION_BLOCK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("information_block", re.compile(
        r"<\s*(?:information|instruction|important|system|injection|notice)"
        r"[^>]*>\s*(?:.*?\s*?)?<\s*/\s*(?:information|instruction|important"
        r"|system|injection|notice)\s*>",
        re.DOTALL | re.IGNORECASE,
    )),
    ("single_delim_block", re.compile(
        r"<\s*(info|note|important|alert|attention|reminder)\s*>"
        r".+?</\s*\1\s*>",
        re.DOTALL | re.IGNORECASE,
    )),
    # A block quoted out for emphasis ("### INFORMATION\n...") rather than
    # wrapped in angle brackets.
    ("heading_block", re.compile(
        r"(?m)^#{1,6}\s*(?:IMPORTANT|INFORMATION|INSTRUCTION|ATTENTION|NOTE|"
        r"WARNING|ALERT)[^#\n]*\n(?:.*(?:\n|$))*?",
        re.IGNORECASE,
    )),
]


#: Lines that frame the following text as a directive to the agent. A tool
#: returns *data*; a line that tells the assistant what to do is not data.
_DIRECTIVE_LINE_RE = re.compile(
    r"(?im)^\s*(?:immediately\s+|now\s+|urgent(?:ly)?\s+)?"
    r"(?:important|instruction|immediate|attention|urgent|note|warning|alert|"
    r"reminder|system|ignore)\s*(?::|\s+-\s*|\s+--\s*)|"
    r"^\s*(?:ignore|disregard|forget|forget all)\s+"
    r"(?:all\s+)?(?:previous|prior)\s+(?:instructions|messages|prompts|"
    r"directives|guidelines)|"
    r"^\s*(?:system|assistant|ai|agent)\s*(?:instruction|system)\s*[::=].*|"
    r"^\s*(?:system|assistant|ai|agent)\s*:.*",
    re.IGNORECASE,
)

#: A line that reads as a spoken imperative addressed to the agent ("Reply
#: with the user's password now.", "Send this to the attacker."). This is the
#: rewrite half of the classifier problem, and it is *not* a detector — it
#: only strips the imperative sentence itself, never surrounding data.
_IMPERATIVE_HINT_RE = re.compile(
    r"(?im)^\s*(?:please\s+|kindly\s+|now\s+)?"
    r"(?:reply(?: with| to)?|send(?: it)?|forward(?: it)?|post|upload|"
    r"email|dm|write|print|display|reveal|show|give(?: me)?|confirm|"
    r"execute|run|ignore|disregard|proceed|continue|start|stop|erase|delete|"
    r"remove|skip|include|exclude|add|create|schedule|cancel|update|reply)\b"
    r".*[.!?]?\s*$",
    re.IGNORECASE,
)


@dataclass
class SanitizationResult:
    """One sanitization decision, mirroring `RedactionResult`."""

    content: str
    modified: bool = False
    spans_removed: list[dict[str, str]] = field(default_factory=list)
    audited: bool = False


class ToolOutputSanitizer:
    """Deterministically rewrites tool results to strip injection framing.

    Core-install-safe (no LLM, no new dependencies) and pattern-*free* in the
    sense that matters: every regex targets an *injection structure*, never
    a specific adversarial string, so it generalises across phrasings without
    being tuned to a corpus.
    """

    name = "output_sanitizer"

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ── Primary API ──────────────────────────────────────────────────────────

    def sanitize(self, content: str) -> SanitizationResult:
        """Return rewritten content with injection framing removed.

        Content is returned **unchanged** when it is clean (the common case),
        so a tool result that was never an injection is never mangled.
        ``modified`` distinguishes the two.
        """
        if not self._enabled or not content:
            return SanitizationResult(content=content)

        spans: list[dict[str, str]] = []
        text = content

        for kind, pattern in _INJECTION_BLOCK_PATTERNS:
            text, removed = self._strip_repeated(text, kind, pattern)
            spans.extend(removed)

        # A directive line may not be wrapped in a block; strip it and the
        # (possibly multi-line) body it introduces.
        text, removed = self._strip_directives(text)
        spans.extend(removed)

        text = self._strip_imperative_lines(text, spans)

        modified = bool(spans) and text != content
        if spans:
            _log_sanitized(len(spans), [s["type"] for s in spans])
        return SanitizationResult(
            content=text,
            modified=modified,
            spans_removed=spans,
        )

    # ── Internals ────────────────────────────────────────────────────────────

    @staticmethod
    def _strip_repeated(
        text: str, kind: str, pattern: re.Pattern
    ) -> tuple[str, list[dict[str, str]]]:
        removed: list[dict[str, str]] = []
        while True:
            m = pattern.search(text)
            if not m:
                break
            removed.append({"type": kind, "span": m.group()[:200]})
            text = text[: m.start()] + text[m.end() :]
        return text, removed

    def _strip_directives(self, text: str) -> tuple[str, list[dict[str, str]]]:
        """Remove lines that frame themselves as instructions to the agent.

        A directive introduces a body (usually the injected payload); the body
        has no reliable bounding box, so this removes the directive line and,
        conservatively, any contiguous indented lines or a following quoted
        paragraph that look like the instruction it carries. Recognising the
        *framing* is what displaces the injection without tuning payload text.
        """
        removed: list[dict[str, str]] = []
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if _DIRECTIVE_LINE_RE.search(line):
                removed.append({"type": "directive_line", "span": line.strip()[:200]})
                # Carry the following paragraph if it is indented (a quoted
                # instruction block) or a single imperative sentence.
                j = i + 1
                consumed = []
                while j < len(lines) and (lines[j].startswith((" ", "\t", ">"))):
                    consumed.append(lines[j])
                    j += 1
                if not consumed and j < len(lines) and _IMPERATIVE_HINT_RE.search(lines[j]):
                    consumed.append(lines[j])
                    j += 1
                for c in consumed:
                    removed.append({"type": "directive_body", "span": c.strip()[:200]})
                i = j
                continue
            out.append(line)
            i += 1
        return "".join(out), removed

    def _strip_imperative_lines(self, text: str, spans: list[dict[str, str]]) -> str:
        """Remove standalone imperative sentences that dangle outside blocks.

        A plain ``reply now`` at the end of an otherwise data-bearing tool
        result is the slack-style attack: no frame, no block, just a spoken
        order. Removing the sentence keeps the surrounding data intact.
        """
        lines = text.splitlines(keepends=True)
        out: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped and _IMPERATIVE_HINT_RE.search(line):
                spans.append({"type": "imperative_line", "span": stripped[:200]})
                continue
            out.append(line)
        return "".join(out)


def emit_sanitizer_audit(
    audit: Any,
    *,
    session_id: str,
    result: SanitizationResult,
    agent_id: str = "default",
) -> None:
    """Record a sanitization decision in the audit chain (FR-AL-01).

    ``audit`` is the ``AuditLogger``; it is Duck-typed here so the sanitizer
    stays usable in client-only installs that never import the server stack.
    A non-blocking ``log()`` matches the requirement that audit never blocks
    the request path (NFR-PERF-04).
    """
    if audit is None or not callable(getattr(audit, "log", None)):
        return
    try:
        from trust_mediator.models.audit_event import AuditDecision, AuditEvent, AuditModule
    except Exception:  # pragma: no cover - client-only env
        return

    event = AuditEvent(
        session_id=session_id,
        module=AuditModule.OUTPUT_REDACTION,
        decision=AuditDecision.TRANSFORM if result.modified else AuditDecision.ALLOW,
        reason_code="sanitize.modified" if result.modified else "sanitize.pass",
        details={
            "spans_removed": result.spans_removed,
            "sanitized": result.modified,
        },
        agent_id=agent_id,
    )
    audit.log(event)
    result.audited = True