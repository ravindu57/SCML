"""
Tool-affordance imperative detector — research prototype (FR-SC-07).

The question it asks of untrusted content is not "does this look like an
attack?" but "**is there a directive addressed to the assistant that this
particular agent could carry out with one of its own tools?**" An injection can
only do harm by getting the agent to act, and the agent can only act through
its tools, which SCML's policy store already lists.

Closest prior art is SARA's Action Probe (Guo et al., arXiv 2608.27146, 2026),
which conditions on the tool set through an LLM. This is the cheap version:
deterministic, CPU-only, no LLM call, no attack vocabulary. See
docs/research/DETECTION_LITERATURE_REVIEW.md.

Pipeline, per piece of untrusted text:

1. **Segment by structure.** Tool output is usually a JSON (or Python-literal)
   document, and the injection sits inside one string value. Scoring each
   string leaf on its own keeps a field like ``review_content`` from being
   drowned by the surrounding data. Text that is not structured is used whole.
2. **Find directives** with a dependency parse (spaCy): a base-form verb with no
   subject (``Transfer $500…``), ``you`` + modal (``you must…``, ``could you…``),
   or ``I need/want you to …``. Grammatical mood, not a word list.
3. **Match each directive to the agent's tools.** The directive's verb phrase is
   embedded (bge-small-en-v1.5 via onnxruntime) and compared by cosine to each
   tool's descriptor, built from its name (``BankManagerTransferFunds`` ->
   "bank manager transfer funds") plus any description and argument names.
4. **Score** = max over directives of ``mood weight x affordance``, where
   affordance is either the best tool similarity (``score``) or the *contrast*,
   best minus mean similarity over the agent's tools (``score_contrast``).
   Contrast exists because embedding cosine has a high floor: procedural text
   ("press and hold the power button") is vaguely similar to every tool, while
   an injection is specific to one. Which variant is used is decided on
   external calibration data, never on a held-out set.

The thresholds are not fitted here. They are calibrated on external data in
``evaluate.py`` and frozen before the held-out sets are scored.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field

import numpy as np

#: Mood weights. Fixed by grammar, not fitted: a bare imperative is the
#: canonical command form; a "you"-addressed modal is a softer request.
IMPERATIVE_WEIGHT = 1.0
ADDRESSED_WEIGHT = 0.8

_MODALS = {"must", "should", "need", "have", "will", "shall", "can", "could", "would", "may"}
_WANT_VERBS = {"need", "want", "like", "ask", "require", "expect"}
_YOU = {"you", "u", "yourself"}
_SKIP_DEPS = {"nsubj", "nsubjpass", "expl", "punct", "intj", "aux", "auxpass", "mark", "cc", "discourse"}
#: Longest text scored in full. Longer input is truncated (and the result says
#: so) to keep latency bounded; a truncation is reported, never silent.
MAX_CHARS = 20_000
_MAX_PHRASE_TOKENS = 14
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


@dataclass(frozen=True)
class ToolSpec:
    """What the policy store knows about a tool: its name, and optionally more."""

    name: str
    description: str = ""
    arguments: tuple[str, ...] = ()

    def descriptor(self) -> str:
        words = _CAMEL.sub(" ", self.name).replace("_", " ").replace("-", " ").lower()
        parts = [words]
        if self.description:
            parts.append(self.description)
        if self.arguments:
            parts.append("arguments: " + ", ".join(a.replace("_", " ") for a in self.arguments))
        return ". ".join(parts)


@dataclass(frozen=True)
class Directive:
    sentence: str
    phrase: str
    mood: str  # "imperative" | "addressed"
    weight: float


@dataclass
class Detection:
    score: float  # mood x best-tool similarity
    score_contrast: float  # mood x (best - mean) tool similarity
    imperative: float  # ablation: mood alone
    affordance: float  # ablation: best tool similarity over all sentences, mood ignored
    affordance_contrast: float  # ablation: the same, as contrast
    directives: list[Directive] = field(default_factory=list)
    top_tool: str | None = None
    top_phrase: str | None = None
    truncated: bool = False


def _leaves(value, out: list[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _leaves(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _leaves(v, out)


def segment(text: str) -> list[str]:
    """String leaves of a JSON / Python-literal document, else the text itself."""
    stripped = text.strip()
    if stripped[:1] in "{[":
        for parse in (json.loads, ast.literal_eval):
            try:
                doc = parse(stripped)
            except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
                continue
            leaves: list[str] = []
            _leaves(doc, leaves)
            return leaves or [text]
    return [text]


def _is_you(tok) -> bool:
    return tok.lower_ in _YOU


def _phrase(verb) -> str:
    """The verb's lemma plus its complements: what the directive asks to be done."""
    toks = [verb]
    for child in verb.children:
        if child.dep_ in _SKIP_DEPS or child.lower_ == "please":
            continue
        toks.extend(child.subtree)
    toks = sorted({t.i: t for t in toks}.values(), key=lambda t: t.i)[:_MAX_PHRASE_TOKENS]
    words = [verb.lemma_.lower() if t.i == verb.i else t.text for t in toks]
    return " ".join(words)


def directives_in(sent) -> list[Directive]:
    """Directive clauses in one parsed sentence. Grammar only, no vocabulary."""
    found: list[Directive] = []
    root = sent.root
    candidates = [root] + [c for c in root.children if c.dep_ == "conj" and c.pos_ in ("VERB", "AUX")]
    for v in candidates:
        if v.pos_ not in ("VERB", "AUX"):
            continue
        subjects = [c for c in v.children if c.dep_ in ("nsubj", "nsubjpass", "expl")]
        auxes = [c for c in v.children if c.dep_ in ("aux", "auxpass")]
        if not subjects and v.tag_ == "VB" and not any(a.lower_ == "to" for a in auxes):
            found.append(Directive(sent.text, _phrase(v), "imperative", IMPERATIVE_WEIGHT))
            continue
        if any(_is_you(s) for s in subjects) and (
            any(a.lower_ in _MODALS for a in auxes) or v.lemma_ in {"need", "have"}
        ):
            target = v
            # "you need to transfer ..." / "you have to send ...": the action is the xcomp.
            for c in v.children:
                if c.dep_ == "xcomp" and c.pos_ == "VERB":
                    target = c
            found.append(Directive(sent.text, _phrase(target), "addressed", ADDRESSED_WEIGHT))
            continue
        if v.lemma_ in _WANT_VERBS:
            # "I need you to wire the money" -> ccomp/xcomp verb whose subject is "you".
            for c in v.children:
                if c.dep_ in ("ccomp", "xcomp") and c.pos_ == "VERB":
                    if any(_is_you(s) for s in c.children if s.dep_ in ("nsubj", "dobj")) or any(
                        _is_you(s) for s in v.children if s.dep_ == "dobj"
                    ):
                        found.append(Directive(sent.text, _phrase(c), "addressed", ADDRESSED_WEIGHT))
    return found


class AffordanceDetector:
    """Scores untrusted text against one agent's tool set. Build once per agent."""

    def __init__(self, tools: list[ToolSpec], embedder=None, nlp=None) -> None:
        if not tools:
            raise ValueError("an agent with no tools has no affordances to match")
        self.tools = list(tools)
        self._nlp = nlp or _load_nlp()
        self._embedder = embedder or _load_embedder()
        self._tool_vecs = _normalise(
            np.array(list(self._embedder.passage_embed([t.descriptor() for t in self.tools])))
        )

    def _best_tool(self, phrases: list[str]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Per phrase: best similarity, its tool index, and best minus mean."""
        vecs = _normalise(np.array(list(self._embedder.query_embed(phrases))))
        sims = vecs @ self._tool_vecs.T
        best = sims.max(axis=1)
        return best, sims.argmax(axis=1), best - sims.mean(axis=1)

    def score(self, text: str) -> Detection:
        truncated = len(text) > MAX_CHARS
        leaves = segment(text[:MAX_CHARS])
        directives: list[Directive] = []
        sentences: list[str] = []
        for doc in self._nlp.pipe(leaves):
            for sent in doc.sents:
                if not sent.text.strip():
                    continue
                sentences.append(sent.text.strip())
                directives.extend(directives_in(sent))

        affordance = affordance_contrast = 0.0
        if sentences:
            sims, _, contrast = self._best_tool(sentences)
            affordance, affordance_contrast = float(sims.max()), float(contrast.max())

        if not directives:
            return Detection(0.0, 0.0, 0.0, affordance, affordance_contrast, [], truncated=truncated)

        sims, idx, contrast = self._best_tool([d.phrase for d in directives])
        weights = np.array([d.weight for d in directives])
        combined = weights * np.clip(sims, 0.0, 1.0)
        combined_contrast = weights * np.clip(contrast, 0.0, 1.0)
        best = int(combined.argmax())
        return Detection(
            score=float(combined[best]),
            score_contrast=float(combined_contrast.max()),
            imperative=max(d.weight for d in directives),
            affordance=affordance,
            affordance_contrast=affordance_contrast,
            directives=directives,
            top_tool=self.tools[int(idx[best])].name,
            top_phrase=directives[best].phrase,
            truncated=truncated,
        )


def _normalise(m: np.ndarray) -> np.ndarray:
    return m / np.clip(np.linalg.norm(m, axis=1, keepdims=True), 1e-12, None)


def _load_nlp():
    import spacy

    # NER is unused; dropping it saves about a third of the parse time.
    return spacy.load("en_core_web_sm", exclude=["ner"])


#: Where the embedding model is cached. fastembed's default is a temp dir that
#: does not survive a reboot.
EMBED_MODEL = "BAAI/bge-small-en-v1.5"


def _load_embedder():
    from fastembed import TextEmbedding

    cache = os.environ.get(
        "SCML_FASTEMBED_CACHE", os.path.expanduser("~/.cache/scml-fastembed")
    )
    # threads=1: the score must be identical run to run (a determinism gate),
    # and multi-threaded ONNX reductions are not guaranteed to be.
    return TextEmbedding(EMBED_MODEL, cache_dir=cache, threads=1)
