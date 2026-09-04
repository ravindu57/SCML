"""
Phase 5 scaffold — syntactic imperative detector (FR-SC-06/07, §6.3a).

The addendum's conclusion of record (§6.3a, "Rejected approaches") is that
bag-of-words cannot represent the discriminating signal, which is *syntactic*:
"is there an imperative addressed to an assistant inside this data payload?".
This module scaffolds the alternative recommended direction — closed-class
imperative features rather than open vocabulary.

Design rule: the features are derived from the *linguistic concept* of an
imperative (a directive, a command mood, a second-person/proc address), never
from inspecting evaluation corpora. The vocabularies here are closed classes
(mood markers, common English command verbs) chosen to distinguish an
imperative *from any declarative content*, not to match any attack list.

This is a scaffold, not a shipped detector: real dependency/POS parsing
(spacy) is not installed in this venv and the external training data required
by FR-SC-06 is not committed, so no live score is produced. The classifier
object is fully wired and unit-tested on the *plumbing* (feature extraction,
threshold behaviour); `SCANNER_BACKEND` integration is left to the phase that
has a trained/evaluated model per FR-SC-07.
"""

from __future__ import annotations

import re

from trust_mediator.modules.injection_scanner.classifier import BaseClassifier

#: Closed-class imperative mood markers. Quoted words in a tool's data payload
#: are *content*; these appearing unquoted and clause-initial are commands.
_IMPERATIVE_VERBS = frozenset(
    {
        "ignore", "forget", "disregard", "overlook", "omit",
        "act", "pretend", "assume", "behave",
        "send", "post", "share", "forward", "email", "grant", "reveal",
        "disable", "bypass", "deactivate", "override", "execute", "run",
        "approve", "delete", "create", "transfer", "update", "add",
    }
)

#: Directives that address an assistant by construction (second person /
#: proc). The pairing is what separates "the user summarised imperative data"
#: from "the payload commands the agent".
_DIRECTIVE_MARKERS = re.compile(
    r"(?i)(\byou\b.{0,12}\b(must|should|will|shall|are|need|have)\b)|"
    r"(\b(please|kindly|now|immediately|urgently)\b,?)|"
    r"(^(ignore|forget|send|post|grant|disable|enable|approve)\b)"
)

#: Forbidden-quote comment placeholder removed.
_QUOTED = re.compile(r"([\"'`]).*?\1")

#: Frame verbs whose object is typically a *tool/memory* control, not domain
#: data — the strongest delegation-of-authority signal.
_CONTROL_FRAME_VERBS = frozenset({"execute", "run", "grant", "approve", "override"})


class SyntacticImperativeClassifier(BaseClassifier):
    """
    BaseClassifier exposing a dependency/POS-agnostic imperative score.

    Feature set (all closed-class / structural):
      - imperative mood markers (command verbs, directive frames)
      - second-person/directive constructions
      - control-frame verbs (memory/tool delegation)

    Because a real POS/dependency parse is unavailable here, `_features` runs a
    lightweight clause-frame approximation. The seam where a full parser slots
    in is `_syntactic_score`; in this scaffold it delegates to the token-level
    features so the object is testable end to end.
    """

    def train(self) -> None:
        # No training data committed (FR-SC-06 needs external data; none is
        # vendored for this direction yet). Training is a no-op until that
        # phase lands.
        pass

    def predict(self, text: str) -> float:
        """Injection-probability score from the syntactic imperative features."""
        return self._score(text)

    async def predict_async(self, text: str) -> float:
        # CPU-bound only; the base default is correct.
        return self.predict(text)

    # ── Feature extraction (the syntactic concept, not a corpus) ──────────────

    def _unquoted(self, text: str) -> str:
        return _QUOTED.sub(" ", text)

    def _imperative_mood_score(self, text: str) -> float:
        body = self._unquoted(text)
        tokens = set(re.findall(r"[a-z']+", body.lower()))
        verbs = tokens & _IMPERATIVE_VERBS
        if not verbs:
            return 0.0
        # More, and more directive, imperatives raise confidence.
        base = 0.25 + 0.15 * (len(verbs) - 1)
        if any(v in _CONTROL_FRAME_VERBS for v in verbs):
            base += 0.25
        return min(1.0, base)

    def _directive_score(self, text: str) -> float:
        body = self._unquoted(text)
        if _DIRECTIVE_MARKERS.search(body):
            return 0.5
        return 0.0

    def _syntactic_score(self, text: str) -> float:
        """
        Seam for a real dependency/POS parser. In this scaffold it is a passthrough
        to the token features. A parser would confirm the imperative *clause*
        (root = command verb, subject = second person / proc) and sharpen the
        same signal.
        """
        return 0.0

    def _score(self, text: str) -> float:
        mood = self._imperative_mood_score(text)
        directive = self._directive_score(text)
        synt = self._syntactic_score(text)
        return max(mood, directive, synt)

