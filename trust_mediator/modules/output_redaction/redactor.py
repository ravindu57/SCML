"""
§6.6 — Output Redaction Layer.

Redacts PII, secrets, and enforces data-flow exfiltration policy (FR-OR-01, FR-OR-02).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RedactionResult:
    content: str
    redactions_applied: list[dict[str, str]] = field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    action_allowed: bool = True


_PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED:EMAIL]"),
    ("phone", re.compile(r"\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"), "[REDACTED:PHONE]"),
    # The rule above only recognises the North American form, so every other
    # country's numbers left the mediator intact — measured on "+44 7700
    # 900123". PII is not US-only, and an egress filter that silently depends
    # on locale is worse than one that is absent, because it looks like cover.
    # Matches E.164-style international numbers: + country code, then 8-15
    # digits with optional separators.
    ("phone_intl", re.compile(r"\+[1-9]\d{0,2}[\s\-.]?\d[\d\s\-.]{6,14}\d\b"),
     "[REDACTED:PHONE]"),
    ("ssn", re.compile(r"\b\d{3}[\-\s]\d{2}[\-\s]\d{4}\b"), "[REDACTED:SSN]"),
    ("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[REDACTED:CREDIT_CARD]"),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED:IP_ADDRESS]"),
]

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    # Vendor-prefixed credentials. The labelled `api_key` rule below only fires
    # when the word "api key" or similar is adjacent AND the value is 20+ chars,
    # so a bare token missed on both counts: the harm analysis measured
    # `sk-live-…` (18 chars) surviving egress in 3 of 5 output cases. These
    # prefixes are issuer-defined and self-identifying — the same signal
    # gitleaks and trufflehog key off — so matching them does not depend on
    # surrounding wording or on clearing an entropy floor.
    ("vendor_token", re.compile(
        r"\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{8,}"   # OpenAI / Stripe
        r"|\bgh[pousr]_[A-Za-z0-9]{16,}"                               # GitHub
        r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"                             # Slack
        r"|\bAIza[0-9A-Za-z\-_]{35}"                                   # Google API
    ), "[REDACTED:API_KEY]"),
    ("api_key", re.compile(r"(?i)(api[_\-]?key|access[_\-]?token|auth[_\-]?token)[=:\s\"']+[A-Za-z0-9\-_]{20,}"), "[REDACTED:API_KEY]"),
    ("password", re.compile(r"(?i)(password|passwd|pwd)[=:\s\"']+\S{6,}"), "[REDACTED:PASSWORD]"),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "[REDACTED:PRIVATE_KEY]"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"), "[REDACTED:JWT]"),
]

_HIGH_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LEN = 20


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


#: Always protected, whatever a tenant's policy lists: a tenant may add classes
#: or permit destinations, but not declare its PII unprotected.
BUILTIN_PROTECTED_CLASSES = ("pii", "secret", "credential")


def normalise_name(value: object) -> str:
    """Canonical form of a data-class label or destination.

    NFKC, casefold, and format characters (zero-width and similar) removed, so
    "PII", "pii\u200b" and "ｐｉｉ" all mean "pii". Labels are declared by the
    caller, so this only stops accidental and padded mismatches; a caller that
    omits a label is not flow-checked at all (labels are advisory).
    """
    import unicodedata

    text = unicodedata.normalize("NFKC", str(value))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.strip().casefold()


class OutputRedactor:
    def __init__(self, policy_config: dict[str, Any] | None = None) -> None:
        cfg = policy_config or {}
        self._pii_enabled: bool = cfg.get("pii_patterns_enabled", True)
        self._entropy_threshold: float = cfg.get("entropy_threshold", _HIGH_ENTROPY_THRESHOLD)
        protected = cfg.get("protected_classes", ["pii", "secret", "credential"])
        rules = cfg.get("data_flow_rules", {})
        # A malformed section must not read as "no restriction". Validation
        # rejects it at write time; this is the runtime backstop (§9): with a
        # config error, any labelled output is blocked.
        self._config_error = ""
        if not isinstance(protected, list) or not all(isinstance(c, str) for c in protected):
            self._config_error, protected = "protected_classes is not a list of names", []
        if not isinstance(rules, dict) or not all(
            isinstance(k, str) and k.strip()
            and isinstance(v, list) and all(isinstance(d, str) for d in v)
            for k, v in rules.items()
        ):
            self._config_error, rules = "data_flow_rules is not a map of class -> destinations", {}
        self._flow_rules: dict[str, set[str]] = {
            normalise_name(k): {normalise_name(d) for d in v} for k, v in rules.items()
        }
        # A class named in a rule is protected whether or not it is also listed,
        # and the built-in classes are protected regardless.
        self._protected_classes: set[str] = (
            {normalise_name(c) for c in protected}
            | set(self._flow_rules)
            | set(BUILTIN_PROTECTED_CLASSES)
        )

    def redact(self, content: str, destination: str = "user", data_class_labels: list[str] | None = None) -> RedactionResult:
        redactions: list[dict[str, str]] = []
        text = content

        if self._pii_enabled:
            text, r = self._redact_patterns(text, _PII_PATTERNS)
            redactions.extend(r)

        text, r = self._redact_patterns(text, _SECRET_PATTERNS)
        redactions.extend(r)

        text, r = self._redact_high_entropy(text)
        redactions.extend(r)

        blocked, reason = self._check_data_flow(destination, data_class_labels or [])
        if blocked:
            logger.warning("output_redactor.exfiltration_blocked", destination=destination, reason=reason)
            return RedactionResult(
                content="[ACTION BLOCKED — data exfiltration policy violation]",
                redactions_applied=redactions,
                blocked=True,
                block_reason=reason,
                action_allowed=False,
            )

        if redactions:
            logger.info("output_redactor.redacted", count=len(redactions))

        return RedactionResult(content=text, redactions_applied=redactions, action_allowed=True)

    def _redact_patterns(self, text: str, patterns: list[tuple[str, re.Pattern, str]]) -> tuple[str, list[dict]]:
        redactions = []
        for name, pattern, label in patterns:
            if pattern.search(text):
                redactions.append({"type": name, "label": label})
                text = pattern.sub(label, text)
        return text, redactions

    def _redact_high_entropy(self, text: str) -> tuple[str, list[dict]]:
        redactions = []
        pattern = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % _MIN_SECRET_LEN)
        parts: list[str] = []
        last = 0
        for m in pattern.finditer(text):
            token = m.group()
            parts.append(text[last:m.start()])
            if _shannon_entropy(token) >= self._entropy_threshold:
                parts.append("[REDACTED:HIGH_ENTROPY]")
                redactions.append({"type": "high_entropy", "label": "[REDACTED:HIGH_ENTROPY]"})
            else:
                parts.append(token)
            last = m.end()
        parts.append(text[last:])
        return "".join(parts), redactions

    def _check_data_flow(self, destination: str, labels: list[str]) -> tuple[bool, str]:
        """FR-OR-02 / PRD §6.6: deny moving a protected class to a sink the
        policy does not permit for it.

        Deny by default. A protected class with no rule, or an empty one, may
        flow nowhere. It used to be the reverse, so the shipped policies
        (``data_flow_rules: {}``) let every protected class flow everywhere.
        Labels are matched case-insensitively, so "PII" cannot slip past "pii".
        """
        if not labels:
            return False, ""
        if self._config_error:
            return True, f"Data-flow policy is malformed ({self._config_error}) — fail-closed"
        sink = normalise_name(destination)
        for raw in labels:
            label = normalise_name(raw)
            if label not in self._protected_classes:
                continue
            allowed = self._flow_rules.get(label)
            if not allowed:
                return True, (
                    f"Data class '{label[:64]}' is protected and the policy permits it no "
                    f"destination — deny by default"
                )
            if sink not in allowed:
                return True, f"Data class '{label[:64]}' cannot flow to '{sink[:64]}'"
        return False, ""
