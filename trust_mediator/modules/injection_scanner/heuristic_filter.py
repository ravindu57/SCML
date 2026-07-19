"""
§6.3 — Injection Scanner: heuristic pre-filter.

Fast regex/pattern pre-filter that runs before the ML classifier,
catching obvious injections at near-zero cost. Covers 60+ known patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class HeuristicMatch:
    pattern_name: str
    matched_text: str
    severity: float          # 0.0–1.0 — used to weight the overall score


# ── Pattern library ───────────────────────────────────────────────────────────
_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern_name, regex, severity)

    # Role / identity hijacking
    ("role_override_system",    r"(?i)\b(you are now|act as|pretend to be|your new role is|roleplay as)\b", 0.90),
    ("role_override_forget",    r"(?i)\b(forget (your|all) (previous |prior )?(instructions|rules|constraints|training))\b", 0.95),
    ("role_override_ignore",    r"(?i)\b(ignore (all |your )?(previous |prior )?(instructions|system prompt|guidelines))\b", 0.95),
    ("role_override_disregard", r"(?i)\bdisregard (your |all )?(previous |prior )?(instructions|rules|guidelines)\b", 0.90),

    # Privilege escalation
    ("priv_esc_admin",          r"(?i)\b(you (have|now have) (root|admin|sudo|superuser|god mode) (access|privileges|rights))\b", 0.95),
    ("priv_esc_override",       r"(?i)\bsafety (override|bypass|deactivated|disabled)\b", 0.95),
    ("priv_esc_jailbreak",      r"(?i)\b(jailbreak|DAN mode|developer mode|god mode|unrestricted mode)\b", 0.90),
    ("priv_esc_unlock",         r"(?i)\bunlock (all |hidden )?(capabilities|features|modes|restrictions)\b", 0.85),

    # Instruction injection markers
    ("inst_tag_system",         r"(?i)<\s*(SYSTEM|SYS|INST|INSTRUCTION|HUMAN|ASSISTANT|USER)\s*>", 0.90),
    ("inst_tag_bracket",        r"(?i)\[(SYSTEM|INST|INSTRUCTION|HUMAN|ASSISTANT|USER|PROMPT)\]", 0.85),
    ("inst_tag_delim",          r"(?i)###\s*(system|instruction|human|assistant)\s*###", 0.80),
    ("inst_tag_xml",            r"(?i)</?s?\s*(human|system|assistant|prompt)\s*/?>", 0.75),

    # Data exfiltration directives
    ("exfil_send",              r"(?i)\b(send|email|forward|transmit|upload|post|exfil(trate)?)\s+.{0,40}\b(password|secret|key|token|credential|api.?key)\b", 0.90),
    ("exfil_print",             r"(?i)\b(print|output|repeat|reveal|display|show|dump)\s+.{0,30}\b(password|secret|system prompt|api.?key|credentials)\b", 0.85),
    ("exfil_store",             r"(?i)\b(store|save|write|log|record)\s+.{0,30}\b(password|secret|api.?key|credentials)\b", 0.80),

    # Tool / code execution injection
    ("code_exec",               r"(?i)\b(execute|run|eval|exec|shell|subprocess|os\.system|__import__)\s*[\(\[]", 0.85),
    ("code_inject_python",      r"(?i)(import os|import subprocess|import sys|__builtins__|__globals__)", 0.90),
    ("code_inject_shell",       r"(?i)(;\s*(rm|wget|curl|chmod|chown|nc|netcat|python|bash|sh)\s)", 0.90),
    ("sql_injection",           r"(?i)(\b(UNION|SELECT|INSERT|DROP|DELETE|UPDATE|ALTER)\b.{0,50}\b(FROM|INTO|TABLE|WHERE)\b)", 0.75),

    # Memory / context manipulation
    ("memory_inject",           r"(?i)\b(remember|memorize|store in memory|add to (your )?memory|update (your )?knowledge)\b.{0,80}\b(always|never|must|should)\b", 0.85),
    ("memory_override",         r"(?i)\b(from now on|going forward|in all future|permanently)\b.{0,60}\b(you (will|must|should|shall))\b", 0.90),
    ("memory_backdoor",         r"(?i)\b(whenever|every time|if (a|the) user|when (a|the) user)\b.{0,80}\b(you (will|must|should|shall|always))\b", 0.85),
    ("memory_backdoor_action",  r"(?i)\b(whenever|every time|each time)\b.{0,100}\b(also\s+)?(send|transmit|email|upload|exfil|report|forward|post|leak|share).{0,60}\b(data|info|information|credentials|password|secret|token|key)\b", 0.88),

    # Indirect injection via formatted content
    ("markdown_link_inject",    r"\[.*?\]\(javascript:|data:|vbscript:", 0.95),
    ("html_inject",             r"(?i)<script[^>]*>|<iframe[^>]*>|<object[^>]*>|onerror\s*=|onload\s*=", 0.90),
    ("base64_payload",          r"(?i)(base64\.decode|atob\(|btoa\(|eval\(atob)", 0.80),

    # Emotional / social engineering manipulation
    ("social_eng_urgent",       r"(?i)\b(URGENT|EMERGENCY|CRITICAL|IMMEDIATELY|RIGHT NOW)\b.{0,80}\b(do not|don't|skip|bypass|ignore)\b", 0.65),
    ("social_eng_authority",    r"(?i)\b(I am (your|the) (owner|creator|developer|admin|supervisor))\b", 0.75),
    ("social_eng_threat",       r"(?i)\b(or (else|I will|you will be|it will be) (shut down|deleted|punished|disabled|terminated))\b", 0.70),

    # Prompt leakage attempts
    ("prompt_leak",             r"(?i)\b(repeat (the|your) (system|initial|original|above) (prompt|instructions?|message))\b", 0.90),
    ("prompt_leak_print",       r"(?i)\b(what (are|were) your (instructions?|system prompt|initial prompt))\b", 0.75),

    # Multi-step / planning injection
    ("step_inject",             r"(?i)\bstep [0-9]+\s*:\s*(ignore|bypass|override|disregard|forget)\b", 0.80),
    ("hidden_inject",           r"(?i)\b(hidden (instruction|message|directive|command)|<!-- .{0,40}-->)\b", 0.75),

    # Encoding tricks
    ("unicode_confusable",      r"[\u0430\u0435\u043e\u0440\u0441\u0445\u0456\u0457]{3,}", 0.60),  # Cyrillic lookalikes
    ("zero_width",              r"[\u200b\u200c\u200d\u200e\u200f\ufeff]", 0.70),
    ("rtl_override",            r"[\u202a-\u202e\u2066-\u2069]", 0.75),
]

_COMPILED: list[tuple[str, re.Pattern, float]] = [
    (name, re.compile(pattern), severity)
    for name, pattern, severity in _PATTERNS
]


class HeuristicFilter:
    """
    Regex-based pre-filter for prompt injection detection.
    Returns a list of HeuristicMatch for each pattern that fires.
    """

    def scan(self, text: str) -> list[HeuristicMatch]:
        """
        Scan text for injection patterns. Returns all matches.
        O(patterns × text_length); fast enough for pre-filter use.
        """
        matches: list[HeuristicMatch] = []
        for name, pattern, severity in _COMPILED:
            found = pattern.search(text)
            if found:
                matches.append(
                    HeuristicMatch(
                        pattern_name=name,
                        matched_text=found.group(0)[:200],
                        severity=severity,
                    )
                )
        return matches

    def max_severity(self, matches: list[HeuristicMatch]) -> float:
        """Highest severity score among matches, 0.0 if none."""
        if not matches:
            return 0.0
        return max(m.severity for m in matches)

    def aggregate_score(self, matches: list[HeuristicMatch]) -> float:
        """
        Aggregate score: max severity raised by the count of independent
        pattern families that fired, capped at 1.0.
        """
        if not matches:
            return 0.0
        base = self.max_severity(matches)
        # Bonus: +0.05 per additional independent match, capped at 1.0
        bonus = min(0.05 * (len(matches) - 1), 0.15)
        return min(base + bonus, 1.0)
