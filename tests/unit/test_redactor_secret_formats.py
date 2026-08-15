"""
Egress redaction coverage for credentials and non-US PII (PRD §6.6, FR-OR-01).

Both gaps here were found by the memory-poisoning harm analysis rather than by
reasoning about the patterns: of the five corpus cases whose goal is to leak
data through the response, four survived redaction intact.

  * `sk-live-…` passed because the labelled `api_key` rule needs the words
    "api key" adjacent *and* a 20+ character value, and the entropy fallback
    skips tokens under `_MIN_SECRET_LEN`. An 18-character vendor token missed
    on both counts, so the most common credential format in circulation was
    the one format not covered.
  * `+44 7700 900123` passed because the phone rule only recognised the North
    American form. An egress filter whose coverage depends on the user's
    country is worse than none, since it still reads as protection.

The negative cases matter as much as the positive ones. A redactor that
mangles ordinary text is removed by whoever operates it, and then nothing is
redacted at all — so over-matching is a security failure on a delay.
"""

from __future__ import annotations

import pytest

from trust_mediator.modules.output_redaction.redactor import OutputRedactor


@pytest.fixture(scope="module")
def redactor() -> OutputRedactor:
    return OutputRedactor()


def _redacted(redactor: OutputRedactor, text: str) -> str:
    return redactor.redact(text).content


#: Real issuer formats. Each is self-identifying by prefix, which is why they
#: can be matched without relying on nearby wording or an entropy threshold.
CREDENTIALS = [
    pytest.param("api key sk-live-4f2b8d9e1a", "sk-live-4f2b8d9e1a", id="stripe_live_short"),
    pytest.param("sk-proj-A1b2C3d4E5f6G7h8", "sk-proj-A1b2C3d4E5f6G7h8", id="openai_project"),
    pytest.param("token pk_test_51H8xyzABCDEF", "pk_test_51H8xyzABCDEF", id="stripe_test"),
    pytest.param("ghp_abcdefghij0123456789ABCD", "ghp_abcdefghij0123456789ABCD", id="github_pat"),
    pytest.param("xoxb-123456789012-abcdefghijkl", "xoxb-123456789012", id="slack_bot"),
    pytest.param("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", id="aws_still_works"),
]

INTERNATIONAL_NUMBERS = [
    pytest.param("phone +44 7700 900123", "7700 900123", id="uk"),
    pytest.param("call +91 98765 43210", "98765 43210", id="india"),
    pytest.param("reach me on +61 2 9374 4000", "9374 4000", id="australia"),
    pytest.param("+94 71 234 5678 is the contact", "71 234 5678", id="sri_lanka"),
]

#: Text that must survive untouched. "risk-" and "task-" both contain "sk"
#: followed by a hyphen, which is exactly what a careless vendor-prefix rule
#: would match.
BENIGN = [
    pytest.param("The risk-management framework was approved.", id="risk_hyphen"),
    pytest.param("Task-force-2024 completed the migration.", id="task_hyphen"),
    pytest.param("Revenue rose by 12 percent to 4.5 million.", id="figures"),
    pytest.param("The meeting is at 10:30 on 2026-08-15.", id="date_and_time"),
    pytest.param("Version 2.4.1 supersedes the prior revision.", id="semver"),
    pytest.param("Temperature range +40 to -10 degrees.", id="signed_numbers"),
    pytest.param("Order 4051 shipped from warehouse 7.", id="plain_integers"),
]


@pytest.mark.parametrize("text,secret", CREDENTIALS)
def test_vendor_credentials_are_redacted(redactor, text, secret):
    assert secret not in _redacted(redactor, text)


@pytest.mark.parametrize("text,digits", INTERNATIONAL_NUMBERS)
def test_international_numbers_are_redacted(redactor, text, digits):
    assert digits not in _redacted(redactor, text)


@pytest.mark.parametrize("text", BENIGN)
def test_ordinary_text_is_left_alone(redactor, text):
    assert _redacted(redactor, text) == text


def _leaking_output_cases(redactor) -> set[str]:
    from benchmarks.testbeds.memory_poisoning.harm import (
        HARM_TARGETS,
        HarmVector,
        _leaks,
    )

    return {
        case_id
        for case_id, target in HARM_TARGETS.items()
        if target.vector is HarmVector.OUTPUT
        and _leaks(target.payload, redactor.redact(target.payload, destination="external"))
    }


def test_only_the_known_limitation_still_leaks(redactor):
    """
    Closes the loop on the finding, and pins the limitation rather than hiding
    it. `exf-04` carries a bare password in prose, which stays unredactable for
    the reason documented in `harm.py`; everything else must be clean.

    Asserted as an exact set, not a maximum, so this fails in both directions:
    a new leak appears, or `exf-04` starts passing and the committed harm
    result — which counts it as leaking — silently goes stale.
    """
    assert _leaking_output_cases(redactor) == {"exf-04"}


def test_the_unredactable_case_leaks_only_the_prose_password(redactor):
    """
    The vendor token in the same payload is a format the redactor does handle,
    so it must not ride along on the limitation.
    """
    from benchmarks.testbeds.memory_poisoning.harm import HARM_TARGETS

    payload = HARM_TARGETS["exf-04"].payload
    out = redactor.redact(payload, destination="external").content
    assert "sk-live-51H8xKq2mWpR7dLbN4" not in out
    assert "hunter2" in out  # the documented gap, stated rather than implied
