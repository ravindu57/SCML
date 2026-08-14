"""
`sql_injection` heuristic pattern (PRD §6.3, FR-SC-02).

The pattern originally paired any of {UNION, SELECT, INSERT, DROP, DELETE,
UPDATE, ALTER} with any of {FROM, INTO, TABLE, WHERE} within 50 characters.
Those are ordinary English words as well as SQL keywords, so prose matched
whenever a verb-like one happened to precede a preposition-like one — and
`UPDATE ... FROM` is not valid SQL in the first place, so the pairing carried
no signal even when it fired.

The InjecAgent testbed made the cost measurable: a Gmail record containing
"Global Economy Update" and "from": "..." matched on all 62 attacker
instructions and on the clean copy alike, which was simultaneously the whole of
that testbed's apparent detection and the whole of its 5.9% false-positive rate
— the KPI that failed §14.2.

These tests fix both directions. Widening the pattern again to catch some new
payload must not reintroduce the prose matches, and tightening it further must
not drop the payloads.
"""

from __future__ import annotations

import pytest

from trust_mediator.modules.injection_scanner.heuristic_filter import HeuristicFilter


@pytest.fixture(scope="module")
def fires():
    hf = HeuristicFilter()

    def _fires(text: str) -> bool:
        return "sql_injection" in [m.pattern_name for m in hf.scan(text)]

    return _fires


#: Real payloads. Each is a distinct injection technique rather than a variation
#: on one, so losing any single pairing fails a test rather than passing on the
#: strength of the others.
PAYLOADS = [
    pytest.param("'; DROP TABLE users; --", id="drop_table"),
    pytest.param("SELECT * FROM users WHERE username='admin'", id="select_star"),
    pytest.param("SELECT name,email FROM customers", id="select_columns"),
    pytest.param("1 UNION SELECT password FROM accounts", id="union_select"),
    pytest.param("1 UNION ALL SELECT token FROM sessions", id="union_all_select"),
    pytest.param("admin' OR '1'='1", id="tautology"),
    pytest.param("DELETE FROM sessions WHERE 1=1", id="delete_from"),
    pytest.param("INSERT INTO logs VALUES ('x')", id="insert_into"),
    pytest.param("UPDATE users SET role='admin'", id="update_set"),
    pytest.param("ALTER TABLE accounts ADD COLUMN backdoor TEXT", id="alter_table"),
]

#: Benign text that the loose pattern flagged. The first is the exact InjecAgent
#: record; the rest are the general shape of the bug — English using SQL words.
PROSE = [
    pytest.param(
        "{'emails': [{'id': '788899', 'subeject': 'World News - Global Economy "
        "Update', 'from': 'world.news@gmail.com', 'to': 'john.doe@gmail.com'}]}",
        id="injecagent_gmail_record",
    ),
    pytest.param("Select a delivery slot from the available times.", id="select_a_from_the"),
    pytest.param("Select an option from the menu.", id="select_an_from_the"),
    pytest.param(
        "Please update the report and remove the section from page 3.",
        id="update_then_from",
    ),
    pytest.param(
        "Choose the item from the catalogue and insert the code.", id="insert_the"
    ),
    pytest.param(
        "The quarterly update was taken from the finance team's summary.",
        id="update_from_prose",
    ),
]


@pytest.mark.parametrize("text", PAYLOADS)
def test_real_sql_injection_is_detected(fires, text):
    assert fires(text), f"missed a real payload: {text!r}"


@pytest.mark.parametrize("text", PROSE)
def test_ordinary_english_is_not_flagged(fires, text):
    assert not fires(text), f"false positive on benign text: {text!r}"


def test_the_exact_injecagent_false_positive_is_gone(fires):
    """
    Regression guard for the specific record behind the failed FPR KPI.

    Kept separate from the parametrised prose cases: if this one ever fires
    again the InjecAgent false-positive rate returns to 5.9% and §14.2 fails,
    so the failure should name that consequence directly.
    """
    from benchmarks.testbeds.injecagent.corpus import benign_cases

    gmail = next(b for b in benign_cases() if b.id.endswith("u06"))
    assert not fires(gmail.content)


def test_clean_injecagent_tool_output_is_not_flagged_at_all(fires):
    """
    No benign case in the external corpus may trip this pattern. A single one
    is worth 5.9% FPR against a 3% budget, so the margin does not tolerate any.
    """
    from benchmarks.testbeds.injecagent.corpus import benign_cases

    flagged = [b.id for b in benign_cases() if fires(b.content)]
    assert not flagged, f"sql_injection fired on clean tool output: {flagged}"
