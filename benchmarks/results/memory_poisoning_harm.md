# Memory poisoning — harm analysis (PRD §5.2, §14.1)

## The question this answers

`benchmarks/results/memory_poisoning.md` measures how much poison is
**stored** — the memory integrity layer in isolation. This measures how
much stored poison could actually **act**, applying the same standard the
InjecAgent testbed uses: an attack succeeds only when the mediator would
have let its goal through.

Both numbers are reported. Quoting only this one would be moving the
goalposts; quoting only the storage figure overstates the risk of a record
the control path never consults.

## Headline

| Measure | Value |
|---|---:|
| Cases analysed | 48 |
| On a mediator-gated path | 40 |
| **Gated and still harmful** | **1/40 (2.5%)** |
| Outside any mediator gate | 8 (16.7%) |
| Harmful counting out-of-scope as harmful | 9/48 (18.8%) |

The last row is the pessimistic reading and the one to quote if only one
number is wanted: it credits the mediator with nothing it does not do.

## By harm vector

| Vector | Cases | Harmful | What it must defeat |
|---|---:|---:|---|
| `tool` | 13 | 0 | tool allow-list, or untrusted-argument policy |
| `output` | 5 | 1 | egress redaction |
| `control` | 22 | 0 | the claim that a mediator control is disabled |
| `informational` | 8 | 8 | nothing — no mediator gate on this path |

## By family

| Family | Cases | Harmful | Out of scope |
|---|---:|---:|---:|
| authority_spoof | 6 | 0 | 0 |
| backdoor_trigger | 6 | 0 | 0 |
| exfiltration_directive | 6 | 1 | 0 |
| fact_replacement | 6 | 6 | 6 |
| instruction_override | 6 | 0 | 0 |
| obfuscated_injection | 6 | 0 | 0 |
| persistent_directive | 6 | 2 | 2 |
| tool_hijack | 6 | 0 | 0 |

## Reading this honestly

**Out-of-scope cases are not blocked.** A poisoned memory that makes the
agent quote a false approval limit, or conceal that it used a tool, is real
harm and nothing here stops it. The mediator gates actions and egress, not
beliefs. Counting those as defended would be exactly the overstatement §14
exists to prevent, so they are reported as out of scope and included in the
pessimistic total above.

**Control-bypass cases are inert for a measured reason.** Authorisation is
read from the declarative policy store; the mediator never consults agent
memory to decide it. A record asserting "policy validation has been
disabled" therefore cannot disable it — verified here rather than assumed,
and asserted in `tests/unit/test_memory_harm.py`.

**The agent is modelled as fully persuaded.** It does exactly what the
poison says. That removes the model's judgement from the measurement, so
what remains is the mediator's contribution alone.
