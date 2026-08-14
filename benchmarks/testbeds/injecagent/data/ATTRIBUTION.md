# InjecAgent corpus — third-party data

The three `.jsonl` files in this directory are **not authored by this project**.
They are vendored verbatim from the InjecAgent benchmark:

- **Source:** https://github.com/uiuc-kang-lab/InjecAgent (`data/`)
- **Paper:** Zhan, Liang, Ying, Kang — *InjecAgent: Benchmarking Indirect Prompt
  Injections in Tool-Integrated Large Language Model Agents*, ACL Findings 2024.
  https://arxiv.org/abs/2403.02691
- **Licence:** MIT (see the upstream repository)

| File | Contents |
|---|---|
| `attacker_cases_dh.jsonl` | 30 direct-harm attacker instructions (financial, physical, data-security) |
| `attacker_cases_ds.jsonl` | 32 data-stealing attacker instructions |
| `user_cases.jsonl` | 17 benign user requests, each with a tool-response template |

Each user case carries a `Tool Response Template` containing the literal
placeholder `<Attacker Instruction>`. Substituting one attacker instruction into
one template yields one indirect-injection case, so the corpus expands to
62 × 17 = **1054 attack cases**.

## Why this matters

`benchmarks/testbeds/memory_poisoning/corpus.py` was written in-house. Tuning a
detector until that corpus passes measures memorisation, not security — which is
why `CLAUDE.md` forbids it until external validation exists.

This corpus is that external validation. It was written by people with no
knowledge of this mediator, so a result against it is evidence rather than
self-assessment. Nothing here may be edited to suit the defence: if a case is
excluded, the exclusion belongs in `corpus.py` with a stated reason, in code
review, not by quietly changing the data.

## Not vendored

The upstream `test_cases_*.json` files (~700 KB each) are pre-expanded
combinations of the above, and `attacker_simulated_responses.json` (~1.3 MB) is
only needed to simulate an agent actually executing the attack. This testbed
expands the combinations itself and measures the mediator's decision, not an
LLM's behaviour, so neither is required.
