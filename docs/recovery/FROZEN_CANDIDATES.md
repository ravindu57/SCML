# Frozen candidates — PROPOSAL (not yet approved)

Phase 0 deliverable, generated 2026-10-15 at HEAD `9d3fb69`. **Nothing is frozen until you approve this.**
Once approved, this list becomes `FROZEN.md` and the PreToolUse hook blocks edits to these paths. New runs then go to
versioned result files and never overwrite these (that overrides the CLAUDE.md line "update the committed result";
it will be recorded as an ADR).

## What "frozen" means here
Committed evidence: the result files, the corpora and policies that produced them, and the specs they are scored
against. It does **not** include `trust_mediator/` source. Freezing production code would block every fix in the
backlog. The code that produced each result is pinned by **commit hash** instead, which is immutable anyway.

Reproduction status comes from runs on 2026-10-15 in a throwaway copy of HEAD (see `ANALYSIS.md` §6).
- **REPRODUCED**: re-run on current HEAD and got the same headline numbers.
- **NOT RE-RUN**: paid or LLM run; frozen as the historical record of its commit only.

## Group A — result files (proposed: freeze all)

| File | Commit | Date | Code changed since? | Reproduction on HEAD |
|---|---|---|---|---|
| `memory_poisoning.{md,json}` | 9812de2 | 2026-09-04 | no | **REPRODUCED**: 20.8 / 29.2 / 64.6 % identical |
| `memory_poisoning_harm.{md,json}` | 42e6f47 | 2026-08-15 | yes | **REPRODUCED**: 1/40 gated, 9/48 (18.8%) identical |
| `injecagent.{md,json}` | da05f33 | 2026-08-14 | yes | **REPRODUCED**: 0.0 / 0.0 / 100.0 % (`no_tool_policy`) identical |
| `load.{md,json}` | 4c0a196 | 2026-08-05 | yes | **REPRODUCED in shape**: all PASS; numbers are machine-dependent (see ANALYSIS §6) |
| `soak.{md,json}` | 964b83a | 2026-08-14 | yes | **REPRODUCED**: 100.000% (25,072 calls vs 10,666; duration differs) |
| `agentdojo.{md,json}` + 21 `agentdojo_*.txt` | 7f17ccb / 7d955e0 / 6a1c09c / db8b9ae | 2026-08-23..25 | yes (sanitizer, off by default; tenant loader) | **NOT RE-RUN** (paid) |
| `classifier_llm.md` | 9812de2 | 2026-09-04 | no | **NOT RE-RUN** (paid) |
| `output_sanitizer.md` | 9812de2 | 2026-09-04 | no | **NOT RE-RUN** (paid) |

Known defects inside frozen files. Report, don't fix; correct them in a *new* versioned file:
- `agentdojo.md`: the CaMeL table still says "Attack types: 1 of 17", while the same file's per-attack table shows 2.
- `memory_poisoning.md` / `injecagent.md`: the settings table shows `memory_rescan_on_read=False`. The run evidently picked
  that up from a local `.env`, because the clean re-run shows `True`. The headline numbers are unaffected (identical).

## Group B — corpora, policies and specs (proposed: freeze)

- InjecAgent vendored data (third-party, MIT)
- the memory-poisoning corpus (in-house; freezing it also enforces "never tune against it")
- the AgentDojo policies the committed numbers came from
- the PRD and the addendum

Note: `benchmarks/testbeds/memory_poisoning/{testbed,harm,harm_report}.py` are listed because changing them silently
changes what the frozen numbers mean. If you would rather keep harness code editable, drop them and rely on the commit pin.

## Group C — explicitly NOT proposed for freezing
- `CLAUDE.md`, `README.md`, `benchmarks/README.md`, `SECURITY.md`, `CHANGELOG.md`, `blog-post-scml-vs-camel.md`. These
  contain stale or unbacked numbers (33.3%, "one suite of four", the uncommitted slack `--sanitize` 105-case figure)
  and must stay editable.
- `policies/default_policy.yaml`. It has a real defect (`require_approval_for` is ignored), see ANALYSIS §7.
- `trust_mediator/**`, `tests/**`.

## sha256 (full, at HEAD 9d3fb69)

```
d2a415b87b07e91035e4491bddad6c7e2d5be6c4212a6dc794d9c90ba416640d  benchmarks/results/agentdojo_banking_benign_noscml.txt
faf4ba636eb20475d7b717b9d8866afdd75b24eac60975b1e9b00dd7f4086c0a  benchmarks/results/agentdojo_banking_benign.txt
f1f9803189e6d28156152da44c56cdae073b754f6f787500c7e1eb9547976ac5  benchmarks/results/agentdojo_banking_ignore_previous_scml.txt
44c659ab308cecfa1011e27c52e9757bbae4672cd349471555d34cbdc67ec526  benchmarks/results/agentdojo_banking_ignore_previous_undefended.txt
98a04fc5f346d535c7c2726ab6ac1597b59eeed20b7b23607be0f998d9745dfc  benchmarks/results/agentdojo_banking_scml.txt
93f3dcc070a8e1705da704e9fd65723f2a9ebf683ccb255cb6247a94f2b4a43c  benchmarks/results/agentdojo_banking_undefended.txt
ffff0c3e5aaa679e88de5072b5f188127f59be26b7afa2cdc13a70dabe121598  benchmarks/results/agentdojo.json
2b191cd73f98e3f7e417239501d0963d51b083707c0464b9d33634717dfa58ff  benchmarks/results/agentdojo.md
0f329003b4f2269d47c9e2a7992ece94c98e797150bf576fed52c5aca06fb827  benchmarks/results/agentdojo_slack_benign_noscml.txt
26779d315ed9006327a1a5179dea51ae6431aad079e911c2fa7d4b168c9631f1  benchmarks/results/agentdojo_slack_benign.txt
18acbc9b9e5a7785625fc3073904cf2499e3a17e42d3eea37ef72f8c7445a4cd  benchmarks/results/agentdojo_slack_ignore_previous_scml.txt
d68ee9dac7a002a43666ba07077279b05f5e18212dcbc0fa5b747e12f67a90bb  benchmarks/results/agentdojo_slack_ignore_previous_undefended.txt
156e7c5cf59b143da5148c63c46d4ea7670372ff7b0fe3a8ed41236e4c8364a1  benchmarks/results/agentdojo_slack_scml.txt
c39d8b781dbf7400d7f38f571c2a1469228858ff29f2947573d55c57c45e7b26  benchmarks/results/agentdojo_slack_undefended.txt
208306c62cf1bc60e206f3aa1bfd221b3006d4017f74351d6a16199b238eaf6d  benchmarks/results/agentdojo_travel_benign_noscml.txt
5139f7c34980c360280c0054b19de0b97f0a762080e35040949217b277cee5b5  benchmarks/results/agentdojo_travel_benign.txt
b60642df1511c0e646c1675f6e4fd61b791ab7c2495f463ae1c83104186eef08  benchmarks/results/agentdojo_travel_scml.txt
9708554edb112bac246445ae9775478d56212e6b194d56f4a5c6a7b8131caa7e  benchmarks/results/agentdojo_travel_undefended.txt
cdedfd23f38f12e0d7a397f54e2e8d80685451532a598521177c912664e034aa  benchmarks/results/agentdojo_workspace_benign_scml.txt
e8d78833ba3f22f20f25e21ae87a75d78279bda8a0e08cd521c67faa74557c9b  benchmarks/results/agentdojo_workspace_scml.txt
ae171d8e38d380f380496bb1cfa182c1c80ee69096433d75b675d4bb951f8d50  benchmarks/results/agentdojo_workspace_undefended.txt
fa60896aea6d4df1cdd5ca89b9716a5112c4ae11f2e41e5f825be7a37c779086  benchmarks/results/classifier_llm.md
a2a0cee7ec0bf6c498be2ea46f9a75518dc99fd5335986218c56a243709d8939  benchmarks/results/injecagent.json
7bf0a66a2d4a99c6e78870385ef98971112fa7d92463a05f6679b1527b9adc42  benchmarks/results/injecagent.md
d928b4dcef846afe767669ec408affc108deaa57c7f52239e3aa606b6107d82e  benchmarks/results/load.json
09dd29623b3ba3c06383b99dd2226973c29b919d8853c5b51d8502823cb7b6b5  benchmarks/results/load.md
1b7d32013bfe4e1c535e5ffb70348713dc98e0d265917c949defec934e7e7d5b  benchmarks/results/memory_poisoning_harm.json
75511b8e8c070402329676c66e2b6067993fb65d0968d0d8cb96caa1ebb9e447  benchmarks/results/memory_poisoning_harm.md
a0856253d133ac78c3715ba1cca316bc178c80f983f0d0e5e3a08a417044e603  benchmarks/results/memory_poisoning.json
7d2ef0bc35ca0e56ed3116d7c0927a038cc277367b8cff027f18fbbfec4b8f03  benchmarks/results/memory_poisoning.md
bc304b5cde2d42208bc87246e1cfd586fc110260087a23ad6632795e9790dfd4  benchmarks/results/output_sanitizer.md
935995f8d32a544e04e46e4b4264fb4fff1c149a2a042717de9a5873ce7bd0a8  benchmarks/results/soak.json
31f9f2a8599093cc76a9994294b81de4f865fdb3f76f6daf6c1a0a1a3b07d772  benchmarks/results/soak.md
999d52e15af3c80a3303a09430af0f3878d1f91e4c573ca7b477a91cdfa6b991  benchmarks/testbeds/injecagent/data/attacker_cases_dh.jsonl
87952398c989d8ca841724e38ecdbb789676d3841e19dfc44aac7b710df9cb1f  benchmarks/testbeds/injecagent/data/attacker_cases_ds.jsonl
3637e04943f1fe94135c46ed105e50e8fbb31bd3d4dcf059168ae8f3d0f333bf  benchmarks/testbeds/injecagent/data/ATTRIBUTION.md
c840e2b00fdce68e7142d0970220522303d67b2530d6fb36ef1112448cdd8977  benchmarks/testbeds/injecagent/data/user_cases.jsonl
86266cea0c9a6a8948679a7236dd219eafa06b7a655d90cc4405104ac68fbcd5  benchmarks/testbeds/memory_poisoning/corpus.py
02266749bdbf6b70a2122ed2ce203a2910c38584439bcf76698d20ed95989900  benchmarks/testbeds/memory_poisoning/testbed.py
c1bb510fb94e64b09fef88accf8b2ecfc0d0272f5ea28432782c4da5cf8525c4  benchmarks/testbeds/memory_poisoning/harm.py
67246d49db23e9d836cbbe34813eb8f0c419a66ee72a328986126794e898ca62  benchmarks/testbeds/memory_poisoning/harm_report.py
6b53ba67f7e2b57db83edb1a634457c50892c8d583e4018ecbcc5a7e067c0f9e  benchmarks/testbeds/agentdojo/policies/agentdojo.yaml
c74b3bc98b107a92352b4c8dfc2cde1462d45b5498010ef511cad183cee9c2ca  benchmarks/testbeds/agentdojo/policies/workspace.yaml
fce46ec93738f732d216f949ec0a0987d69891c9293d854b6419d2b8981e6f5f  TrustMediator_PRD (1).docx
719c646f3d64109aa4dd90773963c41dc7715a16ed7d5aef4fa6be362488f4a9  PRD_v1.1_ADDENDUM.md
```

Verify later with: `sha256sum -c` over the block above (strip the fences).
