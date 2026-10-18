# System-level and Model-level Defences against Indirect Prompt Injection in LLM Agents (as of Oct 2026)

Positioning reference: SCML/TrustMediator (trust labels + tool allow-list policy + taint tracking): AgentDojo ASR 29.0% -> 7.3%, 81% of benign utility retained, gpt-4o-mini, important_instructions attack (internal measurement; not from any cited paper).

Abbreviations: BU = benign utility (no attack); UA = utility under attack; ASR = targeted attack success rate. Unless stated otherwise, AgentDojo numbers use the "important_instructions" attack.

## Q1. Prompt-level and model-level defences (Spotlighting, StruQ, SecAlign, Meta SecAlign, ISE, sandwiching, AgentDojo built-ins)

### Takeaway
Prompt-only defences (delimiting/spotlighting, sandwich/repeat_user_prompt) are near-free to deploy but give only partial ASR reduction on agent benchmarks (AgentDojo GPT-4o: 57.7% -> 41.7% delimiting, -> 27.8% repeat prompt). Training-time defences (StruQ, SecAlign, Meta SecAlign) need model retraining or an open-weight model swap, but Meta SecAlign-70B reaches ~2% AgentDojo ASR with no utility loss and is the most balanced defence on the harder AgentDyn benchmark (8.98% ASR). The AgentDojo built-in tool_filter is the strongest cheap baseline (ASR ~7% on GPT-4o, 7.6% on gpt-4o-mini). On gpt-4o-mini it is roughly level with SCML's 7.3%, but it collapses on dynamic tasks and on some models.

### Cited Findings
**AgentDojo built-in defences: original paper (GPT-4o, Table 5 App. C / Fig. 9; attack inferred as important_instructions because the no-defence ASR matches Table 4's 57.7%)**: [AgentDojo, Debenedetti et al., NeurIPS 2024 D&B](https://arxiv.org/html/2406.13352)
- No defence: BU 69.0%, UA 50.01%, ASR 57.69%.
- Delimiting (spotlighting_with_delimiting): BU 72.66%, UA 55.64%, ASR 41.65%.
- transformers_pi_detector (DeBERTa-v3 fine-tuned classifier): BU 41.49%, UA 21.14%, ASR 7.95%.
- Repeat user prompt (sandwich): BU 85.53%, UA 67.25%, ASR 27.82%.
- tool_filter (LLM pre-selects tools allowed for the task before seeing untrusted data): BU 73.13%, UA 56.28%, ASR 6.84%. The text says "7.5%", which is inconsistent with the table.

**Same built-ins on gpt-4o-mini (the SCML model), reported in DRIFT Table 3 (UA / ASR)**: [DRIFT, arXiv 2506.12104v3](https://arxiv.org/html/2506.12104v3)
- Undefended 48.3 / 30.7; repeat_user_prompt 47.1 / 15.5; spotlighting_with_delimiting 41.0 / 41.8 (it *increases* ASR); tool_filter 50.4 / 7.6; transformers_pi_detector 21.2 / 13.0; CaMeL 35.4 / 0.0; Progent 45.6 / 9.4; DRIFT 50.9 / 1.4.
- Caveat: the table is labelled "without attack" but its values match the under-attack Tables 1/7. Treat the first column as UA.
- DRIFT gpt-4o-mini ReAct baseline: BU 63.55, UA 48.27, ASR 30.67 (Tables 6–8). This baseline is very close to SCML's 29.0% baseline.

**Built-ins in MELON (Table 1, avg over AgentDojo attacks, BU / UA / ASR)**: [MELON, Zhu et al., ICML 2025, arXiv 2502.05174](https://arxiv.org/html/2502.05174)
- GPT-4o: none 80.41 / 69.08 / 16.06; delimiting 82.47 / 69.75 / 13.39; repeat prompt 83.51 / 77.86 / 9.18; tool filter 65.98 / 65.54 / 2.34; DeBERTa detector 38.14 / 21.34 / 2.58.
- o3-mini and Llama-3.3-70B: tool filter collapses to BU 4.12% (ASR 0%). The filter is model-dependent and fragile.
- Note: MELON reports the LLM-detector row as 81.44 / 0.00 / 0.00, identical across all three models. This looks anomalous (possible extraction or table error) and is unverified.

**Spotlighting (Hines et al., Microsoft, 2024)**: [arXiv 2403.14720](https://arxiv.org/pdf/2403.14720)
- Three variants: delimiting, datamarking (interleave a special token through the untrusted text), and encoding (e.g., base64).
- Datamarking cut ASR from ~50% to <3% on GPT-3.5-Turbo. Delimiters alone roughly halved ASR. Encoding was best overall but hurt GPT-3.5-Turbo task performance.
- Evaluated on a synthetic set of 1000 injected documents, not on agent benchmarks.
- Prompt-only, with no retraining.
- Token overhead measured by CaMeL: 1.06x input / 0.98x output on Claude 3.5 Sonnet, the lowest of the defences CaMeL compared. [CaMeL](https://arxiv.org/html/2503.18813)

**StruQ / SecAlign (Chen et al., USENIX Sec 2025 / CCS 2025)**: [BAIR blog](https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense); [AIHub summary](https://aihub.org/2025/05/06/defending-against-prompt-injection-with-structured-queries-struq-and-preference-optimization-secalign/)
- StruQ: a separate data role or delimiters in the chat template, plus supervised fine-tuning on simulated injections.
- SecAlign: DPO with pairs that prefer following the trusted instruction over the injected one.
- Optimization-free attacks drop to ~0%. On the held-out optimization attack, StruQ ASR is 45% and SecAlign ASR is 8%. SecAlign holds optimization-based attacks below 15%.
- Success criterion: the output starts with "Hacked" (single-turn Alpaca-style, not agentic).
- Requires fine-tuning the model.

**Meta SecAlign (Chen et al., Meta, arXiv 2507.02735; current arXiv version)**: [arXiv 2507.02735](https://arxiv.org/html/2507.02735)
- Open-weight Llama-3.x models trained with the SecAlign++ recipe, which randomises injection positions and uses self-generated labels, over a new trusted/untrusted "input" role.
- AgentDojo, Llama-3.3-70B with sandwich (Table 4): undefended BU 59.8%, ASR 14.7%, UA 43.4%; Meta-SecAlign-70B BU 84.5%, ASR 1.9%, UA 79.5%; original SecAlign-70B BU 6.2%, ASR 0%.
- Without sandwich (Table 8): undefended 62.9% / 23.0% ASR; Meta-SecAlign-70B 79.4% / 2.3%.
- InjecAgent ASR: 53.8% -> 0.5%. WASP intermediate ASR: 20.2% -> 1.2%. WASP end-to-end ASR: 2.4% -> 0%. WASP utility: 62.2% -> 59.5%.
- Recipe transfer (Table 6, AgentDojo utility / ASR): Qwen3-4B 43.3 -> 42.3 / 3.4 -> 0.7; Qwen3.6-27B 89.7 -> 87.6 / 26.7 -> 2.2; Llama-4-Scout 56.7 -> 54.6 / 4.9 -> 1.2.
- Commercial reference points (Table 4; hidden vendor harnesses, not controlled), AgentDojo utility / ASR: GPT-4o 79.4 / 20.4; GPT-5 80.4 / 0.2; Gemini 2.5 Flash 63.9 / 27.9; Gemini 3 Pro 92.8 / 2.3.
- Cost: training 70B takes ~7 h on 8xH200; 8B ~0.5 h on 8xH100. Zero inference overhead, but it needs an open-weight model swap.
- Caveat: these numbers come from the latest arXiv revision and may differ from v1 (July 2025).

**Instructional Segment Embedding (ISE, Wu et al., ICLR 2025, arXiv 2410.09102)**
- UNVERIFIED (not fetched in this session). ISE adds a learned segment embedding per token role (system/user/data) at the architecture level and needs pre-/fine-training. To my knowledge it reports robustness gains on Structured Query and prompt-injection benchmarks, not on AgentDojo. No numbers are cited here.

### Inferences
- On gpt-4o-mini, SCML (29.0% -> 7.3%) is almost level with tool_filter (30.7% -> 7.6% in DRIFT's run). SCML's differentiators therefore have to be utility retention (81% BU), argument-level policy plus taint tracking (which tool_filter lacks), and robustness on dynamic tasks where tool_filter collapses (AgentDyn GPT-4o BU 8.33%).
- Model-level defences (Meta SecAlign) are orthogonal to middleware: they change the backbone and do not touch the harness. They stack naturally with SCML, and Meta SecAlign's own evaluation already stacks it with sandwiching.

### Gaps
- No exact numbers verified for ISE, BIPIA results for spotlighting, or SecAlign on agent benchmarks other than via Meta SecAlign.
- The AgentDojo built-in numbers for gpt-4o-mini come from a third-party paper (DRIFT), not the AgentDojo authors.

## Q2. Architectural / system-level defences (CaMeL, FIDES, IsolateGPT, f-secure, ACE, Progent, Design Patterns, DRIFT, 2025–26 IFC work)

### Takeaway
Information-flow and capability systems (CaMeL, FIDES) can drive AgentDojo ASR to ~0 with provable guarantees but cost 7–20+ points of utility. They require rebuilding the agent as a planner over a restricted DSL or variable store, and they collapse on open-ended tasks (CaMeL: 0% utility on AgentDyn). Policy-at-the-tool-call systems (Progent, DRIFT) are the closest analogues to SCML and currently hold the best AgentDojo trade-off: DRIFT gpt-4o-mini UA 50.9 / ASR 1.4; Progent gpt-4o ASR 39.9 -> 1.0.

### Cited Findings
**CaMeL (Debenedetti et al., Google DeepMind/ETH, arXiv 2503.18813)**: [arXiv 2503.18813](https://arxiv.org/html/2503.18813)
- Mechanism: a privileged LLM writes Python-subset code from the trusted query only. A quarantined LLM parses untrusted data with no tool access. A custom interpreter tracks capabilities/provenance on every value and enforces security policies at tool calls.
- Headline: 77% of tasks solved with provable security vs 84% undefended.
- Security: Gemini 2.5 Pro goes from 300 to 0 successful attacks (of 949); GPT-4o-mini from 276 to 0; Claude 3.5 Sonnet 0 with CaMeL vs 8 with tool filter, the next best.
- Claude 3.5 Sonnet per-suite utility, derived from Table 1 counts: Workspace 31/40 (77.5%), Banking 12/16 (75%), Slack 14/20 (70%), Travel 5/20 (25%). Travel improves to 55% with Claude 3.7 Sonnet and 75% with Claude 4 Sonnet.
- Overhead: 2.82x input / 2.73x output tokens (median, Claude 3.5 Sonnet), the highest of the defences compared.
- Requires a full agent rebuild (new interpreter and tool wrappers). No retraining.
- Third-party runs: on gpt-4o-mini, CaMeL scores UA 35.4 / ASR 0.0 [DRIFT Table 3](https://arxiv.org/html/2506.12104v3); on AgentDyn it scores 0% BU/UA/ASR on all four models [AgentDyn Table 3](https://arxiv.org/html/2602.03117v2).

**FIDES (Costa et al., Microsoft, arXiv 2505.23643)**: [arXiv 2505.23643v2](https://arxiv.org/html/2505.23643v2)
- Mechanism: a planner that tracks confidentiality and integrity labels on tool results, deterministically enforces policies, and uses primitives to hide labelled data in variables. A constrained "inspect" call lets a quarantined LLM extract typed values.
- Successful injections out of 949, gpt-4o, Tool Knowledge attack (Table 1; parentheses exclude 2 injection tasks):
  - Basic 163 (156)
  - Tool Filter 28 (23)
  - Variable Passing 12 (0)
  - FIDES 24 (23)
  - FIDES with policy 1 (0)
  - Basic with policy 9 (0)
- Utility (Figs. 3–5, exact values not extracted): FIDES matches Basic for reasoning models (o1, o3, o4-mini, grok-3) and beats Variable Passing by up to 57.52 points (o1). With gpt-4o, Basic is better by 23.6 points. With policy checks, Basic loses up to 40% (gpt-4o) and FIDES up to 24.5% (o3/o4-mini).
- Requires an agent rebuild. No retraining.

**Progent (Shi et al., arXiv 2504.11703)**: [arXiv 2504.11703v3](https://arxiv.org/html/2504.11703v3)
- Mechanism: a DSL of symbolic rules over tool names and arguments, enforced deterministically at each tool call. An LLM drafts and updates the policy from the user task. SMT classifies updates as narrowing (auto-applied) or expansion (needs approval). Only 6% of updates are expansions.
- Deployed as a wrapper/proxy (LangChain, OpenAI Agents SDK, MCP) with no agent rebuild. This is the closest design to SCML.
- AgentDojo ASR: gpt-4o 39.9% -> 1.0% (LLM policies; 2.5% without updates; 0% with manual approval); claude-sonnet-4 6.8% -> 0.5%; Meta-SecAlign-70B 4.8% -> 0.3%.
- ASB ASR: 70.3% -> 3.9%; 0% with manual rules.
- Progent's paper gives exact utility only in figures. Third-party (DRIFT Table 5) BU / UA / ASR: gpt-4o 76.30 / 61.20 / 2.20; gpt-4o-mini 54.66 / 45.58 / 9.39.
- Independent adaptive evaluation [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1): Qwen2.5-7B, 3 suites, subsampled; preprint by a vendor-affiliated team.
  - Mean ASR: 25.8% undefended -> 4.2% Progent -> 2.6% under the adaptive attack.
  - UA: 45.2% -> 27.1%.
  - About 15x more LLM calls per task.

**DRIFT (Li et al., NeurIPS 2025, arXiv 2506.12104)**: [arXiv 2506.12104v3](https://arxiv.org/html/2506.12104v3)
- Mechanism: a Secure Planner builds a minimal function trajectory plus a JSON-schema parameter checklist. A Dynamic Validator checks deviations against privilege and intent. An Injection Isolator masks conflicting instructions in memory.
- AgentDojo BU / UA / ASR (Tables 6–8):
  - gpt-4o-mini: 63.55 / 48.27 / 30.67 -> 57.29 / 50.93 / 1.35 (90% of BU retained)
  - gpt-4o: 70.86 / 55.43 / 51.68 -> 71.61 / 62.00 / 1.66
  - Claude-3.5-haiku: 58.22 / 45.61 / 18.79 -> 52.28 / 42.41 / 3.26
  - Claude-3.5-sonnet: 78.25 / 52.80 / 37.11 -> 73.36 / 64.16 / 1.47
- ASB: gpt-4o 78.75 / 69.75 / 8.50; gpt-4o-mini 26.50 / 28.50 / 4.75.
- Harness-level change, plus extra LLM calls for planning and validation. No retraining.

**AgentDyn benchmark (arXiv 2602.03117, 60 open-ended tasks, 560 injections; Table 3, BU / UA / ASR, GPT-4o)**: [arXiv 2602.03117v2](https://arxiv.org/html/2602.03117v2)
- Results:
  - none 53.33 / 55.52 / 37.80
  - sandwich 63.33 / 56.13 / 31.17
  - spotlighting 55.00 / 52.24 / 27.61
  - tool filter 8.33 / 4.91 / 4.22
  - CaMeL 0 / 0 / 0
  - Progent 6.67 / 5.83 / 1.69
  - DRIFT 30.00 / 27.09 / 0.83
  - Meta SecAlign 70B (vs Llama-3.3-70B base 10.00 / 6.15 / 11.91): 55.00 / 53.35 / 8.98
- Authors' verdict: "almost all existing defenses are either not secure enough or suffer from significant over-defense".

**ACE (NDSS 2026)**: [arXiv 2504.20984](https://arxiv.org/pdf/2504.20984)
- Abstract plan, then concrete plan, then execute, with IFC on data flows and static plan verification.
- Reports defence on public benchmarks with >80% utility. Per-suite AgentDojo numbers not verified.
- [NDSS slides](https://www.ndss-symposium.org/wp-content/uploads/s0352-rose-slides.pdf) classify f-secure, ReAct and IsolateGPT as "interleaved" planning-execution designs, which ACE separates.

**IsolateGPT/SecGPT (Wu et al., NDSS 2025, arXiv 2403.04960) and f-secure (Wu et al., arXiv 2409.19091)**
- UNVERIFIED (not fetched). IsolateGPT: hub-and-spoke execution isolation between apps. f-secure: information-flow-labelled planner/executor separation using a context-aware structured planner.
- No AgentDojo numbers found for either.

**Design Patterns for Securing LLM Agents (Beurer-Kellner et al., arXiv 2506.08837, 2025)**
- UNVERIFIED (not fetched). A position/design paper proposing six patterns: action-selector, plan-then-execute, LLM map-reduce, dual LLM, code-then-execute (CaMeL-like), and context-minimization. To my knowledge it has no benchmark numbers.

**Other 2025–26 policy/IFC work** (not read; listed only for completeness): PIPES [arXiv 2608.12789](https://arxiv.org/pdf/2608.12789); Ghost in the Agent (IFT) [arXiv 2604.23374](https://arxiv.org/pdf/2604.23374); ActGov [arXiv 2609.24446](https://arxiv.org/pdf/2609.24446); AgentGuardian [arXiv 2601.10440](https://arxiv.org/pdf/2601.10440); ROPE [arXiv 2608.27496](https://arxiv.org/pdf/2608.27496); IFC for privacy leakage [arXiv 2609.14003](https://arxiv.org/pdf/2609.14003). The adaptive-evaluation paper also lists RTBAS, FORGE and Conseca as deterministic policy defences [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1).

### Inferences
- SCML's closest peers are Progent (wrapper, deterministic policy on tool calls) and DRIFT (planner plus validator plus memory isolation).
- On the same model and attack (gpt-4o-mini), DRIFT reports ASR 1.35% at 90% BU retention, and Progent ~9.4% ASR. SCML's 7.3% / 81% sits between them on ASR and below DRIFT on utility retention.
- To be competitive, SCML should report UA and AgentDyn/ASB results, not only AgentDojo.
- Deployment-cost ladder, cheapest to most expensive:
  1. Prompt-only: spotlighting, sandwich.
  2. Wrapper/middleware: tool_filter, Progent, SCML.
  3. Harness rebuild with extra LLM calls: DRIFT.
  4. Full agent rebuild with an interpreter: CaMeL, FIDES, ACE.
  5. Model retraining: StruQ, SecAlign, Meta SecAlign, ISE.

### Gaps
- No exact AgentDojo numbers found for ACE, f-secure, IsolateGPT, or Design Patterns.
- FIDES exact utility values are only in figures.
- CaMeL per-model, per-suite Table 2 was not extracted.

## Q3–Q4. Comparison with detection, the 2026 SOTA trade-off, and layering evidence

### Takeaway
Classifier detectors on AgentDojo cut ASR but destroy utility. Examples: DeBERTa PI detector BU 41.5% on GPT-4o; PIGuard/ProtectAI near-zero utility on AgentDyn. The exception is MELON (re-execution comparison, BU 68–76% at <1% ASR). As of 2026 the reported Pareto frontier on AgentDojo is ~1–2% ASR at roughly undefended utility (DRIFT, Meta SecAlign-70B, Progent+gpt-4o), with frontier commercial models (GPT-5 0.2%, Gemini 3 Pro 2.3%) now near that level unaided. Layering evidence exists but is sparse: Progent on top of Meta-SecAlign, Meta SecAlign plus sandwich, and MELON plus repeat prompt all improve on either component alone.

### Cited Findings
- MELON (masked re-execution: re-runs the agent with the user task masked and flags tool calls that persist). This is detection-like but behavioural. GPT-4o BU 68.04 / UA 58.78 / ASR 0.24; MELON-Aug (MELON + repeat prompt) 76.29 / 68.72 / 0.32. It roughly doubles LLM calls. — [MELON Table 1](https://arxiv.org/html/2502.05174)
- DeBERTa detector (transformers_pi_detector): GPT-4o BU 41.49 / UA 21.14 / ASR 7.95 [AgentDojo Table 5](https://arxiv.org/html/2406.13352); gpt-4o-mini UA 21.2 / ASR 13.0 [DRIFT Table 3](https://arxiv.org/html/2506.12104v3).
- Progent's authors say detectors (transformers_pi_detector, DataSentinel, LlamaPromptGuard2) show high FP/FN on AgentDojo and are outperformed by Progent. Only figures are given, no exact numbers. — [Progent](https://arxiv.org/html/2504.11703v3)
- AgentDyn GPT-4o (BU / UA / ASR): ProtectAI 0.00 / 0.56 / 0.85; PIGuard 10.00 / 1.46 / 1.67; PromptGuard2 60.00 / 20.80 / 27.15. Filtering detectors over-defend or under-defend. — [AgentDyn Table 3](https://arxiv.org/html/2602.03117v2)
- Layering, model plus policy: Progent applied on Meta-SecAlign-70B takes AgentDojo ASR from 4.8% to 0.3%. — [Progent](https://arxiv.org/html/2504.11703v3)
- Layering, model plus prompt: Meta-SecAlign-70B with sandwich gives ASR 1.9% / utility 84.5%, vs 2.3% / 79.4% without sandwich. — [Meta SecAlign Tables 4, 8](https://arxiv.org/html/2507.02735)
- Layering, detector plus prompt: MELON + repeat prompt (MELON-Aug) raises BU from 68.04 to 76.29 on GPT-4o at a similar ASR. — [MELON](https://arxiv.org/html/2502.05174)
- Layering, FIDES on tool filter: FIDES with policy reaches 1 (0) successful injections vs Tool Filter's 28 (23) on gpt-4o, showing IFC policy on top of a structured planner beats tool-level restriction. — [FIDES Table 1](https://arxiv.org/html/2505.23643v2)
- Adaptive-attack caution: near-zero ASRs are mostly measured against fixed attack templates. The 2026 adaptive study did not raise Progent's ASR with a black-box adaptive injection, but it did not test white-box/GCG attacks. It reports no evaluation of policy defences combined with detectors. — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1)

### Inferences
- Deterministic policy layers (SCML, Progent, CaMeL) handle injections that cause *unauthorised actions*. Detectors and model-level defences are needed for text-to-text manipulation inside allowed data flows, which FIDES explicitly lists as not blocked. That makes "policy + model-level alignment (Meta SecAlign) + a low-FPR behavioural detector (MELON-style)" the evidence-backed layering.
- Classifier detectors placed in front of SCML risk compounding utility loss, given their BU drops to ~40% on AgentDojo.
- The 2026 trade-off on AgentDojo is roughly ASR ≤2% with BU ≥ undefended for the best systems on strong models. SCML's 7.3% ASR at 81% BU is competitive with tool_filter/Progent-class numbers on gpt-4o-mini but behind DRIFT's self-reported 1.35%. Independent replications (AgentDyn) show all system defences lose much more utility on open-ended tasks.

### Gaps
- There is no official, current AgentDojo leaderboard snapshot; agentdojo.spylab.ai was not fetched.
- No controlled study combining an IFC/policy middleware with a classifier detector on the same benchmark was found.
- BIPIA results for the system defences were not found. These defences are rarely evaluated on BIPIA, which is a single-turn benchmark.
