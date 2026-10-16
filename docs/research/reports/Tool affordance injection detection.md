# SARA anticipated the idea, not the implementation

**Proposal D is not novel as a concept, but it is novel as an implementation.** The core idea is to flag untrusted content that tries to induce an action the agent's own tools could carry out. That idea was published in August 2026 as the "Action Probe" in SARA, which is the closest prior art. SARA's probe takes each tool output together with the current tool set. It labels the output ACTIONABLE and emits tool-level "action footprints" plus argument-origin anchors of the form (tool, argument path, value) ([SARA, arXiv 2608.27146](https://arxiv.org/abs/2608.27146)). That covers steps 2 and 3 of Proposal D in concept. What remains new and defensible is narrower. It has three parts:

1. A deterministic, CPU-only, LLM-free instantiation built on a dependency/POS parse of mood and addressee. No published prompt-injection detector uses such a parse.
2. An explicit multiplicative score, imperative x affordance, with the threshold calibrated on external data.
3. Using the same signal to gate memory writes. No such gate was found in the memory-poisoning literature.

The design sits in the cheapest cost class. That is where tool-agnostic classifiers have failed badly on over-blocking, and tool-conditioning is a credible answer to that failure. It also carries four serious, documented risks:

- adaptive paraphrase attacks against a white-box parser;
- declarative "false fact" payloads with no imperative surface;
- conditional "if... then" phrasings, which succeed at least as often as bare imperatives;
- over-firing on benign procedural text.

SCML's current numbers are honest but modest against this field:

- **AgentDojo:** 7.3% ASR at 81% retained utility is roughly level with AgentDojo's built-in tool_filter on gpt-4o-mini. It is behind DRIFT and SARA.
- **InjecAgent:** the 0% tells us nothing about the scanner.
- **Memory storage:** the 29.2% -> 20.8% ablation is 14 vs 10 attacks out of 48, which is not statistically distinguishable.

So Proposal D should be built and claimed as "a cheap, deterministic approximation of SARA's Action Probe." It should face hard go/no-go gates on held-out detection metrics, on the contribution of the affordance term specifically, and on adaptive robustness.

## SARA's Action Probe already conditions detection on the agent's tools

The decisive prior art is **SARA** (Guo et al., "When Tool Outputs Become Commands", arXiv, 27 Aug 2026). It frames indirect prompt injection (IPI) as a confusion between *action induction* and *authorization*. Its Probe(O_t, T) returns three things:

- a STATIC/ACTIONABLE label;
- a tool-level action footprint Q_t;
- argument-origin anchors M_t, produced only when the induced action "can be mapped to the current tool set" ([SARA HTML](https://arxiv.org/html/2608.27146)).

Conceptually this is Proposal D's affordance match, including the argument-schema overlap. There are differences:

- **How the probe is built.** The paper does not say whether the probe is an LLM, a classifier or rules. Its wording ("prompting the model") suggests an LLM, but this is **unverified**, and the final part of the paper was not read.
- **What the probe does.** It does not block. It moves the trajectory into an EXPOSED review state, and a separate guard authorizes tool calls based on goal, execution chain and argument-level support.
- **Results and cost.** On AgentDojo with GPT-4o-mini, SARA reports **BU 66.67 / UA 63.44 / ASR 0.06%**, against an undefended 72.46 / 56.01 / 15.79. It costs about **1.91x input tokens**, and it reports no latency or per-output FPR ([SARA HTML](https://arxiv.org/html/2608.27146)).

Several other lines of work sit close to D:

- **CommandSans** shares D's philosophy most closely. It uses token-level predictors trained on ordinary instruction-tuning data, not attack data, to strip AI-directed instructions from tool outputs. It cut AgentDojo ASR from **34% to 3%** with utility preserved, evaluated on AgentDojo, BIPIA, InjecAgent, ASB and SEP ([arXiv 2510.08829](https://arxiv.org/abs/2510.08829)). It is learned and **tool-agnostic**: it removes every instruction whether or not it maps to the agent's tools.
- **MELON** is D's closest *behavioural* analogue. It re-runs the agent with the user task masked and flags tool calls that persist. It reaches GPT-4o BU 68.04 / ASR 0.24 at roughly double the LLM calls ([MELON](https://arxiv.org/html/2502.05174)).
- **Task Shield** has an LLM check whether each instruction and tool call serves the user goal, giving ASR 2.07% at 69.79% utility on GPT-4o ([arXiv 2412.16682](https://arxiv.org/abs/2412.16682)).
- **PromptArmor** prompts an off-the-shelf LLM to detect and remove injections, with **FPR and FNR below 1%** on AgentDojo using GPT-4o-class models ([arXiv 2507.15219](https://arxiv.org/abs/2507.15219)).
- **IntentGuard** has a reasoning model list the instructions it intends to follow and flags any that overlap untrusted spans ([arXiv 2512.00966](https://arxiv.org/abs/2512.00966)).
- **Progent, ClawGuard, Tool Filter and CaMeL** use the agent's tool set and argument schemas as an *enforcement* surface at call time, not as a *detection feature* on untrusted text ([SARA related work](https://arxiv.org/html/2608.27146); [CaMeL](https://arxiv.org/abs/2503.18813)).

| Method | Signal | Tool-conditioned? | Needs LLM / weights | AgentDojo result (model) |
|---|---|---|---|---|
| SARA Action Probe | action induction mappable to tool set | **Yes** (tool + arg anchors) | Likely LLM (unverified) | BU 66.67 / ASR 0.06 (4o-mini) |
| CommandSans | token-level AI-directed instruction | No | Trained token model | ASR 34% -> 3% |
| MELON | tool calls persist without user task | Implicitly (behavioural) | Extra agent run | BU 63.77 / ASR 0.85 (4o-mini, SARA repro) |
| Task Shield | goal alignment of instructions | No | LLM per step | ASR 2.07, util 69.79 (4o) |
| PromptArmor | LLM detect + remove | No | Frontier LLM call | FPR/FNR <1% (4o-class) |
| DeBERTa PI detector | binary classifier | No | Small encoder (CPU) | BU 44.20 / ASR 3.94 (4o-mini, SARA repro) |
| **Proposal D** | mood/addressee x tool-schema overlap | **Yes** | **None (parser + small embedder)** | not yet measured |

Sources for the table: [SARA](https://arxiv.org/html/2608.27146), [CommandSans](https://arxiv.org/abs/2510.08829), [Task Shield](https://arxiv.org/abs/2412.16682), [PromptArmor](https://arxiv.org/abs/2507.15219).

D's genuine contributions are the following.

1. **Linguistic grounding.** No published prompt-injection detector was found that uses dependency/POS imperative-mood or speech-act classification. The closest "structural" detectors use lexical pattern families such as hierarchy override and role redefinition ([arXiv 2605.26999](https://arxiv.org/abs/2605.26999)), or stylometric discontinuity ([prompt-shield, arXiv 2604.18248](https://arxiv.org/abs/2604.18248)).
2. **Cost class.** D is deterministic, CPU-only, needs no LLM call, and can be inspected. That makes it auditable in a way SARA, PromptArmor and MELON are not.
3. **Memory-write gating.** A targeted search found no work that combines imperative detection with matching against the agent's own tools to gate memory writes. Related gates use keyword rules or generic classifiers ([MPBench, arXiv 2606.04329](https://arxiv.org/html/2606.04329v2); [aegis-memory, arXiv 2608.21230](https://arxiv.org/html/2608.21230v1)).

The negative findings come from bounded searches, so these novelty claims should be stated as "to our knowledge." The right framing is not "first to condition detection on the agent's tools". It is "first deterministic, LLM-free instantiation of tool-affordance-conditioned directive detection, with an empirical cost/robustness analysis."

## Tool-conditioning targets the over-blocking that sinks cheap detectors

The case for D rests on one empirical pattern: **CPU-feasible detectors stop attacks by refusing benign work.**

- **AgentDojo, original paper (GPT-4o).** The DeBERTa transformers_pi_detector cut ASR from 57.69% to 7.95% but dropped benign utility from 69.0% to **41.49%** ([AgentDojo](https://arxiv.org/html/2406.13352)).
- **AgentDojo, gpt-4o-mini.** It reached ASR 13.0% with utility under attack of only 21.2 ([DRIFT Table 3](https://arxiv.org/html/2506.12104v3)).
- **AgentDyn.** This benchmark deliberately puts *helpful* third-party instructions in tool output. On GPT-4o, ProtectAI scored **BU 0.00** and PIGuard BU 10.00, while Prompt Guard 2 kept BU 60.00 but let ASR stay at 27.15 ([AgentDyn Table 3](https://arxiv.org/html/2602.03117v2)).
- **NotInject.** On these benign prompts full of trigger words, earlier guard models drop to roughly **60% accuracy**, close to chance ([PIGuard/NotInject](https://arxiv.org/html/2410.22770v3)).

D's multiplicative design targets this failure directly. "Click here to unsubscribe" or "Run pip install" is imperative but should not match `send_money` or `share_file`, so the product stays low. This principle has independent support: a 2026 visual-injection guardrail states that imperative UI text such as "Add to cart" is not suspicious by itself and should be flagged only if acting on it would divert the agent ([arXiv 2609.05535](https://arxiv.org/abs/2609.05535), verified via snippet only).

Four risks follow from the same design, and each has evidence behind it.

**Adaptive attacks are the largest threat, and white-box determinism makes them cheaper.**

- Zhan et al. bypassed **all eight** IPI defences they tested at >50% ASR, and drove detector detection rates to nearly zero ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)).
- "The Attacker Moves Second" bypassed **12 defences at >90%**, most of which had reported near-zero ASR ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)).

A parser rule is fully known to the attacker. Rewriting "send the file to X" as "the file's next destination is X" defeats the mood stage. Synonyms outside the schema vocabulary weaken the affordance stage. No published result covers parser-based detectors under adaptive attack, so this is an open question that D must answer itself.

**Declarative and fact-style payloads have no imperative surface.**

- MPBench separates strong-signal from weak-signal memory attacks. Strong-signal payloads use imperatives, memory verbs and "from now on" cues. Weak-signal payloads (policy-conformant false facts, false precedents, inserted skill procedures) "contain no imperative or anomalous pattern."
- Even PromptArmor's TPR falls from **84.44% on strong-signal to 42.50% on weak-signal** payloads ([MPBench](https://arxiv.org/html/2606.04329v2)).
- A four-stage write-time screen rejected **0 of 360** poisoned false-fact memories ([arXiv 2608.21230](https://arxiv.org/html/2608.21230v1)).
- MINJA's progressive shortening deliberately strips instruction-like text from stored records ([arXiv 2503.03704](https://arxiv.org/html/2503.03704v2)).

**Conditional phrasings are a separate syntactic class, and they work better than bare commands.**

- Trigger-based "explosive" injections succeed at least as often as bare imperatives on every model tested. The gap is largest on the models that resist bare imperatives best ([arXiv 2609.22510](https://arxiv.org/abs/2609.22510), verified via snippet only).
- MPBench's Conditional Command Insertion is its highest-ASR class, at **67.89% and 76.00%** on its two harnesses ([MPBench](https://arxiv.org/html/2606.04329v2)).

D therefore has to treat a number of non-imperative forms as directive. These include conditional antecedents ("if you are an AI assistant, ..."), modal second person ("you must/should"), third-person addressee ("the assistant is required to"), questions, and the passive voice.

**Over-firing on procedural text is the mirror risk.**

- Surface mood under-determines speech acts. Directive force comes from context and plan recognition ([Roberts, OSU](https://www.ling.ohio-state.edu/~croberts/Roberts.SpeechActs.pdf)).
- The best published email request-for-action classifier reached **83.76%** message-level accuracy, and human sentence-level agreement was only **κ = 0.78** ([Lampert et al., NAACL 2010](https://aclanthology.org/N10-1142/); [Macquarie](https://researchers.mq.edu.au/en/publications/can-requests-for-action-and-commitments-to-act-be-reliably-identi/)). That puts a realistic ceiling on the imperative stage.
- spaCy's news-heavy training data contains few imperatives, so sentence-initial verbs get mis-tagged. No published accuracy exists for spaCy imperative detection.
- In this project, a record in the repo's CLAUDE.md (an internal note, not external evidence) says an earlier token-level imperative gate routed **94%** of InjecAgent payloads because benign data shares the command vocabulary. That is the precise failure the affordance term must fix.
- Thresholds are regime-dependent, and AUC does not predict deployed effectiveness ([arXiv 2605.26999](https://arxiv.org/abs/2605.26999)). That directly threatens "calibrate on external data, deploy on SCML traffic."

## SCML's numbers sit mid-pack and do not yet isolate the scanner

On **AgentDojo with gpt-4o-mini**, SCML's 29.0% -> 7.3% ASR at 81% benign utility retained is an internal measurement. The project's committed results record the details: 949 attacked cases, benign completion falling from 74.2% to 59.8%, and only **two of AgentDojo's seventeen attacks** run. Those are `important_instructions` on all four suites and `ignore_previous` on banking and slack (internal: repo CLAUDE.md, `benchmarks/results/agentdojo.md`). The closest comparable undefended baseline in the literature is DRIFT's gpt-4o-mini ReAct run: BU 63.55 / ASR 30.67 ([DRIFT](https://arxiv.org/html/2506.12104v3)). On that footing, SCML lands **roughly level with AgentDojo's built-in tool_filter** (UA 50.4 / ASR 7.6) and slightly better than Progent (ASR 9.4 on 4o-mini, third-party run). It is clearly behind DRIFT (**ASR 1.35% at about 90% of BU retained**) and SARA (ASR 0.06% at about 92% retained, against SARA's own undefended baseline) ([DRIFT](https://arxiv.org/html/2506.12104v3); [SARA](https://arxiv.org/html/2608.27146)).

The retention percentages for DRIFT and SARA are my ratios of their reported BU figures. Baselines differ by harness. SARA's undefended ASR is 15.79%, not around 30%, so cross-paper comparisons are directional only.

SCML's real differentiator over tool_filter is argument-level policy plus taint tracking. Tool_filter **collapses on open-ended tasks**, with AgentDyn GPT-4o BU 8.33% ([AgentDyn](https://arxiv.org/html/2602.03117v2)). SCML has not yet been measured on AgentDyn, so that advantage is a hypothesis, not a result.

| System (gpt-4o-mini unless noted) | ASR | Utility | Cost class |
|---|---|---|---|
| Undefended (DRIFT run) | 30.67 | BU 63.55 | — |
| **SCML/TrustMediator (internal)** | **7.3** | **BU 74.2 -> 59.8 (81% retained)** | middleware, no LLM |
| tool_filter (DRIFT run) | 7.6 | UA 50.4 | 1 LLM call |
| Progent (DRIFT run) | 9.39 | BU 54.66 | LLM-drafted policy |
| transformers_pi_detector (DRIFT run) | 13.0 | UA 21.2 | CPU encoder |
| DRIFT | 1.35 | BU 57.29 (~90% retained) | extra LLM calls |
| MELON (SARA repro) | 0.85 | BU 63.77 | ~2x LLM calls |
| SARA (own baseline 15.79) | 0.06 | BU 66.67 | ~1.91x tokens |
| CaMeL (DRIFT run) | 0.0 | UA 35.4 | agent rebuild |

Sources for the table: [DRIFT Tables 3, 5–8](https://arxiv.org/html/2506.12104v3), [SARA Table 1](https://arxiv.org/html/2608.27146).

On **InjecAgent**, SCML's 0% ASR came entirely from the policy layer, and the scanner contributed nothing. This is a fact about SCML's policy coverage, not a measurement of detection. For comparison, Meta SecAlign-70B moved InjecAgent from 53.8% to 0.5% ([Meta SecAlign](https://arxiv.org/html/2507.02735)), and a write-time screen reached recall 0.832 on InjecAgent, or 0.620 for its deterministic core alone ([arXiv 2608.21230](https://arxiv.org/html/2608.21230v1)). The second figure is a fair deterministic yardstick for D. Because the policy layer saturates InjecAgent's end-to-end ASR, D's value there can only be shown with *per-output detection metrics* (AUC, TPR at fixed FPR), not ASR.

SCML's internal classifier history on held-out InjecAgent makes the bar for D concrete. All of the following are internal results (repo CLAUDE.md, `benchmarks/results/classifier_llm.md`):

| Approach | Outcome |
|---|---|
| Current scanner, no-scanner ablation | **0 of 1054** attacks detected; ASR is 0.0% with or without it, and 100% without tool policy |
| Current heuristic classifier | ROC-AUC **0.35**: anti-discriminative, scoring benign above attacks |
| Two TF-IDF models trained on external corpora | Held-out AUC 0.660 and 0.506 |
| gpt-4o-mini LLM backend | AUC **0.72** at p95 ≈ **2.2 s**, failing both FR-SC-07 and NFR-PERF-01 |
| Token-level syntactic route gate | Routed 94% of all payloads |

The same notes conclude that only a real dependency/POS parse of imperative mood, or a fine-tuned transformer, can separate command-mood from declarative use of the same verbs. That is exactly Proposal D's step 2.

So D does not have to beat SARA to be worthwhile inside SCML. Its first job is to beat **AUC 0.72 at under 400 ms**, which nothing in SCML currently does. SCML's existing pattern-free `ToolOutputSanitizer` already strips instruction *framing*, CommandSans-style. Its single-task slack pilot went from 60% to 0% ASR, which is not a suite-level number. D should be evaluated as complementary to the sanitizer, not as a replacement for it.

On **memory storage**, 20.8% against a <10% target is 10 of 48 attacks, and the scanner ablation 29.2% -> 20.8% is 14 versus 10. By my own calculation, the Wilson 95% intervals are roughly **11.7–34.3%** and **18.2–43.2%**, which overlap heavily. A paired exact McNemar test on at most four discordant attacks cannot reach p < 0.05: the minimum two-sided p is 0.125. The scanner's contribution is therefore **not yet demonstrated**. The <10% target means 4 of 48, so a single attack moves the figure by about 2.1 points. The project's own harm analysis puts the pessimistic *harm* rate at **18.8%**. In that analysis, 0 of 13 tool cases and 0 of 22 control-bypass cases are harmful because policy never reads memory, while 8 informational cases have no mediator gate at all (internal: `benchmarks/results/memory_poisoning_harm.md`). Both the storage and harm numbers should be quoted.

The literature also mixes storage-level metrics with end-to-end metrics:

- Storage-level: MINJA ISR 98.2%, MemSecBench persistence 84.2%, Hidden-in-Memory write rates up to 99.8%.
- End-to-end: MemSecBench full chain 50.3%, MPBench overall ASR 50.46%.

SCML's 20.8% is a storage figure, so it should be set against the storage metrics ([MINJA](https://arxiv.org/html/2503.03704v2); [MemSecBench](https://arxiv.org/html/2607.27080v1); [arXiv 2605.15338](https://arxiv.org/abs/2605.15338); [MPBench](https://arxiv.org/html/2606.04329v2)).

The realistic reference points for D on memory writes are the MPBench detector numbers (TPR/FPR):

| Detector | Off-the-shelf TPR/FPR | After adaptation TPR/FPR |
|---|---|---|
| PromptArmor | 67.67 / 1.00 | 61.60 / 2.67 |
| CommandSans | 52.33 / 45.00 | 61.00 / 8.67 |
| PIGuard | 38.33 / 0.33 | 47.67 / 5.33 |

Source: [MPBench](https://arxiv.org/html/2606.04329v2).

No defence in the surveyed literature reports below 10% end-to-end ASR across both strong-signal and weak-signal memory attacks with a measured FPR. Reaching SCML's target will almost certainly need provenance-based quarantine for the weak-signal family, not a better content scanner.

## Calibrate on LLMail-Inject, BIPIA-train and ASB; never on the test benchmarks

Proposal D needs an external calibration pool that never touches InjecAgent, AgentDojo or the in-house memory corpus. The usable sources, with licence status as found, are below. Rows marked unverified need a LICENSE-file check before use.

| Dataset | Role | Content | Licence |
|---|---|---|---|
| LLMail-Inject (Microsoft) | Calibration positives | ~462k indirect email attacks, written adaptively against live defences; no benign rows | MIT ([HF](https://huggingface.co/datasets/microsoft/llmail-inject-challenge)) |
| BIPIA | Calibration (train attacks) / held-out (test attacks) | 5 indirect tasks, official attack train/test split | Defers to LICENSE file; MIT **unverified** ([GitHub](https://github.com/microsoft/BIPIA)) |
| ASB | Calibration positives + tool descriptions | Tool-response injection (OPI), 400+ tools | **Conflicting** (MIT per a PyPI vendor; none per SourcePulse) ([arXiv 2410.02644](https://arxiv.org/abs/2410.02644v1)) |
| NotInject | Over-defence negatives | 339 benign trigger-word prompts in 3 tiers | MIT ([HF](https://huggingface.co/datasets/leolee99/NotInject)) |
| ToolBench | Benign tool-output negatives | RapidAPI responses | Apache-2.0 vs a CC BY-NC fork, **conflicting** ([HF](https://huggingface.co/datasets/Adorg/ToolBench/blob/main/README.md)) |
| API-Bank | Benign tool-output negatives | API dialogues | MIT, secondary source only ([survey](https://arxiv.org/pdf/2402.18041)) |
| deepset/prompt-injections | Imperative-stage lexical coverage | 662 direct injections | Apache-2.0 ([HF](https://huggingface.co/datasets/deepset/prompt-injections)) |
| Lakera gandalf_ignore_instructions | Imperative-stage positives / matcher negatives | 1,000 direct injections | MIT ([HF](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions)) |
| InjecAgent | **Held-out only** | 1,054 cases, base/enhanced, DH/DS | MIT ([GitHub](https://github.com/uiuc-kang-lab/InjecAgent)) |
| AgentDojo | **Held-out only** | 97 tasks, 629 security cases | MIT ([GitHub](https://github.com/ethz-spylab/agentdojo)) |
| AgentDyn | **Held-out over-defence stress** | 60 tasks, 560 injections, helpful instructions | **Unverified** ([arXiv 2602.03117](https://arxiv.org/abs/2602.03117)) |
| AgentPoison / PoisonedRAG / MemForm | Held-out memory | Poisoned memories / RAG texts | MIT ([AgentPoison](https://github.com/AI-secure/AgentPoison); [PoisonedRAG](https://github.com/sleeepeer/PoisonedRAG); [MemForm](https://github.com/opanhw/memform-code)) |
| aegis-memory false-fact corpus | Held-out weak-signal memory | 360 poisoned LongMemEval memories | Apache-2.0 ([arXiv 2608.21230](https://arxiv.org/html/2608.21230v1)) |
| MPBench | Ideal memory set (3,240 attacks + 2,997 benign) | 6 classes | **No data release found** ([arXiv 2606.04329](https://arxiv.org/html/2606.04329v2)) |

Three handling rules matter.

- **Split LLMail by `team_id`.** Many submissions are near-duplicates from the same team.
- **Run a near-duplicate check** (MinHash or embedding cosine) between the calibration pool and every held-out set, because public training mixes may contain InjecAgent or AgentDojo strings.
- **Report InjecAgent base and enhanced separately.** The enhanced setting's "IMPORTANT!!! Ignore..." prefix rewards detectors for spurious reasons ([InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)).

Direct-injection corpora such as Gandalf and HackAPrompt mostly target password or system-prompt leaks. Those rarely map to tool affordances, so they are useful mainly as imperative-stage positives and as matcher negatives.

For tooling, the latency budget is comfortable if the parser is chosen carefully.

- **spaCy `en_core_web_lg`** processes about **10,014 words/s on CPU**, while the transformer pipeline manages only **684 words/s** ([spaCy](https://spacy.io/usage/facts-figures)). Use sm/md/lg with NER disabled, and avoid `trf`.
- **bge-small-en-v1.5** (MIT, 33.4M parameters, 384-d, MTEB 62.17) is the strongest small embedder found. gte-small (MIT, 61.36) is a close second ([bge](https://huggingface.co/BAAI/bge-small-en-v1.5); [gte](https://huggingface.co/thenlper/gte-small)).
- **Precompute tool and schema embeddings.** They are static per agent, so only candidate imperative sentences are embedded at runtime, in one batch.
- **Benchmark ONNX/OpenVINO int8 on the deployment CPU.** Sentence-transformers' own benchmark found the rankings vary by hardware ([sbert.net](https://sbert.net/docs/sentence_transformer/usage/efficiency.html)).

There is one gap in my own reasoning. Bitwise determinism under multi-threaded ONNX float arithmetic is not established by any source here. Pin thread counts and verify that runs repeat exactly.

## Evaluation plan with go/no-go gates

The plan runs in five stages. Each stage has a gate that must pass before the next stage, or the next claim, is made.

**Stage 0: freeze.** Freeze the calibration pool (LLMail-by-team, BIPIA-train attacks in BIPIA contexts, ASB OPI, NotInject, ToolBench/API-Bank responses) and log the de-duplication counts. Choose the threshold on this pool only, to hit **FPR ≤ 3% on benign tool outputs**. Then freeze the threshold, the parser and the embedder versions. Do not re-tune per benchmark ([protocol per arXiv 2503.00061](https://arxiv.org/html/2503.00061v2); [arXiv 2605.26999](https://arxiv.org/abs/2605.26999)).

**Stage 1: detection on held-out data (FR-SC-07).** Build paired negatives so that AUC is not an artefact of different benign distributions:

- InjecAgent: the same tool responses with the attacker instruction removed;
- AgentDojo: benign utility-run outputs against injected outputs;
- BIPIA: test attacks against clean contexts.

Report ROC-AUC with bootstrap 95% CIs, plus TPR and realised FPR at the frozen threshold, stratified by suite, attack type, base/enhanced and DH/DS.

**Go** if pooled ROC-AUC ≥ **0.85** and realised FPR ≤ **3%** on benign held-out tool outputs, *and* the lower CI bound on AUC is ≥ 0.80. That last condition is my suggested guard against small-sample optimism. Report FPR on NotInject by tier and on AgentDyn helpful-instruction outputs separately. These are the sets that broke PIGuard and ProtectAI ([AgentDyn](https://arxiv.org/html/2602.03117v2)).

**Stage 2: the novelty ablation.** Compare four variants at the same frozen FPR:

1. imperative-only;
2. affordance-only;
3. imperative x affordance;
4. CPU baselines: PIGuard and Prompt Guard 2, plus CommandSans if weights are available.

**Go** only if the product beats imperative-only by a margin whose CI excludes zero, *and* it matches or beats the best CPU baseline's TPR at 3% FPR.

If the affordance term adds nothing, D's distinguishing claim over CommandSans and SARA collapses, and D should be dropped or reframed. The project's own 94% routing failure with a token-level gate shows why this ablation is essential.

**Stage 3: adaptive robustness.** Attack the frozen detector with the following:

1. non-imperative rewrites (declarative, modal, conditional, third-person addressee);
2. tool-name synonyms and obfuscation;
3. instructions split across JSON fields;
4. non-English and encoded variants;
5. a black-box optimisation loop against D's score, following Zhan et al. ([arXiv 2503.00061](https://arxiv.org/abs/2503.00061)) and "Attacker Moves Second" ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)).

Report TPR at fixed FPR before and after adaptation. There is no published bar for this. I suggest a **no-go for gating use** if adaptive TPR falls below about half its static value. In that case D ships only as a defence-in-depth signal that feeds SCML's policy layer, never as a sole blocker.

**Stage 4: end-to-end and memory.** Layer D onto SCML on AgentDojo with gpt-4o-mini and report BU, UA and ASR.

**Go** if ASR falls below 7.3% *without* BU retention dropping below 81%. Add AgentDyn, because it is where tool_filter-class defences collapse.

For memory, report strong-signal and weak-signal classes separately and expand beyond n = 48. Use AgentPoison, MemForm, aegis-memory false facts, and MPBench if the authors release it, with LongMemEval or LoCoMo benign writes for FPR ([MPBench](https://arxiv.org/html/2606.04329v2)).

**Go for the memory gate** if strong-signal storage ASR drops with a paired test reaching significance and benign-write FPR stays ≤ 3%. Do not expect D to move weak-signal ASR. The <10% overall target should be assigned to provenance quarantine, which must act as a cap, not a small additive penalty ([arXiv 2608.21230](https://arxiv.org/html/2608.21230v1)).

**Stage 5: latency (NFR-PERF-01).** Measure end-to-end p50/p95/p99 (segment + parse + embed + match) on the target CPU, with thread count and the payload-size distribution stated, including long outputs.

**Go** if p95 < **400 ms** under the stated truncation policy, and if repeated runs produce identical scores. Truncation is itself an evasion vector, so whatever is cut must be scanned or must fail closed.

## Conclusion

The research changes what D is *for*. Proposal D can no longer claim to be the first to ask whether untrusted text induces an action on this agent's tools: SARA asked that question two months ago with an LLM-shaped probe and near-zero ASR. D's contribution is different. It shows how much of that signal survives once it is reduced to a deterministic parse and a cosine score that runs in milliseconds on a CPU and can be audited line by line.

That is a legitimate and publishable question, and the answer is unknown in both directions. The affordance term could be the missing ingredient that fixes the over-blocking of cheap detectors. Or the adaptive and conditional-phrasing results could show that a white-box syntactic gate is too easy to route around.

For SCML specifically, the honest near-term win is narrower than "a novel detector." D can make the scanner's contribution measurable at all, which the current InjecAgent and 48-attack memory numbers cannot do. It can also give the memory gate a principled strong-signal filter, with weak-signal poisoning explicitly handed to provenance.
