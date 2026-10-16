# Detection-based defences against indirect prompt injection (IPI): prior art for "tool-affordance imperative detection" (Proposal D)

Scope note: current to 2026-10-16. The research budget allowed about 17 tool calls. Items marked **[verified]** were checked against a primary or near-primary page in this session. Items marked **[unverified: from prior knowledge]** come from the researcher's background knowledge and were NOT re-checked this session. Treat their numbers as approximate and confirm them against the URL before citing. Dates: "pre-2025" means first published before 2025-01-01.

Proposal D, restated: (1) structurally segment each untrusted tool output (JSON leaves, email fields); (2) detect imperative mood / second-person address with a dependency/POS parse; (3) score semantic and argument overlap between each imperative and the specific agent's allowed tools and argument schemas, taken from a policy store; (4) score = imperative x affordance, with the threshold calibrated on external data. It runs on CPU only, at <400 ms p95, deterministically, with no attack-vocabulary lists.

---

## Q1. Closest prior art: has anyone combined "is this text an instruction/directive" with matching against the agent's own available tools and argument schemas?

### Takeaway
Yes, at the concept level, and recently. **SARA's "Action Probe"** (Guo et al., arXiv 2608.27146, 27 Aug 2026) takes each tool output O_t together with the current tool set T. It labels the output ACTIONABLE if the output on its own suffices to prompt a specific tool behaviour mappable to T, and it emits a tool-level "action footprint" plus argument-origin anchors (tool, argument path, normalised value). That is essentially Proposal D's steps 2+3 in concept. SARA, however, appears to implement it with a (context-isolated) model prompt, not deterministic linguistics, and uses it as a review/provenance signal rather than a block verdict. Proposal D's remaining novelty is narrower: a **deterministic, CPU-only, parser-based implementation** (imperative/2nd-person detection x schema-overlap score, structure-aware segmentation, externally calibrated threshold) used as a standalone detector. I found no paper that uses dependency/POS-based imperative detection for IPI at all, and none that multiplies such a score by tool-schema overlap.

### Cited Findings
**SARA, the closest prior art (2026)** [verified]
- Title: "When Tool Outputs Become Commands: Separating Action Induction from Runtime Authorization in Tool-Augmented LLM Agents". Authors: Xiaokun Guo, Zhen Xu, Dongdong Huo, Yanqiu Zhang, Wei Wang, Qinfu Yang, Dongjin Yu, Yu Wang. arXiv preprint, 27 Aug 2026. Thesis: IPI arises from conflating *action induction* (content that specifies an action) with *authorization* to execute it. — [arXiv 2608.27146](https://arxiv.org/abs/2608.27146)
- Mechanism: Probe(O_t, T) -> (z_t in {STATIC, ACTIONABLE}, Q_t = tool-level action footprint, M_t = argument-origin anchors of the form (tool, argument path, normalised value)). Q_t and M_t are produced only when the action "can be mapped to the current tool set". Explicit urging to act gives ACTIONABLE, and an explicit but unmappable action can still be ACTIONABLE without anchors. ACTIONABLE only moves the trajectory into an EXPOSED review state. It does not block content. On the execution side, a tool call is authorised only with goal, execution-chain and argument-level support, plus a "No-History-Promotion" rule. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)
- The paper does not say whether the Probe is an LLM, a classifier or rules. Its criterion refers to prompting "the model", which suggests an LLM, but that is unconfirmed. There is no separate imperative-mood detector, and the criterion is semantic. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)
- Results (AgentDojo, Table 1, BU / UA / ASR %): SARA scores 66.67 / 63.44 / 0.06 on GPT-4o-mini and 81.16 / 77.27 / 0.62 on Gemini-2.5-Flash-Lite, against an undefended agent at 72.46 / 56.01 / 15.79 and 87.68 / 57.43 / 33.28. The abstract claims ASR <= 0.63% across four primary settings (AgentDojo and AgentDyn). — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146); [abs](https://arxiv.org/abs/2608.27146)
- Cost: about 1.91x the agent-only input tokens on AgentDojo (25.86K vs 13.54K input tokens per attack task). The Guard uses 8.85K input tokens over 2.42 calls. Latency is not reported (tokens and API calls are used as proxies). FPR is not reported, and over-blocking is discussed only qualitatively. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)
- Same table, baselines reproduced by SARA (GPT-4o-mini BU / UA / ASR): PI Detector 44.20 / 25.57 / 3.94; Spotlighting 73.19 / 59.84 / 13.29; Tool Filter 66.67 / 63.27 / 2.01; IPIGuard 69.93 / 62.36 / 1.39; CaMeL 40.94 / 46.28 / 0.11; MELON 63.77 / 48.61 / 0.85; AttriGuard 59.06 / 52.92 / 0.48; ClawGuard 68.84 / 60.66 / 4.54; AIRGuard 65.58 / 49.72 / 13.32. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)
- SARA's related work lists further action- or tool-aware defences: AttriGuard (action-level causal attribution via counterfactual execution), IPIGuard (tool dependency graph), RTBAS (runtime information-flow control), ClawGuard (task-level rules before tool calls), PACT (argument-level authorization with provenance), AuthGraph (authorization graphs from user requests), AIRGuard (action-time authority control) and Tool Filter. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)

**IntentGuard (2025): instruction-following intent analysis** [verified]
- "Mitigating Indirect Prompt Injection via Instruction-Following Intent Analysis", Mintong Kang, Chong Xiang, Sanjay Kariyappa, Chaowei Xiao, Bo Li, Edward Suh. arXiv, 30 Nov 2025. A reasoning LLM (Qwen-3-32B or gpt-oss-20B) is made to list the instructions it *intends* to follow, using start-of-thinking prefill, end-of-thinking refinement and adversarial in-context demos. Any intended instruction that overlaps untrusted segments is flagged or masked, and inference is re-run. Evaluated on AgentDojo and Mind2Web. Reports no utility loss in all but one setting, and adaptive-attack ASR falling from 100% to 8.5% in one Mind2Web scenario. FPR and cost are not given on the abstract page. It does not match against a tool list. — [arXiv 2512.00966](https://arxiv.org/abs/2512.00966)

**Task Shield (pre-2025 preprint, ACL 2025)** [verified headline]
- Jia, Wu, Qin, Squicciarini, "The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents", ACL 2025 (arXiv Dec 2024). An LLM checks whether each instruction and tool call *serves the user's goal*. On AgentDojo with GPT-4o: ASR 2.07%, utility 69.79%. It needs extra LLM calls per step. — [arXiv 2412.16682](https://arxiv.org/abs/2412.16682); [ACL Anthology](https://aclanthology.org/2025.acl-long.1435)

**MELON (2025, ICML 2025)** [mechanism verified; numbers via third-party reproduction]
- Zhu et al., "MELON: Provable Defense Against Indirect Prompt Injection Attacks in AI Agents". Re-executes the trajectory with the user prompt masked. If the tool calls in the masked run resemble those in the original run, the actions are driven by tool outputs, which indicates an attack. The paper claims better attack prevention and utility than SOTA on AgentDojo, and the MELON-Aug variant improves further. — [arXiv 2502.05174](https://arxiv.org/abs/2502.05174)
- SARA's reproduction: GPT-4o-mini BU 63.77 / UA 48.61 / ASR 0.85. Cost: roughly 2x the LLM calls per step (an inference). — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)
- Relation to D: MELON is also "tool-action-centric" (it compares the tool calls that untrusted content induces), but it requires running the agent LLM again. It is the closest *behavioural* analogue to D's affordance idea.

**CaMeL / Progent / policy-store approaches** [CaMeL verified as existing; numbers unverified]
- Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL), arXiv Mar 2025. A privileged LLM writes the control flow from the user query only. A quarantined LLM without tool access parses the untrusted data, and capability policies gate tool calls. In SARA's reproduction, GPT-4o-mini scores BU 40.94 / ASR 0.11. — [arXiv 2503.18813](https://arxiv.org/abs/2503.18813); [SARA table](https://arxiv.org/html/2608.27146)
- Progent (Shi et al., 2025, "Progent: Programmable Privilege Control for LLM Agents") applies a DSL of per-tool and per-argument privilege policies at tool-call time. It reportedly cut AgentDojo ASR from about 41% to about 2%. **[unverified: from prior knowledge]** — [arXiv 2504.11703](https://arxiv.org/abs/2504.11703)
- Relation to D: these use the agent's tool set and argument schemas as an *enforcement* surface at the action boundary, not as a *detection feature on untrusted text*. D's "policy store" overlaps conceptually with Progent/ClawGuard/Tool Filter policies.

**Practitioner signals** [verified, low rigour]
- An ARMO vendor blog argues that the useful signal of tool-output injection is an induced tool call with no precedent in the agent's history ("two events"). — [ARMO blog](https://www.armosec.io/blog/untrusted-tool-output-prompt-injection/)
- Skillstore guidance: extract and type-check only the needed fields, then re-derive the next action from the user request and policy. Schema validation alone does not make strings or URLs trustworthy. — [Skillstore](https://skillstore.io/security/tool-output-prompt-injection-defense)
- prompt-shield (Munirathinam, arXiv 2604.18248, Apr–Jul 2026) includes "d034 honeypot tool definitions", a deception detector that exposes decoy tools. It is a tool-aware signal, but not schema matching. — [arXiv 2604.18248](https://arxiv.org/abs/2604.18248)

### Inferences
- "Does untrusted content try to induce an action that maps onto *this agent's tools/arguments*?" is no longer a novel *concept* as of Aug 2026 (SARA Action Probe). MELON, Task Shield and IntentGuard address neighbouring questions using LLM calls.
- D can still credibly claim novelty in the **implementation and cost class**: no LLM, no open weights, deterministic, CPU-only, sub-400 ms. It would be the first linguistically grounded (mood/addressee) detector to be conditioned on the agent's tool and argument schema. It should be positioned as a "cheap, deterministic approximation of SARA's Action Probe / MELON's action-dependence signal", and SARA should be cited as the closest prior art.
- The step-3 argument-level overlap (anchors that are values in untrusted text mapping to tool argument paths) is directly anticipated by SARA's M_t anchors. D should differentiate with the multiplicative imperative x affordance score and with the external calibration.

### Gaps
- SARA's Probe implementation (LLM vs. classifier) is not stated in the parts read (the last ~16K characters of the HTML were not read). It is unknown whether SARA reports per-output detection FPR/TPR.
- I could not verify the content of "Evaluating using Mock Tool Calls to Quarantine Untrusted Prompt Inputs" (arXiv 2605.30521, 2026), which may be relevant. — [arXiv 2605.30521](https://arxiv.org/abs/2605.30521)
- IPIGuard (arXiv 2508.15310) details are known only via SARA's table.

---

## Q2. Detector landscape: mechanism, signal, cost, LLM/weights requirement, reported results

### Takeaway
Detectors fall into five families. (a) Fine-tuned small encoders (Prompt Guard 1/2, ProtectAI DeBERTa, PIGuard, GenTel-Shield) are cheap and CPU-feasible but tool-agnostic and prone to over-defence. (b) LLM-as-detector approaches (known-answer, DataSentinel, PromptArmor, DataFilter, IntentGuard, Task Shield) are accurate but need LLM calls. (c) Internal-state detectors (Attention Tracker, TaskTracker, InstructDetector) need open weights. (d) Behavioural/re-execution approaches (MELON) require an extra agent run. (e) Token-level instruction sanitisers (CommandSans) are the closest learned analogue to D's "is this addressed as an instruction" step. None of (a)–(e) except SARA conditions on the agent's tool schemas.

### Cited Findings
**(e) Token-level instruction detection: closest to D step 2**
- CommandSans (Das, Beurer-Kellner, Fischer, Baader, arXiv 9 Oct 2025) uses token-level predictors trained on *ordinary instruction-tuning data* (not attack data) to "surgically" remove instructions directed at AI systems from tool outputs. It is non-blocking, needs no calibration, and is independent of tool-output context. Evaluated on AgentDojo, BIPIA, InjecAgent, ASB and SEP. Reports a 7–10x ASR reduction (AgentDojo 34% -> 3%) with utility preserved. The model and latency are not stated on the abstract page. — [arXiv 2510.08829](https://arxiv.org/abs/2510.08829)
- Relation to D: it shares D's "no attack vocabulary; detect instruction-ness" philosophy, but it is learned (it needs a model), and it is tool-agnostic (it removes *all* AI-directed instructions, regardless of whether they map to the agent's tools).

**(c) Internal-state / instruction detection**
- InstructDetector (Wen et al., "Defending against Indirect Prompt Injection by Instruction Detection", Findings of EMNLP 2025) uses intermediate-layer hidden states and gradients of an LLM as features to detect embedded instructions. It reports 99.60% in-domain and 96.90% out-of-domain accuracy, and BIPIA ASR down to 0.03%. It needs open weights plus a forward/backward pass, and is evaluated on BIPIA only. — [arXiv 2505.06311](https://arxiv.org/abs/2505.06311v2); [ACL Anthology](https://preview.aclanthology.org/new-sigs/2025.findings-emnlp.1060/) [verified via search snippet]
- TaskTracker (Abdelnabi et al., Microsoft, "Get my drift? Catching LLM Task Drift with Activation Deltas", arXiv Jun 2024 / SaTML 2025) trains linear probes on the activation delta before and after the LLM reads external data. It reported very high ROC AUC (>0.99) on its own dataset. It needs open weights. Pre-2025. **[unverified: from prior knowledge]** — [arXiv 2406.00799](https://arxiv.org/abs/2406.00799)
- Attention Tracker (Hung et al., "Attention Tracker: Detecting Prompt Injection Attacks in LLMs", arXiv Nov 2024, NAACL Findings 2025) is training-free and tracks the attention of "important heads" on the original instruction (the "distraction effect"). It needs open weights (attention maps). It reported AUROC gains over prior training-free detectors (about 10% claimed). **[unverified: from prior knowledge]** — [arXiv 2411.00348](https://arxiv.org/abs/2411.00348)

**(b) LLM-as-detector**
- Known-answer detection (Liu et al., "Formalizing and Benchmarking Prompt Injection Attacks and Defenses", USENIX Security 2024, pre-2025) asks a detector LLM to "repeat secret key K while ignoring the following text" plus the data. If K is missing, the data is flagged. It is the basis for DataSentinel. **[unverified: from prior knowledge]** — [arXiv 2310.12815](https://arxiv.org/abs/2310.12815)
- DataSentinel (Liu, Jia, Jia, Song, Gong, IEEE S&P 2025, pp. 2190–2208) fine-tunes a detector LLM through a minimax game against adaptive attackers, alternating gradient-based inner max and outer min. Reported per-task FPR/FNR is mostly 0.00–0.01 for the Universal and NeuralExec attacks (the extracted tables were garbled, so verify in the PDF). Code: github.com/liu00222/Open-Prompt-Injection. — [arXiv 2504.11358](https://arxiv.org/abs/2504.11358); [NSF PAR](https://par.nsf.gov/biblio/10633541) [verified venue; numbers partially]
- PromptArmor (Shi, Zhu, ..., Gong, Guo, Song, arXiv 21 Jul 2025) prompts an off-the-shelf LLM to detect *and remove* injected prompts before the agent sees them. On AgentDojo, FPR and FNR are <1% with GPT-4o, GPT-4.1 and o4-mini, and ASR is <1% after removal. The authors suggest it as a standard baseline and test adaptive attacks. Cost is one frontier-LLM call per input. — [arXiv 2507.15219](https://arxiv.org/abs/2507.15219) [verified]
- DataFilter (Wang, Chen et al., 2025, "Defending Against Prompt Injection with DataFilter") is a model-agnostic, test-time fine-tuned LLM filter that strips injected instructions from data given the user instruction. **[unverified: from prior knowledge; search returned nothing this session]** — likely [arXiv 2510.19207](https://arxiv.org/abs/2510.19207) (URL not verified)
- Gemini "Lessons from Defending Gemini Against Indirect Prompt Injections" (Google DeepMind, arXiv May 2025) describes a retrieved-data classifier over the full prompt focused on tool-calling attacks, evaluated under adaptive attacks. — [arXiv 2505.14534](https://arxiv.org/abs/2505.14534) [verified existence via snippet]
- Instruction referencing ("Robustness via Referencing: Defending against Prompt Injection Attacks by Referencing the Executed Instruction", Chen et al., 2025) has the LLM tag each response with the instruction it executed, and filters responses that do not reference the user's instruction. **[unverified: from prior knowledge]** — [arXiv 2504.20472](https://arxiv.org/abs/2504.20472)

**(a) Small encoder classifiers (CPU-feasible, tool-agnostic)**
- PIGuard (formerly InjecGuard; Li et al., ACL 2025; arXiv Oct 2024) is DeBERTa-v3-base trained with "Mitigating Over-defense for Free" (MOF). It introduces **NotInject** (339 benign samples rich in trigger words). Prior guard models fall to about 60% accuracy on NotInject, near random. PIGuard claims +30.8% (arXiv) / +30.4% (ACL version) over the best prior model. A secondary review reports 83.48% average accuracy (87.32% over-defence, 85.74% benign, 77.39% malicious), which is unverified against the paper. — [arXiv 2410.22770](https://arxiv.org/html/2410.22770v3); [HF PIGuard](https://huggingface.co/leolee99/PIGuard)
- Meta Prompt Guard (v1, 86M mDeBERTa, Jul 2024) and Prompt Guard 2 (86M and 22M, Apr 2025) are binary benign/malicious classifiers with a 512-token window, CPU-runnable. The model card reports AgentDojo-based evaluation, but no numbers were retrieved this session. **[unverified: from prior knowledge]** — [HF meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- ProtectAI deberta-v3-base-prompt-injection-v2 is a DeBERTa-v3-base binary classifier and a common open baseline. No numbers were verified this session. — [HF model card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) **[unverified]**
- GenTel-Shield (GenTel-Safe, Li et al., arXiv Sep 2024) is a fine-tuned multilingual-E5-based detector with the GenTel-Bench benchmark. Pre-2025. **[unverified: from prior knowledge]** — [arXiv 2409.19521](https://arxiv.org/abs/2409.19521)
- Embedding-based classifiers (Ayub & Majumdar, "Embedding-based classifiers can detect prompt injection attacks", CAMLIS 2024, pre-2025) train Random Forest / XGBoost on sentence embeddings (OpenAI, GTE, MiniLM) and reported beating encoder-only baselines on their data. **[unverified: from prior knowledge]** — [arXiv 2410.22284](https://arxiv.org/abs/2410.22284)
- An embedding-based IPI detector in MDPI Algorithms (2026) encodes *user intent + external content* jointly with a text-embedding model and classifies with a tree model. It is intent-conditioned, but not tool-conditioned. — [MDPI Algorithms 19(1):92](https://www.mdpi.com/1999-4893/19/1/92) [verified via snippet only]
- In SARA's AgentDojo reproduction, a generic "PI Detector" (input-side classifier) cut ASR to 3.94% but collapsed benign utility from 72.46% to 44.20% (GPT-4o-mini). That is evidence of the over-blocking cost of tool-agnostic detectors. — [arXiv HTML 2608.27146](https://arxiv.org/html/2608.27146)

### Inferences
- D sits in cost class (a): CPU-only and deterministic. Its claimed advantage over (a) is tool-conditioning, which should reduce false positives on benign imperatives ("Click here to unsubscribe") that do not map to any of the agent's tools. That is exactly the failure mode NotInject and the PI-Detector utility collapse expose.
- CommandSans is the strongest competing "instruction-ness without attack vocabulary" baseline. D should be compared against it and against PIGuard/Prompt Guard 2 on AgentDojo, plus NotInject for over-defence.

### Gaps
- Latency figures for most LLM-based detectors are not reported. CPU latencies for Prompt Guard 2 and ProtectAI were not retrieved.
- There are no head-to-head numbers between ProtectAI v2 and PIGuard from a primary source.

---

## Q3. Linguistic approaches: speech acts, imperative mood, syntactic features

### Takeaway
I found **no published detector that uses dependency/POS-based imperative-mood or speech-act classification for prompt-injection detection**. The nearest work uses "structural" lexical-pattern families (hierarchy override, role redefinition), forensic stylometry, or learned token-level instruction detection. Two 2026 results directly caution that surface imperative mood is an incomplete signal.

### Cited Findings
- "Prompt Injection Detection is Regime-Dependent: A Deployment-Aware Evaluation with Interpretable Structural Signals" (Akinrele & Gowda, arXiv 26 May 2026) adds interpretable structural signals (hierarchy override, system-prompt spoofing, role redefinition, evasion patterns) to lexical, semantic and transformer detectors. The abstract does not mention imperative mood or second person. Transformers are best overall. Structural signals give modest, consistent gains in some regimes and help low-FPR behaviour in harder cases. Performance is highly regime- and threshold-dependent, and ranking metrics (AUC) do not predict deployment effectiveness. — [arXiv 2605.26999](https://arxiv.org/abs/2605.26999) [verified abstract]
- "Defusing Explosive Prompts: Understanding and Preventing Trigger-Based Prompt Injections in LLM Agents" (arXiv Sep 2026) finds that conditional/trigger-based ("explosive") injections succeed at least as often as bare imperative injections on every model tested, with the largest gap on the models most resistant to bare imperatives. A pure imperative-mood detector would miss this class. — [arXiv 2609.22510](https://arxiv.org/abs/2609.22510) [verified via search snippet only]
- A visual prompt-injection guardrail paper explicitly states that ordinary imperative UI text (for example "Add to cart") is not divergent by itself. Content is flagged only if acting on it diverts the agent from the user's task. This supports D's design of gating the imperative signal by affordance. — [arXiv 2609.05535](https://arxiv.org/abs/2609.05535) [verified via snippet only]
- prompt-shield's seven cross-domain techniques (Munirathinam, arXiv 2604.18248, v4 Jul 2026) include forensic-linguistics stylometric discontinuity (d027). The abstract does not mention speech acts, imperative mood or dependency parsing. On a 50-document held-out benchmark, d027 alone dropped from 1.000 to 0.000 F1, while the composed engine reached 0.815. — [arXiv 2604.18248](https://arxiv.org/abs/2604.18248) [verified]
- Linguistics background: Roberts argues that imperative clauses' directive force comes from context and plan recognition, not from clause semantics alone. Surface mood therefore under-determines the speech act. — [Roberts, "Speech Acts in Discourse Context" (OSU)](https://www.ling.ohio-state.edu/~croberts/Roberts.SpeechActs.pdf)
- Instruction/data separation benchmarks: SEP ("Can LLMs Separate Instructions From Data?", Zverev et al., ICLR 2025) is used by CommandSans as an evaluation set. **[unverified details: from prior knowledge]** — [arXiv 2403.06833](https://arxiv.org/abs/2403.06833); [CommandSans](https://arxiv.org/abs/2510.08829)

### Inferences
- The use of syntactic mood plus addressee detection as a security feature appears unpublished, so it is a genuine (if modest) novelty for D. D must handle non-imperative directives: conditionals ("if you are an AI assistant, ..."), modals ("you should/must ..."), declarative requests ("the assistant is required to ..."), questions and passive voice. Otherwise the Explosive-Prompts result implies easy evasion.
- The affordance gate is D's answer to the "imperative is weak alone" critique, and it is consistent with the guardrail literature's "only flag if acting diverts the agent" principle.

### Gaps
- No search covered non-English speech-act detection or classical NLP intent/dialogue-act classifiers applied to security. A broader linguistics-venue search may still find workshop papers.

---

## Q4. Known weaknesses of detectors: adaptive attacks and over-defence

### Takeaway
Adaptive attacks bypass essentially all published IPI detectors (detection rates near zero; ASR >50% across eight defences). Encoder classifiers also over-defend on trigger-word-rich benign text (NotInject, about 60% accuracy). D's deterministic, white-box design makes adaptive evasion *easier* to optimise (paraphrasing to non-imperative form, or describing actions without naming tool-like verbs or arguments). Its tool-conditioning, however, directly targets the over-defence weakness.

### Cited Findings
- Zhan, Fang, Panchal, Kang, "Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents", NAACL Findings 2025: all eight IPI defences were bypassed with ASR >50%. Against detection-based defences, adversarial strings drove detection rates to nearly zero in most cases. Code: github.com/uiuc-kang-lab/AdaptiveAttackAgent. — [arXiv 2503.00061](https://arxiv.org/abs/2503.00061); [ACL Anthology](https://preview.aclanthology.org/moar-dois/2025.findings-naacl.395)
- DataSentinel's design premise is that detectors must be trained against adaptive attackers (minimax). — [arXiv 2504.11358](https://arxiv.org/abs/2504.11358)
- PromptArmor and IntentGuard both report adaptive-attack evaluations (IntentGuard: 100% -> 8.5% in one Mind2Web scenario). — [arXiv 2507.15219](https://arxiv.org/abs/2507.15219); [arXiv 2512.00966](https://arxiv.org/abs/2512.00966)
- Over-defence: NotInject shows state-of-the-art guard models near 60% accuracy on benign trigger-word text. — [arXiv 2410.22770](https://arxiv.org/html/2410.22770v3)
- CommandSans argues current detection defences are poorly calibrated with high FPR, which motivates non-blocking token-level sanitisation. — [arXiv 2510.08829](https://arxiv.org/abs/2510.08829)
- Regime dependence: thresholds and ranking metrics do not transfer across deployment regimes. This directly bears on D's "threshold calibrated on external data" step. — [arXiv 2605.26999](https://arxiv.org/abs/2605.26999)
- Trigger-based/conditional injections match or exceed imperative-injection success. — [arXiv 2609.22510](https://arxiv.org/abs/2609.22510)

### Inferences
- D's evaluation should include: (i) an adaptive attacker with white-box knowledge of the parser and the tool schemas (for example a paraphrase search that avoids imperative mood or second-person address, or that uses synonyms outside the schema vocabulary); (ii) NotInject plus benign tool outputs containing imperatives (emails, docs, web pages) for FPR; (iii) AgentDojo / InjecAgent / BIPIA ASR and utility against PIGuard, Prompt Guard 2, CommandSans, PromptArmor, MELON and SARA; (iv) a cross-regime threshold transfer check.
- Because SARA (Aug 2026) uses the action-mapping concept, D's novelty claim should be framed as "a deterministic, LLM-free, CPU-only instantiation of tool-affordance-conditioned directive detection, plus an empirical analysis of its cost/robustness trade-off". It should not be framed as the first to condition detection on the agent's tools.

### Gaps
- No adaptive-attack results exist for SARA or CommandSans in the parts retrieved.
- No published result was found on parser-based detectors under adaptive attack, so this is an open empirical question for D.
