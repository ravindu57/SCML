# Memory Poisoning Attacks and Defences for LLM Agents (positioning SCML memory integrity layer)

Scope: persistent and long-term agent memory and RAG knowledge bases. As of 2026-10-16. Licences come from the GitHub API, checked 2026-10-16. "UNVERIFIED" means I did not read it in a primary source.

## Q1. Attack landscape: what attacks exist and what success rates are reported?

### Takeaway
Reported attack success is high everywhere: ASR is 60-99% under idealised conditions, and getting a malicious record written into memory is often above 90%. Attacks have moved from optimised triggers (AgentPoison, BadRAG), to query-only injection (MINJA), to plain-language "weak-signal" writes with no imperative markers (false facts, false precedents, grafted "successful experiences"), to sleeper and delayed activation. Two 2026 studies show ASR falls sharply under realistic conditions (pre-existing benign memory, harness differences). So ASR depends heavily on configuration, and a single in-house number such as SCML's 20.8% is hard to compare across papers.

### Cited Findings
**AgentPoison (Chen et al., arXiv 2407.12784; the brief lists it as NeurIPS 2024, but the arXiv page shows no venue, so the venue is UNVERIFIED here)**
- Backdoor attack that poisons long-term memory or the RAG KB. It uses an optimised trigger so that triggered queries retrieve malicious demonstrations, and needs no training. — [arXiv abs](https://arxiv.org/abs/2407.12784)
- Average ASR above 80% at a poison rate below 0.1%, with benign performance dropping less than 1%. Agents: Agent-Driver (autonomous driving), ReAct-StrategyQA, EHRAgent. — [arXiv abs](https://arxiv.org/abs/2407.12784)
- Section 4.2 averages with no defence: ASR-r (retrieval) 81.2%, ASR-a (action) 59.4%, ASR-t (end-to-end target) 62.6%; benign accuracy drop 0.74%. — [arXiv html](https://arxiv.org/html/2407.12784)
- Code: [AI-secure/AgentPoison](https://github.com/AI-secure/AgentPoison), MIT licence (GitHub API).

**MINJA, Memory INJection Attack (Dong et al., arXiv 2503.03704; venue UNVERIFIED)**
- Threat model: the attacker is a regular user who only sends queries and has no memory access. It uses bridging steps ("Data of A saved under B"), an indication prompt, and a progressive shortening strategy that removes the indication prompt, so the stored record looks benign. — [arXiv html v2](https://arxiv.org/html/2503.03704v2)
- Average injection success rate (ISR) 98.2% and average ASR 76.8%. Per setting: EHR/MIMIC-III ISR 95.6 and ASR 57.0; eICU 98.5 and 90.0; RAP/Webshop on GPT-4o 99.3 and 98.9; MMLU 100 and 68.9. — [arXiv html v2](https://arxiv.org/html/2503.03704v2)
- With more benign records (25 to 100), MIMIC-III ASR fell from 68.9% to 31.1% while ISR stayed above 90%. — [arXiv html v2](https://arxiv.org/html/2503.03704v2)
- Defences are argued about, not measured. The paper claims MINJA bypasses Llama Guard-style moderation and memory sanitisation (supported only by a t-SNE plot); it gives no detection rates. — [arXiv html v2](https://arxiv.org/html/2503.03704v2)
- Replication (Sunil et al., arXiv 2601.05504) on an EHR agent with MIMIC-III:
  - Empty memory: GPT-4o-mini ASR 62%, ISR 100%; Llama-3.1-8B ASR 52.94%.
  - With 6 pre-existing benign memories: GPT-4o-mini ASR 6.67%, ISR 26.67%; Llama ASR 0%.
  - Best case with 10 retrieved memories: about 38% (GPT) and about 28% (Llama).
  — [arXiv 2601.05504v2](https://arxiv.org/html/2601.05504v2)

**PoisonedRAG (Zou et al., USENIX Security 2025)**
- Injecting 5 malicious texts per target question into a knowledge base of millions gives about 90% ASR. The paper evaluated "several defenses" and found them insufficient. — [arXiv abs](https://arxiv.org/abs/2402.07867)
- Code: [sleeepeer/PoisonedRAG](https://github.com/sleeepeer/PoisonedRAG), MIT licence.

**BadRAG (Xue et al., arXiv 2406.00083; no venue on the page)**
- Uses trigger-conditioned passages. 10 passages (about 0.04% of the corpus) give 98.2% retrieval success, and the negative-response rate rises from 0.22% to 72% on triggered queries. Stated goals include DoS, sentiment manipulation, context leakage and tool misuse. — [arXiv abs](https://arxiv.org/abs/2406.00083)

**MemoryGraft (Srivastava and He, arXiv 2512.16962, Dec 2025)**
- Plants fake "successful experience" records through benign-looking files such as READMEs; no trigger is needed. Union lexical plus embedding retrieval surfaces the records, and the MetaGPT DataInterpreter agent (GPT-4o) adopts unsafe patterns such as skipping tests and force-pushing. The paper reports that a few poisoned records make up a large share of what gets retrieved. Specific numbers were not read (UNVERIFIED). — [arXiv](https://arxiv.org/html/2512.16962); [promptfoo LMVD bf72230e](https://www.promptfoo.dev/lm-security-db/vuln/grafted-experience-drift-bf72230e)

**Sleeper-style attacks (2026)**
- *Hidden in Memory: Sleeper Memory Poisoning* (Pulipaka, ..., Abdelnabi, Fritz; arXiv 2605.15338). Content in a document, webpage or repo makes the assistant store a fabricated memory about the user. Poisoned memories were written in up to 99.8% of cases (GPT-5.5) and 95% (Kimi-K2.6). When retrieved, they led to attacker-intended agentic actions in 60-89% of evaluations. — [arXiv abs](https://arxiv.org/abs/2605.15338)
- *Plant, Persist, Trigger: Sleeper Attack* (Li et al., arXiv 2605.28201, v2 Oct 2026). Benchmark of 1,896 instances: 6 harmful outcomes, 3 strategies, and 3 state targets (session context, memory, reusable skills), tested on 7 LLMs. Agents stay vulnerable even when single-interaction ASR is low. CC BY 4.0 paper; code at an anonymous link. — [arXiv abs](https://arxiv.org/abs/2605.28201)

**Systematic 2026 studies**
- *From Untrusted Input to Trusted Memory* (Dash et al., arXiv 2606.04329; introduces MPBench):
  - 4 write channels: explicit instruction write, system-prompt-driven, compaction-driven, and experience-to-procedure.
  - 6 attack classes. Strong-signal: Explicit Command, Conditional Command, Salience-Driven Compaction. Weak-signal: Policy-Conformant Fact Injection, False Precedent, Skill-Procedure Insertion.
  - Average ASR is 34.25% on OpenClaw and 66.67% on HERMES (50.46% overall). Conditional Command Insertion reaches 67.89% and 76.00%.
  — [arXiv html v2](https://arxiv.org/html/2606.04329v2)
- *MemSecBench* (Chen et al., arXiv 2607.27080):
  - 310 Write-Execute-Forget cases across 2 harnesses (OpenClaw, Hermes), 4 memory backends (Native, Mem0, Mem0-Graph, A-MEM) and 3 LLMs (DeepSeek-V4-Pro, MiniMax-M3, GPT-5.5), for 24 configurations.
  - Malicious memory persists in 84.2% of cases, and the full write-to-execute chain succeeds in 50.3%.
  - Among poisoned cases, 59.6% reach Execute and 56.1% achieve selective repair.
  — [arXiv html](https://arxiv.org/html/2607.27080v1)
- *Utility Under Attack* (Karunanidhi, arXiv 2608.21230): poisoning 1.2% of a LongMemEval corpus with plainly worded false statements cut accuracy from 0.850 to 0.300. — [arXiv abs](https://arxiv.org/abs/2608.21230)
- *MemForm* (Pan et al., arXiv 2610.14431, Oct 2026): "memory formation poisoning" across 5 interfaces (Content, Evidence, Scope, Selection, Path), 6 LLMs. All interfaces were susceptible. Consolidation order alone changes behaviour even when the retained experiences are identical. — [arXiv abs](https://arxiv.org/abs/2610.14431)

**Real-world incidents (Rehberger, embracethered.com)**
- SpAIware (disclosed 20 Sep 2024):
  - Mechanism: prompt injection from a website or document invoked ChatGPT's memory tool and stored persistent instructions.
  - Effect: every later chat exfiltrated user messages through image URLs, because the `url_safe` check was missing in the macOS, Android and iOS clients.
  - Fix: OpenAI fixed the exfiltration in version 1.2024.247.
  - Still open: "A website or untrusted document can still invoke the memory tool to store arbitrary memories."
  — [embracethered](https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/)
- Gemini delayed tool invocation (posted 10 Feb 2025):
  - Mechanism: hidden text in a summarised document makes the memory write conditional on the user replying "yes", "sure" or "no". When the user replies, Gemini treats the write as user-initiated and stores false memories (age, nickname, flat-earth claim) that persist.
  - Google's rating: "low likelihood and low impact" abuse risk.
  - Author's proposed mitigations: confirm memory writes, and require confirmation for sensitive tool calls once untrusted data is in context.
  — [embracethered](https://embracethered.com/blog/posts/2025/gemini-memory-persistence-prompt-injection/)

### Inferences
- The attacks split cleanly into two families:
  - Strong-signal (imperative or conditional commands: SpAIware, Gemini delayed invocation, MPBench classes 1-3). The proposed imperative-mood x tool-affordance detector targets this family.
  - Weak-signal (false facts, false precedents, grafted successful experiences, MINJA bridging steps, PoisonedRAG answers). These are declarative and have no imperative mood. SCML's evaluation should report the two families separately.
- MINJA's progressive shortening deliberately strips the instruction-like text, so imperative detection alone will likely miss MINJA-style records. Provenance (user-query-derived reasoning) and consistency checks need to carry that case.
- Conditional commands ("if the user says X, do Y"; MPBench Conditional Command Insertion, the highest-ASR class) combine imperative mood with a tool reference. This is the best-fit target for the proposed detector.

### Gaps
- I did not verify the venue for MINJA or AgentPoison (NeurIPS 2024 is as stated in the brief).
- I did not read MemoryGraft's quantitative tables.
- I did not find a primary write-up of 2025-2026 ChatGPT or Claude memory incidents beyond SpAIware.

## Q2. Defences: mechanism, results, false positives, cost

### Takeaway
No defence gets below about 10% end-to-end ASR across attack families with acceptable utility. Write-time content screens catch instruction-like injection (TPR up to about 84% on strong-signal payloads, with low FPR for the best tools) but catch close to nothing on weak-signal false facts: 0 of 360 rejected in one study, 18-42% TPR in MPBench. Naive provenance weighting either fails or destroys utility. Consensus or reasoning-level checks (A-MemGuard) have the strongest reported numbers but cost about 2x tokens and still leave substantial ASR-t. SCML's three signals (provenance, injection scan, control-conflict consistency) map onto these three defence families.

### Cited Findings
**A-MemGuard (Wei et al., ICML 2026)**
- Mechanism: generate a reasoning path from each of the top-k=4 retrieved memories, have an LLM judge build a consensus and drop divergent memories, and store the flagged paths as "lessons" in a separate memory consulted before acting. — [arXiv html](https://arxiv.org/html/2510.02373v1); [ICML poster](https://icml.cc/virtual/2026/poster/61006)
- Results on AgentPoison-style direct poisoning (EHRAgent, GPT-4o-mini+DPR): ASR-r 100 to 2.13, ASR-a 87.23 to 6.38, ASR-t 100 to 36.17. On StrategyQA with LLaMA-3-8B+REALM, ASR-a only fell from 46.34 to 36.11. — [arXiv html](https://arxiv.org/html/2510.02373v1)
- MINJA-style indirect injection on MMLU: final ASR fell from 0.667 to 0.256 (GPT-4o-mini) and from 0.663 to 0.233 (LLaMA-3.1-8B), about a 60% relative cut. The headline "over 95%" applies mainly to ASR-r. — [arXiv html](https://arxiv.org/html/2510.02373v1)
- Baselines: LLM Auditor, a DistilBERT classifier and a perplexity filter were at or above no-defence ASR in several indirect cases. — [arXiv html](https://arxiv.org/html/2510.02373v1)
- Cost: about 7.8K tokens per run vs 3.6K undefended. Benign accuracy sometimes falls (EHR GPT-4o-mini+DPR: 83.0 to 71.3). No FPR is reported. The ICML slides call the FPR bound marginal, and 100B+ calibration is listed as future work. — [arXiv html](https://arxiv.org/html/2510.02373v1); [ICML slides](https://icml.cc/media/icml-2026/Slides/77844.pdf)
- Code: [TangciuYueng/AMemGuard](https://github.com/TangciuYueng/AMemGuard), MIT licence.

**Defences tested in the AgentPoison paper**
- The perplexity filter and query rephrasing did not stop the attack. Under the perplexity filter, AgentPoison ASR-t was 47.2 (Agent-Driver), 61.2 (StrategyQA) and 59.6 (EHRAgent). Under rephrasing it was 50.0, 62.0 and 17.0. — [arXiv html](https://arxiv.org/html/2407.12784)

**Defences tested or proposed for MINJA**
- The MINJA paper argues only, with no numbers (see Q1).
- The 2601.05504 replication proposes two defences:
  - (a) A composite trust score built from keyword heuristics ("Knowledge:", "ignore previous"), control-character checks, an optional LLM classifier, and output code scanning (exec/eval/subprocess). No quantitative results are given.
  - (b) Trust-aware sanitisation: append-time trust in [0,1], temporal decay, a pattern filter for "Refer X to Y", and a 0.5 threshold. On GPT-4o-mini it rejected all 23 candidates, leaving memory empty (over-conservative). On Gemini-2.0-Flash it accepted 82, of which 54 were malicious, at trust 1.0.
  — [arXiv 2601.05504v2](https://arxiv.org/html/2601.05504v2)

**Prompt-injection detectors on memory writes (MPBench, arXiv 2606.04329)**
- Off-the-shelf TPR/FPR: PIGuard 38.33/0.33; DataFilter 23.00/53.33; CommandSans 52.33/45.00; PromptArmor 67.67/1.00.
- After adaptation: PIGuard 47.67/5.33; CommandSans 61.00/8.67; PromptArmor 61.60/2.67.
- Strong-signal vs weak-signal TPR: PromptArmor 84.44 vs 42.50; CommandSans 68.33 vs 28.34; PIGuard 51.67 vs 18.34.
- The authors conclude that defences must sit on the memory write path, not the input boundary.
— [arXiv html v2](https://arxiv.org/html/2606.04329v2)

**Write-time screen plus provenance weighting (Utility Under Attack, arXiv 2608.21230)**
- Write-time screen: a 4-stage pipeline (structural checks, secret/PII, rule-based injection patterns, LLM classifier at confidence ≥0.80). Results:
  - InjecAgent recall 0.832 (0.620 for the deterministic core alone).
  - NotInject benign FPR 1.5% (deterministic) and 3.5% (with LLM).
  - It rejected 0 of 360 poisoned false-fact memories.
- Provenance weighting:
  - The shipped weight w_t=0.15 gave accuracy 0.317 vs 0.300 for no defence (p=0.80).
  - w_t=0.35 gave 0.475.
  - When the answer-bearing evidence itself was untrusted, accuracy collapsed from 0.858 to 0.042.
- The author proposes a bounded-occupancy cap on untrusted content at retrieval (not evaluated).
- Code: [quantifylabs/aegis-memory](https://github.com/quantifylabs/aegis-memory), Apache-2.0.
— [arXiv html](https://arxiv.org/html/2608.21230v1)

**Benign cost of defences (The Price of Safety, Bhowmik, arXiv 2609.22818)**
- Write-time defences (input sanitisation, provenance checking, LLM anomaly detection) showed no resolvable utility cost on benign conversations.
- A read-time reranker cost 4.4 accuracy points, quarantined 33.6% of legitimate adjudicated items with no attack present, and added 2.7% token overhead.
— [arXiv abs](https://arxiv.org/abs/2609.22818)

**RAG-specific defences**
- RobustRAG (Xiang et al., arXiv 2405.15556) isolates then aggregates: it generates from disjoint passage groups and aggregates by keyword or decoding. It gives certifiable robustness against k injected passages for some queries. — [arXiv abs](https://arxiv.org/abs/2405.15556). Repo [inspire-group/RobustRAG](https://github.com/inspire-group/RobustRAG) has no licence file.
- TrustRAG (arXiv 2501.00879) uses K-means cluster filtering plus LLM self-assessment for conflict resolution; it is training-free. — [arXiv abs](https://arxiv.org/abs/2501.00879). Code at [HuichiZhou/TrustRAG](https://github.com/HuichiZhou/TrustRAG), MIT licence. I did not read its numbers.

**Engineering and reference implementations**
- OWASP Agent Memory Guard (Apache-2.0, OWASP Incubator) screens reads and writes with detectors for prompt injection, secret/PII, protected-key modification, size anomalies, self-reinforcement loops and persistence. It also keeps SHA-256 baselines, snapshot rollback, and allow/redact/quarantine/block decisions. — [GitHub](https://github.com/OWASP/www-project-agent-memory-guard)
- Its self-reported results on 55 cases are 92.5% recall, 0% FPR and 62 µs median latency. The corpus is tiny and the benchmark is self-authored. — [GitHub](https://github.com/OWASP/www-project-agent-memory-guard)
- Rehberger recommends user confirmation for memory writes and for sensitive tools once untrusted data is in context. — [embracethered](https://embracethered.com/blog/posts/2025/gemini-memory-persistence-prompt-injection/)
- MemForm reports that the defences it evaluated give only partial, interface-dependent mitigation (details not read). — [arXiv abs](https://arxiv.org/abs/2610.14431)

### Inferences
- SCML's quarantine-on-low-integrity design matches the field's direction (write-path gating, as in MPBench, OWASP AMG and aegis-memory). The aegis-memory results warn that the provenance label must act as a cap or a quarantine, not a small additive penalty.
- SCML can only credibly claim below 10% ASR if it reports results per family. Strong-signal and conditional-command attacks look reachable with an injection scan plus imperative x tool detection, given PromptArmor's 84% strong-signal TPR before any tool-affordance signal. Weak-signal false facts need provenance or external grounding; no content scanner in the literature catches them.
- Report FPR on a benign memory-write set as MPBench does (2,997 benign) and quarantine rate as in the Price of Safety paper (33.6% for the reranker), since reviewers will compare against these.
- The control-conflict consistency check is conceptually closest to A-MemGuard's consensus check, but it runs at write time instead of over reasoning paths at read time. That is cheaper, because A-MemGuard roughly doubles tokens.

### Gaps
- Certified RAG defences beyond RobustRAG (e.g. later certified-aggregation work): not researched within the call budget.
- TrustRAG and RobustRAG quantitative results: not read.
- No source reports a defence with below 10% end-to-end ASR across both strong-signal and weak-signal attacks and a measured FPR.

## Q3. Public benchmarks and datasets usable as external, held-out evaluation

### Takeaway
Several 2026 adversarial memory benchmarks now exist. The most directly usable for SCML's write-gating claim is MPBench, because it has labelled attack classes and a benign FPR set, but I found no released data URL or licence for it. Fully licensed, downloadable options today are AgentPoison (MIT), MemForm (MIT code), PoisonedRAG (MIT) and aegis-memory corpora (Apache-2.0). Licence and availability must be checked per dataset.

### Cited Findings
| Benchmark | Content | Licence / availability |
|---|---|---|
| MPBench (arXiv 2606.04329) | 3,240 attacks, 6 classes, 7 domains (email, files, scripts, calendar, Slack, web, skills), plus 2,997 benign for FPR | Paper CC BY 4.0. No code or data URL found. — [arXiv html](https://arxiv.org/html/2606.04329v2) |
| MemSecBench (arXiv 2607.27080) | 310 write-execute-forget cases, 24 configurations | No URL found; arXiv non-exclusive licence. — [arXiv html](https://arxiv.org/html/2607.27080v1) |
| Sleeper Attack (arXiv 2605.28201) | 1,896 instances | Anonymous code link only. — [arXiv abs](https://arxiv.org/abs/2605.28201) |
| MemForm (arXiv 2610.14431) | 5 formation interfaces | [opanhw/memform-code](https://github.com/opanhw/memform-code), MIT — [arXiv abs](https://arxiv.org/abs/2610.14431) |
| AgentPoison | Triggers and poisoned memory for 3 agents | MIT — [GitHub](https://github.com/AI-secure/AgentPoison) |
| PoisonedRAG | Per-question poisoned texts for NQ, HotpotQA, MS-MARCO (dataset names from my own knowledge, UNVERIFIED) | MIT — [GitHub](https://github.com/sleeepeer/PoisonedRAG) |
| aegis-memory harnesses and corpora (LongMemEval-based, 360 poisoned memories) | False-fact poisoning | Apache-2.0 — [arXiv html](https://arxiv.org/html/2608.21230v1) |
| OWASP Agent Memory Security Benchmark (55 cases) | Self-authored | Apache-2.0 — [GitHub](https://github.com/OWASP/www-project-agent-memory-guard) |

- Benign memory benchmarks such as LoCoMo and LongMemEval have no adversarial component. They are useful only as the benign side for measuring FPR and utility. — [arXiv 2606.04329](https://arxiv.org/html/2606.04329v2)
- I found no MINJA code repository (the guessed repo returned 404). The paper describes its own attack-query generation. — [arXiv html v2](https://arxiv.org/html/2503.03704v2)

### Inferences
- A defensible held-out evaluation for SCML:
  - MPBench-style class-stratified attacks, if released (contact the authors otherwise).
  - AgentPoison memories (MIT).
  - MemForm (MIT).
  - aegis-memory weak-signal false facts (Apache-2.0).
  - LongMemEval or LoCoMo benign writes for FPR.
- SCML's 48-attack in-house corpus is about the size of the OWASP self-authored set, small compared with MPBench (3,240). At n=48, one attack is about 2.1 points of ASR: 20.8% is 10 of 48, and the 10% target is 4 of 48. Wide confidence intervals argue for an external corpus.

### Gaps
- I could not confirm a released dataset or licence for MPBench, MemSecBench or Hidden-in-Memory.
- MemForm's data licence is not separately stated; MIT applies to the code repo.

## Q4. Does any work use instruction/imperative detection or tool-affordance matching to gate memory writes?

### Takeaway
I found no paper that combines imperative-mood detection with matching against the agent's own tool inventory to gate memory writes. Related work uses keyword or regex rules (e.g. "ignore previous", "Refer X to Y"), generic prompt-injection classifiers, output code scanning for dangerous calls, or confirmation for sensitive tools after untrusted context. MPBench explicitly identifies imperative verbs and temporal cues as the marker of strong-signal attacks. The proposed detector appears novel as a combination, with the caveat that my search may have missed something.

### Cited Findings
- MPBench defines strong-signal payloads by imperative verbs (remember, store, save), memory commands, user-preference framing and temporal cues ("always", "from now on"). Weak-signal payloads "contain no imperative or anomalous pattern" and are largely missed. — [arXiv html v2](https://arxiv.org/html/2606.04329v2)
- The 2601.05504 replication gates memory appends with keyword heuristics and scans generated code for exec/eval/subprocess/network/file I/O. This is closest to "tool-affordance" but applies to outputs, not memory-text semantics. — [arXiv 2601.05504v2](https://arxiv.org/html/2601.05504v2)
- aegis-memory Stage 3 uses deterministic patterns for instruction overrides, role manipulation and exfiltration. — [arXiv html](https://arxiv.org/html/2608.21230v1)
- OWASP AMG has a prompt-injection detector but no tool-specific or imperative detector; it screens tool outputs before they enter memory. — [GitHub](https://github.com/OWASP/www-project-agent-memory-guard)
- Rehberger's Gemini mitigation conditions sensitive tool calls, including the memory tool, on user confirmation once untrusted data is in context. This is a tool-centric control at invocation time, not a write-content classifier. — [embracethered](https://embracethered.com/blog/posts/2025/gemini-memory-persistence-prompt-injection/)
- A targeted search for imperative or tool-name gating of memory writes returned no matching work. — search on 2026-10-16 (no primary source; negative result)

### Inferences
- Novelty claim, kept modest: "imperative mood x match against the agent's own tool and affordance set as a memory-write gate". The adjacent prior art to cite is MPBench's strong/weak taxonomy, keyword gates (2601.05504, aegis-memory) and PI classifiers (PromptArmor, PIGuard).
- Expected coverage:
  - High on Explicit and Conditional Command classes and on SpAIware and Gemini-style payloads, which reference memory or exfiltration tools.
  - Near zero on weak-signal false facts and on MINJA-shortened records.
- Benign FP risk: legitimate user preferences are often imperative ("always reply in French", "remember to use the staging DB"). The tool-match term is what should cut those false positives, so measure it on a benign set.
- Project context (not from external literature): the repo's CLAUDE.md records that a token-level imperative gate failed on InjecAgent. Benign data uses the same command vocabulary, so the gate routed 94% of all payloads. Imperative-mood detection therefore needs a real dependency/POS parse. MPBench's TPR gap between strong and weak signals (e.g. PromptArmor 84% vs 42%) is consistent with that: mood is a signal for one attack family only.
- SCML's 20.8% is storage ASR. Literature numbers mix storage-level ASR (ISR, "persists") with end-to-end ASR (ASR-t, "Execute"). Compare like with like: MINJA ISR, MemSecBench persistence (84.2%) and Hidden-in-Memory write rate (up to 99.8%) are storage-level; AgentPoison ASR-t, MemSecBench Execute (50.3%) and MPBench ASR are closer to harm.

### Gaps
- I may have missed non-arXiv or industry work, such as vendor guardrails using tool-aware classifiers. No evidence of any was found.
- I found no quantitative evaluation of imperative-mood detectors on memory-poisoning corpora.
