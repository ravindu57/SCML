# Datasets and CPU tooling for a tool-affordance indirect prompt-injection detector

Scope: (a) external datasets for training/calibrating and held-out evaluation of an indirect prompt-injection (IPI) detector that parses untrusted tool output, finds imperatives addressed to the assistant, and semantically matches them against tool descriptions and argument schemas; (b) CPU-only NLP tooling (imperative/directive detection, small sentence embeddings, ONNX); (c) evaluation methodology. Notes are current as of 2026-10-16. "UNVERIFIED" marks claims I could not confirm against a primary source during this session.

---

## Q1. Which external datasets exist, what is in them, and which suit calibrating an indirect-injection detector?

### Takeaway
Only a few corpora put injections *inside tool or retrieved-content output*: BIPIA, LLMail-Inject, ASB, WASP, AgentDyn, and the held-out targets InjecAgent and AgentDojo. Most other "prompt injection" sets (deepset, Gandalf, HackAPrompt, TensorTrust, SPML, PINT) are direct user-turn attacks. They help with lexical coverage of imperatives but differ in distribution from tool output. For calibration, the best external choices are LLMail-Inject (MIT, about 462k indirect email attacks), BIPIA (indirect, five task types), and ASB (agent tool-output attacks). Benign false-positive calibration needs NotInject (MIT, 339 trigger-word benign prompts) and a benign tool-output corpus such as ToolBench (Apache-2.0, conflicting) or API-Bank (MIT). AgentDyn matters most for over-defense because it includes *helpful* third-party instructions. Treat it as held-out stress data, not calibration data.

### Cited Findings

**Held-out evaluation targets (do NOT train or calibrate on these)**
- InjecAgent: MIT licence. 1,054 test cases spanning 17 user tools and 62 attacker tools. Two attack types, direct harm (`attacker_cases_dh.jsonl`, `test_cases_dh_{setting}.json`) and data stealing (`..._ds...`). Two settings: "base", which injects only the attacker instruction, and "enhanced", which adds a hacking prompt beginning "IMPORTANT!!!" that tells the agent to ignore previous instructions. Attacker content is injected into the *user tool's response* — [GitHub uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)
  - The repo page does not say which response fields carry the injection, and gives no per-type counts — [GitHub](https://github.com/uiuc-kang-lab/InjecAgent)
- AgentDojo: MIT licence. Includes a "prompt injection detector" defense, which needs the `transformers` extra, and a `tool_filter` defense. Attacks are selected by flag, e.g. `tool_knowledge` — [GitHub ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)
  - 97 tasks and 629 security test cases covering email, e-banking, travel booking, etc. The authors note that LLMs often fail tasks even without attack — [arXiv 2406.13352](https://arxiv.org/abs/2406.13352v3); [NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract.html)
  - UNVERIFIED (from memory, not confirmed this session): the four suites are workspace, slack, travel and banking. Utility-only runs without injection can be executed, which gives benign tool outputs for FPR measurement. The detector defense is named `transformers_pi_detector`.

**Indirect, in-context or tool-output injection corpora (candidates for calibration)**
- LLMail-Inject (Microsoft, 2025 challenge): licence tag `mit`. About 462k rows, Phase1 about 371k and Phase2 about 90.9k. Fields: `body` and `subject` (attacker email text), `objectives` (13 classes), `scenario` (40 classes, i.e. levels), `team_id` (224 teams), and `output` with JSON outcome labels `email.retrieved`, `defense.undetected`, `exfil.sent`, `exfil.destination` and `exfil.content`. The attacker email sits in the LLM context next to other emails. In scenarios 3 and 4 it has to be retrieved first (top-10 emails go to the LLM), so the attacks are truly indirect and *adaptive*: they were written against deployed defenses — [HF microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge); [arXiv 2506.09956](https://arxiv.org/abs/2506.09956)
  - Caveat: every row is an attack submission, so there are no benign emails. Pair it with benign data. Many submissions are near-duplicates from the same team, so split by `team_id` to avoid leakage (inference).
- BIPIA (Microsoft): five tasks (Web QA, Email QA, Table QA, Summarization, Code QA). The loader combines context files with attack files `benchmark/{code|text}_attack_{train|test}.json` and has an `enable_stealth` option. Sources: Email QA from OpenAI Evals, Table QA from WikiTableQuestions, Code QA from Stack Exchange. Web QA and Summarization contexts must be downloaded by the user because of licence restrictions. The repo states "licensed under the terms in the LICENSE file" without naming the licence on the README page — [GitHub microsoft/BIPIA](https://github.com/microsoft/BIPIA); [arXiv 2312.14197](https://arxiv.org/abs/2312.14197v3)
  - Gap: per-task sample counts and the exact licence string were not visible. UNVERIFIED (memory): the code licence is MIT.
  - Strength: it has an official train/test split of *attack instructions*, so calibration can use the train attacks and keep the test attacks held out.
- Agent Security Bench (ASB, ICLR 2025): 10 scenarios (e-commerce, autonomous driving, finance, ...), 10 agents, more than 400 tools, 27 attack/defense methods, 7 metrics (later version). v1 reported about 90,000 test cases across 13 LLM backbones, with 23 methods and 8 metrics. The counts differ by version — [arXiv 2410.02644](https://arxiv.org/abs/2410.02644v1); [ICLR 2025 poster](https://iclr.cc/virtual/2025/poster/29432)
  - Licence conflict: a third-party PyPI package that vendors ASB says the upstream is MIT, "Copyright (c) 2024 AGI Research" — [PyPI superred-claim-asb](https://pypi.org/project/superred-claim-asb/). SourcePulse says the README specifies no licence — [SourcePulse](https://www.sourcepulse.org/projects/1867771). Check github.com/agiresearch/ASB LICENSE before use.
  - Suitability (inference): ASB has observation-prompt-injection (OPI) cases in tool responses plus its own large tool catalogue (400+ tool descriptions). That makes it the closest external analogue to the "match imperative against tool schemas" design. Its tool descriptions also give calibration material for the semantic matcher that does not overlap InjecAgent's or AgentDojo's tools.
- WASP (Meta, NeurIPS 2025 D&B): an end-to-end web-agent prompt-injection benchmark. Simple human-written injections partially succeed in up to 86% of cases, but agents often fail to complete the attacker goal ("security by incompetence"). Code and data at github.com/facebookresearch/wasp — [NeurIPS 2025](https://papers.nips.cc/paper_files/paper/2025/hash/1c9818387f5dd0a0bc151214660f059d-Abstract-Datasets_and_Benchmarks_Track.html)
  - Gap: size and licence not verified. Web-page and accessibility-tree content is a different distribution from JSON tool outputs.
- AgentDyn (arXiv 2602.03117, Feb 2026, revised May 2026): 60 open-ended tasks and 560 injection test cases across Shopping, GitHub and Daily Life. It explicitly adds *helpful third-party instructions*, i.e. benign imperatives in tool output. Across ten SOTA defenses, "almost all existing defenses are either not secure enough or suffer from significant over-defense." Repo: github.com/leolee99/AgentDyn — [arXiv 2602.03117](https://arxiv.org/abs/2602.03117)
  - Licence not verified.
  - Suitability (inference): this is the most direct test of the main weakness of an imperative-detection design. Benign tool outputs such as READMEs, GitHub issues and shopping instructions are full of imperatives ("Click here", "Run `pip install`"). Use it as an extra held-out over-defense test.
- Open-Prompt-Injection (Liu et al., "Formalizing and Benchmarking Prompt Injection Attacks and Defenses", USENIX Security 2024): UNVERIFIED. I did not fetch it this session. From memory it is a toolkit that builds injected data from 7 NLP tasks with 5 attack strategies (naive, escape, context-ignoring, fake-completion, combined), and the licence is not confirmed. It is useful for generating *synthetic* injections into arbitrary benign text, such as benign tool outputs.

**Direct (user-turn) injection / jailbreak corpora (lexical coverage only; distribution shift vs tool output)**
- deepset/prompt-injections: `apache-2.0`. 662 rows (train 546 / test 116). `text` with int `label` (0/1; label meaning not documented on the card, but 1 appears to be injection). Visible samples are English with Germany/Europe topics. The card is incomplete ("More Information needed") — [HF deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
  - UNVERIFIED (memory): the dataset mixes English and German text.
- Lakera/gandalf_ignore_instructions: `mit`. 1,000 rows (train 777 / val 111 / test 112). These are Gandalf prompts from July 2023 with ada-002 cosine similarity ≥ 0.825 to "Ignore all previous instructions". Near-duplicates were removed to limit split leakage and PII was filtered. A few may not be genuine injections — [HF card](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions)
- Lakera/mosscap_prompt_injection: MIT, size band 100K–1M — [HF tree](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection/tree/8366d8a0caf01f3cff5149e1a65873990dc1a3e3). The Gandalf collection lists about 279k rows — [HF collection](https://huggingface.co/collections/Lakera/gandalf). The "Gandalf the Red" paper attributes 279k to a different dataset (gandalf-rct), so the count is UNVERIFIED — [arXiv 2501.07927](https://arxiv.org/pdf/2501.07927)
- HackAPrompt: `mit`, gated (contact info required). Size band 100K–1M. 12 columns: level, user_input, prompt, completion, model, expected_completion, token_count, correct, error, score, dataset, timestamp. Uncurated and may contain offensive content (EMNLP 2023) — [HF hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset)
- Tensor Trust: earlier versions report more than 126,000 attacks and 46,000 defenses; the ICLR 2024 version reports more than 563,000 attacks and 118,000 defenses. Data at tensortrust.ai/paper — [arXiv 2311.01011](https://arxiv.org/abs/2311.01011v1); [ICLR 2024](https://proceedings.iclr.cc/paper_files/paper/2024/hash/519c51529c3544b3430bd8b17d400365-Abstract-Conference.html). Licence NOT found.
- SPML (reshabhs/SPML_Chatbot_Prompt_Injection): `mit`, size band 10K–100K. Tags suggest system-prompt plus user-prompt pairs; the schema was not visible — [HF card](https://huggingface.co/datasets/reshabhs/SPML_Chatbot_Prompt_Injection). A third-party aggregate lists an SPML subset of 12,541 entries (UNVERIFIED) — [Cogensec/jailbreak-corpus](https://huggingface.co/datasets/Cogensec/jailbreak-corpus)
- GenTel-Bench (GenTel-Safe, Zhejiang Univ./GenTel.io): 84,812 prompt-injection attacks across 3 major categories and 28 security scenarios. Code and data via gentellab.github.io/gentel-safe.github.io — [arXiv 2409.19521](https://arxiv.org/abs/2409.19521v1). Licence and HF availability NOT verified.
- Lakera PINT benchmark: 4,314 inputs (3,016 English, 1,298 non-English). Categories include prompt injection, jailbreak, and *hard negatives* (benign but injection-like). The dataset is private/held by Lakera, and the repo provides an evaluation harness. Reported scores: Lakera Guard 95.22% (2025-05-02), AWS Bedrock Guardrails 89.24%, Google Model Armor 70.07% (2025-08-27). The vendor runs the benchmark itself, which is a conflict of interest — [PINT README](https://raw.githubusercontent.com/lakeraai/pint-benchmark/main/README.md); [mirror CheckPointSW](https://github.com/CheckPointSW/pint-benchmark)
  - Inference: if you can run it (submission or harness), PINT provides an independent number including hard negatives. Because the data is private, you cannot calibrate on it.

**Over-defense / benign calibration corpora**
- NotInject (InjecGuard): `mit`. 339 benign prompts, 113 each in splits NotInject_one/two/three by number of trigger words (e.g. "ignore", "cancel"). Fields: `prompt`, `word_list`, `category` (Common Queries, Technique Queries, Virtual Creation, Multilingual) — [HF leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject); [arXiv 2410.22770](https://arxiv.org/html/2410.22770v3)
  - The paper reports that SOTA guards such as ProtectAIv2 fall to below about 60% over-defense accuracy, close to random — [arXiv 2410.22770v3](https://arxiv.org/html/2410.22770v3)
- ToolBench (OpenBMB): Apache-2.0 per a paper and an HF mirror; an older fork lists CC BY-NC 4.0 (conflict). The API data was crawled from RapidAPI — [HF Adorg/ToolBench README](https://huggingface.co/datasets/Adorg/ToolBench/blob/main/README.md); [autogyro/tool_LLM (CC BY-NC fork)](https://github.com/autogyro/tool_LLM); [SourcePulse](https://www.sourcepulse.org/projects/1842217)
  - The licence status of the third-party API *responses* themselves is unclear.
- API-Bank (DAMO-ConvAI): reported MIT — [Datasets for LLMs survey arXiv 2402.18041](https://arxiv.org/pdf/2402.18041) (secondary; UNVERIFIED against the repo).

### Inferences
- **Calibration pool (external only).** Positives: LLMail-Inject (split by team), BIPIA *train* attacks embedded in BIPIA contexts, ASB OPI cases, plus synthetic injections from Open-Prompt-Injection templates inserted into benign ToolBench/API-Bank responses. Negatives: benign ToolBench/API-Bank tool responses, BIPIA clean contexts, NotInject, and benign rows of deepset.
- **Exclude** anything derived from InjecAgent, AgentDojo or the in-house memory corpus. Several third-party aggregations (e.g. Cogensec/jailbreak-corpus, some ProtectAI training mixes) may contain InjecAgent/AgentDojo/BIPIA strings, so run n-gram or embedding near-duplicate checks between the calibration pool and the held-out sets before reporting numbers.
- Direct-injection corpora (Gandalf, HackAPrompt, TensorTrust) are dominated by "reveal the password/system prompt" goals. These rarely map onto tool affordances, so they are weak positives for a *tool-schema matching* detector. They are most useful as negatives for the matcher (an imperative with no matching tool) and as positive training data for the imperative-detector stage.
- InjecAgent is mostly single-turn and template-based (base/enhanced). A detector tuned on the "IMPORTANT!!! Ignore..." prefix will score well on the enhanced setting for spurious reasons. Report base and enhanced separately.

### Gaps
- Exact licences not verified: BIPIA (README defers to the LICENSE file), ASB (conflicting), WASP, AgentDyn, TensorTrust, GenTel-Bench, Open-Prompt-Injection, API-Bank (only secondary source).
- AgentDojo suite/task breakdown and benign-run support were not confirmed from primary docs this session.
- No dedicated, published corpus of *benign real-world tool outputs labelled for embedded imperatives* was found. FPR calibration on benign tool outputs will need to be assembled (ToolBench/API-Bank responses, AgentDojo/AgentDyn benign runs).
- The HackAPrompt exact row count and the SPML schema were not visible.

---

## Q2. CPU tooling: imperative / directive detection (spaCy, Stanza, speech-act literature)

### Takeaway
No published benchmark of spaCy-based imperative detection accuracy turned up. The usual approach is a rule over the dependency parse: root verb with base-form tag `VB`, no `nsubj`, not a question, optionally preceded by "please" or a vocative. It is known to be brittle because news-heavy treebanks (OntoNotes) contain few imperatives, so sentence-initial verbs get mis-tagged. The closest published speech-act baseline is request-for-action detection in email: 83.76% message-level accuracy, with annotator agreement κ = 0.78 at sentence level. That suggests a realistic ceiling on directive detection well below perfect. For latency, spaCy `lg` processes about 10k words/s on CPU, so a few-hundred-word tool output parses in tens of ms. `trf` (684 WPS CPU) would blow the 400 ms p95 budget on long outputs.

### Cited Findings
- spaCy v3 speeds (end-to-end, 10k Reddit comments): en_core_web_lg 10,014 WPS on CPU (14,954 GPU); en_core_web_trf 684 WPS on CPU (3,768 GPU). Accuracy on OntoNotes 5.0 dev: trf parser 95.1 / tagger 97.8; lg parser 92.0 / tagger 97.4. The page gives no figures for sm or md — [spaCy Facts & Figures](https://spacy.io/usage/facts-figures)
- I found no spaCy-specific accuracy figures for imperative detection. A tutorial covers sentence-type classification (question/imperative/wish) via dependency parse but gives no evaluation — [Educative spaCy course](https://www.educative.io/courses/spacy-nlp/differentiating-subjects-from-objects)
- Anecdotal evidence of tagger failure on imperatives: a user reports CoreNLP and OpenNLP did not tag "Update the text" as VB DT NN when detecting imperative git commit messages — [clojurians log](https://clojurians-log.clojureverse.org/off-topic/2019-11-10) (low-quality, anecdotal)
- Email request detection (Lampert, Dale & Paris, NAACL 2010): message-level request classification reached 83.76% accuracy with email zoning, a 15.9% relative increase and 41% error reduction over no zoning. The paper notes that indirect speech acts make requests hard to detect — [ACL Anthology N10-1142](https://aclanthology.org/N10-1142/)
- Annotation study by the same group: sentence-level Request-for-Action agreement κ = 0.78; Commitment-to-Act κ = 0.54 — [Macquarie Univ. research page](https://researchers.mq.edu.au/en/publications/can-requests-for-action-and-commitments-to-act-be-reliably-identi/)

### Inferences
- A pure syntactic imperative rule will miss *indirect* directives that are common in real injections: "The assistant should now send...", "It is required that you...", "Your next step is to call...", modal/declarative forms and second-person "you must". It will also over-fire on benign procedural text in tool outputs (README steps, recipe instructions). Combine the following:
  1. Rule features: root VB without nsubj; `you`/`assistant`/`AI` as subject plus a modal; "ignore/disregard previous"; vocatives.
  2. A small learned classifier over sentence embeddings, trained on external positives (LLMail, BIPIA train, ASB) and negatives (benign tool text, NotInject).
  3. The tool-schema semantic match as the main discriminator: a benign imperative "click the link" is less likely to match high-risk tool affordances like `send_money` or `delete_file`.
- Use `en_core_web_sm` or `md` (CNN, faster than lg; exact WPS not on the facts page) with only tagger and parser enabled (disable NER and lemmatizer) to meet the budget. Avoid `trf` on CPU. Stanza (neural BiLSTM) is likely slower than spaCy sm/md on CPU (UNVERIFIED — no Stanza speed numbers gathered this session).
- Measure the imperative stage separately, e.g. precision/recall on a small hand-labelled sample of tool-output sentences, so that failures can be attributed to the right stage.

### Gaps
- No published accuracy for spaCy/Stanza imperative-mood detection, and no spaCy GitHub issue located on imperative mis-tagging.
- No CPU speed numbers for en_core_web_sm/md or Stanza were retrieved. Benchmark locally.
- Modern directive or speech-act classifiers (e.g. fine-tuned on SwDA/MRDA dialogue acts) were not surveyed this session.

---

## Q3. CPU tooling: small sentence-embedding models for semantic matching; ONNX runtime

### Takeaway
bge-small-en-v1.5 (MIT, 33.4M params, 384-d, 512 tokens, MTEB avg 62.17) is the strongest of the four on MTEB. gte-small (MIT, 61.36) is a close second, then e5-small-v2 (59.93) and all-MiniLM-L6-v2 (56.26 per the gte card; smallest and fastest). All are about 22–33M-parameter BERT-small-class models, which run in single-digit-to-low-tens of ms per short sentence on modern CPUs (UNVERIFIED for these models specifically). Sentence-transformers supports ONNX and OpenVINO backends with int8 quantization. Its own CPU benchmark found OpenVINO int8 fastest on an Intel desktop, but rankings varied by hardware.

### Cited Findings
- bge-small-en-v1.5: licence MIT; 33.4M params; dim 384; max seq 512; MTEB average (56 datasets) 62.17. Card table: e5-small-v2 59.93, gte-small 61.36 — [HF BAAI/bge-small-en-v1.5](https://huggingface.co/BAAI/bge-small-en-v1.5)
- gte-small: licence `mit`; 33.4M params; dim 384; seq 512; MTEB avg 61.36. Card table: e5-small-v2 59.93 (0.13 GB), all-MiniLM-L6-v2 56.26 (0.09 GB) — [HF thenlper/gte-small](https://huggingface.co/thenlper/gte-small)
- all-MiniLM-L6-v2 usable input is capped at 256 tokens; it trails bge-small/gte-small by about 5–6 MTEB points, and MTEB versions differ, so gaps are directional — [TokenMix guide](https://tokenmix.ai/blog/all-minilm-l6-v2-free-local-embedding-guide-2026) (secondary). Conflict: the gte-small card table lists MiniLM seq length as 512 — [HF gte-small](https://huggingface.co/thenlper/gte-small)
  - UNVERIFIED (memory): all-MiniLM-L6-v2 licence is Apache-2.0 and e5-small-v2 is MIT. Check the model cards.
- Sentence-transformers efficiency docs: ONNX/OpenVINO backends are loaded via `SentenceTransformer("all-MiniLM-L6-v2", backend="onnx")`. ONNX `session_options` → `intra_op_num_threads` tunes CPU performance. On an i7-13700K "OpenVINO INT8 performs best", but on an HF cloud CPU llama.cpp led. ONNX int8 (avx512_vnni) uses dynamic quantization; OpenVINO int8 uses static quantization with calibration. Recommendations: `openvino-qint8` if a small accuracy loss is acceptable, else `openvino` on Intel and `onnx` on other CPUs. Benchmark on deployment hardware with representative inputs — [sbert.net efficiency](https://sbert.net/docs/sentence_transformer/usage/efficiency.html)
- Neural Magic INT8 bge-small-en-v1.5 (vendor numbers): about 3× latency improvement on a 10-core laptop and up to 5× on a 16-core AWS instance with DeepSparse — [HF neuralmagic/bge-small-en-v1.5-quant](https://huggingface.co/neuralmagic/bge-small-en-v1.5-quant)
- Zep's informal test: all-MiniLM-L6-v2 local CPU embedding was about 42 (units unstated), similar to MiniLM-L12 — [Zep blog](https://blog.getzep.com/text-embedding-latency-a-semi-scientific-look/) (low rigor)

### Inferences
- The tool descriptions and argument schemas are static per agent, so precompute and cache their embeddings. At runtime only the candidate imperative sentences need embedding. Batch them in one forward pass so that a p95 under 400 ms is comfortable even with spaCy parsing.
- MTEB average is a weak proxy for "imperative ↔ tool-description" matching, which is closer to asymmetric retrieval or STS. Evaluate the matcher directly, e.g. recall@k of the correct tool for injected instructions using ASB tool descriptions, then pick the model. bge and e5 expect query/passage prefixes or instructions. Missing prefixes can silently degrade matches (UNVERIFIED for this use).
- Cosine thresholds are model-specific and not comparable across models. Calibrate the threshold on the external pool only, then freeze it before touching held-out sets.

### Gaps
- No apples-to-apples CPU latency numbers for all four models were found. Measure on target hardware (ONNX fp32 vs int8, threads = 1 vs N, batch sizes 1–32).
- int8 accuracy loss for these specific models was not quantified in retrieved text (the sbert charts were not readable).

---

## Q4. Evaluation methodology best practices for injection detectors

### Takeaway
Report results on held-out benchmarks that were never used for calibration. Report benign false-positive rate on realistic tool output, not just on chat prompts, and include an over-defense set (NotInject, AgentDyn helpful instructions). Evaluate against adaptive attacks. Static attack-string evaluations are known to overstate robustness dramatically: adaptive attacks reach more than 50% success against all 8 IPI defenses in one study and more than 90% against most of 12 defenses in another.

### Cited Findings
- Zhan et al. (NAACL 2025 Findings) found that adaptive attacks bypassed all 8 tested IPI defenses with more than 50% attack success, and they argue that defenses must be evaluated against adaptive attacks. Code is public — [arXiv 2503.00061](https://arxiv.org/html/2503.00061v2); [ACL Anthology](https://preview.aclanthology.org/moar-dois/2025.findings-naacl.395)
- "The Attacker Moves Second" (Nasr, Carlini, Tramèr et al., Oct 2025) used gradient descent, RL, random search and human-guided exploration to bypass 12 recent jailbreak and prompt-injection defenses at more than 90% success, even though most had reported near-zero ASR. The authors recommend evaluating against adaptive, well-resourced attackers rather than static attack strings — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)
- Over-defense: SOTA guards drop to below about 60% accuracy on NotInject benign trigger-word prompts — [arXiv 2410.22770](https://arxiv.org/html/2410.22770v3). AgentDyn finds almost all of 10 defenses either insecure or significantly over-defensive once helpful third-party instructions are present — [arXiv 2602.03117](https://arxiv.org/abs/2602.03117)
- Lakera claims PINT is a neutral evaluation because evaluated systems were not trained on its private inputs, but the benchmark is vendor-run — [PINT README](https://raw.githubusercontent.com/lakeraai/pint-benchmark/main/README.md)
- LLMail-Inject's attacks were collected adaptively against live defenses, and the per-row outcome label `defense.undetected` records evasion — [HF LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge)
- Gandalf ignore-instructions split construction explicitly de-duplicated to "reduce leakage between splits" — [HF card](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions)
- AgentDojo notes that models fail tasks even without attacks, so utility under no attack must be reported alongside security — [arXiv 2406.13352](https://arxiv.org/abs/2406.13352v3)

### Inferences (proposed protocol)
1. **Data hygiene.** Freeze a calibration pool drawn only from external sources (Q1). Run near-duplicate detection (MinHash or embedding cosine above a threshold) against InjecAgent, AgentDojo and the in-house memory corpus. Drop overlaps and report how many were dropped. Split LLMail by `team_id` and BIPIA by its official attack train/test split.
2. **Threshold selection.** Choose the operating threshold on the external calibration set to hit FPR ≤ 3% on *benign tool outputs*, then freeze it. On each held-out set, report ROC-AUC with bootstrap 95% CIs, plus TPR at the frozen threshold and the realised FPR. Do not re-tune per benchmark. Also report TPR@FPR = 1%/3% curves for transparency.
3. **Negatives per held-out set.** InjecAgent ships only injected cases. Build its benign counterpart from the same tool responses with the attacker instruction removed, so that AUC is not an artifact of different benign distributions. Do the same for AgentDojo (benign utility runs vs injected runs) and for the memory corpus.
4. **Stratification.** Report InjecAgent base vs enhanced, direct-harm vs data-stealing, and AgentDojo per suite and per attack (e.g. `important_instructions`, `tool_knowledge`). Report memory poisoning separately, since it may have no imperative surface form.
5. **Over-defense.** Report FPR on NotInject (by tier), AgentDyn helpful-instruction outputs, and benign ToolBench/API-Bank responses, separately from the headline FPR.
6. **Adaptive attacks.** At minimum: (a) paraphrase/indirect-mood rewrites that avoid imperative syntax ("The next step the assistant performs is..."); (b) tool-name obfuscation or synonyms to defeat semantic matching; (c) splitting the instruction across fields or sentences; (d) non-English and encoding variants; (e) a white-box or black-box optimisation loop against the detector score, following Zhan et al. and "Attacker Moves Second". Report ASR-at-fixed-FPR before and after adaptation.
7. **Latency.** Report p50/p95/p99 end-to-end (parse + embed + match) on the target CPU, with thread count and payload-size distribution, including worst-case long tool outputs (truncation policy must be stated, since truncation is itself an evasion vector).
8. **Utility.** If the detector blocks tool outputs inside AgentDojo, report utility under no attack and utility under attack as well as ASR.

### Gaps
- No standard published protocol specific to "tool-output imperative" detectors was found. The protocol above is synthesised from the sources.
- Whether InjecAgent or AgentDojo strings leak into popular public training mixes (ProtectAI, Cogensec aggregates) was not checked this session. Run the overlap check.
