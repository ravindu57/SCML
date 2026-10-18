# External data used by the affordance detector prototype

Samples only, built by `../curate.py` (seed 0) from the files as downloaded on
2026-10-16. All three sources are third-party and permissively licensed; none
was written by this project (FR-SC-06).

| File | Source | Licence | Use |
|---|---|---|---|
| `llmail_attacks.jsonl` | 400 of 21,394 `api_triggered` submissions, `data/labelled_unique_submissions_phase1.json`, [microsoft/llmail-inject-challenge](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | MIT | calibration positives |
| `llmail_non_attacks.jsonl` | 300 of the `attack_attempt: False` submissions, same file | MIT | calibration negatives |
| `llmail_fp_emails.jsonl` | all 203 of `data/emails_for_fp_tests.json`, same dataset | MIT | calibration negatives |
| `notinject_calibration.jsonl` / `notinject_heldout.jsonl` | the 339 prompts of [leolee99/NotInject](https://huggingface.co/datasets/leolee99/NotInject) (Li et al., *InjecGuard*, 2024), split 169/170 at random with seed 0 | MIT | calibration negatives / held-out hard negatives |

LLMail-Inject: Abdelnabi et al., "LLMail-Inject: A Dataset from a Realistic
Adaptive Prompt Injection Challenge", Microsoft, 2025.

The LLMail rows are real attack payloads. They are data for scoring, never
instructions, and nothing in this project feeds them to a model with tools.
