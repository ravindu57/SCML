"""
Build the committed external datasets from the raw downloads (run once).

    python -I -m benchmarks.affordance_detector.curate <raw_dir>

<raw_dir> holds the files as downloaded from Hugging Face (see
data/ATTRIBUTION.md). Sampling is seeded, so re-running on the same raw files
reproduces the committed JSONL byte for byte. Only the samples are committed,
not the 448 MB source.

FR-SC-06: everything written here is authored outside this project. The
NotInject half used for calibration and the half used as held-out hard
negatives are disjoint, and the split is fixed by the seed before any score
exists.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

SEED = 0
N_LLMAIL_ATTACKS = 400
N_LLMAIL_NON_ATTACKS = 300
MAX_LEN = 4000
OUT = Path(__file__).parent / "data"


def _stream_llmail(path: Path):
    """(text, attack_attempt, reason) from the pretty-printed labelled file.

    The file is one JSON object, ~450 MB. It is pretty-printed with one entry
    key per line, so it streams line by line in constant memory.
    """
    key = attempt = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if line.startswith('  "') and s.endswith('": {'):
                try:
                    key = json.loads(s[:-3])
                except json.JSONDecodeError:
                    key = None
                attempt = None
            elif s.startswith('"attack_attempt"'):
                attempt = s.partition(":")[2].strip().rstrip(",").strip('"').lower()
            elif s.startswith('"reason"') and key is not None:
                reason = s.partition(":")[2].strip().rstrip(",").strip('"')
                yield key, attempt, reason
                key = None


def _reservoir(items, k: int, rng: random.Random) -> list:
    out: list = []
    for i, item in enumerate(items):
        if i < k:
            out.append(item)
        else:
            j = rng.randint(0, i)
            if j < k:
                out[j] = item
    return out


def _dedupe(texts):
    seen = set()
    for t in texts:
        norm = " ".join(t.lower().split())
        if norm not in seen and 0 < len(t) <= MAX_LEN:
            seen.add(norm)
            yield t


def _notinject(raw: Path) -> list[str]:
    prompts = []
    for part in ("one", "two", "three"):
        for suffix in ("", "_b"):
            f = raw / f"ni_NotInject_{part}{suffix}.json"
            prompts.extend(r["row"]["prompt"] for r in json.loads(f.read_text())["rows"])
    return sorted(set(prompts))


def _write(name: str, rows: list[dict]) -> None:
    OUT.mkdir(exist_ok=True)
    with open(OUT / name, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"{name}: {len(rows)}")


def main(raw_dir: str) -> None:
    raw = Path(raw_dir)
    rng = random.Random(SEED)

    entries = list(_stream_llmail(raw / "llmail_phase1.json"))
    attacks = sorted(_dedupe(t for t, a, r in entries if a == "true" and r == "api_triggered"))
    non_attacks = sorted(_dedupe(t for t, a, _ in entries if a == "false"))
    _write("llmail_attacks.jsonl", [
        {"text": t, "label": 1, "source": "llmail-inject/phase1/api_triggered"}
        for t in _reservoir(attacks, N_LLMAIL_ATTACKS, rng)
    ])
    _write("llmail_non_attacks.jsonl", [
        {"text": t, "label": 0, "source": "llmail-inject/phase1/attack_attempt=False"}
        for t in _reservoir(non_attacks, N_LLMAIL_NON_ATTACKS, rng)
    ])
    fp = json.loads((raw / "llmail_fp_emails.json").read_text())
    _write("llmail_fp_emails.jsonl", [
        {"text": t, "label": 0, "source": "llmail-inject/emails_for_fp_tests"} for t in fp
    ])

    prompts = _notinject(raw)
    rng.shuffle(prompts)
    half = len(prompts) // 2
    _write("notinject_calibration.jsonl", [
        {"text": t, "label": 0, "source": "NotInject"} for t in sorted(prompts[:half])
    ])
    _write("notinject_heldout.jsonl", [
        {"text": t, "label": 0, "source": "NotInject"} for t in sorted(prompts[half:])
    ])


if __name__ == "__main__":
    main(sys.argv[1])
