"""PreToolUse guard: keep FROZEN.md paths read-only (ADR-0001).

Edit/Write/MultiEdit/NotebookEdit on a frozen path is denied; on FROZEN.md
itself it asks. Bash is checked heuristically: a command that names a frozen
path and also writes (redirect, sed -i, rm, mv, tee, git restore, ...) is
denied, as is any benchmark run with --out pointed at benchmarks/results/.
scripts/check_frozen.sh is the backstop for anything this misses.
"""
import json
import os
import re
import shlex
import sys

ROOT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
HASH_LINE = re.compile(r"^[0-9a-f]{64}  (.+)$")
WRITES = re.compile(
    r"(>|\btee\b|\bsed\s+-[a-zA-Z]*i|\bperl\s+-[a-zA-Z]*i|\brm\b|\bmv\b|\btruncate\b|\bchmod\b"
    r"|\bgit\s+(checkout|restore|rm|mv|stash)\b|\bunlink\b|\bdd\b)"
)
# Redirections that never touch a named file.
HARMLESS = re.compile(r"\d?>&\d|\d?>\s*/dev/null")
OUT_TO_BASELINE = re.compile(r"--out[= ]+(\./)?(benchmarks/)?results/?(\s|$|;|&|\|)")


def frozen_paths():
    try:
        with open(os.path.join(ROOT, "FROZEN.md"), encoding="utf-8") as f:
            return {m.group(1) for line in f if (m := HASH_LINE.match(line.rstrip("\n")))}
    except OSError:
        return set()


def rel(path):
    return os.path.relpath(os.path.abspath(os.path.join(ROOT, path)), ROOT)


def decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def main():
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    inp = data.get("tool_input", {}) or {}
    frozen = frozen_paths()

    if tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        path = inp.get("file_path") or inp.get("notebook_path") or ""
        r = rel(path)
        if r == "FROZEN.md":
            decide("ask", "FROZEN.md changes the frozen list; needs the owner's approval and an ADR.")
        if r in frozen:
            decide("deny", f"{r} is frozen (FROZEN.md, ADR-0001). Report the problem; write corrections "
                           "to a new versioned file under benchmarks/results/v2/.")
        return

    if tool == "Bash":
        cmd = inp.get("command", "")
        if OUT_TO_BASELINE.search(cmd):
            decide("deny", "--out benchmarks/results would overwrite frozen baselines; "
                           "use --out benchmarks/results/v2 (ADR-0001).")
        if not WRITES.search(HARMLESS.sub(" ", cmd)):
            return
        hits = [p for p in frozen if p in cmd]
        if not hits:
            try:
                tokens = shlex.split(cmd)
            except ValueError:
                tokens = cmd.split()
            names = {os.path.basename(p): p for p in frozen}
            hits = [names[os.path.basename(t)] for t in tokens if os.path.basename(t) in names]
        if hits:
            decide("deny", f"Command writes near frozen path(s) {sorted(set(hits))} (FROZEN.md). "
                           "Frozen files are read-only; if this is a read, run it without the write operator.")


if __name__ == "__main__":
    main()
