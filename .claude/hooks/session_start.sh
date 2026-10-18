#!/usr/bin/env bash
# SessionStart: print PROGRESS.md's current-state block into context.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
[ -f PROGRESS.md ] || exit 0
sed -n '/<!-- current-state:start -->/,/<!-- current-state:end -->/p' PROGRESS.md | sed '1d;$d'
