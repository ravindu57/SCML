#!/usr/bin/env bash
# Verify every file listed in FROZEN.md still matches its recorded sha256.
set -euo pipefail
cd "$(dirname "$0")/.."
sed -n '/^```$/,/^```$/p' FROZEN.md | grep -E '^[0-9a-f]{64}  ' | sha256sum -c --quiet && echo "frozen: all $(grep -cE '^[0-9a-f]{64}  ' FROZEN.md) files unchanged"
