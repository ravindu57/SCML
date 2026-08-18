#!/usr/bin/env bash
# =============================================================================
# Build the SCML TypeScript client tarball that demo-agent/ and orchestrator/
# depend on.
#
#   bash bootstrap.sh
#
# Why this exists: both agent packages declare
#
#     "scml-client": "file:../clients/typescript/scml-client-1.0.0.tgz"
#
# and that tarball is a build artifact, so it is gitignored rather than
# committed. A fresh clone therefore has the client's *source* but not the
# packed file, and `npm install` fails with ENOENT before it prints anything
# useful. Run this once after cloning — on the mediator machine and on any
# machine running an agent.
#
# Committing the tarball instead would make `npm install` work immediately but
# would also let a stale binary outlive the source it was built from, which is
# a worse failure because it is silent.
# =============================================================================
set -euo pipefail

C=$'\033[0;36m'; G=$'\033[0;32m'; R=$'\033[0;31m'; N=$'\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT="$DIR/clients/typescript"

command -v node >/dev/null || { echo -e "${R}Node.js 18+ is required.${N}"; exit 1; }

echo -e "\n${C}Building the SCML client…${N}"
cd "$CLIENT"

[[ -d node_modules ]] || npm install --silent
npm run build --silent

# `npm pack` runs prepack, which rebuilds — so the tarball can never be older
# than the source it was packed from.
TARBALL=$(npm pack --silent | tail -1)

echo -e "${G}  ✔${N} $CLIENT/$TARBALL"
echo -e "\nNow install the agent packages:\n"
echo -e "  cd $DIR/orchestrator && npm install && npm run build"
echo -e "  cd $DIR/demo-agent   && npm install && npm run build\n"
