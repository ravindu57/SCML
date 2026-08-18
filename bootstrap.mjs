#!/usr/bin/env node
/**
 * Build the SCML TypeScript client tarball that demo-agent/ and orchestrator/
 * depend on. Cross-platform — works in PowerShell, cmd and any POSIX shell.
 *
 *   node bootstrap.mjs
 *
 * Why this exists: both agent packages declare
 *
 *     "scml-client": "file:../clients/typescript/scml-client-1.0.0.tgz"
 *
 * and that tarball is a build artifact, so it is gitignored rather than
 * committed. A fresh clone has the client's *source* but not the packed file,
 * and `npm install` then dies with a bare ENOENT before printing anything
 * useful. Run this once after cloning, on every machine.
 *
 * Committing the tarball instead would make install work immediately but would
 * let a stale binary outlive the source it was built from — a worse failure,
 * because it is silent.
 *
 * This is the Node version of bootstrap.sh. It exists because device B may be
 * on Windows, where `bash bootstrap.sh` needs Git Bash or WSL; Node is already
 * a hard requirement, so depending on it costs nothing.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const CLIENT = path.join(DIR, 'clients', 'typescript');

const c = { cyan: '\x1b[36m', green: '\x1b[32m', red: '\x1b[31m', dim: '\x1b[2m', off: '\x1b[0m' };

// npm is a .cmd shim on Windows and execvp will not find it without the
// extension, so resolve the right binary name rather than assuming "npm".
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(args, opts = {}) {
  const r = spawnSync(NPM, args, {
    cwd: CLIENT,
    stdio: opts.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    encoding: 'utf8',
    // Windows needs a shell to resolve .cmd shims in some Node versions.
    shell: process.platform === 'win32',
  });
  if (r.status !== 0) {
    console.error(`${c.red}npm ${args.join(' ')} failed${c.off}`);
    if (r.stderr) console.error(r.stderr);
    process.exit(1);
  }
  return (r.stdout || '').trim();
}

if (!existsSync(CLIENT)) {
  console.error(`${c.red}Cannot find ${CLIENT}${c.off}`);
  console.error('Run this from the repository root.');
  process.exit(1);
}

console.log(`\n${c.cyan}Building the SCML client…${c.off}`);

if (!existsSync(path.join(CLIENT, 'node_modules'))) {
  console.log(`${c.dim}  installing client dependencies${c.off}`);
  run(['install', '--silent']);
}

run(['run', 'build', '--silent']);

// The agent packages depend on this DIRECTORY (file:../clients/typescript),
// not on a packed tarball. That matters: a tarball dependency records an
// integrity hash in package-lock.json, and `npm pack` is not byte-reproducible
// across machines — line endings and tar metadata differ — so a lockfile
// committed from one OS fails EINTEGRITY on another. A directory dependency
// carries no hash, so it works everywhere. All this step has to do is make
// sure dist/ exists, since npm links the directory without building it.
const built = path.join(CLIENT, 'dist', 'index.js');
if (!existsSync(built)) {
  console.error(`${c.red}Build produced no ${built}${c.off}`);
  process.exit(1);
}

console.log(`${c.green}  OK${c.off} ${built}`);
console.log(`\nNow install an agent package:\n`);
console.log(`  cd ${path.join(DIR, 'orchestrator')}`);
console.log(`  npm install`);
console.log(`  npm run build\n`);
