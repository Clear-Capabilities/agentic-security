#!/usr/bin/env node
// The committed bundle must equal a fresh build of the committed source: the same check hosted CI runs ("Verify committed bundle matches source":
// `npm run build` then `git diff --exit-code dist/agentic-security.mjs dist/agentic-security.mjs.sha256`).
//
// WHY THE LOCAL GATE NEEDS IT. The gate's `bundle-integrity` check compares the bundle to its own SHA-256 sidecar, which proves the two files agree with
// each other and nothing about the source. Editing `src/` after the last build leaves both files consistent and stale, so the gate passed and hosted
// CI failed (0.159.0, PR #66: three source edits after the last rebuild). A stale bundle is also a worse bug than a red check: `npx` users run the bundle.
//
// It builds in place, compares, and RESTORES the two files if they differ, so a failing run leaves the working tree as it found it.

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FILES = ['dist/agentic-security.mjs', 'dist/agentic-security.mjs.sha256'];

/** @param {{run: (cmd: string, args: string[]) => {status: number|null, stderr?: string}}} p */
export function bundleMatchesSource({ run }) {
  const build = run('npm', ['run', 'build']);
  if (build.status !== 0) return { ok: false, reason: `the build failed (exit ${build.status}); the bundle cannot be compared`, restored: false };
  const diff = run('git', ['diff', '--exit-code', '--', ...FILES]);
  if (diff.status === 0) return { ok: true };
  // exit 1 = they differ; anything else (git missing, not a repository) is not "equal", so it is not a pass either
  const restore = run('git', ['checkout', '--', ...FILES]);
  const differ = diff.status === 1;
  return {
    ok: false, restored: restore.status === 0,
    reason: differ
      ? 'the committed bundle is STALE against the source: a fresh build produces a different dist/agentic-security.mjs. Run `npm run build` in scanner/ and commit dist/agentic-security.mjs and dist/agentic-security.mjs.sha256.'
      : `git could not compare the bundle (exit ${diff.status})`,
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'scanner');
  const run = (cmd, args) => spawnSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'ignore', 'pipe'], timeout: 15 * 60 * 1000 });
  const r = bundleMatchesSource({ run });
  if (r.ok) { process.stdout.write('the committed bundle equals a fresh build of the source\n'); process.exit(0); }
  process.stderr.write(`${r.reason}${r.restored === false ? '\n(the working tree could not be restored: run `git checkout -- scanner/dist`)' : ''}\n`);
  process.exit(1);
}
