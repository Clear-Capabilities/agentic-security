// Regression guard for the third instance of one bug class (see .gitignore's
// comment above `!scanner/dist/*.index.js`): dist/agentic-security.mjs is
// documented and committed as a self-contained single-file bundle — the
// reusable workflow fetches ONLY that file via raw.githubusercontent.com —
// but ncc code-splits every dynamically-imported internal module
// (bin/agentic-security.js has ~58 `await import('../src/...')` call sites,
// one per lazily-loaded subcommand) into its own dist/NNN.index.js chunk,
// loaded by the bundle at runtime via a path relative to its own location on
// disk. A chunk that exists on disk (because someone ran `npm run build`
// locally) but isn't git-tracked is invisible to this check by construction
// — and was invisible to every human and gate here for exactly that reason
// — so `git ls-files` is the only source of truth that matches what a fresh
// checkout actually has.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST = path.join(SCANNER, 'dist');

test('every dist/*.index.js chunk the bundle can produce is git-tracked', () => {
  const onDisk = fs.readdirSync(DIST).filter((f) => /^\d+\.index\.js$/.test(f));
  assert.ok(onDisk.length > 0, 'expected at least one chunk file — run `npm run build` first');

  const tracked = new Set(
    execFileSync('git', ['ls-files', 'dist'], { cwd: SCANNER, encoding: 'utf8' })
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean),
  );

  const untracked = onDisk.filter((f) => !tracked.has(`dist/${f}`));
  assert.deepEqual(
    untracked,
    [],
    `chunk file(s) exist on disk but are not git-tracked, so a fresh checkout ` +
    `will throw ERR_MODULE_NOT_FOUND the moment the lazy subcommand behind ` +
    `them runs: ${untracked.join(', ')}`,
  );
});
