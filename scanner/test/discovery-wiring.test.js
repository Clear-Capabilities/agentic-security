import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const REPO = path.resolve(SCANNER, '..');

test('a test:discovery scope exists and is part of the full test chain', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
  assert.ok(pkg.scripts['test:discovery'], 'missing test:discovery script');
  assert.match(pkg.scripts.test, /test:discovery/, 'test:discovery must run in the full gate');
});

test('the discovery subsystem has a local CLAUDE.md', () => {
  assert.ok(fs.existsSync(path.join(SCANNER, 'src', 'discovery', 'CLAUDE.md')));
});

test('the scan command documents that --hunt is not yet wired', () => {
  const md = fs.readFileSync(path.join(REPO, 'commands', 'scan.md'), 'utf8');
  assert.match(md, /not yet wired/);
  const hasHuntModeRow = md.split('\n').some(line => /^\|\s/.test(line) && line.includes('`--hunt`'));
  assert.ok(!hasHuntModeRow, '--hunt must not appear as a documented mode row in the modes table');
});

test('the repository layout table lists the discovery subsystem', () => {
  const md = fs.readFileSync(path.join(REPO, 'CLAUDE.md'), 'utf8');
  assert.match(md, /scanner\/src\/discovery\//);
});
