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

test('the hunt command is documented AND actually reachable from the CLI', () => {
  // Both halves matter. This file previously asserted only that `--hunt` was
  // mentioned somewhere in scan.md, which passed happily while the flag did
  // nothing — the dispatcher did not recognise it and silently ran a full scan
  // instead. Documentation alone is not wiring.
  const md = fs.readFileSync(path.join(REPO, 'commands', 'scan.md'), 'utf8');
  assert.match(md, /## Discovery layer \(`hunt`\)/);
  assert.match(md, /AGENTIC_SECURITY_LLM_ENDPOINT/);
  assert.ok(!/not yet wired/.test(md), 'the not-yet-wired disclaimer must be gone once it is wired');

  const cli = fs.readFileSync(path.join(SCANNER, 'bin', 'agentic-security.js'), 'utf8');
  assert.match(cli, /case 'hunt':/, 'the dispatcher must route `hunt`');
  assert.match(cli, /async function cmdHunt\(/, 'cmdHunt must exist');
  assert.match(cli, /runDiscovery/, 'cmdHunt must actually call the discovery orchestrator');
});

test('the repository layout table lists the discovery subsystem', () => {
  const md = fs.readFileSync(path.join(REPO, 'CLAUDE.md'), 'utf8');
  assert.match(md, /scanner\/src\/discovery\//);
});
