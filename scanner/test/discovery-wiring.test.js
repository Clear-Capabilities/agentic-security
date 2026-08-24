import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCOPES, unionFiles, extractFiles } from '../../scripts/run-unit-tests.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const REPO = path.resolve(SCANNER, '..');

test('a test:discovery scope exists and its files actually run under `npm test`', () => {
  // `npm test` used to be a literal `&&`-chain of `npm run test:<scope>`, so a
  // scope's name appearing as a substring of the `test` script WAS the proof
  // it ran. `npm test` now runs scripts/run-unit-tests.mjs, which derives its
  // file list from SCOPES instead of chaining scripts by name — so that
  // substring match no longer means anything (the string "test:discovery"
  // does not appear anywhere in the new `test` script, whether or not
  // discovery's files are actually covered). The proof now has to be: (1)
  // 'discovery' is a scope the runner reads, and (2) every file test:discovery
  // names is present in the union of files the runner will actually pass to
  // `node --test`. Checking only (1) would pass even if run-unit-tests.mjs's
  // own extraction regex silently stopped matching this scope's files.
  const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
  assert.ok(pkg.scripts['test:discovery'], 'missing test:discovery script');
  assert.ok(SCOPES.includes('discovery'), 'scripts/run-unit-tests.mjs SCOPES must list "discovery"');

  const covered = new Set(unionFiles(pkg));
  const discoveryFiles = extractFiles(pkg.scripts['test:discovery']);
  assert.ok(discoveryFiles.length > 0, 'test:discovery names no files — nothing to prove coverage of');
  for (const f of discoveryFiles) {
    assert.ok(covered.has(f), `${f} is in test:discovery but missing from the combined npm-test run`);
  }
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
