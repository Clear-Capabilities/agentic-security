// scripts/check-doc-drift.mjs — mechanical CLAUDE.md drift checker
// (Stage 6 correctness audit, item 4).
//
// Regenerates the mechanically-checkable subset of doc drift (a
// backtick-quoted file path that doesn't exist; a `file.js#export`
// reference where the export is gone) — the durable, re-runnable
// replacement for the 146-item doc-drift punch list an earlier audit
// stage lost to context compaction before finishing it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { candidatesIn, resolveCandidate, exportExistsIn, checkFile } from '../../scripts/check-doc-drift.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

test('candidatesIn: extracts a backtick-quoted source-file path', () => {
  const c = candidatesIn('See `src/posture/foo.js` for details.');
  assert.equal(c.length, 1);
  assert.equal(c[0].filePath, 'src/posture/foo.js');
  assert.equal(c[0].exportName, null);
});

test('candidatesIn: extracts a file#export reference', () => {
  const c = candidatesIn('Calls `src/posture/foo.js#doThing` internally.');
  assert.equal(c.length, 1);
  assert.equal(c[0].filePath, 'src/posture/foo.js');
  assert.equal(c[0].exportName, 'doThing');
});

test('candidatesIn: does not truncate .json to .js (alternation-order regression)', () => {
  // The exact bug this checker's own regex had: `js` matching as a prefix
  // of `json` when the longer alternative isn't tried first.
  const c = candidatesIn('See `scanner/package.json` for the version field.');
  assert.equal(c.length, 1);
  assert.equal(c[0].filePath, 'scanner/package.json');
  assert.equal(c[0].exportName, null, 'the "on" tail of "json" must not be misread as an export name');
});

test('candidatesIn: skips CLI flags, env vars, and URLs even when extension-shaped', () => {
  const c = candidatesIn('Run `--format json`, set `$AGENTIC_SECURITY_LLM_MODEL`, see `https://example.com/x.js`.');
  assert.equal(c.length, 0);
});

test('candidatesIn: skips known runtime-state and example-manifest paths', () => {
  const c = candidatesIn('Reads `.agentic-security/last-scan.json` and `last-scan.json` and `docker-compose.yml`.');
  assert.equal(c.length, 0);
});

test('candidatesIn: strips fenced code blocks before scanning (own file, integration)', () => {
  // checkFile strips fences before calling candidatesIn — verify the whole
  // pipeline via a real temp CLAUDE.md so an illustrative snippet inside a
  // ``` block (e.g. a JSON example) is never reported as drift.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'doc-drift-'));
  const claudeMd = path.join(dir, 'CLAUDE.md');
  fs.writeFileSync(claudeMd, [
    '# Example',
    '```json',
    '{ "example": "totally-nonexistent-file.json" }',
    '```',
  ].join('\n'));
  const findings = checkFile(claudeMd);
  assert.equal(findings.length, 0, `expected the fenced example to be ignored; got ${JSON.stringify(findings)}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('resolveCandidate: resolves a path relative to repo root', () => {
  const claudeMd = path.join(REPO, 'CLAUDE.md');
  const resolved = resolveCandidate(claudeMd, 'scanner/package.json');
  assert.ok(resolved, 'expected scanner/package.json to resolve');
  assert.ok(fs.existsSync(resolved));
});

test('resolveCandidate: resolves a partial path via the basename fallback', () => {
  // Referenced from root CLAUDE.md as a bare `posture/...` path (no
  // `scanner/src/` prefix) — the exact shape that motivated the fallback.
  const claudeMd = path.join(REPO, 'CLAUDE.md');
  const resolved = resolveCandidate(claudeMd, 'posture/finding-defaults.js');
  assert.ok(resolved, 'expected the partial path to resolve via basename fallback');
  assert.match(resolved, /posture[\\/]finding-defaults\.js$/);
});

test('resolveCandidate: returns null for a genuinely nonexistent path', () => {
  const claudeMd = path.join(REPO, 'CLAUDE.md');
  assert.equal(resolveCandidate(claudeMd, 'this/path/does/not/exist.js'), null);
});

test('exportExistsIn: finds a real export function', () => {
  const target = path.join(REPO, 'scanner', 'src', 'posture', 'model-rescan.js');
  assert.equal(exportExistsIn(target, 'runModelRescan'), true);
});

test('exportExistsIn: reports false for a name that is not exported or mentioned', () => {
  const target = path.join(REPO, 'scanner', 'src', 'posture', 'model-rescan.js');
  assert.equal(exportExistsIn(target, 'totallyMadeUpExportName12345'), false);
});

test('checkFile: flags a dangling file reference with the correct line number', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'doc-drift-'));
  const claudeMd = path.join(dir, 'CLAUDE.md');
  fs.writeFileSync(claudeMd, [
    '# Header',
    '',
    'See `this/file/does/not/exist.js` for details.',
  ].join('\n'));
  const findings = checkFile(claudeMd);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'missing-path');
  assert.equal(findings[0].line, 3);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('checkFile: the real repository currently has zero mechanically-checkable drift', () => {
  // Regression guard for the two real bugs this checker found and fixed
  // during Stage 6 (a dangling `test/CLAUDE.md` pointer in scanner/CLAUDE.md,
  // and a stale `scorecard.js` name that should have been
  // `accuracy-scorecard.js` in posture/CLAUDE.md) — if either reappears, or
  // a new one is introduced, this test catches it.
  const claudeMdFiles = [
    path.join(REPO, 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'dataflow', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'discovery', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'ir', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'mcp', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'posture', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'sandbox', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'sast', 'CLAUDE.md'),
    path.join(REPO, 'scanner', 'src', 'sca', 'CLAUDE.md'),
  ];
  const allFindings = [];
  for (const f of claudeMdFiles) allFindings.push(...checkFile(f));
  assert.deepEqual(allFindings, [], `expected zero drift; got ${JSON.stringify(allFindings, null, 2)}`);
});
