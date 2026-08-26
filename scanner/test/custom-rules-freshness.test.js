// FR-207: custom rule pack freshness (posture/custom-rules.js's
// customRulesFreshness). Zero existing tests import posture/custom-rules.js
// directly before this file (its DSL is otherwise only exercised through
// bin/agentic-security.js's CLI paths, per test/smoke.test.js) — this file
// is the first direct unit coverage of the module, scoped to the one new
// function this cycle added.
//
// Deliberately does NOT go through loadCustomRules/verifyRulePack — a rule
// pack's SIGNING status is orthogonal to its REVIEW freshness, so
// customRulesFreshness reads the YAML directly and needs no trusted-keys
// setup, no AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS, and produces no console
// warnings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { customRulesFreshness } from '../src/posture/custom-rules.js';

function makeScanRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-security-rules-freshness-'));
  const rulesDir = path.join(root, '.agentic-security', 'rules');
  fs.mkdirSync(rulesDir, { recursive: true });
  return { root, rulesDir };
}

function writeRulePack(rulesDir, name, yamlText) {
  fs.writeFileSync(path.join(rulesDir, name), yamlText, 'utf8');
}

test('customRulesFreshness: no rules directory at all is never stale', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-security-rules-freshness-empty-'));
  const out = customRulesFreshness(root);
  assert.equal(out.stale, false);
  assert.equal(out.checked, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test('customRulesFreshness: a rule pack with no review-interval-days opt-in is never stale, regardless of age', () => {
  const { root, rulesDir } = makeScanRoot();
  writeRulePack(rulesDir, 'no-opt-in.yml', `
rules:
  - id: my-org/no-eval
    title: "no eval"
    severity: high
    cwe: CWE-95
    languages: [javascript]
    match: { pattern: "eval" }
    message: "no eval"
`);
  const out = customRulesFreshness(root);
  assert.equal(out.stale, false);
  assert.equal(out.checked, 0, 'a pack with no opt-in field must not even be counted as checked');
  fs.rmSync(root, { recursive: true, force: true });
});

test('customRulesFreshness: an opted-in pack reviewed well within its interval is fresh', () => {
  const { root, rulesDir } = makeScanRoot();
  const reviewedAt = new Date(Date.now() - 5 * 86400000).toISOString(); // 5 days ago
  writeRulePack(rulesDir, 'fresh.yml', `
review-interval-days: 90
reviewed-at: "${reviewedAt}"
rules:
  - id: my-org/no-eval
    severity: high
    cwe: CWE-95
    languages: [javascript]
    match: { pattern: "eval" }
    message: "no eval"
`);
  const out = customRulesFreshness(root);
  assert.equal(out.checked, 1);
  assert.equal(out.stale, false);
  fs.rmSync(root, { recursive: true, force: true });
});

test('customRulesFreshness: an opted-in pack reviewed long past its interval is stale, by file', () => {
  const { root, rulesDir } = makeScanRoot();
  const reviewedAt = new Date(Date.now() - 200 * 86400000).toISOString(); // 200 days ago
  writeRulePack(rulesDir, 'old.yml', `
review-interval-days: 90
reviewed-at: "${reviewedAt}"
rules:
  - id: my-org/no-eval
    severity: high
    cwe: CWE-95
    languages: [javascript]
    match: { pattern: "eval" }
    message: "no eval"
`);
  const out = customRulesFreshness(root);
  assert.equal(out.stale, true);
  assert.equal(out.staleFiles.length, 1);
  assert.equal(out.staleFiles[0].file, 'old.yml');
  fs.rmSync(root, { recursive: true, force: true });
});

test('customRulesFreshness: an opted-in pack with review-interval-days but no reviewed-at at all is treated as never-reviewed (maximally stale), not a free pass', () => {
  const { root, rulesDir } = makeScanRoot();
  writeRulePack(rulesDir, 'never-reviewed.yml', `
review-interval-days: 90
rules:
  - id: my-org/no-eval
    severity: high
    cwe: CWE-95
    languages: [javascript]
    match: { pattern: "eval" }
    message: "no eval"
`);
  const out = customRulesFreshness(root);
  assert.equal(out.stale, true, 'no reviewed-at with an opted-in interval must be treated as already stale, not silently fresh');
  fs.rmSync(root, { recursive: true, force: true });
});

test('customRulesFreshness: mixed pack directory reports only the genuinely stale files, others unaffected', () => {
  const { root, rulesDir } = makeScanRoot();
  writeRulePack(rulesDir, 'fresh.yml', `
review-interval-days: 90
reviewed-at: "${new Date().toISOString()}"
rules:
  - { id: a, severity: low, cwe: CWE-1, languages: [javascript], match: { pattern: "x" }, message: "x" }
`);
  writeRulePack(rulesDir, 'stale.yml', `
review-interval-days: 30
reviewed-at: "${new Date(Date.now() - 100 * 86400000).toISOString()}"
rules:
  - { id: b, severity: low, cwe: CWE-1, languages: [javascript], match: { pattern: "y" }, message: "y" }
`);
  writeRulePack(rulesDir, 'no-opt-in.yml', `
rules:
  - { id: c, severity: low, cwe: CWE-1, languages: [javascript], match: { pattern: "z" }, message: "z" }
`);
  const out = customRulesFreshness(root);
  assert.equal(out.checked, 2, 'only the two opted-in packs count toward checked');
  assert.equal(out.stale, true);
  assert.deepEqual(out.staleFiles.map(f => f.file), ['stale.yml']);
  fs.rmSync(root, { recursive: true, force: true });
});
