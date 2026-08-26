// 0.6.0 Feat-3: Material change detection — F1 over labelled synthetic diffs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { classifyDiff, classifyFixMaterialRisk, HIGH_IMPACT_CATEGORY_OF_KIND } from '../src/posture/material-change.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesPath = path.join(__dirname, 'fixtures', 'material-change', 'diffs.json');
const FIXTURES = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

test('Material change detection — classifyDiff hits expected severity tier per fixture', () => {
  let TP = 0, FP = 0, FN = 0;
  const detail = [];
  for (const [name, fx] of Object.entries(FIXTURES)) {
    if (name.startsWith('_')) continue;
    const isVuln = name.startsWith('vuln_');
    const result = classifyDiff(fx.diff);
    const got = result.materialRisk;
    const expected = fx.expectedSeverity;
    // Vuln cases: result must be at least the expected severity tier
    if (isVuln) {
      if (SEV_RANK[got] >= SEV_RANK[expected]) { TP++; detail.push(`TP ${name} (${got}>=${expected})`); }
      else { FN++; detail.push(`FN ${name} (got ${got}, expected ${expected})`); }
    } else {
      // Routine cases: result must NOT exceed 'low'
      if (SEV_RANK[got] <= SEV_RANK['low']) { detail.push(`TN ${name} (got ${got})`); }
      else { FP++; detail.push(`FP ${name} (got ${got}; expected ≤ low)`); }
    }
  }
  const precision = TP / Math.max(TP + FP, 1);
  const recall    = TP / Math.max(TP + FN, 1);
  const f1        = (2 * precision * recall) / Math.max(precision + recall, 1e-9);
  // eslint-disable-next-line no-console
  console.log(`[Material-change] TP=${TP} FP=${FP} FN=${FN} | P=${precision.toFixed(2)} R=${recall.toFixed(2)} F1=${f1.toFixed(2)}\n  ${detail.join('\n  ')}`);
  assert.ok(f1        >= 0.85, `F1 below floor: ${f1.toFixed(2)};\n  ${detail.join('\n  ')}`);
  assert.ok(recall    >= 0.83, `recall below floor: ${recall.toFixed(2)}`);
  assert.ok(precision >= 0.83, `precision below floor: ${precision.toFixed(2)}`);
});

test('Material change detection — single auth-removed hunk lands as critical', () => {
  const r = classifyDiff(FIXTURES.vuln_auth_removed.diff);
  assert.equal(r.materialRisk, 'critical');
  assert.ok(r.findings.some(f => f.kind === 'auth-removed'), `expected auth-removed kind; got: ${r.findings.map(f => f.kind).join(', ')}`);
});

test('Material change detection — pure comment add lands as none/low', () => {
  const r = classifyDiff(FIXTURES.routine_comment_only.diff);
  assert.ok(r.materialRisk === 'none' || r.materialRisk === 'low', `got ${r.materialRisk}`);
});

// ── FR-307: classifyFixMaterialRisk — before/after content, not diff text ──

test('classifyFixMaterialRisk: new weak-crypto and schema-DDL kinds are classified with the correct FR-307 category', () => {
  const r1 = classifyFixMaterialRisk({ 'a.js': { before: '', after: 'const h = md5(pw);\n' } });
  assert.ok(r1.findings.some(f => f.kind === 'weak-crypto-added'));
  assert.deepEqual(r1.highImpactCategories, ['crypto']);

  const r2 = classifyFixMaterialRisk({ 'm.sql': { before: '', after: 'CREATE TABLE accounts (id INT);\n' } });
  assert.ok(r2.findings.some(f => f.kind === 'schema-change'));
  assert.deepEqual(r2.highImpactCategories, ['schema']);
});

test('classifyFixMaterialRisk: a new PII-shaped field is classified pii, reusing dataflow/privacy-taxonomy.js\'s field-name vocabulary', () => {
  const r = classifyFixMaterialRisk({ 'u.js': { before: 'const x = 1;\n', after: 'const x = 1;\nconst email = req.body.email;\n' } });
  assert.ok(r.findings.some(f => f.kind === 'new-pii-field'));
  assert.deepEqual(r.highImpactCategories, ['pii']);
});

test('classifyFixMaterialRisk: identical before/after content produces no findings and no categories', () => {
  const r = classifyFixMaterialRisk({ 'a.js': { before: 'const x = 1;\n', after: 'const x = 1;\n' } });
  assert.equal(r.findings.length, 0);
  assert.deepEqual(r.highImpactCategories, []);
});

test('classifyFixMaterialRisk: multiple files, multiple categories in one candidate are all surfaced, deduplicated and sorted', () => {
  const r = classifyFixMaterialRisk({
    'auth.js': { before: 'if(!requireAuth(req)) return;\n', after: '\n' },
    'crypto.js': { before: '', after: 'const h = sha1(x);\n' },
  });
  assert.deepEqual(r.highImpactCategories, ['auth', 'crypto']);
});

test('classifyFixMaterialRisk: a routine, single-file, non-pattern-matching change has zero high-impact categories', () => {
  const r = classifyFixMaterialRisk({ 'a.js': { before: 'const a = 1;\n', after: 'const a = 2;\n' } });
  assert.deepEqual(r.highImpactCategories, []);
});

test('classifyFixMaterialRisk: missing/null before or after content degrades safely, never throws', () => {
  assert.doesNotThrow(() => classifyFixMaterialRisk({ 'a.js': { after: 'const x = 1;\n' } }));
  assert.doesNotThrow(() => classifyFixMaterialRisk({ 'a.js': {} }));
  assert.doesNotThrow(() => classifyFixMaterialRisk({}));
  assert.doesNotThrow(() => classifyFixMaterialRisk());
});

test('HIGH_IMPACT_CATEGORY_OF_KIND names exactly the 7 PRD categories: auth, authZ, crypto, pii, schema, infra-privilege, public-api', () => {
  const categories = new Set(Object.values(HIGH_IMPACT_CATEGORY_OF_KIND));
  assert.deepEqual([...categories].sort(), ['auth', 'authZ', 'crypto', 'infra-privilege', 'pii', 'public-api', 'schema']);
});
