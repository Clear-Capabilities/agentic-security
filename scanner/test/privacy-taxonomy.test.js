// FR-402 (assurance-hardening PRD): the privacy data-classification
// taxonomy is versioned and customizable without modifying source.
//
// Proves both halves of the acceptance criterion directly:
//   - versioned: BUILTIN_TAXONOMY_VERSION is a stable, inspectable string,
//     and loadPrivacyTaxonomy()'s returned version reflects whether an
//     operator config customized anything.
//   - customizable without modifying source: an operator's
//     .agentic-security/privacy-taxonomy.json can add a brand-new
//     organization-defined class, or extend/replace an existing class's
//     patterns, without editing privacy-taxonomy.js or privacy-taint.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  BUILTIN_TAXONOMY_VERSION, DEFAULT_TAXONOMY, compileTaxonomy,
  loadPrivacyTaxonomy, classifyFieldAgainst, severityForClasses,
} from '../src/dataflow/privacy-taxonomy.js';
import { classifyField, annotatePrivacyTaint } from '../src/dataflow/privacy-taint.js';

async function tmpProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'privacy-taxonomy-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return dir;
}

async function writeTaxonomyConfig(dir, obj) {
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-taxonomy.json'), JSON.stringify(obj, null, 2));
}

test('BUILTIN_TAXONOMY_VERSION is a stable, non-empty version string', () => {
  assert.equal(typeof BUILTIN_TAXONOMY_VERSION, 'string');
  assert.ok(BUILTIN_TAXONOMY_VERSION.length > 0);
});

test('DEFAULT_TAXONOMY carries every class the PRD names by name', () => {
  for (const cls of ['PII', 'PHI', 'PCI', 'FIN', 'CREDENTIALS', 'GEOLOCATION', 'DEVICE_ID']) {
    assert.ok(DEFAULT_TAXONOMY[cls], `expected built-in class ${cls}`);
    assert.ok(Array.isArray(DEFAULT_TAXONOMY[cls].patterns) && DEFAULT_TAXONOMY[cls].patterns.length > 0);
    assert.ok(typeof DEFAULT_TAXONOMY[cls].severity === 'string');
  }
});

test('classifyField backward compat: existing 4-bucket callers see identical results with no taxonomy argument', () => {
  assert.deepEqual(classifyField('email'), ['PII']);
  assert.deepEqual(classifyField('credit_card_number'), ['PCI']);
  assert.deepEqual(classifyField('diagnosis'), ['PHI']);
  assert.deepEqual(classifyField('salary'), ['FIN']);
  assert.deepEqual(classifyField('not_personal_data'), []);
});

test('new built-in classes classify their own field names correctly', () => {
  assert.deepEqual(classifyField('api_key'), ['CREDENTIALS']);
  assert.deepEqual(classifyField('password'), ['CREDENTIALS']);
  assert.deepEqual(classifyField('latitude'), ['GEOLOCATION']);
  assert.deepEqual(classifyField('precise_location'), ['GEOLOCATION']);
  assert.deepEqual(classifyField('device_id'), ['DEVICE_ID']);
  assert.deepEqual(classifyField('imei'), ['DEVICE_ID']);
});

test('severityForClasses returns the worst-case severity across matched classes, per the taxonomy', () => {
  const compiled = compileTaxonomy(DEFAULT_TAXONOMY);
  assert.equal(severityForClasses(['PII'], compiled), 'medium');
  assert.equal(severityForClasses(['PHI'], compiled), 'high');
  assert.equal(severityForClasses(['CREDENTIALS'], compiled), 'critical');
  assert.equal(severityForClasses(['DEVICE_ID'], compiled), 'low');
  assert.equal(severityForClasses(['PII', 'CREDENTIALS'], compiled), 'critical', 'worst-case across multiple matched classes');
  assert.equal(severityForClasses([], compiled), 'medium', 'empty match list falls back to medium, the pre-FR-402 default');
});

test('loadPrivacyTaxonomy with no scanRoot returns the built-in taxonomy unchanged', () => {
  const r = loadPrivacyTaxonomy(null);
  assert.equal(r.version, BUILTIN_TAXONOMY_VERSION);
  assert.equal(r.customized, false);
  assert.deepEqual(Object.keys(r.taxonomy).sort(), Object.keys(DEFAULT_TAXONOMY).sort());
});

test('loadPrivacyTaxonomy with a scanRoot but no config file present returns the built-in taxonomy unchanged', async () => {
  const dir = await tmpProject();
  try {
    const r = loadPrivacyTaxonomy(dir);
    assert.equal(r.version, BUILTIN_TAXONOMY_VERSION);
    assert.equal(r.customized, false);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402: a brand-new organization-defined class is picked up from config with ZERO source changes', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: {
        EMPLOYEE_ID: { severity: 'medium', patterns: ['\\bemployee[_-]?id\\b', '\\bbadge[_-]?number\\b'] },
      },
    });
    const r = loadPrivacyTaxonomy(dir);
    assert.equal(r.customized, true);
    assert.ok(r.version.includes('custom'), `expected the version to reflect customization, got ${r.version}`);
    assert.deepEqual(classifyFieldAgainst('employee_id', r.compiled), ['EMPLOYEE_ID']);
    assert.deepEqual(classifyFieldAgainst('badge_number', r.compiled), ['EMPLOYEE_ID']);
    // Built-in classes are still intact alongside the new one.
    assert.deepEqual(classifyFieldAgainst('email', r.compiled), ['PII']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402: extending an existing built-in class (mode: extend, the default) keeps the original patterns AND adds the new one', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: { PII: { patterns: ['\\bemployee[_-]?badge\\b'] } },
    });
    const r = loadPrivacyTaxonomy(dir);
    assert.deepEqual(classifyFieldAgainst('employee_badge', r.compiled), ['PII'], 'new pattern picked up');
    assert.deepEqual(classifyFieldAgainst('email', r.compiled), ['PII'], 'original built-in pattern still works');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402: mode "replace" discards the built-in patterns for that class entirely', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: { FIN: { mode: 'replace', patterns: ['\\bcustom[_-]?money[_-]?field\\b'] } },
    });
    const r = loadPrivacyTaxonomy(dir);
    assert.deepEqual(classifyFieldAgainst('custom_money_field', r.compiled), ['FIN']);
    assert.deepEqual(classifyFieldAgainst('salary', r.compiled), [], 'the built-in "salary" pattern was replaced, not extended');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402: a malformed config file degrades to the built-in taxonomy rather than throwing', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-taxonomy.json'), '{ this is not valid json');
    const r = loadPrivacyTaxonomy(dir);
    assert.equal(r.version, BUILTIN_TAXONOMY_VERSION);
    assert.equal(r.customized, false);
    assert.deepEqual(classifyFieldAgainst('email', r.compiled), ['PII']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402: an operator-supplied invalid regex pattern is skipped, not thrown, and other patterns in the same class still work', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: { PII: { patterns: ['(unclosed', '\\bemployee[_-]?badge\\b'] } },
    });
    const r = loadPrivacyTaxonomy(dir);
    assert.deepEqual(classifyFieldAgainst('employee_badge', r.compiled), ['PII']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-402 end-to-end: annotatePrivacyTaint({scanRoot}) picks up a custom class and surfaces taxonomyVersion on the result', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: { EMPLOYEE_ID: { severity: 'high', patterns: ['\\bemployee[_-]?id\\b'] } },
    });
    const perFileIR = new Map();
    perFileIR.set('a.js', {
      _content: 'const employee_id = req.body.employee_id;\nconsole.log(employee_id);\n',
      decls: [{ name: 'employee_id', line: 1 }],
      calls: [{ callee: 'log', receiver: 'console', fullPath: 'console.log', args: [{ text: 'employee_id' }], line: 2 }],
    });
    const r = annotatePrivacyTaint(perFileIR, { scanRoot: dir });
    assert.ok(r.taxonomyVersion.includes('custom'));
    assert.equal(r.findings.length, 1);
    assert.deepEqual(r.findings[0].piiClass, ['EMPLOYEE_ID']);
    assert.equal(r.findings[0].severity, 'high', 'severity comes from the custom class definition, not a hardcoded PCI/PHI check');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('annotatePrivacyTaint with no opts still classifies against the built-in taxonomy only (no customization leaks in without scanRoot)', async () => {
  const dir = await tmpProject();
  try {
    await writeTaxonomyConfig(dir, {
      classes: { EMPLOYEE_ID: { patterns: ['\\bemployee[_-]?id\\b'] } },
    });
    const perFileIR = new Map();
    perFileIR.set('a.js', {
      _content: 'const employee_id = req.body.employee_id;\nconsole.log(employee_id);\n',
      decls: [{ name: 'employee_id', line: 1 }],
      calls: [{ callee: 'log', receiver: 'console', fullPath: 'console.log', args: [{ text: 'employee_id' }], line: 2 }],
    });
    // No scanRoot passed — must NOT reach into dir's config.
    const r = annotatePrivacyTaint(perFileIR);
    assert.equal(r.findings.length, 0);
    assert.equal(r.taxonomyVersion, BUILTIN_TAXONOMY_VERSION);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
