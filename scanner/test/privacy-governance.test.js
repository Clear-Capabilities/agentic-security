// FR-407 (assurance-hardening PRD): expand DPIA and RoPA scaffolds with
// fields for purpose, lawful basis, subject, retention, residency,
// recipient, transfer, minimization, consent, access, and deletion.
// Unknown governance fields are marked `manual_required`, not inferred.
//
// The property under test throughout: NONE of these 11 fields are ever
// computed from code — a class with no operator config must show
// manual_required for every single one, and a class WITH operator config
// must show exactly and only the configured fields as operator-provided,
// never partially inferring or defaulting an unconfigured field to
// anything other than manual_required.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  MANUAL_REQUIRED, GOVERNANCE_FIELDS, loadPrivacyGovernanceConfig,
  governanceRecordFor, emitRopaArtifact,
} from '../src/dataflow/privacy-governance.js';
import { emitDpiaArtifact } from '../src/dataflow/privacy-taint.js';

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'privacy-governance-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

async function writeGovernanceConfig(dir, obj) {
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-governance.json'), JSON.stringify(obj, null, 2));
}

test('GOVERNANCE_FIELDS carries all 11 fields the PRD names by name', () => {
  assert.deepEqual(GOVERNANCE_FIELDS, [
    'purpose', 'lawfulBasis', 'subject', 'retention', 'residency',
    'recipient', 'transfer', 'minimization', 'consent', 'access', 'deletion',
  ]);
});

test('loadPrivacyGovernanceConfig with no scanRoot or no config file returns the empty config', async () => {
  assert.deepEqual(loadPrivacyGovernanceConfig(null), { byClass: {}, default: {} });
  const dir = await tmpProject();
  try {
    assert.deepEqual(loadPrivacyGovernanceConfig(dir), { byClass: {}, default: {} });
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('loadPrivacyGovernanceConfig degrades to empty on malformed JSON, without throwing', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-governance.json'), 'not json{{{');
    assert.deepEqual(loadPrivacyGovernanceConfig(dir), { byClass: {}, default: {} });
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('governanceRecordFor with no config: every one of the 11 fields is manual_required, none inferred', () => {
  const record = governanceRecordFor('PII', null);
  assert.equal(Object.keys(record).length, 11);
  for (const field of GOVERNANCE_FIELDS) {
    assert.equal(record[field].value, MANUAL_REQUIRED, `expected ${field} to be manual_required`);
    assert.equal(record[field].source, 'manual_required');
  }
});

test('governanceRecordFor: an operator-supplied per-class field is used and tagged operator_provided; everything else stays manual_required', () => {
  const config = { byClass: { PII: { purpose: 'user account management', retention: '3 years post deletion' } }, default: {} };
  const record = governanceRecordFor('PII', config);
  assert.equal(record.purpose.value, 'user account management');
  assert.equal(record.purpose.source, 'operator_provided');
  assert.equal(record.retention.value, '3 years post deletion');
  assert.equal(record.retention.source, 'operator_provided');
  // Every OTHER field must still be manual_required — no partial inference.
  for (const field of GOVERNANCE_FIELDS) {
    if (field === 'purpose' || field === 'retention') continue;
    assert.equal(record[field].value, MANUAL_REQUIRED, `expected ${field} to remain manual_required`);
  }
});

test('governanceRecordFor: a scan-wide default applies to every class, but a per-class value takes precedence over it', () => {
  const config = { byClass: { PII: { residency: 'EU' } }, default: { residency: 'US' } };
  assert.equal(governanceRecordFor('PII', config).residency.value, 'EU', 'per-class overrides default');
  assert.equal(governanceRecordFor('PHI', config).residency.value, 'US', 'a class with no override gets the default');
  assert.equal(governanceRecordFor('PHI', config).residency.source, 'operator_provided', 'the default is still operator-provided, not manual_required');
});

test('governanceRecordFor: a config field with an empty string is treated as unset (manual_required), not as a supplied blank value', () => {
  const config = { byClass: { PII: { purpose: '' } }, default: {} };
  const record = governanceRecordFor('PII', config);
  assert.equal(record.purpose.value, MANUAL_REQUIRED);
  assert.equal(record.purpose.source, 'manual_required');
});

test('emitRopaArtifact: no data classes produces a plain "none identified" scaffold, not an empty table', () => {
  const md = emitRopaArtifact([], null);
  assert.match(md, /No regulated data classes were identified/);
  assert.doesNotMatch(md, /\| Data class \|/);
});

test('emitRopaArtifact: renders one row per data class with all 11 governance columns, manual_required by default', () => {
  const piiFields = [
    { file: 'a.js', line: 1, name: 'email', classes: ['PII'] },
    { file: 'b.js', line: 2, name: 'diagnosis', classes: ['PHI'] },
  ];
  const md = emitRopaArtifact(piiFields, null);
  assert.match(md, /\| Data class \| purpose \| lawfulBasis \|/);
  assert.match(md, /\| PII \|/);
  assert.match(md, /\| PHI \|/);
  // Every cell for a class with no config is manual_required — count exact
  // occurrences on the PII row: 11 fields, so 11 manual_required cells.
  const piiRow = md.split('\n').find(l => l.startsWith('| PII |'));
  assert.ok(piiRow);
  const manualCount = (piiRow.match(new RegExp(MANUAL_REQUIRED, 'g')) || []).length;
  assert.equal(manualCount, 11);
  assert.match(md, /22 field\(s\) across 2 data class\(es\)/, '11 fields x 2 classes (PII, PHI), each fully manual_required');
});

test('emitRopaArtifact: an operator-supplied field appears in the table and reduces the reported gap count', () => {
  const piiFields = [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'] }];
  const config = { byClass: { PII: { purpose: 'account management' } }, default: {} };
  const md = emitRopaArtifact(piiFields, config);
  assert.match(md, /account management/);
  const piiRow = md.split('\n').find(l => l.startsWith('| PII |'));
  const manualCount = (piiRow.match(new RegExp(MANUAL_REQUIRED, 'g')) || []).length;
  assert.equal(manualCount, 10, 'one of the 11 fields is now operator-provided');
});

test('emitDpiaArtifact: a per-class "Governance fields" subsection appears, manual_required by default', () => {
  const piiFields = [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'], declaredType: 'string' }];
  const md = emitDpiaArtifact(piiFields, []);
  assert.match(md, /Governance fields for PII/);
  assert.match(md, /purpose: `manual_required`/);
  assert.match(md, /deletion: `manual_required`/);
});

test('emitDpiaArtifact: an operator-supplied governance field is rendered and marked as such, distinct from manual_required ones', async () => {
  const dir = await tmpProject();
  try {
    await writeGovernanceConfig(dir, { byClass: { PII: { lawfulBasis: 'consent (GDPR Art. 6(1)(a))' } }, default: {} });
    const governanceConfig = loadPrivacyGovernanceConfig(dir);
    const piiFields = [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'], declaredType: 'string' }];
    const md = emitDpiaArtifact(piiFields, [], { governanceConfig });
    assert.match(md, /lawfulBasis: `consent \(GDPR Art\. 6\(1\)\(a\)\)`\s*\(operator-provided\)/);
    assert.match(md, /purpose: `manual_required`/, 'unconfigured fields on the SAME class remain manual_required');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('emitDpiaArtifact with no governanceConfig option still renders the section (backward compatible default: everything manual_required)', () => {
  const piiFields = [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'], declaredType: 'string' }];
  const md = emitDpiaArtifact(piiFields, []);
  assert.match(md, /Governance fields for PII/);
});
