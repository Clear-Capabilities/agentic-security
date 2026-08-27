// Finding schema tests (assurance-hardening PRD, Milestone 0, FR-105).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFindingCompleteness, FINDING_SCHEMA_VERSION, FINDING_FIELD_GROUPS } from '../src/pipeline/finding-schema.js';
import { normalizeFindings } from '../src/report/index.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

test('describeFindingCompleteness: a well-formed finding has no missing required fields', () => {
  // `findingProvenance` joined the identity group's required fields (Task 14).
  // It is never legitimately absent — the provenance coordinator's terminal-
  // status guarantee means "no provenance object" is only ever reachable by a
  // finding that escaped annotation, so a well-formed fixture carries one, with
  // `not_available` standing in for the fixture having no repository behind it.
  const f = {
    id: 'a1', kind: 'sast', vuln: 'SQL Injection', file: 'app.js', line: 10, severity: 'high',
    findingProvenance: { status: 'not_available' },
  };
  const d = describeFindingCompleteness(f);
  assert.equal(d.schemaVersion, FINDING_SCHEMA_VERSION);
  assert.deepEqual(d.missingRequiredFields, []);
  assert.equal(d.isComplete, true);
});

test('describeFindingCompleteness: a finding missing a required field is reported, not thrown on', () => {
  const f = { id: 'a1', kind: 'sast', file: 'app.js', line: 10 }; // no vuln, no severity
  const d = describeFindingCompleteness(f);
  assert.ok(d.missingRequiredFields.includes('vuln'));
  assert.ok(d.missingRequiredFields.includes('severity'));
  assert.equal(d.isComplete, false);
});

test('describeFindingCompleteness: does not throw on null/undefined/garbage input', () => {
  assert.doesNotThrow(() => describeFindingCompleteness(null));
  assert.doesNotThrow(() => describeFindingCompleteness(undefined));
  assert.doesNotThrow(() => describeFindingCompleteness('not an object'));
  assert.doesNotThrow(() => describeFindingCompleteness(42));
  const d = describeFindingCompleteness(null);
  assert.equal(d.isComplete, false);
});

test('describeFindingCompleteness: optional fields split into populated vs missing correctly', () => {
  const f = {
    id: 'a1', kind: 'sast', vuln: 'XSS', file: 'app.js', line: 5, severity: 'medium',
    cwe: 'CWE-79', confidence: 0.8, proof: { verdict: 'unproven' },
  };
  const d = describeFindingCompleteness(f);
  assert.ok(d.populatedOptionalFields.includes('cwe'));
  assert.ok(d.populatedOptionalFields.includes('confidence'));
  assert.ok(d.populatedOptionalFields.includes('proof'));
  assert.ok(d.missingOptionalFields.includes('exploitability'));
});

test('every FINDING_FIELD_GROUPS field name is a real key normalizeFindings can produce', () => {
  // Guards against the schema silently drifting from the actual canonical
  // shape it claims to describe (decision D-0003's whole point): build one
  // real normalized finding via a real scan and confirm every field this
  // module names is at least a key on that object (populated or not).
  return (async () => {
    const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
    const { scan } = await runScan(root, { network: false });
    const normalized = normalizeFindings(scan);
    assert.ok(normalized.length > 0, 'fixture should produce at least one finding');
    const sample = normalized[0];
    const sampleKeys = new Set(Object.keys(sample));
    const allNamedFields = Object.values(FINDING_FIELD_GROUPS).flatMap(g => [...g.required, ...g.optional]);
    const unknown = allNamedFields.filter(field => !sampleKeys.has(field));
    assert.deepEqual(unknown, [], `finding-schema.js names field(s) normalizeFindings does not produce: ${JSON.stringify(unknown)}`);
  })();
});

test('a real scan finding is schema-complete on its required fields', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  const normalized = normalizeFindings(scan);
  for (const f of normalized) {
    const d = describeFindingCompleteness(f);
    assert.equal(d.isComplete, true, `finding ${f.id} missing required fields: ${JSON.stringify(d.missingRequiredFields)}`);
  }
});
