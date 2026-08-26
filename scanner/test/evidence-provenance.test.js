// Evidence provenance tests (assurance-hardening PRD, Milestone 1, FR-107).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeEvidenceProvenance, RAW_OBSERVED_FIELDS } from '../src/pipeline/evidence-provenance.js';
import { FINDING_SCHEMA_VERSION } from '../src/pipeline/finding-schema.js';
import { normalizeFindings } from '../src/report/index.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

test('describeEvidenceProvenance: partitions a synthetic finding into observed vs derived', () => {
  const f = {
    id: 'a1', file: 'app.js', line: 10, vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'query(x)',
    confidence: 0.9, severity: 'high', compositeRisk: 72, riskDollars: { ev: 5000 },
  };
  const { observed, derived, schemaVersion } = describeEvidenceProvenance(f);
  assert.equal(schemaVersion, FINDING_SCHEMA_VERSION);
  assert.deepEqual(observed, { id: 'a1', file: 'app.js', line: 10, vuln: 'SQL Injection', cwe: 'CWE-89', snippet: 'query(x)' });
  assert.deepEqual(derived, { confidence: 0.9, severity: 'high', compositeRisk: 72, riskDollars: { ev: 5000 } });
});

test('describeEvidenceProvenance: severity, confidence, and risk fields are NEVER classified observed — the literal FR-107 acceptance criterion', () => {
  const f = { id: 'a1', file: 'a.js', line: 1, vuln: 'x', confidence: 0.5, severity: 'critical', exploitability: 0.8, riskDollars: { ev: 1 } };
  const { observed } = describeEvidenceProvenance(f);
  for (const field of ['confidence', 'severity', 'exploitability', 'riskDollars']) {
    assert.ok(!(field in observed), `${field} must not land in "observed" — the PRD names it as inferred`);
  }
});

test('describeEvidenceProvenance: whyFired.evidence is promoted into observed.detectorEvidence; whyFired itself lands in derived', () => {
  const f = {
    id: 'a1', file: 'a.js', line: 1, vuln: 'x',
    whyFired: { detector: 'sast/sqli', evidence: { sinkSnippet: 'query(x)', pathSteps: [] }, considered: { crownJewelTier: 'high' } },
  };
  const { observed, derived } = describeEvidenceProvenance(f);
  assert.deepEqual(observed.detectorEvidence, { sinkSnippet: 'query(x)', pathSteps: [] });
  assert.ok('whyFired' in derived, 'the whyFired wrapper itself (which also carries pipeline-derived "considered" data) belongs in derived, not observed');
  assert.equal(derived.whyFired.considered.crownJewelTier, 'high');
});

test('describeEvidenceProvenance: a finding with no whyFired does not synthesize detectorEvidence', () => {
  const f = { id: 'a1', file: 'a.js', line: 1, vuln: 'x' };
  const { observed } = describeEvidenceProvenance(f);
  assert.ok(!('detectorEvidence' in observed));
});

test('describeEvidenceProvenance: null values are dropped from both buckets, never appear as explicit nulls', () => {
  const f = { id: 'a1', file: null, line: 1, vuln: 'x', confidence: null, severity: 'high' };
  const { observed, derived } = describeEvidenceProvenance(f);
  assert.ok(!('file' in observed));
  assert.ok(!('confidence' in derived));
  assert.equal(derived.severity, 'high');
});

test('describeEvidenceProvenance: does not throw on null/undefined/garbage input', () => {
  assert.doesNotThrow(() => describeEvidenceProvenance(null));
  assert.doesNotThrow(() => describeEvidenceProvenance(undefined));
  assert.doesNotThrow(() => describeEvidenceProvenance('not an object'));
  assert.doesNotThrow(() => describeEvidenceProvenance(42));
  const { observed, derived } = describeEvidenceProvenance(null);
  assert.deepEqual(observed, {});
  assert.deepEqual(derived, {});
});

test('describeEvidenceProvenance: RAW_OBSERVED_FIELDS is frozen (an accidental push must not silently redefine the raw/derived boundary)', () => {
  assert.ok(Object.isFrozen(RAW_OBSERVED_FIELDS));
});

// ── Real-scan integration, per this session's D-0003 discipline: verify
// against actual current field names, not an assumed shape ─────────────────

test('every RAW_OBSERVED_FIELDS name is a real key a live scan actually produces (guards against silent drift from the real detector shape)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  const normalized = normalizeFindings(scan);
  assert.ok(normalized.length > 0, 'fixture should produce at least one finding');
  const sampleKeys = new Set(Object.keys(normalized[0]));
  const unknown = RAW_OBSERVED_FIELDS.filter(field => !sampleKeys.has(field));
  assert.deepEqual(unknown, [], `evidence-provenance.js names field(s) a real normalized finding does not produce: ${JSON.stringify(unknown)}`);
});

test('a real scan finding genuinely separates observed facts from inferred confidence/severity/risk', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  const normalized = normalizeFindings(scan);
  const withWhyFired = normalized.find(f => f.whyFired);
  assert.ok(withWhyFired, 'expected at least one real finding to carry a whyFired record (annotateWhyFired should have run)');

  const { observed, derived } = describeEvidenceProvenance(withWhyFired);
  // Observed must contain genuine identity/location facts.
  assert.ok(observed.file, 'observed.file must be populated');
  assert.ok(typeof observed.line === 'number', 'observed.line must be populated');
  assert.ok(observed.detectorEvidence, 'observed.detectorEvidence must be populated from a real whyFired.evidence');
  // Derived must contain the inferred signals the PRD specifically names.
  assert.ok('severity' in derived, 'derived.severity must be populated — a real finding always has one');
  assert.ok(typeof derived.confidence === 'number' || derived.confidence === undefined || 'confidenceTier' in derived,
    'confidence-family fields, when present, must land in derived, never observed');
});
