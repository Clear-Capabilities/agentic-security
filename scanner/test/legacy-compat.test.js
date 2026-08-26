// Legacy field compatibility adapter tests (assurance-hardening PRD,
// Milestone 1, FR-108).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyLegacyCompat, legacyFieldDeprecationNotice, LEGACY_FIELD_ALIASES } from '../src/pipeline/legacy-compat.js';
import { normalizeFindings, toJSON } from '../src/report/index.js';

test('applyLegacyCompat: backfills the deprecated confidenceFloor from the current confidenceWeight', () => {
  const f = { id: 'a1', riskDollars: { ev: 100, confidenceWeight: 0.8 } };
  const applied = applyLegacyCompat(f);
  assert.deepEqual(applied, ['riskDollars.confidenceFloor']);
  assert.equal(f.riskDollars.confidenceFloor, 0.8);
  assert.equal(f.riskDollars.confidenceWeight, 0.8, 'the new field must survive untouched');
  assert.deepEqual(f._legacyFields, ['riskDollars.confidenceFloor']);
});

test('applyLegacyCompat: a finding with no riskDollars at all gets no backfill and no _legacyFields marker', () => {
  const f = { id: 'a1' };
  const applied = applyLegacyCompat(f);
  assert.deepEqual(applied, []);
  assert.ok(!('_legacyFields' in f));
  assert.ok(!('riskDollars' in f), 'must not fabricate a riskDollars shell that never ran');
});

test('applyLegacyCompat: does not clobber an old field value a caller already set explicitly', () => {
  const f = { id: 'a1', riskDollars: { confidenceFloor: 0.99, confidenceWeight: 0.5 } };
  applyLegacyCompat(f);
  assert.equal(f.riskDollars.confidenceFloor, 0.99, 'an explicitly-set legacy value must survive, not be overwritten');
});

test('applyLegacyCompat: does not throw on null/undefined/garbage input', () => {
  assert.doesNotThrow(() => applyLegacyCompat(null));
  assert.doesNotThrow(() => applyLegacyCompat(undefined));
  assert.doesNotThrow(() => applyLegacyCompat('not an object'));
  assert.deepEqual(applyLegacyCompat(null), []);
});

test('LEGACY_FIELD_ALIASES is frozen (each entry too) — an accidental mutation must not silently redefine a documented alias', () => {
  assert.ok(Object.isFrozen(LEGACY_FIELD_ALIASES));
  assert.ok(Object.isFrozen(LEGACY_FIELD_ALIASES[0]));
});

// ── legacyFieldDeprecationNotice ─────────────────────────────────────────

test('legacyFieldDeprecationNotice: null when no finding used a legacy alias (the intended eventual steady state)', () => {
  const findings = [{ id: 'a1' }, { id: 'a2', riskDollars: { confidenceWeight: 0.9 } }];
  // Deliberately does NOT call applyLegacyCompat first — nothing backfilled, nothing to notice.
  assert.equal(legacyFieldDeprecationNotice(findings), null);
});

test('legacyFieldDeprecationNotice: names the exact field, replacement, and reason when a legacy alias was used', () => {
  const findings = [{ id: 'a1', riskDollars: { confidenceWeight: 0.9 } }];
  applyLegacyCompat(findings[0]);
  const notice = legacyFieldDeprecationNotice(findings);
  assert.ok(notice);
  assert.equal(notice.fields.length, 1);
  assert.equal(notice.fields[0].oldPath, 'riskDollars.confidenceFloor');
  assert.equal(notice.fields[0].newPath, 'riskDollars.confidenceWeight');
  assert.ok(notice.fields[0].reason);
  assert.match(notice.message, /deprecated/i);
});

test('legacyFieldDeprecationNotice: does not throw on non-array input', () => {
  assert.doesNotThrow(() => legacyFieldDeprecationNotice(null));
  assert.equal(legacyFieldDeprecationNotice(null), null);
});

// ── Integration: normalizeFindings() actually applies this for every consumer ──

test('normalizeFindings: a real finding with riskDollars.confidenceWeight gets the legacy confidenceFloor backfilled', () => {
  const scan = {
    findings: [{
      id: 'a1', kind: 'sast', vuln: 'SQL Injection', file: 'app.js', line: 10, severity: 'high',
      riskDollars: { ev: 5000, prob: 0.2, impact: 250000, discount: 0.9, confidenceWeight: 0.85 },
    }],
  };
  const normalized = normalizeFindings(scan);
  assert.equal(normalized.length, 1);
  assert.equal(normalized[0].riskDollars.confidenceFloor, 0.85, 'a legacy consumer reading the OLD field name must still get the value');
  assert.equal(normalized[0].riskDollars.confidenceWeight, 0.85);
});

test('normalizeFindings: a finding without riskDollars is unaffected — no fabricated legacy shell', () => {
  const scan = { findings: [{ id: 'a1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'low' }] };
  const normalized = normalizeFindings(scan);
  assert.equal(normalized[0].riskDollars, null);
});

// ── toJSON: the report-level notice FR-108 asks for ─────────────────────

test('toJSON: legacyFieldNotice is null when nothing used a deprecated field (the steady state)', () => {
  const scan = { findings: [{ id: 'a1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'low' }] };
  const out = toJSON(scan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.equal(out.legacyFieldNotice, null);
});

test('toJSON: legacyFieldNotice is populated when a real finding uses the deprecated confidenceFloor alias', () => {
  const scan = {
    findings: [{
      id: 'a1', kind: 'sast', vuln: 'SQL Injection', file: 'app.js', line: 10, severity: 'high',
      riskDollars: { ev: 5000, confidenceWeight: 0.85 },
    }],
  };
  const out = toJSON(scan, { scanId: 't', startedAt: '2026-01-01T00:00:00Z' });
  assert.ok(out.legacyFieldNotice);
  assert.equal(out.legacyFieldNotice.fields[0].oldPath, 'riskDollars.confidenceFloor');
  assert.equal(out.findings[0].riskDollars.confidenceFloor, 0.85);
});
