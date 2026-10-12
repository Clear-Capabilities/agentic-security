import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeRuntimeAssurance, RUNTIME_STATUS_VALUES } from '../../src/lineage/runtime-assurance.js';

function obs(overrides = {}) {
  return {
    id: 'observation:aaaaaaaaaaaa',
    matchMethod: 'destination_literal',
    lastObservedAt: '2026-08-30T10:00:00.000Z',
    ...overrides,
  };
}

function importRecord(overrides = {}) {
  return {
    windowStart: '2026-08-01T00:00:00.000Z',
    windowEnd: '2026-08-31T00:00:00.000Z',
    importedAt: '2026-08-31T12:00:00.000Z',
    observations: [obs()],
    ...overrides,
  };
}

test('RA/1: RUNTIME_STATUS_VALUES is exactly the three documented values, frozen', () => {
  assert.deepEqual([...RUNTIME_STATUS_VALUES], ['complete', 'partial', 'unavailable']);
  assert.ok(Object.isFrozen(RUNTIME_STATUS_VALUES));
});

test('RA/2a: no store consulted at all (importRecords null) reads "unavailable", never "complete" and never a silent empty report', () => {
  const r = computeRuntimeAssurance({ importRecords: null, correlation: { evaluated: false } });
  assert.equal(r.runtimeStatus, 'unavailable');
  assert.equal(r.missingTelemetry, true);
  assert.ok(r.limitations.length > 0);
});

test('RA/2b: an empty import store reads "unavailable"', () => {
  const r = computeRuntimeAssurance({ importRecords: [], correlation: { evaluated: true } });
  assert.equal(r.runtimeStatus, 'unavailable');
});

test('RA/2c: correlation.evaluated === false (even with import records somehow present) reads "unavailable" — defensive, never trusts importRecords alone', () => {
  const r = computeRuntimeAssurance({ importRecords: [importRecord()], correlation: { evaluated: false } });
  assert.equal(r.runtimeStatus, 'unavailable');
});

test('RA/3a: fully matched, fresh observations read "complete"', () => {
  const r = computeRuntimeAssurance({
    importRecords: [importRecord()],
    correlation: { evaluated: true },
    now: '2026-08-31T13:00:00.000Z',
  });
  assert.equal(r.runtimeStatus, 'complete');
  assert.equal(r.mappingPercentage, 100);
  assert.equal(r.unmatchedObservationCount, 0);
  assert.equal(r.missingTelemetry, false);
  assert.equal(r.parseFailures, 0);
});

test('RA/3b: any unmatched observation demotes to "partial", with an honest mapping percentage', () => {
  const r = computeRuntimeAssurance({
    importRecords: [importRecord({ observations: [obs(), obs({ matchMethod: 'unmatched' })] })],
    correlation: { evaluated: true },
    now: '2026-08-31T13:00:00.000Z',
  });
  assert.equal(r.runtimeStatus, 'partial');
  assert.equal(r.mappingPercentage, 50);
  assert.equal(r.unmatchedObservationCount, 1);
  assert.ok(r.limitations.some((l) => l.includes('unmatched')));
});

test('RA/3c: stale telemetry (older than staleAfterHours) demotes to "partial" even with 100% mapping', () => {
  const r = computeRuntimeAssurance({
    importRecords: [importRecord()],
    correlation: { evaluated: true },
    now: '2026-12-01T00:00:00.000Z', // far past the 30-day default bar
  });
  assert.equal(r.runtimeStatus, 'partial');
  assert.equal(r.freshness.stale, true);
  assert.ok(r.limitations.some((l) => l.includes('stale') || l.includes('old')));
});

test('RA/3d: staleAfterHours is configurable', () => {
  const r = computeRuntimeAssurance({
    importRecords: [importRecord()],
    correlation: { evaluated: true },
    now: '2026-08-31T13:00:00.000Z',
    staleAfterHours: 0.001,
  });
  assert.equal(r.runtimeStatus, 'partial');
  assert.equal(r.freshness.stale, true);
});

test('RA/4: telemetryWindow spans the min/max across every import record', () => {
  const r = computeRuntimeAssurance({
    importRecords: [
      importRecord({ windowStart: '2026-07-01T00:00:00.000Z', windowEnd: '2026-07-31T00:00:00.000Z' }),
      importRecord({ windowStart: '2026-08-01T00:00:00.000Z', windowEnd: '2026-08-31T00:00:00.000Z' }),
    ],
    correlation: { evaluated: true },
  });
  assert.equal(r.telemetryWindow.start, '2026-07-01T00:00:00.000Z');
  assert.equal(r.telemetryWindow.end, '2026-08-31T00:00:00.000Z');
});

test('RA/5: zero total observations (an import with an empty observations array) is "partial", never "complete" — nothing to corroborate anything', () => {
  const r = computeRuntimeAssurance({
    importRecords: [importRecord({ observations: [] })],
    correlation: { evaluated: true },
  });
  assert.equal(r.runtimeStatus, 'partial');
  assert.equal(r.mappingPercentage, null);
  assert.ok(r.limitations.some((l) => l.includes('zero observation')));
});

test('RA/6: parseFailures is always reported as 0 with an explicit disclosure note — never silently implying a clean history', () => {
  const r = computeRuntimeAssurance({ importRecords: [importRecord()], correlation: { evaluated: true } });
  assert.equal(r.parseFailures, 0);
  assert.ok(typeof r.parseFailuresNote === 'string' && r.parseFailuresNote.length > 20);
});

test('RA/7: never throws on malformed opts', () => {
  for (const bad of [null, undefined, 42, 'x', [], {}]) {
    assert.doesNotThrow(() => computeRuntimeAssurance(bad));
  }
});
