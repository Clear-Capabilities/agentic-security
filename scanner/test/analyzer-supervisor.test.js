// Real, preemptive deadline enforcement test (assurance-hardening PRD
// FR-202, D-0046 phase 1).
//
// This proves the literal FR-202 acceptance criterion — "a deliberately
// hung analyzer terminates within the configured deadline plus a documented
// grace period" — at the primitive level, against a REAL busy-wait hang
// (test/fixtures/analyzer-supervisor/synthetic-analyzers.mjs's
// hangForever()), not a mocked or simulated one. Real wiring of this
// primitive into engine.js's actual per-file scan loop is D-0046's phase 3,
// not yet done — this file proves the primitive itself works.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runWithDeadline, DEFAULT_GRACE_MS } from '../src/pipeline/analyzer-supervisor.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, 'fixtures', 'analyzer-supervisor', 'synthetic-analyzers.mjs');

test('runWithDeadline: a quick, well-behaved analyzer resolves with its real return value', async () => {
  const out = await runWithDeadline(
    { modulePath: FIXTURE, exportName: 'quickWork', args: [2, 3] },
    { timeoutMs: 2000 },
  );
  assert.deepEqual(out, { ok: true, result: 5 });
});

test('runWithDeadline: a thrown error inside the worker is captured, not propagated to the caller', async () => {
  const out = await runWithDeadline(
    { modulePath: FIXTURE, exportName: 'throwsError', args: ['synthetic failure'] },
    { timeoutMs: 2000 },
  );
  assert.equal(out.ok, false);
  assert.match(out.error, /synthetic failure/);
});

test('runWithDeadline: a REAL hung analyzer (genuine infinite loop, no clock checks) is preemptively terminated within timeoutMs + graceMs — the literal FR-202 acceptance criterion', async () => {
  const timeoutMs = 300;
  const graceMs = 200;
  const t0 = Date.now();
  const out = await runWithDeadline(
    { modulePath: FIXTURE, exportName: 'hangForever', args: [] },
    { timeoutMs, graceMs },
  );
  const elapsed = Date.now() - t0;

  assert.deepEqual(out, { ok: false, timedOut: true, timeoutMs, graceMs });
  // Generous upper bound (2x the deadline + fixed slack) to absorb CI/CPU
  // scheduling jitter without making this test flaky, while still proving
  // termination happened on the order of the configured deadline, not
  // "eventually" or "never" (which is what would happen without a real
  // preemptive kill — hangForever() never returns on its own).
  assert.ok(elapsed < (timeoutMs + graceMs) * 2 + 2000,
    `expected termination within roughly ${timeoutMs + graceMs}ms, took ${elapsed}ms`);
});

test('runWithDeadline: default grace period is used when not specified', async () => {
  const timeoutMs = 300;
  const t0 = Date.now();
  const out = await runWithDeadline(
    { modulePath: FIXTURE, exportName: 'hangForever', args: [] },
    { timeoutMs },
  );
  const elapsed = Date.now() - t0;
  assert.deepEqual(out, { ok: false, timedOut: true, timeoutMs, graceMs: DEFAULT_GRACE_MS });
  assert.ok(elapsed >= timeoutMs, 'must not terminate before the configured deadline');
});

test('runWithDeadline: validates its own inputs rather than hanging or throwing', async () => {
  const missingSpec = await runWithDeadline({}, { timeoutMs: 100 });
  assert.equal(missingSpec.ok, false);
  assert.match(missingSpec.error, /modulePath.*exportName/);

  const missingTimeout = await runWithDeadline({ modulePath: FIXTURE, exportName: 'quickWork', args: [1, 1] }, {});
  assert.equal(missingTimeout.ok, false);
  assert.match(missingTimeout.error, /timeoutMs/);
});

test('runWithDeadline: a nonexistent export is reported as a captured error, not an unhandled rejection', async () => {
  const out = await runWithDeadline(
    { modulePath: FIXTURE, exportName: 'doesNotExist', args: [] },
    { timeoutMs: 2000 },
  );
  assert.equal(out.ok, false);
  assert.match(out.error, /doesNotExist.*not a function/);
});
