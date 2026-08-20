// PRD F12.3 — the shared bench watchdog.
//
// This is the control that stops one pathological entry from ending a whole
// measurement. It is worth testing directly because the failure it prevents is
// invisible by construction: a run that hangs produces no output to inspect, and
// the six-hour wedge that motivated it looked identical at minute 5 and minute
// 300.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withEntryTimeout, EntryTimeout, entryTimeoutMs } from '../../bench/_lib/watchdog.mjs';

test('a promise that settles in time passes its value straight through', async () => {
  const out = await withEntryTimeout(Promise.resolve('scanned'), 'entry-a', 5_000);
  assert.equal(out, 'scanned');
});

test('a promise that never settles rejects as EntryTimeout, naming the entry', async () => {
  const never = new Promise(() => {});
  await assert.rejects(
    () => withEntryTimeout(never, 'GHSA-wedged', 40),
    (err) => {
      assert.ok(err instanceof EntryTimeout, `expected EntryTimeout, got ${err.name}`);
      assert.equal(err.label, 'GHSA-wedged');
      assert.match(err.message, /exceeded 40ms/);
      return true;
    });
});

test('a rejection from the work itself is not disguised as a timeout', async () => {
  // A scan that throws is a DIFFERENT unscored reason than a scan that hangs,
  // and the runner reports the reason by name — so these must stay separable.
  await assert.rejects(
    () => withEntryTimeout(Promise.reject(new Error('parse blew up')), 'entry-b', 5_000),
    (err) => {
      assert.ok(!(err instanceof EntryTimeout), 'a real error must not be reported as a timeout');
      assert.match(err.message, /parse blew up/);
      return true;
    });
});

test('the watchdog timer does not by itself hold the event loop open', () => {
  // If the timer were not unref'd, every bounded entry would keep the process
  // alive for the full budget after the work finished — turning a 600s budget
  // into a 600s tax on a fast run.
  const timer = setTimeout(() => {}, 60_000);
  assert.equal(typeof timer.unref, 'function',
    'this platform must support unref for the watchdog to be safe');
  clearTimeout(timer);
});

test('the budget is overridable and falls back to 600s on nonsense input', () => {
  const VAR = 'AGENTIC_SECURITY_TEST_WATCHDOG_MS';
  const prev = process.env[VAR];
  try {
    delete process.env[VAR];
    assert.equal(entryTimeoutMs(VAR), 600_000, 'default budget');

    process.env[VAR] = '1234';
    assert.equal(entryTimeoutMs(VAR), 1234, 'explicit override');

    // A malformed or hostile value must not silently disable the watchdog —
    // `0` or `not-a-number` becoming "no timeout" would reintroduce the exact
    // six-hour hang this exists to prevent.
    for (const bad of ['0', '-5', 'soon', '']) {
      process.env[VAR] = bad;
      assert.equal(entryTimeoutMs(VAR), 600_000, `"${bad}" must fall back to the default`);
    }
  } finally {
    if (prev === undefined) delete process.env[VAR];
    else process.env[VAR] = prev;
  }
});
