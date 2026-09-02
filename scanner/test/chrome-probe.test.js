import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { probeChromeAvailable, resetChromeProbe, _validTimeoutMs } from '../src/ir/chrome-probe.mjs';

test('_validTimeoutMs: direct input/output table pinning the 0-vs-default boundary', () => {
  // Found by a third scoped re-review: the outcome-based integration
  // tests below (probing/exporting with a malformed env var) can't
  // distinguish `timeout: 0` from `timeout: <default>` when the real
  // command finishes quickly either way — both a working chrome
  // --version and a 0ms-vs-5000ms bound look identical from the
  // outcome. A direct table of this function's own input/output pairs
  // is what actually pins every boundary all three rounds fixed.
  const DEFAULT = 5000;
  const cases = [
    [undefined, DEFAULT], [null, DEFAULT], ['', DEFAULT], ['   ', DEFAULT], ['\t\n ', DEFAULT],
    ['0', 0], ['00', 0], [' 0 ', 0],
    ['-0', DEFAULT],
    ['-1', DEFAULT], ['-1.5', DEFAULT],
    ['oops', DEFAULT], ['NaN', DEFAULT], ['Infinity', DEFAULT], ['-Infinity', DEFAULT],
    ['1.5', DEFAULT], ['0.5', DEFAULT], ['1e-3', DEFAULT],
    ['1e400', DEFAULT], [String(Number.MAX_SAFE_INTEGER + 1), DEFAULT],
    ['1500', 1500], [' 250 ', 250], ['1e3', 1000],
  ];
  for (const [input, expected] of cases) {
    assert.equal(_validTimeoutMs(input, DEFAULT), expected, `input ${JSON.stringify(input)}`);
  }
});

test('probeChromeAvailable: finds a real Chrome on this machine (environment-dependent, skip if absent)', () => {
  resetChromeProbe();
  const r = probeChromeAvailable();
  // This test runs on the maintainer's own machine, which is confirmed
  // (this session) to have a real Chrome install — assert the REAL
  // contract shape either way rather than assuming ok:true, since CI
  // environments may genuinely lack Chrome.
  if (r.ok) {
    assert.equal(typeof r.chrome, 'string');
    assert.ok(r.chrome.length > 0);
  } else {
    assert.equal(typeof r.reason, 'string');
  }
});

test('probeChromeAvailable: result is cached — a second call does not re-probe', () => {
  resetChromeProbe();
  const a = probeChromeAvailable();
  const b = probeChromeAvailable();
  assert.equal(a, b, 'same object reference — proves no re-probe happened');
});

test('probeChromeAvailable: AGENTIC_SECURITY_CHROME_PATH override is honored when it points at a real, working binary', () => {
  resetChromeProbe();
  const real = probeChromeAvailable();
  if (!real.ok) return; // nothing real to point the override at on this machine
  resetChromeProbe();
  const prev = process.env.AGENTIC_SECURITY_CHROME_PATH;
  process.env.AGENTIC_SECURITY_CHROME_PATH = real.chrome;
  try {
    const r = probeChromeAvailable();
    assert.equal(r.ok, true);
    assert.equal(r.chrome, real.chrome);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PATH;
    else process.env.AGENTIC_SECURITY_CHROME_PATH = prev;
    resetChromeProbe();
  }
});

test('probeChromeAvailable: a bogus AGENTIC_SECURITY_CHROME_PATH degrades cleanly, never throws', () => {
  resetChromeProbe();
  const prev = process.env.AGENTIC_SECURITY_CHROME_PATH;
  process.env.AGENTIC_SECURITY_CHROME_PATH = '/definitely/not/a/real/binary/anywhere';
  try {
    const r = probeChromeAvailable();
    assert.equal(r.ok, false);
    assert.equal(typeof r.reason, 'string');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PATH;
    else process.env.AGENTIC_SECURITY_CHROME_PATH = prev;
    resetChromeProbe();
  }
});

// Shared by every malformed-timeout-env-var case below. Compared
// against a real baseline probe (env unset), not merely asserting "any
// well-shaped {ok:false}" — found by this fix's own scoped re-review:
// a bug that makes the probe wrongly report no-chrome-found on a
// machine with working Chrome IS a well-shaped {ok:false, reason:
// string}, so the weaker assertion passed with that exact bug present.
// A fresh module instance (cache-busted query string) is required
// because the timeout is computed once, at module load. Only
// meaningful when this machine actually has Chrome — with none, the
// baseline is itself {ok:false} and the comparison passes vacuously
// (mirrors the honest early-return the PATH-ordering test above uses
// for its own no-real-Chrome case).
async function _assertMalformedTimeoutDegradesToDefault(envValue) {
  resetChromeProbe();
  const baseline = probeChromeAvailable();
  resetChromeProbe();
  if (!baseline.ok) return;

  const prev = process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS;
  process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS = envValue;
  try {
    const mod = await import(`../src/ir/chrome-probe.mjs?bustcache=${Date.now()}-${Math.random()}`);
    mod.resetChromeProbe();
    const r = mod.probeChromeAvailable();
    assert.deepEqual(r, baseline);
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS;
    else process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS = prev;
    resetChromeProbe();
  }
}

test('probeChromeAvailable: a malformed (non-numeric) AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS degrades to the default instead of throwing', async () => {
  // Number('oops') is NaN, and NaN as spawnSync's `timeout` option throws
  // ERR_OUT_OF_RANGE synchronously — found by the final whole-branch
  // review. _tryBinary's own try/catch happened to swallow that throw,
  // but then misreported no-chrome-found even on a machine with a
  // genuinely working Chrome, since spawnSync throws for EVERY candidate.
  await _assertMalformedTimeoutDegradesToDefault('oops');
});

test('probeChromeAvailable: a blank AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS degrades to the default, not to a real 0 (no timeout)', async () => {
  // Number('') is 0, and a naive `n >= 0` guard let an empty-but-exported
  // env var through as a real `timeout: 0` — which spawnSync treats as
  // NO timeout at all, an unbounded-hang risk — found by a scoped
  // re-review of this file's first attempt at this guard.
  await _assertMalformedTimeoutDegradesToDefault('');
});

test('probeChromeAvailable: a fractional AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS degrades to the default instead of throwing', async () => {
  // Number.isFinite(1.5) is true, so a naive finite-number guard passed
  // a fractional value straight through to spawnSync's `timeout` option,
  // which requires a safe INTEGER and throws ERR_OUT_OF_RANGE for any
  // non-integer — found live by a second scoped re-review, reproducing
  // the exact original NaN-throw symptom for a different malformed
  // input.
  await _assertMalformedTimeoutDegradesToDefault('1.5');
});

test('probeChromeAvailable: prefers a known absolute install path over a same-named binary earlier on PATH', () => {
  resetChromeProbe();
  const real = probeChromeAvailable();
  if (!real.ok || !(real.chrome.includes('/') || real.chrome.includes('\\'))) {
    return; // no real absolute-path Chrome on this machine to compare against
  }
  resetChromeProbe();

  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-fake-chrome-'));
  const fakeBin = path.join(fakeDir, 'google-chrome-stable');
  fs.writeFileSync(fakeBin, '#!/bin/sh\necho "Chromium 1.0.0 (fake)"\nexit 0\n');
  fs.chmodSync(fakeBin, 0o755);

  const prevPath = process.env.PATH;
  process.env.PATH = `${fakeDir}${path.delimiter}${prevPath}`;
  try {
    const r = probeChromeAvailable();
    assert.equal(r.ok, true);
    assert.notEqual(r.chrome, fakeBin, 'must not select the PATH-planted binary over a known-good absolute path');
    assert.equal(r.chrome, real.chrome);
  } finally {
    process.env.PATH = prevPath;
    fs.rmSync(fakeDir, { recursive: true, force: true });
    resetChromeProbe();
  }
});
