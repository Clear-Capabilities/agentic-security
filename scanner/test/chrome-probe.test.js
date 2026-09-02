import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probeChromeAvailable, resetChromeProbe } from '../src/ir/chrome-probe.mjs';

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
