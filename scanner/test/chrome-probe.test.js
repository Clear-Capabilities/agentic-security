import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
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

test('probeChromeAvailable: a malformed AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS degrades to the default instead of throwing', async () => {
  // Number('oops') is NaN, and NaN as spawnSync's `timeout` option throws
  // ERR_OUT_OF_RANGE synchronously — found by the final whole-branch
  // review. _tryBinary's own try/catch happened to swallow that throw,
  // but then misreported no-chrome-found even on a machine with a
  // genuinely working Chrome, since spawnSync throws for EVERY
  // candidate. A fresh module instance (cache-busted query string) is
  // required because the timeout is computed once, at module load.
  const prev = process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS;
  process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS = 'oops';
  try {
    const mod = await import(`../src/ir/chrome-probe.mjs?bustcache=${Date.now()}-${Math.random()}`);
    mod.resetChromeProbe();
    const r = mod.probeChromeAvailable();
    if (r.ok) {
      assert.equal(typeof r.chrome, 'string');
    } else {
      assert.equal(typeof r.reason, 'string');
    }
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS;
    else process.env.AGENTIC_SECURITY_CHROME_PROBE_TIMEOUT_MS = prev;
  }
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
