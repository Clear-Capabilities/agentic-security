import { test, describe } from 'node:test';
import assert from 'node:assert';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { detectBackend, resetCapabilityCache } from '../src/sandbox/capabilities.js';
import { runDisabled } from '../src/sandbox/backend-disabled.js';

describe('capability detection', () => {
  test('returns one of the three known backends', () => {
    resetCapabilityCache();
    const b = detectBackend();
    assert.ok(['userspace', 'namespace', 'disabled'].includes(b), `unexpected backend: ${b}`);
  });

  test('force selects a backend without probing', () => {
    resetCapabilityCache();
    assert.equal(detectBackend({ force: 'disabled' }), 'disabled');
  });
});

describe('fail-closed contract', () => {
  test('the disabled backend refuses to execute and never reports success', () => {
    const r = runDisabled(['/bin/echo', 'should-not-run'], {});
    assert.equal(r.status, 'disabled');
    assert.equal(r.exitCode, null);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /no confinement primitive/i);
  });

  test('the disabled backend does NOT execute the command it was given', () => {
    // Proof by side effect: if it ran, the file would exist.
    const marker = path.join(os.tmpdir(), `sbx-disabled-${process.pid}.marker`);
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    runDisabled(['/bin/sh', '-c', `touch ${marker}`], {});
    assert.equal(fs.existsSync(marker), false, 'disabled backend executed the command — fail-closed violated');
  });
});
