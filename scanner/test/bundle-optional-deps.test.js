// The built bundle must start on a machine that does not have the optional packages installed.
// An external package that is imported statically at the top of the bundle crashes every command
// with ERR_MODULE_NOT_FOUND (this broke the posture, labs and compliance "no prior scan" tests and the
// packed-package test in one run). Optional packages are loaded at first use through createRequire.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BUNDLE = path.join(HERE, '..', 'dist', 'agentic-security.mjs');
const OPTIONAL = ['z3-solver'];

test('bundle-optional-deps: no optional package is imported statically by the bundle', () => {
  const text = fs.readFileSync(BUNDLE, 'utf8');
  for (const pkg of OPTIONAL) {
    const q = pkg.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
    const staticImport = new RegExp(`(?:^|[;}\\n])\\s*import\\s*(?:[^;'"()]*?\\bfrom\\s*)?["']${q}["']`);
    assert.ok(!staticImport.test(text), `${pkg} is imported statically at the top of the bundle; load it with createRequire at first use`);
  }
});

test('bundle-optional-deps: the bundle starts and answers a command that needs no scan', async () => {
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync(process.execPath, [BUNDLE, 'version'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(r.status, 0, r.stderr);
});
