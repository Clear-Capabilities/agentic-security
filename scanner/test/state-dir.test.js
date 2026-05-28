// Regression test: prevent nested .agentic-security/ folders from being
// created inside subdirectories (e.g., migrations/, config/).
//
// User report: scanner created .agentic-security/ in a DB migrations folder,
// breaking the user's migration system. User uninstalled the plugin.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { resolveProjectRoot, stateDir, statePath, isSafeStateDir, ensureStateDir, safeWriteState } from '../src/posture/state-dir.js';

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-state-test-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"test","version":"1.0.0"}');
  fs.mkdirSync(path.join(root, 'migrations'));
  fs.writeFileSync(path.join(root, 'migrations', '001_init.sql'), '-- init');
  return root;
}

test('resolveProjectRoot prefers explicit scanRoot', () => {
  const tmp = _mkTmpProject();
  try {
    assert.equal(resolveProjectRoot(tmp), tmp);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('resolveProjectRoot walks upward from cwd to find project root', () => {
  const tmp = _mkTmpProject();
  const origCwd = process.cwd();
  try {
    process.chdir(path.join(tmp, 'migrations'));
    const resolved = resolveProjectRoot(null);
    // Should resolve to tmp (the parent with package.json), NOT migrations/
    assert.equal(fs.realpathSync(resolved), fs.realpathSync(tmp));
  } finally {
    process.chdir(origCwd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('stateDir always returns <projectRoot>/.agentic-security', () => {
  const tmp = _mkTmpProject();
  try {
    const dir = stateDir(tmp);
    assert.equal(dir, path.join(tmp, '.agentic-security'));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('isSafeStateDir requires a project marker in the parent', () => {
  const tmp = _mkTmpProject();
  try {
    assert.equal(isSafeStateDir(path.join(tmp, '.agentic-security')), true);
    assert.equal(isSafeStateDir(path.join(tmp, 'migrations', '.agentic-security')), false);
    assert.equal(isSafeStateDir('/tmp/random/.agentic-security'), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('safeWriteState refuses to write outside a project root', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-unsafe-'));
  try {
    const result = safeWriteState(path.join(tmp, '.agentic-security', 'foo.json'), '{}');
    assert.equal(result, false);
    assert.equal(fs.existsSync(path.join(tmp, '.agentic-security')), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('safeWriteState writes when parent has a project marker', () => {
  const tmp = _mkTmpProject();
  try {
    const result = safeWriteState(path.join(tmp, '.agentic-security', 'foo.json'), '{}');
    assert.equal(result, true);
    assert.equal(fs.existsSync(path.join(tmp, '.agentic-security', 'foo.json')), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('regression: cwd in migrations subdir does NOT create nested .agentic-security', () => {
  const tmp = _mkTmpProject();
  const origCwd = process.cwd();
  try {
    process.chdir(path.join(tmp, 'migrations'));
    // Invoke with no scanRoot, simulating an MCP tool or hook from a subdir
    const dir = ensureStateDir(null);
    // Must write to <tmp>/.agentic-security/, NOT <tmp>/migrations/.agentic-security/
    assert.ok(dir);
    assert.equal(fs.realpathSync(dir), fs.realpathSync(path.join(tmp, '.agentic-security')));
    assert.equal(fs.existsSync(path.join(tmp, 'migrations', '.agentic-security')), false,
      'nested .agentic-security/ folder should NOT be created in migrations/');
  } finally {
    process.chdir(origCwd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
