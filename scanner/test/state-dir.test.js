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

// A nested state directory inside an ALREADY-VALID state root must be writable.
//
// This was broken, silently, for as long as the guard existed: `isSafeStateDir`
// looked for a project marker in the immediate parent, and `.agentic-security`
// deliberately does not count as one — so `<project>/.agentic-security/llm-cache`
// was refused, and `safeWriteState` returned false without writing. The
// llm-validator's `writeCache` goes through that path, so the validator cache
// never persisted a single entry while a `validator-cache stats|gc` subcommand
// existed to manage it. Found by a positive-control test asserting a legitimately
// written cache entry round-trips.
test('nested state dirs inside a valid state root are writable', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nested-'));
  try {
    fs.writeFileSync(path.join(d, 'package.json'), '{}');
    for (const sub of ['llm-cache', 'fix-history', 'sbom-history']) {
      const nested = path.join(d, '.agentic-security', sub);
      assert.equal(isSafeStateDir(nested), true, `${sub} should be a safe state dir`);
      assert.equal(safeWriteState(path.join(nested, 'x.json'), '{}'), true,
        `${sub} write was refused`);
      assert.equal(fs.existsSync(path.join(nested, 'x.json')), true,
        `${sub} reported success but wrote nothing`);
    }
    // Deeper nesting too — the rule is "inside a valid state root", not "one level".
    const deep = path.join(d, '.agentic-security', 'a', 'b', 'c');
    assert.equal(safeWriteState(path.join(deep, 'y.json'), '{}'), true);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a nested state dir with NO project above it is still refused', () => {
  // The guard's actual purpose — stopping state folders appearing in unrelated
  // directories — must survive the fix.
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'bare-'));
  try {
    assert.equal(isSafeStateDir(path.join(bare, '.agentic-security', 'llm-cache')), false);
    assert.equal(safeWriteState(path.join(bare, '.agentic-security', 'llm-cache', 'x.json'), '{}'), false);
    assert.equal(isSafeStateDir(path.join(bare, 'somewhere', 'else')), false);
  } finally { fs.rmSync(bare, { recursive: true, force: true }); }
});
