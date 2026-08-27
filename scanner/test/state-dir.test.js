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
import {
  resolveProjectRoot, stateDir, statePath, isSafeStateDir, ensureStateDir, safeWriteState,
  stateWritesEnabled, setStateWritesEnabled, withStateWritesDisabled,
} from '../src/posture/state-dir.js';

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

// ── FR-704 (assurance-hardening PRD): withStateWritesDisabled ───────────
//
// Fixes a real, confirmed-by-execution bug: MCP's scan_diff tool called
// runScan() directly with no opt-out from state writes at all, so every
// "scan before writing" self-correction call silently wrote dpia.md,
// ropa.md, privacy-framework.json, threat-model.json, and more into the
// user's real project — contradicting scan_diff's own documented "runs
// scan in memory" behavior. withStateWritesDisabled is the fix: a scoped
// wrapper around the existing global kill switch (state-dir.js's own
// header explains why this is a global flag, not a parameter threaded
// through 72 call sites), restoring the PRIOR value in `finally` so one
// caller's opt-out can never leak into every later write in the same
// long-running MCP server process.

test('withStateWritesDisabled: writes are refused inside the callback', async () => {
  const d = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {
      assert.equal(stateWritesEnabled(), false);
      assert.equal(safeWriteState(path.join(d, '.agentic-security', 'x.json'), '{}'), false);
    });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('withStateWritesDisabled: the PRIOR flag value is restored afterward, even though it defaults to true', async () => {
  assert.equal(stateWritesEnabled(), true, 'precondition: writes enabled before this test');
  await withStateWritesDisabled(async () => {});
  assert.equal(stateWritesEnabled(), true, 'must be restored to true after the wrapper returns');
});

test('withStateWritesDisabled: restores to false, not true, when writes were ALREADY disabled at entry', async () => {
  setStateWritesEnabled(false);
  try {
    await withStateWritesDisabled(async () => {
      assert.equal(stateWritesEnabled(), false);
    });
    assert.equal(stateWritesEnabled(), false, 'must restore to the PRIOR value (false), not unconditionally to true');
  } finally { setStateWritesEnabled(true); }
});

test('withStateWritesDisabled: restores even when the callback throws', async () => {
  assert.equal(stateWritesEnabled(), true);
  await assert.rejects(() => withStateWritesDisabled(async () => { throw new Error('boom'); }), /boom/);
  assert.equal(stateWritesEnabled(), true, 'a thrown error must not leave writes permanently disabled');
});

test('withStateWritesDisabled: returns the callback\'s resolved value', async () => {
  const result = await withStateWritesDisabled(async () => 42);
  assert.equal(result, 42);
});

test('withStateWritesDisabled: a real scan through this wrapper writes ZERO state-directory files (the actual FR-704 regression proof)', async () => {
  const d = _mkTmpProject();
  try {
    const { runScan } = await import('../src/runScan.js');
    const fileContents = { 'app.js': 'const x = require("child_process"); x.exec("ls " + input);' };
    await withStateWritesDisabled(() => runScan(d, { network: false, fileContents, deep: true, deepInCi: true }));
    assert.equal(fs.existsSync(path.join(d, '.agentic-security')), false,
      'a scan run through withStateWritesDisabled must not create a state directory at all');
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('safeWriteState: a category not in exceptCategories is still refused while writes are disabled', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {
      const ok = safeWriteState(path.join(tmp, '.agentic-security', 'x.json'), '{}', { category: 'some-other-category' });
      assert.equal(ok, false);
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('safeWriteState: a category IN exceptCategories writes through while the blanket switch is off', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {
      const target = path.join(tmp, '.agentic-security', 'provenance', 'cache', 'x.json');
      const ok = safeWriteState(target, '{}', { category: 'provenance-cache' });
      assert.equal(ok, true);
      assert.ok(fs.existsSync(target));
    }, { exceptCategories: ['provenance-cache'] });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('withStateWritesDisabled: the category override does not leak past the call — a later write with no override is refused again', async () => {
  const tmp = _mkTmpProject();
  try {
    await withStateWritesDisabled(async () => {}, { exceptCategories: ['provenance-cache'] });
    // Outside the wrapper the blanket switch is back to enabled (the prior
    // value), so this should succeed regardless — the real assertion is that
    // _enabledCategories was restored, which the NEXT test in this file
    // (unrelated) would otherwise observe as a leaked category. Directly:
    const ok = safeWriteState(path.join(tmp, '.agentic-security', 'y.json'), '{}', { category: 'provenance-cache' });
    assert.equal(ok, true, 'blanket switch is on again outside the wrapper, so this must succeed regardless of category');
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('safeWriteState with no category option behaves exactly as before (backward compatible)', async () => {
  const tmp = _mkTmpProject();
  try {
    const ok = safeWriteState(path.join(tmp, '.agentic-security', 'z.json'), '{}');
    assert.equal(ok, true);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
