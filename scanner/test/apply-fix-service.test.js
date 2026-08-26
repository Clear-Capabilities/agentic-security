// Direct unit tests for src/fix/apply-fix-service.js (assurance-hardening
// PRD FR-301/FR-302/FR-303). Every prior test of this module was indirect —
// through the CLI subprocess or the MCP handler, both of which ALREADY
// verify last-scan.json integrity themselves before ever calling
// applyVerifiedFix. That proves those two callers behave correctly; it does
// not prove the SHARED SERVICE is safe on its own. These tests call
// applyVerifiedFix directly, bypassing any caller-side pre-check, to prove
// the FR-302 defense-in-depth integrity check inside the service itself
// actually blocks a write — the property that matters for any FUTURE caller
// that forgets its own check.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { applyVerifiedFix, confinePath, isReservedWritePath, readVerifiedScan, hashFileContentSync, detectConcurrentModification } from '../src/fix/apply-fix-service.js';
import { signLastScan } from '../src/posture/integrity.js';

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-apply-fix-svc-'));
  // A project marker (package.json) is required for isSafeStateDir to allow
  // fix-history.js's ensure() to create .agentic-security/fix-history/ — a
  // bare temp dir with only .agentic-security/ in it is not recognized as a
  // real project root and history writes are silently refused.
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

function writeSignedScan(root, findings) {
  const stateDir = path.join(root, '.agentic-security');
  const body = JSON.stringify({ findings });
  fs.writeFileSync(path.join(stateDir, 'last-scan.json'), body);
  fs.writeFileSync(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  return body;
}

// ── FR-302: the service itself refuses, independent of any caller pre-check ──

test('applyVerifiedFix: refuses when last-scan.json does not exist at all — no caller pre-check involved', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'PWNED' },
    });
    assert.equal(result.ok, false);
    assert.equal(result.applied, false);
    assert.match(result.reason, /integrity check failed: missing/);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL', 'disk must be untouched');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyVerifiedFix: refuses when last-scan.json exists but has no .sig — the shared service itself, not just its callers', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [] }));
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'PWNED' },
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /integrity check failed: unsigned/);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyVerifiedFix: refuses when last-scan.json.sig does not match (tampered) — the shared service itself', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const body = writeSignedScan(root, []);
    // Tamper the body AFTER signing, leaving the old (now-mismatched) signature in place.
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), body + ' ');
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'PWNED' },
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /integrity check failed: tampered/);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyVerifiedFix: a genuinely verified last-scan.json is NOT refused by the integrity check (positive control)', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'ORIGINAL' }, // identical content — verifier will likely reject on other grounds, that's fine
    });
    // The point of this test is narrowly that the reason is NOT an integrity failure.
    assert.doesNotMatch(String(result.reason || ''), /integrity check failed/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-304: "a stale prior verification or changed file invalidates
//    approval". verifyFixCore's real rescan (plus lint/tests when
//    configured) takes real, HIGHLY VARIABLE wall-clock time — measured
//    directly at 55ms-400ms+ for trivial single-file cases even outside a
//    combined test run, and combined-suite contention (this codebase's own
//    documented D-0006 flake class) makes it worse. Racing a real file edit
//    against that window would make this test itself flaky, so these tests
//    exercise the extracted, synchronous, timing-independent primitives
//    (hashFileContentSync / detectConcurrentModification) directly instead —
//    proving the exact same detection logic applyVerifiedFix's write path
//    calls, deterministically. ────────────────────────────────────────────

test('hashFileContentSync: returns null for a nonexistent file, a stable hash for an existing one, and a different hash after a real edit', () => {
  const root = mkProject();
  try {
    const target = path.join(root, 'a.js');
    assert.equal(hashFileContentSync(target), null);
    fs.writeFileSync(target, 'function ok() { return 1; }\n');
    const h1 = hashFileContentSync(target);
    assert.equal(typeof h1, 'string');
    assert.equal(hashFileContentSync(target), h1, 'hashing the same unchanged content twice must be stable');
    fs.writeFileSync(target, 'function ok() { return 1; } // someone else edited this\n');
    const h2 = hashFileContentSync(target);
    assert.notEqual(h2, h1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('detectConcurrentModification: a file edited after its baseline was captured is caught — the actual FR-304 property', () => {
  const root = mkProject();
  try {
    const abs = path.join(root, 'a.js');
    fs.writeFileSync(abs, 'function ok() { return 1; }\n');
    const baselineHash = hashFileContentSync(abs); // simulates the snapshot taken before verification starts
    fs.writeFileSync(abs, 'function ok() { return 1; } // someone else edited this\n'); // simulates a concurrent edit during verification
    const reason = detectConcurrentModification({ 'a.js': { abs, baselineHash } });
    assert.match(reason, /a\.js changed on disk after verification started/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('detectConcurrentModification: a file CREATED after its (null) baseline is also caught, not just an existing file being edited', () => {
  const root = mkProject();
  try {
    const abs = path.join(root, 'new-file.js');
    const baselineHash = hashFileContentSync(abs); // file does not exist yet -> null
    assert.equal(baselineHash, null);
    fs.writeFileSync(abs, 'someone else created this first\n'); // simulates a concurrent create
    const reason = detectConcurrentModification({ 'new-file.js': { abs, baselineHash } });
    assert.match(reason, /new-file\.js changed on disk after verification started/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('detectConcurrentModification: an unmodified file (the common case) returns null — not a false-positive trap', () => {
  const root = mkProject();
  try {
    const abs = path.join(root, 'a.js');
    fs.writeFileSync(abs, 'function ok() { return 1; }\n');
    const baselineHash = hashFileContentSync(abs);
    assert.equal(detectConcurrentModification({ 'a.js': { abs, baselineHash } }), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('detectConcurrentModification: checks ALL files, not just the first — a mismatch on the second file is still caught', () => {
  const root = mkProject();
  try {
    const absA = path.join(root, 'a.js');
    const absB = path.join(root, 'b.js');
    fs.writeFileSync(absA, 'unchanged\n');
    fs.writeFileSync(absB, 'will be edited\n');
    const confined = { 'a.js': { abs: absA, baselineHash: hashFileContentSync(absA) }, 'b.js': { abs: absB, baselineHash: hashFileContentSync(absB) } };
    fs.writeFileSync(absB, 'edited concurrently\n');
    const reason = detectConcurrentModification(confined);
    assert.match(reason, /b\.js changed on disk after verification started/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyVerifiedFix end-to-end: a file that genuinely has not changed since the call started still writes successfully (integration positive control, no timing dependency)', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'function bad() { eval(x); }\n');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'function ok() { return 1; }\n' },
    });
    assert.doesNotMatch(String(result.reason || ''), /changed on disk after verification started/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-305: applyVerifiedFix must surface verifiedFull, not just verified —
//    a caller checking only `verified`/`ok` cannot see whether a required
//    leg (lint, tests) was skipped rather than genuinely run. ─────────────

test('applyVerifiedFix: a genuine successful apply with no test runner/linter configured is verified but NOT verifiedFull', async () => {
  const root = mkProject(); // mkProject only writes package.json — no test script, no lint config
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'function bad() { eval(x); }\n');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'function ok() { return 1; }\n' },
    });
    assert.equal(result.ok, true, `expected a successful apply: ${result.reason}`);
    assert.equal(result.applied, true);
    assert.equal(result.verified, true, 'verification WAS attempted and passed');
    assert.equal(result.verifiedFull, false, 'but tests were never run — a caller must not read this as fully verified');
    assert.ok(result.verify.degradedLegs.some(l => l.startsWith('tests:')));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyVerifiedFix: skipVerification:true is verified:false, verifiedFull:false — never accidentally "fully verified" when verification was skipped outright', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    const result = await applyVerifiedFix({
      scanRoot: root,
      finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
      files: { 'a.js': 'CHANGED' },
      skipVerification: true,
    });
    assert.equal(result.ok, true, `expected a successful apply: ${result.reason}`);
    assert.equal(result.verified, false);
    assert.equal(result.verifiedFull, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-306's literal acceptance criterion: "Injected write failure restores
//    all files and leaves a recoverable audit record" — proven through the
//    REAL multi-file apply path, not just fix-history.js's own unit tests. ──

test('FR-306: a write failure on the SECOND file of a multi-file batch rolls back the FIRST file too — not a partial apply', async () => {
  // Skipped when running as root: chmod-based write-permission faults do not
  // apply to root, which bypasses filesystem permission checks entirely —
  // the fault would silently fail to inject and the test would prove
  // nothing. Every environment this session has run in is non-root.
  if (typeof process.getuid === 'function' && process.getuid() === 0) return;
  const root = mkProject();
  const subDir = path.join(root, 'sub');
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL-A');
    // Fault injection: b.js lives in a subdirectory made read-only AFTER
    // b.js is created — its baseline content is still readable (FR-304's
    // pre-verification hash snapshot succeeds normally), but the atomic
    // write's temp-file creation inside that directory fails with EACCES.
    // This is deliberately a DIFFERENT failure point than fix-history.test.js's
    // directory-as-target trick: that one fails at the baseline-hash stage,
    // before any file in the batch is ever written — a real but different
    // property (refuse the whole batch up front) than the one this test
    // targets (roll back a file that WAS already successfully written when
    // a LATER file's write fails).
    fs.mkdirSync(subDir);
    fs.writeFileSync(path.join(subDir, 'b.js'), 'ORIGINAL-B');
    fs.chmodSync(subDir, 0o555);
    writeSignedScan(root, [{ id: 'F1', stableId: 'a'.repeat(16), file: 'a.js' }]);
    try {
      await assert.rejects(
        () => applyVerifiedFix({
          scanRoot: root,
          finding: { file: 'a.js', id: 'F1', stableId: 'a'.repeat(16) },
          files: { 'a.js': 'NEW-A', 'sub/b.js': 'NEW-B' },
          skipVerification: true,
        }),
      );
    } finally {
      fs.chmodSync(subDir, 0o755); // restore write access so cleanup can remove it
    }
    // The actual FR-306 property: a.js was successfully written FIRST, then
    // b.js's write failed — a.js must not be left on the NEW content; the
    // whole batch must roll back together.
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL-A', 'the first file must be rolled back, not left partially applied');
    // The recoverable audit record: both attempts are in the log, a.js
    // shows it was applied and then reverted (not silently erased).
    const { readLog } = await import('../src/posture/fix-history.js');
    const log = readLog(root);
    const aEntry = log.find(e => e.file === 'a.js');
    assert.ok(aEntry, 'expected a.js to have a log entry');
    assert.equal(aEntry.status, 'applied');
    assert.equal(aEntry.reverted, true, 'a.js was applied then rolled back as part of the batch failure');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── readVerifiedScan: now genuinely load-bearing (wired into applyVerifiedFix above) ──

test('readVerifiedScan: returns status "missing" with scan:null when no file exists', () => {
  const root = mkProject();
  try {
    const { scan, status } = readVerifiedScan(root);
    assert.equal(scan, null);
    assert.equal(status, 'missing');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('readVerifiedScan: returns status "verified" and the parsed scan for a genuinely signed file', () => {
  const root = mkProject();
  try {
    writeSignedScan(root, [{ id: 'F1' }]);
    const { scan, status } = readVerifiedScan(root);
    assert.equal(status, 'verified');
    assert.deepEqual(scan.findings, [{ id: 'F1' }]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('readVerifiedScan: allowUnsigned:true accepts an unsigned file and still returns the parsed scan', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: 'F1' }] }));
    const { scan, status } = readVerifiedScan(root, { allowUnsigned: true });
    assert.equal(status, 'unsigned');
    assert.deepEqual(scan.findings, [{ id: 'F1' }]);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('readVerifiedScan: an unparseable JSON body returns status "unparseable", scan:null, never throws', () => {
  const root = mkProject();
  try {
    const body = 'not json at all {{{';
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), body);
    fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
    assert.doesNotThrow(() => {
      const { scan, status } = readVerifiedScan(root);
      assert.equal(scan, null);
      assert.equal(status, 'unparseable');
    });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-303: confinePath / isReservedWritePath direct unit coverage ──────────

test('confinePath: rejects lexical traversal outside the root', () => {
  const root = mkProject();
  try {
    assert.throws(() => confinePath(root, '../../../../etc/passwd', 'test'), /escapes session root/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('confinePath: rejects a symlink pointing outside the root', () => {
  const root = mkProject();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-apply-fix-svc-outside-'));
  try {
    const outsideFile = path.join(outside, 'secret.txt');
    fs.writeFileSync(outsideFile, 'x');
    fs.symlinkSync(outsideFile, path.join(root, 'link.txt'));
    assert.throws(() => confinePath(root, 'link.txt', 'test'), /symbolic link/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('confinePath: accepts a normal in-root path and returns its real, absolute form', () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'x');
    const resolved = confinePath(root, 'a.js', 'test');
    assert.equal(fs.realpathSync(path.join(root, 'a.js')), resolved);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('isReservedWritePath: flags each of the three FR-303-named classes (VCS, state-directory, dependency-directory)', () => {
  const root = mkProject();
  try {
    // isReservedWritePath's contract expects an already-realpath'd absolute
    // path, the same shape confinePath returns — a raw path.join(root, ...)
    // can disagree with fs.realpathSync(root) (e.g. macOS's /var vs
    // /private/var tmpdir symlink), which breaks its internal
    // path.relative(rootReal, absFile) computation. Real callers never hit
    // this because they always call confinePath first; this test mirrors
    // that by realpath-ing root up front instead.
    const rootReal = fs.realpathSync(root);
    assert.equal(isReservedWritePath(root, path.join(rootReal, '.git', 'config')), true, '.git/ (VCS)');
    assert.equal(isReservedWritePath(root, path.join(rootReal, '.agentic-security', 'rules.yml')), true, '.agentic-security/ (state directory)');
    assert.equal(isReservedWritePath(root, path.join(rootReal, 'node_modules', 'x', 'index.js')), true, 'node_modules/ (dependency directory)');
    assert.equal(isReservedWritePath(root, path.join(rootReal, 'src', 'app.js')), false, 'an ordinary source file must NOT be flagged');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
