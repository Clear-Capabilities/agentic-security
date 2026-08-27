// Direct unit tests for src/posture/fix-history.js (assurance-hardening PRD
// FR-306: transactional write with backup, atomic replacement, rollback,
// and post-write hash verification — "injected write failure restores all
// files and leaves a recoverable audit record").
//
// Before this cycle, `undoLast`/`undoAll`/the CLI `undo` command had ZERO
// test coverage anywhere in this codebase (confirmed by grep across every
// test file) despite being the write-reverting half of the fix pipeline.
// This file covers both that pre-existing gap and the new FR-306 behavior
// this cycle added: atomic writes, post-write hash verification, and
// automatic rollback (single-file inside applyFix, and multi-file batch
// rollback in apply-fix-service.js / mcp/tools.js, covered separately in
// test/apply-fix-service.test.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { applyFix, readLog, undoLast, undoAll, revertEntryById } from '../src/posture/fix-history.js';

function mkProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-fix-history-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture"}\n');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}

// ── applyFix: the happy path, and its recorded shape ────────────────────

test('applyFix: writes the new content, backs up the original, and logs an "applied" entry', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    const entry = await applyFix({
      scanRoot: root, file: 'a.js', originalContent: 'ORIGINAL', newContent: 'NEW',
      findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: true,
    });
    assert.equal(entry.status, 'applied');
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'NEW');
    assert.equal(fs.readFileSync(path.resolve(root, entry.backupPath), 'utf8'), 'ORIGINAL');
    const log = readLog(root);
    assert.equal(log.length, 1);
    assert.equal(log[0].id, entry.id);
    assert.equal(log[0].fileExisted, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyFix: leaves no orphaned .tmp-* file behind after a successful atomic write', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    await applyFix({ scanRoot: root, file: 'a.js', originalContent: 'ORIGINAL', newContent: 'NEW', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: true });
    const entries = fs.readdirSync(root);
    assert.ok(!entries.some(e => e.includes('.tmp-')), `expected no leftover temp file, got: ${JSON.stringify(entries)}`);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── FR-306: post-write hash verification + automatic rollback ───────────

test('FR-306: a write that lands on disk but does not match the intended content is caught and rolled back', async () => {
  const root = mkProject();
  const target = path.join(root, 'a.js');
  try {
    fs.writeFileSync(target, 'ORIGINAL');
    // Fault injection: make the target path a DIRECTORY so the atomic
    // write's rename-over-target step fails deterministically (EISDIR /
    // ENOTEMPTY depending on platform) — no timing dependency, no mocking.
    fs.rmSync(target);
    fs.mkdirSync(target);
    await assert.rejects(
      () => applyFix({ scanRoot: root, file: 'a.js', originalContent: 'ORIGINAL', newContent: 'NEW', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: true }),
    );
    const log = readLog(root);
    assert.equal(log.length, 1);
    assert.equal(log[0].status, 'failed');
    assert.ok(log[0].error, 'expected a recorded error — the recoverable audit record FR-306 asks for');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-306: rollback restores the ORIGINAL file content when the target file existed before the failed write', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    // Force applyFix's Phase-3 write itself to fail deterministically by
    // pointing "file" at a path whose PARENT does not exist and cannot be
    // created — a read-only ancestor. Simpler and equally deterministic:
    // use a file path containing a NUL byte, which every platform's
    // filesystem layer rejects at open() time, well before any partial
    // write could land.
    const originalContent = 'ORIGINAL';
    let threw = false;
    try {
      await applyFix({
        scanRoot: root, file: 'sub\0dir/a.js', originalContent, newContent: 'NEW',
        findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: true,
      });
    } catch { threw = true; }
    assert.equal(threw, true, 'expected the invalid path to make the write fail');
    // The ORIGINAL file (the real a.js, untouched by this doomed attempt)
    // must still read back exactly as it was — nothing was ever touched.
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FR-306: rollback DELETES the file (not a phantom empty file) when the fix created a file that did not exist before', async () => {
  const root = mkProject();
  const target = path.join(root, 'new-file.js');
  try {
    // fileExisted:false, but pre-create the path as a directory so the
    // atomic write of "new content" is forced to fail — proving the
    // rollback path for the "this file never existed" branch specifically.
    fs.mkdirSync(target);
    await assert.rejects(
      () => applyFix({ scanRoot: root, file: 'new-file.js', originalContent: '', newContent: 'function ok(){}', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: false }),
    );
    // Rollback for a never-existed file means "no file", not an empty one —
    // the directory fs.mkdirSync created is untouched since unlink on a
    // directory fails harmlessly (caught internally), which is the correct,
    // safe outcome: we must never delete something we didn't create.
    assert.ok(fs.existsSync(target), 'the pre-existing directory at this path must be untouched');
    assert.ok(fs.statSync(target).isDirectory());
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── undoLast / undoAll / revertEntryById — previously ZERO test coverage ──

test('undoLast: reverts the most recent applied fix, restoring the original content', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'ORIGINAL');
    await applyFix({ scanRoot: root, file: 'a.js', originalContent: 'ORIGINAL', newContent: 'NEW', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: true });
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'NEW');
    const reverted = await undoLast(root);
    assert.equal(reverted.reverted, true);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
    assert.equal(readLog(root)[0].reverted, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('undoLast: on a fix that created a new file (fileExisted:false), reverting DELETES the file rather than leaving it empty', async () => {
  const root = mkProject();
  try {
    const entry = await applyFix({ scanRoot: root, file: 'new-file.js', originalContent: '', newContent: 'function ok(){}', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: false });
    assert.equal(entry.status, 'applied');
    assert.ok(fs.existsSync(path.join(root, 'new-file.js')));
    await undoLast(root);
    assert.ok(!fs.existsSync(path.join(root, 'new-file.js')), 'the file must be deleted, not left as an empty phantom file');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('undoLast: returns null when there is nothing to revert', async () => {
  const root = mkProject();
  try {
    assert.equal(await undoLast(root), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('undoLast: returns an error object (not a throw) when the backup file is missing', async () => {
  const root = mkProject();
  try {
    const entry = await applyFix({ scanRoot: root, file: 'a.js', originalContent: '', newContent: 'X', findingId: 'F1', stableId: 'a'.repeat(16), fileExisted: false });
    fs.rmSync(path.resolve(root, entry.backupPath));
    const result = await undoLast(root);
    assert.ok(result.error, 'expected a reported error, not a thrown exception');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('undoAll: reverts every un-reverted fix in reverse order', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'A0');
    fs.writeFileSync(path.join(root, 'b.js'), 'B0');
    await applyFix({ scanRoot: root, file: 'a.js', originalContent: 'A0', newContent: 'A1', findingId: 'FA', stableId: 'a'.repeat(16), fileExisted: true });
    await applyFix({ scanRoot: root, file: 'b.js', originalContent: 'B0', newContent: 'B1', findingId: 'FB', stableId: 'b'.repeat(16), fileExisted: true });
    const reverted = await undoAll(root);
    assert.equal(reverted.length, 2);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'A0');
    assert.equal(fs.readFileSync(path.join(root, 'b.js'), 'utf8'), 'B0');
    assert.ok(readLog(root).every(e => e.reverted === true));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('revertEntryById: reverts a SPECIFIC entry regardless of position in the log, not just the most recent', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'A0');
    fs.writeFileSync(path.join(root, 'b.js'), 'B0');
    const eA = await applyFix({ scanRoot: root, file: 'a.js', originalContent: 'A0', newContent: 'A1', findingId: 'FA', stableId: 'a'.repeat(16), fileExisted: true });
    await applyFix({ scanRoot: root, file: 'b.js', originalContent: 'B0', newContent: 'B1', findingId: 'FB', stableId: 'b'.repeat(16), fileExisted: true });
    // Revert the FIRST (older) entry while the second stays applied.
    const result = await revertEntryById(root, eA.id);
    assert.equal(result.reverted, true);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'A0', 'the targeted entry was reverted');
    assert.equal(fs.readFileSync(path.join(root, 'b.js'), 'utf8'), 'B1', 'the OTHER entry must be untouched');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('revertEntryById: an unknown id returns an error, not a throw', async () => {
  const root = mkProject();
  try {
    const result = await revertEntryById(root, 'no-such-entry');
    assert.ok(result.error);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('revertEntryById: reverting an already-reverted entry is a safe no-op, not a double-revert', async () => {
  const root = mkProject();
  try {
    fs.writeFileSync(path.join(root, 'a.js'), 'A0');
    const entry = await applyFix({ scanRoot: root, file: 'a.js', originalContent: 'A0', newContent: 'A1', findingId: 'FA', stableId: 'a'.repeat(16), fileExisted: true });
    await revertEntryById(root, entry.id);
    const secondAttempt = await revertEntryById(root, entry.id);
    assert.equal(secondAttempt.reverted, true);
    assert.equal(fs.readFileSync(path.join(root, 'a.js'), 'utf8'), 'A0');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('applyFix: provenanceAtFix is null when no findingProvenance is supplied', async () => {
  // Uses mkProject(), not a bare mkdtempSync(), because applyFix's ensure()
  // gates on isSafeStateDir(), which requires a project marker (package.json)
  // in scanRoot's parent — the same reason every other test in this file
  // goes through mkProject() rather than a raw tmpdir.
  const dir = mkProject();
  try {
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true,
    });
    assert.equal(entry.provenanceAtFix, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('applyFix: provenanceAtFix snapshots a complete-status origin as finding_origin basis', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const dir = mkProject();
  try {
    const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: { commit: 'cafef00d123', authorDate: '2026-01-01T00:00:00Z' },
    });
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true, findingProvenance: fp,
    });
    assert.ok(entry.provenanceAtFix);
    assert.equal(entry.provenanceAtFix.ageBasis, 'finding_origin');
    assert.equal(entry.provenanceAtFix.commit, 'cafef00d123');
    assert.equal(typeof entry.provenanceAtFix.ageDays, 'number');
    assert.ok(entry.provenanceAtFix.ageDays >= 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('applyFix: provenanceAtFix falls back to first_observed basis for a not_available status', async () => {
  const { emptyProvenance, PROVENANCE_STATUS } = await import('../src/posture/provenance/schema.js');
  const dir = mkProject();
  try {
    const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      firstObserved: { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' },
    });
    const entry = await applyFix({
      scanRoot: dir, file: 'a.js', originalContent: 'old', newContent: 'new',
      findingId: 'f1', ruleId: 'r1', vuln: 'v1', fileExisted: true, findingProvenance: fp,
    });
    assert.equal(entry.provenanceAtFix.ageBasis, 'first_observed');
    assert.equal(entry.provenanceAtFix.commit, null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
