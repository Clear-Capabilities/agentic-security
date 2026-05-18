// Fix history — preview, apply, undo for auto-fixes.
//
// Every applied fix:
//   1. Saves the original file contents to .agentic-security/fix-history/<id>.bak
//   2. Records {findingId, file, originalSha256, appliedAt, ruleId} in
//      .agentic-security/fix-history/log.json
//
// `agentic-security undo` reverts the most recent applied fix (or `--all`
// to revert every fix in the log, in reverse order).

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

function historyDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'fix-history');
}
function logPath(scanRoot) { return path.join(historyDir(scanRoot), 'log.json'); }

function ensure(scanRoot) { fs.mkdirSync(historyDir(scanRoot), { recursive: true }); }

export function readLog(scanRoot) {
  const fp = logPath(scanRoot);
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return []; }
}
function writeLog(scanRoot, log) {
  ensure(scanRoot);
  fs.writeFileSync(logPath(scanRoot), JSON.stringify(log, null, 2));
}
function sha(s) { return crypto.createHash('sha256').update(s).digest('hex').slice(0, 16); }

// Build a unified-diff-ish preview between two strings, with line numbers.
// Not a real `diff -u`, but readable enough for the vibecoder use case.
export function preview(originalContent, newContent, file) {
  const a = originalContent.split('\n');
  const b = newContent.split('\n');
  const max = Math.max(a.length, b.length);
  const out = [`--- ${file} (before)`, `+++ ${file} (after)`];
  let firstDiff = -1, lastDiff = -1;
  for (let i = 0; i < max; i++) {
    if ((a[i] || '') !== (b[i] || '')) {
      if (firstDiff < 0) firstDiff = i;
      lastDiff = i;
    }
  }
  if (firstDiff < 0) { out.push('(no changes)'); return out.join('\n'); }
  const ctx = 3;
  const start = Math.max(0, firstDiff - ctx);
  const end = Math.min(max, lastDiff + ctx + 1);
  for (let i = start; i < end; i++) {
    const sa = a[i], sb = b[i];
    if (sa === sb) out.push(`  ${String(i + 1).padStart(4)}  ${sa ?? ''}`);
    else {
      if (sa !== undefined) out.push(`- ${String(i + 1).padStart(4)}  ${sa}`);
      if (sb !== undefined) out.push(`+ ${String(i + 1).padStart(4)}  ${sb}`);
    }
  }
  return out.join('\n');
}

// Apply a fix and record it in history. Two-phase commit (premortem P2-9):
//
//   1. Write the backup file + fsync.
//   2. Write the log with the entry marked status='pending' + fsync.
//   3. Write the new file content + fsync.
//   4. Update the log entry to status='applied' + fsync.
//
// If we crash between (1) and (3) — backup exists, log entry says 'pending',
// file is untouched. `recover()` rolls forward by deleting the pending entry.
// If we crash between (3) and (4) — backup exists, log entry says 'pending',
// file IS the new content. `recover()` checks file hash; if it matches newSha
// the entry is promoted to 'applied'; if it matches originalSha it's dropped.
//
// This guarantees the file is never modified without a corresponding
// recoverable log entry.
export async function applyFix({ scanRoot, file, originalContent, newContent, findingId, ruleId, vuln }) {
  ensure(scanRoot);
  const absFile = path.resolve(scanRoot, file);
  const id = `fix-${Date.now().toString(36)}-${sha(file + findingId).slice(0, 6)}`;
  const bakPath = path.join(historyDir(scanRoot), `${id}.bak`);
  // Phase 1: backup + fsync.
  await _writeAndSync(bakPath, originalContent);
  const entry = {
    id,
    findingId,
    ruleId: ruleId || null,
    vuln: vuln || null,
    file,
    backupPath: path.relative(scanRoot, bakPath),
    originalSha: sha(originalContent),
    newSha: sha(newContent),
    appliedAt: new Date().toISOString(),
    status: 'pending',
    reverted: false,
  };
  // Phase 2: log entry marked pending + fsync.
  const log = readLog(scanRoot);
  log.push(entry);
  await _writeLogAndSync(scanRoot, log);
  // Phase 3: write the new content to the target file + fsync.
  try {
    await _writeAndSync(absFile, newContent);
  } catch (e) {
    // File write failed — undo log entry, leave backup.
    entry.status = 'failed';
    entry.error = e.message;
    await _writeLogAndSync(scanRoot, log);
    throw e;
  }
  // Phase 4: promote to applied.
  entry.status = 'applied';
  await _writeLogAndSync(scanRoot, log);
  return entry;
}

async function _writeAndSync(fp, content) {
  await fsp.mkdir(path.dirname(fp), { recursive: true });
  const handle = await fsp.open(fp, 'w');
  try {
    await handle.writeFile(content);
    if (typeof handle.sync === 'function') await handle.sync();
  } finally {
    await handle.close();
  }
}

async function _writeLogAndSync(scanRoot, log) {
  ensure(scanRoot);
  const fp = logPath(scanRoot);
  const handle = await fsp.open(fp, 'w');
  try {
    await handle.writeFile(JSON.stringify(log, null, 2));
    if (typeof handle.sync === 'function') await handle.sync();
  } finally {
    await handle.close();
  }
}

// Recover from a crash mid-applyFix. Reads the log, examines any 'pending'
// entries, compares the file's current sha against entry.newSha / .originalSha,
// and either promotes to 'applied' or drops the entry. Returns the recovered
// entries.
export async function recover(scanRoot) {
  const log = readLog(scanRoot);
  const recovered = [];
  for (const e of log) {
    if (e.status !== 'pending') continue;
    const absFile = path.resolve(scanRoot, e.file);
    let curr;
    try { curr = await fsp.readFile(absFile, 'utf8'); }
    catch { e.status = 'failed'; e.error = 'file-missing'; recovered.push(e); continue; }
    const currSha = sha(curr);
    if (currSha === e.newSha) {
      e.status = 'applied';
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    } else if (currSha === e.originalSha) {
      e.status = 'failed';
      e.error = 'file-untouched-during-crash';
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    } else {
      e.status = 'failed';
      e.error = `file-content-mismatch-curr-sha=${currSha}`;
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    }
  }
  if (recovered.length) await _writeLogAndSync(scanRoot, log);
  return recovered;
}

// Revert the most recent un-reverted fix. Returns the entry or null.
export async function undoLast(scanRoot) {
  const log = readLog(scanRoot);
  for (let i = log.length - 1; i >= 0; i--) {
    if (!log[i].reverted) {
      const entry = log[i];
      const bak = path.resolve(scanRoot, entry.backupPath);
      const absFile = path.resolve(scanRoot, entry.file);
      if (!fs.existsSync(bak)) return { error: `backup missing: ${bak}` };
      const original = await fsp.readFile(bak, 'utf8');
      await fsp.writeFile(absFile, original);
      entry.reverted = true;
      entry.revertedAt = new Date().toISOString();
      writeLog(scanRoot, log);
      return entry;
    }
  }
  return null;
}

// Revert everything that hasn't been reverted, in reverse order.
export async function undoAll(scanRoot) {
  const reverted = [];
  let r;
  while ((r = await undoLast(scanRoot)) && !r.error) reverted.push(r);
  return reverted;
}

export function listHistory(scanRoot) { return readLog(scanRoot); }
