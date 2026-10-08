// The verified-remediation lifecycle shared by the language fixers (Haskell, Nix).
//
// A fix is APPLIED only after every gate passes:
//   syntax    the patched file parses with no more errors than before
//   behavior  an optional caller-supplied check that nothing unrelated changed
//   rescan    the original finding is gone from a rescan of the patched tree AND nothing at medium or above
//             is new (a syntactically correct edit that the effective configuration shadows leaves the
//             finding in place, so it is blocked rather than called fixed)
//   compile   strictly opt-in; the default path never starts a compiler or evaluator
// Preview never writes. Apply writes a backup first and refuses a file that changed since planning.
// Undo restores the backup byte for byte.

import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { statePath } from '../posture/state-dir.js';
import { maybeEncryptForWrite, maybeDecryptForRead } from '../posture/encryption-provider.js';
import { recordExternalFix, markRevertedByBackup } from '../posture/fix-history.js';

export const RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });
const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);

export function unifiedDiff(file, a, b) {
  const x = a.split('\n'), y = b.split('\n'); const out = [`--- a/${file}`, `+++ b/${file}`];
  let i = 0; while (i < x.length && i < y.length && x[i] === y[i]) i++;
  let ea = x.length, eb = y.length; while (ea > i && eb > i && x[ea - 1] === y[eb - 1]) { ea--; eb--; }
  out.push(`@@ -${i + 1},${ea - i} +${i + 1},${eb - i} @@`);
  for (let k = i; k < ea; k++) out.push(`-${x[k]}`);
  for (let k = i; k < eb; k++) out.push(`+${y[k]}`);
  return out.join('\n');
}
const safeRel = (root, rel) => { const p = join(root, rel); if (!p.startsWith(join(root) + '/')) throw new Error(`path escapes the root: ${rel}`); return p; };

/** Save the pre-image of `rel` (customer source: it follows the encryption policy) and return its backup. Writes nothing to the target. */
function saveBackup(root, rel, before, after) {
  const target = safeRel(root, rel);
  const id = `${Date.now().toString(36)}-${randomBytes(5).toString('hex')}`;
  const dir = statePath(root, 'fix-backups', id);
  const disk = existsSync(target) ? readFileSync(target, 'utf8') : null;
  if (disk !== before) throw new Error('the file changed on disk since the fix was planned; refusing to overwrite');
  // A policy that REQUIRES encryption with no working provider refuses the fix before anything is written.
  const enc = maybeEncryptForWrite(root, 'fix-backups', before);
  if (!enc.ok) throw new Error(enc.reason);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'original'), enc.content);
  writeFileSync(join(dir, 'meta.json'), JSON.stringify({ file: rel, appliedAt: new Date().toISOString(), sizeBefore: before.length, sizeAfter: after.length }));
  return { id, dir, target };
}

export function writeWithBackup(root, rel, before, after) {
  const { id, dir, target } = saveBackup(root, rel, before, after);
  writeFileSync(target, after);
  return { id, dir };
}

/**
 * Apply several file edits as ONE unit. Nothing is written until every file has been checked (inside the root, unchanged
 * since planning) and every pre-image is backed up. If a write then fails, every file already written (and the one that
 * failed, which may be truncated) is put back, and the error says whether that rollback was complete.
 * @param {string} root
 * @param {Array<{file:string,before:string,after:string}>} edits
 * @param {{writeFile?:Function}} [hooks]  test seam for the file writer
 * @returns {{id:string, dir:string, members:Array<{id:string,dir:string,file:string}>}}
 */
export function writeManyWithBackup(root, edits, hooks = {}) {
  const write = hooks.writeFile || writeFileSync;
  const seen = new Set();
  for (const e of edits) { if (seen.has(e.file)) throw new Error(`the same file is edited twice in one fix: ${e.file}`); seen.add(e.file); safeRel(root, e.file); }
  const members = [];
  const cleanup = () => { for (const m of members) { try { rmSync(m.dir, { recursive: true, force: true }); } catch { /* best effort */ } } };
  try { for (const e of edits) { const b = saveBackup(root, e.file, e.before, e.after); members.push({ id: b.id, dir: b.dir, file: e.file, target: b.target, before: e.before, after: e.after }); } }
  catch (err) { cleanup(); throw new Error(`${err.message} (no file was written)`); }
  const written = [];
  for (const m of members) {
    written.push(m);
    try { write(m.target, m.after); } catch (err) {
      const failed = [];
      for (const w of written.slice().reverse()) { try { write(w.target, w.before); } catch { failed.push(w.file); } }
      if (!failed.length) cleanup();
      const e = new Error(failed.length
        ? `write to ${m.file} failed (${err.message}); ROLLBACK INCOMPLETE, restore these from the backups under .agentic-security/fix-backups: ${failed.join(', ')}`
        : `write to ${m.file} failed (${err.message}); every file in this fix was restored to its original content`);
      e.rolledBack = failed.length === 0; e.rollbackFailed = failed; e.failedFile = m.file;
      throw e;
    }
  }
  const groupId = `g${Date.now().toString(36)}-${randomBytes(5).toString('hex')}`;
  const dir = statePath(root, 'fix-backups', groupId);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'meta.json'), JSON.stringify({ file: members[0].file, group: members.map((m) => ({ id: m.id, file: m.file })), appliedAt: new Date().toISOString() }));
  return { id: groupId, dir, members: members.map((m) => ({ id: m.id, dir: m.dir, file: m.file })) };
}

/**
 * Undo a fix. A multi-file fix is restored as a unit: every pre-image is read and every target resolved before the first
 * write, and if a restore fails the files already restored are put back to the content they had, so a partial undo is
 * never left behind.
 */
export function undoFix(root, backupId, hooks = {}) {
  const write = hooks.writeFile || writeFileSync;
  const dir = statePath(root, 'fix-backups', backupId);
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  if (!Array.isArray(meta.group)) {
    const target = safeRel(root, meta.file);
    writeFileSync(target, maybeDecryptForRead(readFileSync(join(dir, 'original'), 'utf8')));
    try { markRevertedByBackup(root, backupId); } catch { /* history is best effort */ }
    return { ok: true, file: meta.file, files: [meta.file] };
  }
  const items = meta.group.map((m) => {
    const mdir = statePath(root, 'fix-backups', m.id);
    const md = JSON.parse(readFileSync(join(mdir, 'meta.json'), 'utf8'));
    return { file: md.file, target: safeRel(root, md.file), original: maybeDecryptForRead(readFileSync(join(mdir, 'original'), 'utf8')), id: m.id };
  });
  const current = items.map((it) => (existsSync(it.target) ? readFileSync(it.target, 'utf8') : null));
  const touched = [];
  for (let i = 0; i < items.length; i++) {
    touched.push(i);
    try { write(items[i].target, items[i].original); } catch (err) {
      const failed = [];
      for (const j of touched.slice().reverse()) { try { if (current[j] !== null) write(items[j].target, current[j]); } catch { failed.push(items[j].file); } }
      const e = new Error(failed.length
        ? `undo failed at ${items[i].file} (${err.message}); ROLLBACK INCOMPLETE for: ${failed.join(', ')}`
        : `undo failed at ${items[i].file} (${err.message}); no file was changed`);
      e.rolledBack = failed.length === 0; e.rollbackFailed = failed;
      throw e;
    }
  }
  for (const id of [backupId, ...items.map((it) => it.id)]) { try { markRevertedByBackup(root, id); } catch { /* history is best effort */ } }
  return { ok: true, file: items[0].file, files: items.map((it) => it.file) };
}

/**
 * @param {{plan: {file:string, before:string, after:string, label?:string}, files: Record<string,string>, matchKey: (f:object)=>string,
 *          finding: object, rescan: (files:object)=>Promise<object[]>, syntax: (plan)=>{ok:boolean, detail?:string},
 *          behaviorCheck?: Function, compile?: (patched)=>{ran:boolean, ok:boolean|null, detail:string}, requireCompile?: boolean,
 *          apply?: boolean, root?: string, extraWrites?: Array<{file:string,before:string,after:string}>}} o
 */
/** A repository-relative path that stays inside the root: not absolute, no `..` segment, no NUL, not empty. */
export function isRootRelativePath(rel) {
  if (typeof rel !== 'string' || !rel || rel.includes('\0')) return false;
  const norm = rel.replace(/\\/g, '/');
  if (norm.startsWith('/') || /^[A-Za-z]:\//.test(norm)) return false;
  return !norm.split('/').some((seg) => seg === '..');
}

export async function runFixLifecycle(o) {
  const { plan, files, finding } = o;
  const gates = {};
  // A patch may only touch a file inside the project: a target that escapes the root is refused before anything else runs.
  // A plan may carry `edits` (several files, one logical fix); a plan without them is the single edit of `plan.file`.
  const edits = Array.isArray(plan.edits) && plan.edits.length ? plan.edits : [{ file: plan.file, before: plan.before, after: plan.after }];
  const escaping = edits.filter((e) => !isRootRelativePath(e.file));
  gates.path = { ok: escaping.length === 0, detail: edits.map((e) => e.file).join(', ') };
  if (!gates.path.ok) return { status: 'blocked', applied: false, reason: `path-escape: ${escaping.map((e) => String(e.file).slice(0, 120)).join(', ')} is outside the project root`, plan, gates, label: plan.label };
  gates.syntax = o.syntax(plan);
  const patched = { ...files };
  for (const e of edits) patched[e.file] = e.after;
  const blocked = (why) => ({ status: 'blocked', applied: false, reason: why, plan, gates, label: plan.label });
  if (!gates.syntax.ok) return blocked(`syntax: ${gates.syntax.detail}`);
  if (o.behaviorCheck) { gates.behavior = o.behaviorCheck(plan); if (gates.behavior && gates.behavior.ok === false) return blocked(`behavior: ${gates.behavior.detail || 'unrelated behavior change'}`); }
  let before, after;
  try { before = await o.rescan(files); after = await o.rescan(patched); } catch (e) { return blocked(`rescan failed: ${e.message}`); }
  const key = o.matchKey;
  const b = new Map(), a = new Map();
  for (const f of before) bump(b, key(f));
  for (const f of after) bump(a, key(f));
  const k = key(finding);
  const gone = (a.get(k) || 0) < (b.get(k) || 0);
  const added = after.filter((f) => RANK[f.severity] >= RANK.medium && (a.get(key(f)) || 0) > (b.get(key(f)) || 0));
  gates.rescan = { ok: gone && added.length === 0, originalGone: gone, newMediumOrHigher: [...new Set(added.map((f) => `${f.cwe || f.vuln}@${f.file}:${f.line}`))] };
  if (!gone) return blocked('the original finding is still reported after the patch');
  if (added.length) return blocked(`the patch introduces ${added.length} new medium-or-higher finding(s)`);
  // Optional effective-configuration gate: the rescan above only proves a finding stopped being REPORTED, which a patch that
  // turns the option into a module-system conflict also achieves. The check says whether the option now HAS the intended value.
  if (o.effectiveCheck) {
    gates.effective = o.effectiveCheck(plan, patched, files) || { ok: false, detail: 'no effective-configuration result' };
    if (gates.effective.ok === false) return blocked(`effective: ${gates.effective.detail}`);
  }
  // Optional controlled-witness gate (X-009): the hook returns judgeFixWitness(before, after). A patch that STILL
  // reproduces the effect is blocked; a witness that could not be judged (unsupported, invalid, unavailable) verifies
  // nothing and, unless `requireWitness` is set, does not block (it is recorded as not-verified).
  if (o.witness) {
    gates.witness = o.witness(plan, files, patched) || { ok: false, verified: false, reason: 'no witness result' };
    if (gates.witness.stillReproduces) return blocked(`witness: ${gates.witness.reason}`);
    if (o.requireWitness && !gates.witness.verified) return blocked(`witness verification required but ${gates.witness.reason}`);
  }
  gates.compile = o.compile ? o.compile(patched) : { ran: false, ok: null, detail: 'not requested (default static scans never start a compiler or evaluator)' };
  if (gates.compile.ran && !gates.compile.ok) return blocked(`compile: ${gates.compile.detail}`);
  if (o.requireCompile && !gates.compile.ran) return blocked(`compile verification required but ${gates.compile.detail}`);
  const verified = { syntax: true, rescan: true, compile: gates.compile.ran ? 'passed' : 'not-run', witness: gates.witness ? (gates.witness.verified ? 'passed' : 'not-verified') : 'not-run' };
  const res = { status: 'verified', applied: false, plan, gates, label: plan.label, verified, preview: edits.map((e) => unifiedDiff(e.file, e.before, e.after)).join('\n'), files: edits.map((e) => e.file) };
  if (o.apply) {
    if (!o.root) return blocked('apply requires a root directory');
    const base = { scanRoot: o.root, findingId: finding.id || `${finding.file}:${finding.line}`, ruleId: finding.rule || null, vuln: finding.vuln || null, stableId: finding.stableId || null, fixLabel: plan.label || null, verification: verified, findingProvenance: finding.findingProvenance || null };
    if (edits.length === 1) {
      res.backup = writeWithBackup(o.root, plan.file, plan.before, plan.after);
      res.applied = true; res.status = 'applied';
      // One ledger: the same fix-history `agentic-security undo` reads, with the tier and the gates that passed.
      try { res.history = await recordExternalFix({ ...base, file: plan.file, originalContent: plan.before, newContent: plan.after, backup: res.backup }); } catch { res.history = null; }
    } else {
      try { res.backup = writeManyWithBackup(o.root, edits, { writeFile: o.writeFile }); } catch (err) {
        return { ...blocked(`apply failed, nothing was left changed: ${err.message}`), rolledBack: err.rolledBack !== false, rollbackFailed: err.rollbackFailed || [] };
      }
      res.applied = true; res.status = 'applied';
      // One ledger entry per touched file, all carrying the group id so `undo` reverts them together.
      res.history = [];
      for (let i = 0; i < edits.length; i++) {
        try { res.history.push(await recordExternalFix({ ...base, file: edits[i].file, originalContent: edits[i].before, newContent: edits[i].after, backup: res.backup.members[i], languageGroupId: res.backup.id })); } catch { res.history.push(null); }
      }
    }
  }
  return res;
}
