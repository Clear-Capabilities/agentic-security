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

import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
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

export function writeWithBackup(root, rel, before, after) {
  const target = safeRel(root, rel);
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const dir = statePath(root, 'fix-backups', id);
  const disk = existsSync(target) ? readFileSync(target, 'utf8') : null;
  if (disk !== before) throw new Error('the file changed on disk since the fix was planned; refusing to overwrite');
  // The pre-image is customer source: it follows the project's encryption policy for confidential state, and a policy
  // that REQUIRES encryption with no working provider refuses the fix before anything is written.
  const enc = maybeEncryptForWrite(root, 'fix-backups', before);
  if (!enc.ok) throw new Error(enc.reason);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'original'), enc.content);
  writeFileSync(join(dir, 'meta.json'), JSON.stringify({ file: rel, appliedAt: new Date().toISOString(), sizeBefore: before.length, sizeAfter: after.length }));
  writeFileSync(target, after);
  return { id, dir };
}

export function undoFix(root, backupId) {
  const _afterUndo = () => { try { markRevertedByBackup(root, backupId); } catch { /* history is best effort */ } };
  const dir = statePath(root, 'fix-backups', backupId);
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  const target = safeRel(root, meta.file);
  writeFileSync(target, maybeDecryptForRead(readFileSync(join(dir, 'original'), 'utf8')));
  _afterUndo();
  return { ok: true, file: meta.file };
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
  gates.path = { ok: isRootRelativePath(plan.file), detail: plan.file };
  if (!gates.path.ok) return { status: 'blocked', applied: false, reason: `path-escape: ${String(plan.file).slice(0, 120)} is outside the project root`, plan, gates, label: plan.label };
  gates.syntax = o.syntax(plan);
  const patched = { ...files, [plan.file]: plan.after };
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
  const res = { status: 'verified', applied: false, plan, gates, label: plan.label, verified, preview: unifiedDiff(plan.file, plan.before, plan.after) };
  if (o.apply) {
    if (!o.root) return blocked('apply requires a root directory');
    res.backup = writeWithBackup(o.root, plan.file, plan.before, plan.after);
    res.applied = true; res.status = 'applied';
    // One ledger: the same fix-history `agentic-security undo` reads, with the tier and the gates that passed.
    try {
      res.history = await recordExternalFix({ scanRoot: o.root, file: plan.file, originalContent: plan.before, newContent: plan.after, findingId: finding.id || `${finding.file}:${finding.line}`, ruleId: finding.rule || null, vuln: finding.vuln || null, stableId: finding.stableId || null, fixLabel: plan.label || null, verification: verified, backup: res.backup, findingProvenance: finding.findingProvenance || null });
    } catch { res.history = null; }
  }
  return res;
}
