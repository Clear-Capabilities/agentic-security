// Project context for Haskell and Nix when a surface scans only part of a project (X-014).
//
// The MCP `scan_diff` / `verify_fix` / `synthesize_fix` tools and the LSP on-save scan hand the engine ONE file (or a
// few). For Haskell and Nix that is not enough to be right: a taint flow crosses modules, and an effective NixOS value
// is decided by the modules a configuration imports. So these surfaces add the import closure of the file(s) as
// context, plus the manifests, read from disk, bounded in files and bytes. Findings are still reported only for the
// files the caller asked about. Nothing here writes, executes or fetches anything.

import fs from 'node:fs';
import path from 'node:path';
import { STATE_DIR_NAME } from '../posture/state-dir.js';
import { isLanguageSource, isLanguageManifest, isLanguageExcludedPath, buildImportGraph, importClosure } from './discovery.js';
import { planHaskellFix, validateHaskellFix, unifiedDiff as hsDiff } from './haskell-fix.js';
import { planNixFix, validateNixFix, planNixUpgrade } from './nix-fix.js';
import { planHaskellUpgrade, unifiedDiff as _hsDiff } from './haskell-fix.js';
import { writeWithBackup } from './fix-lifecycle.js';
import { recordExternalFix } from '../posture/fix-history.js';

export const CONTEXT_BUDGETS = Object.freeze({ maxFiles: 600, maxBytes: 4 * 1024 * 1024, maxFileBytes: 400_000, maxDepth: 12 });
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', 'dist-newstyle', '.stack-work', '.cabal-sandbox', '.direnv', 'result', STATE_DIR_NAME]);

const norm = (p) => String(p).split(path.sep).join('/');
export const isLanguagePath = (rel) => /\.(?:l?hs|hs-boot|hsc|nix)$/i.test(rel);

/** Reads every Haskell/Nix source and manifest under `root`, bounded. Returns {files, manifests, truncated}. */
export function loadLanguageProject(root, budgets = {}) {
  const b = { ...CONTEXT_BUDGETS, ...budgets };
  const files = {}; const manifests = {};
  let count = 0; let bytes = 0; let truncated = false;
  const walk = (dir, depth) => {
    if (truncated || depth > b.maxDepth) { if (depth > b.maxDepth) truncated = true; return; }
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((x, y) => (x.name < y.name ? -1 : 1));
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full, depth + 1); continue; }
      if (!e.isFile()) continue;
      const rel = norm(path.relative(root, full));
      const src = isLanguageSource(rel); const man = isLanguageManifest(rel);
      if (!(src || man) || isLanguageExcludedPath(rel)) continue;
      let st; try { st = fs.statSync(full); } catch { continue; }
      if (st.size > b.maxFileBytes) continue;
      if (count >= b.maxFiles || bytes + st.size > b.maxBytes) { truncated = true; return; }
      try { (src ? files : manifests)[rel] = fs.readFileSync(full, 'utf8'); count++; bytes += st.size; } catch { /* unreadable: skipped */ }
    }
  };
  walk(root, 0);
  return { files, manifests, truncated };
}

/**
 * Expands a partial scan with the language context it needs. `fileContents` entries always win over disk. With no
 * Haskell/Nix file in `fileContents` the inputs come back unchanged (same objects), so other languages are untouched.
 * @returns {{fileContents:object, depFileContents:object, context:string[], truncated:boolean}}
 */
export function withLanguageContext(root, fileContents, depFileContents = {}, budgets = {}) {
  const wanted = Object.keys(fileContents || {}).map(norm).filter(isLanguagePath);
  if (!wanted.length || !root) return { fileContents, depFileContents, context: [], truncated: false };
  const proj = loadLanguageProject(root, budgets);
  const merged = { ...proj.files, ...fileContents };
  const { graph } = buildImportGraph(merged);
  const need = new Set();
  for (const f of wanted) { need.add(f); for (const d of importClosure(graph, f).files) need.add(d); }
  // importers matter too: a changed callee can make a caller (un)safe
  const rev = new Map();
  for (const [k, ds] of graph) for (const d of ds) { if (!rev.has(d)) rev.set(d, []); rev.get(d).push(k); }
  let frontier = [...wanted];
  while (frontier.length) { const next = []; for (const f of frontier) for (const r of rev.get(f) || []) if (!need.has(r)) { need.add(r); next.push(r); } frontier = next; }
  const out = { ...fileContents };
  const context = [];
  for (const k of need) if (!(k in out) && k in proj.files) { out[k] = proj.files[k]; context.push(k); }
  return { fileContents: out, depFileContents: { ...proj.manifests, ...depFileContents }, context: context.sort(), truncated: proj.truncated };
}

/** The language fixer a finding belongs to, or null. */
export function languageOfFinding(f) {
  const file = String((f && (f.file || (f.sink && f.sink.file))) || '');
  if (/\.l?hs$|\.hs-boot$|\.hsc$/i.test(file)) return 'haskell';
  if (/\.nix$/i.test(file)) return 'nix';
  return null;
}

/**
 * A READ-ONLY fix preview for a Haskell/Nix finding: the planned patch, its tier, and what the verification gates say.
 * Never writes. `files` is the project's language sources (see loadLanguageProject).
 */
export async function languageFixPreview(finding, files, { apply = false, root = null } = {}) {
  const lang = languageOfFinding(finding);
  if (!lang) return { ok: false, status: 'unsupported', reason: 'not a Haskell or Nix finding' };
  const plan = lang === 'haskell' ? planHaskellFix(finding, files) : planNixFix(finding, files);
  if (!plan || plan.ok === false) return { ok: false, status: (plan && plan.status) || 'unsupported', tier: (plan && plan.tier) || null, reason: (plan && plan.reason) || 'no deterministic fix', proposal: (plan && plan.proposal) || null };
  let res;
  try { res = lang === 'haskell' ? await validateHaskellFix(finding, { files, apply, root }) : await validateNixFix(finding, { files, apply, root }); } catch (e) { res = { status: 'blocked', reason: `verification failed: ${String((e && e.message) || e)}` }; }
  return {
    ok: res.status === 'verified' || res.status === 'applied',
    status: res.status, applied: res.applied === true, backup: res.backup || null,
    label: plan.label || null, tier: res.tier || plan.tier || null,
    file: plan.file, before: plan.before, after: plan.after,
    diff: res.preview || hsDiff(plan.file, plan.before, plan.after),
    gates: res.gates || null, reason: (res.status === 'verified' || res.status === 'applied') ? null : (res.reason || null),
    explanation: plan.explanation || null, consequences: res.consequences || plan.consequences || [],
  };
}

/** A minimal line-range text edit turning `before` into `after` (for an LSP/editor workspace edit). */
export function minimalEdit(before, after) {
  const a = before.split('\n'); const b = after.split('\n');
  let i = 0; while (i < a.length && i < b.length && a[i] === b[i]) i++;
  let ea = a.length; let eb = b.length;
  while (ea > i && eb > i && a[ea - 1] === b[eb - 1]) { ea--; eb--; }
  const endOfDoc = { line: a.length - 1, character: a[a.length - 1].length };
  if (i >= a.length) return { range: { start: endOfDoc, end: endOfDoc }, newText: `\n${b.slice(i).join('\n')}` };   // appended lines
  if (ea === a.length) return { range: { start: { line: i, character: 0 }, end: endOfDoc }, newText: b.slice(i, eb).join('\n') };
  return { range: { start: { line: i, character: 0 }, end: { line: ea, character: 0 } }, newText: eb > i ? `${b.slice(i, eb).join('\n')}\n` : '' };
}

// ── model-assisted workflows ─────────────────────────────────────────────────
import crypto from 'node:crypto';
import { computeLanguageDigests } from './discovery.js';
const _digestMemo = new WeakMap();

/**
 * A digest of `file` and everything its verdict depends on: the modules it imports, every manifest and lock file.
 * Used where a cached model verdict must be invalidated when a DEPENDENCY changes, not only the file itself. For a
 * non-language file the plain content hash is returned.
 */
export function languageClosureDigest(fileContents, file) {
  if (!fileContents || !file) return '';
  if (!isLanguagePath(file)) return crypto.createHash('sha256').update(String(fileContents[file] ?? '')).digest('hex').slice(0, 32);
  let memo = _digestMemo.get(fileContents);
  if (!memo) {
    const manifests = {};
    for (const k of Object.keys(fileContents)) if (isLanguageManifest(k)) manifests[k] = fileContents[k];
    memo = computeLanguageDigests(fileContents, { manifests }).digests;
    _digestMemo.set(fileContents, memo);
  }
  return String(memo.get(norm(file)) || crypto.createHash('sha256').update(String(fileContents[file] ?? '')).digest('hex')).slice(0, 32);
}

/**
 * The extra context a model needs to judge a Haskell/Nix finding whose evidence is NOT on the reported line: the other
 * files on its evidence chain and the files that decided a configuration value. Only files the finding itself names are
 * included (never a project dump), a few lines each, bounded in total. Returns [{file, startLine, text}].
 */
export function languagePromptExtras(finding, fileContents, { maxFiles = 4, windowLines = 5, maxChars = 3000 } = {}) {
  if (!finding || !fileContents || !isLanguagePath(String(finding.file || ''))) return [];
  const want = []; const seen = new Set([finding.file]);
  for (const step of Array.isArray(finding.chain) ? finding.chain : []) {
    if (step && typeof step.file === 'string' && !seen.has(step.file) && typeof fileContents[step.file] === 'string') { seen.add(step.file); want.push({ file: step.file, line: Number.isInteger(step.line) ? step.line : 1 }); }
  }
  for (const f of Array.isArray(finding.controlFiles) ? finding.controlFiles : []) {
    if (typeof f === 'string' && !seen.has(f) && typeof fileContents[f] === 'string') { seen.add(f); want.push({ file: f, line: 1 }); }
  }
  const out = []; let used = 0;
  for (const w of want.slice(0, maxFiles)) {
    const lines = fileContents[w.file].split('\n');
    const start = Math.max(0, w.line - 1 - windowLines); const end = Math.min(lines.length, w.line + windowLines);
    const text = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
    if (used + text.length > maxChars) break;
    used += text.length; out.push({ file: w.file, startLine: start + 1, text });
  }
  return out;
}

// ── dependency upgrades ─────────────────────────────────────────────────────────
/** Whether a finding is a dependency finding the language upgrade planners can act on. */
export function isLanguageDependencyFinding(f) {
  return !!f && f.family === 'vulnerable-dep' && (f.ecosystem === 'hackage' || (f.ecosystem === 'nix' && /(^|\/)flake\.nix$/.test(String(f.file || ''))));
}

/**
 * A dependency fix for a Hackage dependency (raise the declared constraint to a fixed version) or a flake input (point its
 * ref at `toRef`). Both are SOURCE edits whose real effect needs a re-resolve or a re-lock the scanner will not run, so they
 * carry a tier that says so: nothing here claims the dependency is fixed until it has been re-resolved.
 */
export async function languageUpgradePreview(finding, files, { apply = false, root = null, toRef = null } = {}) {
  let plan;
  if (finding.ecosystem === 'hackage') {
    plan = planHaskellUpgrade({ name: finding.package, fixedIn: Array.isArray(finding.fixedIn) ? finding.fixedIn : [], unfixed: !finding.fixedIn, file: finding.declaringFile || finding.file, line: finding.declaringLine }, files);
    if (!plan.ok) return { ok: false, status: plan.status || 'blocked', tier: 'blocked', reason: plan.reason };
    plan = { ...plan, file: plan.file, tier: plan.status === 'fixed' ? 'full-source-edit' : 'constraints-only (not re-resolved)', label: plan.status === 'fixed' ? 'FULL' : 'WORKAROUND', note: plan.note || null,
      explanation: `Raise the declared bound of ${finding.package} from ${plan.from} to ${plan.to}.`, consequences: ['Re-resolve (for example `cabal build --dry-run`) and rescan: this edit changes a constraint, not the resolved version.'] };
  } else {
    if (!toRef) return { ok: false, status: 'blocked', tier: 'blocked', reason: 'a flake input fix needs a target: pass --to <ref or revision>' };
    const up = planNixUpgrade({ files, input: finding.package, toRef });
    if (!up.ok) return { ok: false, status: up.status || 'blocked', tier: up.tier || 'blocked', reason: up.reason };
    plan = { ...up, file: up.edits[0].file, before: up.edits[0].before, after: up.edits[0].after, label: 'WORKAROUND', note: up.note || null, explanation: `Point input ${up.input} at ${up.to} (was ${up.from}).`, consequences: up.consequences || [] };
  }
  const out = { ok: true, status: plan.status, tier: plan.tier, label: plan.label, file: plan.file, before: plan.before, after: plan.after, diff: plan.preview || hsDiff(plan.file, plan.before, plan.after), explanation: plan.explanation, consequences: [...(plan.consequences || []), ...(plan.note ? [plan.note] : [])], applied: false, gates: { path: { ok: true }, syntax: { ok: true }, rescan: { ran: false }, compile: { ran: false } } };
  if (apply) {
    if (!root) return { ...out, ok: false, status: 'blocked', reason: 'apply requires a root directory' };
    out.backup = writeWithBackup(root, plan.file, plan.before, plan.after);
    out.applied = true; out.status = 'applied';
    try { await recordExternalFix({ scanRoot: root, file: plan.file, originalContent: plan.before, newContent: plan.after, findingId: finding.id, ruleId: finding.osvId || 'dependency-upgrade', vuln: finding.vuln || 'Vulnerable dependency', stableId: finding.stableId || null, fixLabel: plan.label, verification: { tier: plan.tier, rescan: 'not-run' }, backup: out.backup }); } catch { /* the ledger is best effort here */ }
  }
  return out;
}
