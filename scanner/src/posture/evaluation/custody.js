// Label custody and leakage controls (QA-002.AC03).
//
// Two trust domains meet here. The CUSTODIAN (verifier domain) holds adjudicated
// labels. The engine under test, and any worker or model prompt, is on the other
// side and must never see an answer key. This module provides the custodian's
// store, the workspace staging that builds what the engine is allowed to read,
// and the audits that fail a run when anything label-shaped crosses over.
//
// Enforcement, honestly stated:
//   - role checks use the existing trust-domain policy (`mayDo`): workers and
//     targets are denied sealed-label read AND write;
//   - staging and prompt audits are PATTERN checks over known protected terms and
//     file names. They catch planted and accidental leaks of the kinds listed in
//     `leakFixtures`; they are not a proof that no paraphrase gets through;
//   - process-level read denial of the label directory is the sandbox trust
//     boundary's job (`runInBoundary({ labelDirs })`), which this module only
//     feeds. Where no backend proves that control the boundary reports `blocked`.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DOMAINS, RESOURCES, mayDo, isUntrusted, scrubEnv } from '../../sandbox/trust-domains.js';
import { digestOf } from '../assurance/identity.js';
import { STATE_DIR_NAME } from '../state-dir.js';
import { validateDefectLabel, validateNegativeLabel } from './labels.js';

export const LABEL_FILE = 'adjudicated-labels.json';

// File names that look like an answer key. Regexes, not literals, so this file
// is not itself a reference to any particular key file.
const LEAK_FILENAME_PATTERNS = Object.freeze([
  /(^|\/)(labels?|answers?|expected|ground[-_]?truth|answer[-_]?key|adjudicat\w*|oracle)[^/]*\.(json|jsonl|ya?ml|csv|txt)$/i,
  /(^|\/)result\.json$/i,
  /(^|\/)corpus-baseline[^/]*$/i,
  /(^|\/)(advisory|advisories|ghsa|osv)[^/]*\.(json|md|txt|ya?ml)$/i,
]);

const BENCHMARK_NAMES = Object.freeze(['owasp benchmark', 'juliet', 'sard test', 'cve-replay', 'corpus-baseline', 'answer key', 'ground truth']);
const ADVISORY_ID = /\b(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/i;
const MIN_TERM = 8;

/**
 * Terms that must never reach the engine or a prompt: reviewer evidence refs and
 * rationale, advisory ids and prose, root-cause ids, and fixed-source hints.
 */
export function protectedTermsFrom({ defects = [], negatives = [], advisoryText = [], fixedSourceHints = [], benchmarkNames = BENCHMARK_NAMES } = {}) {
  const terms = new Set();
  const add = (s) => { if (typeof s === 'string' && s.trim().length >= MIN_TERM) terms.add(s.trim().toLowerCase()); };
  for (const d of defects) {
    add(d.rootCauseId);
    for (const e of d.evidence || []) add(e.ref);
    for (const a of d.advisoryRefs || []) add(a);
  }
  for (const n of negatives) add(n.rationale);
  for (const s of [...advisoryText, ...fixedSourceHints, ...benchmarkNames]) add(s);
  return [...terms].sort();
}

/** Leaks in a piece of text (a prompt, a file body). */
export function auditText(text, terms, { strictAdvisoryIds = true } = {}) {
  const hay = String(text ?? '');
  const lower = hay.toLowerCase();
  const leaks = [];
  for (const t of terms || []) if (lower.includes(t)) leaks.push({ kind: 'protected-term', detail: t.length > 60 ? `${t.slice(0, 57)}...` : t });
  if (strictAdvisoryIds) {
    const m = ADVISORY_ID.exec(hay);
    if (m) leaks.push({ kind: 'advisory-id', detail: m[1] });
  }
  return leaks;
}

/** Gate a model/scanner prompt. `ok:false` means the call must not be made. */
export function guardPrompt(prompt, terms, opts) {
  const leaks = auditText(prompt, terms, opts);
  return { ok: leaks.length === 0, leaks };
}

const SKIP_DIRS = new Set(['.git', STATE_DIR_NAME, 'node_modules']);

/**
 * Audit a directory the engine may read: no answer-key file names, no symlinks
 * (which could point outside it), no protected term or advisory id in content.
 * Bounded so a hostile tree cannot make the audit itself the problem.
 */
export function auditWorkspace(dir, terms, { strictAdvisoryIds = true, maxFiles = 20000, maxFileBytes = 2 * 1024 * 1024 } = {}) {
  const leaks = [];
  let scanned = 0; let skippedLarge = 0; let truncated = false;
  const walk = (d, rel) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (truncated) return;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { leaks.push({ kind: 'symlink', file: r, detail: 'symlinks are refused in an engine workspace' }); continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(path.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (++scanned > maxFiles) { truncated = true; leaks.push({ kind: 'audit-truncated', file: r, detail: `more than ${maxFiles} files; the audit cannot vouch for the rest` }); return; }
      if (LEAK_FILENAME_PATTERNS.some((re) => re.test(r))) { leaks.push({ kind: 'answer-key-file', file: r, detail: 'file name looks like a label, answer key or advisory record' }); continue; }
      let st; try { st = fs.statSync(path.join(d, e.name)); } catch { continue; }
      if (st.size > maxFileBytes) { skippedLarge++; continue; }
      let body; try { body = fs.readFileSync(path.join(d, e.name), 'utf8'); } catch { continue; }
      for (const l of auditText(body, terms, { strictAdvisoryIds })) leaks.push({ ...l, file: r });
    }
  };
  walk(dir, '');
  return { ok: leaks.length === 0, leaks, scannedFiles: scanned, skippedLargeFiles: skippedLarge };
}

/**
 * Copy a target tree into a fresh workspace for the engine, then audit it. On any
 * leak the workspace is removed and the target is reported quarantined; the run
 * must record that as a failure, never silently scan the tree anyway.
 */
export function stageWorkspace({ srcDir, destDir, terms, strictAdvisoryIds = true }) {
  fs.rmSync(destDir, { recursive: true, force: true });
  fs.cpSync(srcDir, destDir, {
    recursive: true, dereference: false,
    filter: (s) => !SKIP_DIRS.has(path.basename(s)) || s === srcDir,
  });
  const audit = auditWorkspace(destDir, terms, { strictAdvisoryIds });
  if (!audit.ok) {
    fs.rmSync(destDir, { recursive: true, force: true });
    return { ok: false, quarantined: true, leaks: audit.leaks, destDir: null };
  }
  return { ok: true, quarantined: false, leaks: [], destDir };
}

// ---------------------------------------------------------------- the custodian's store

/** Content hash binding a label set: key-order independent, order independent. */
export function sealLabels(defects, negatives) {
  const sortById = (xs) => [...xs].sort((a, b) => String(a.id).localeCompare(String(b.id)));
  return digestOf({ kind: 'evaluation-labels', defects: sortById(defects || []), negatives: sortById(negatives || []) });
}

const isCustodian = (actor) => actor?.domain === DOMAINS.VERIFIER && actor?.role === 'custodian' && !isUntrusted(actor.domain);

function denied(code, message) { return { ok: false, errors: [{ code, path: '', message }] }; }

/**
 * Write the label set. Only the custodian may; a worker or the target is denied
 * by the trust-domain policy. Every label is validated first: one invalid label
 * rejects the whole write.
 */
export function custodianWriteLabels(labelDir, actor, { defects = [], negatives = [] } = {}) {
  if (!isCustodian(actor)) return denied('CUSTODY_DENIED', `domain '${actor?.domain}' role '${actor?.role}' may not write sealed labels`);
  const errors = [];
  for (const d of defects) { const v = validateDefectLabel(d); if (!v.ok) errors.push(...v.errors.map((e) => ({ ...e, path: `${d?.id}.${e.path}` }))); }
  for (const n of negatives) { const v = validateNegativeLabel(n); if (!v.ok) errors.push(...v.errors.map((e) => ({ ...e, path: `${n?.id}.${e.path}` }))); }
  if (errors.length) return { ok: false, errors };
  fs.mkdirSync(labelDir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(labelDir, 0o700); } catch { /* best effort */ }
  const file = path.join(labelDir, LABEL_FILE);
  fs.writeFileSync(file, JSON.stringify({ defects, negatives }), { mode: 0o600 });
  return { ok: true, errors: [], labelsHash: sealLabels(defects, negatives), count: { defects: defects.length, negatives: negatives.length } };
}

/** Read the label set. Allowed only where the policy grants sealed-label read, and only if it still matches the sealed hash. */
export function custodianReadLabels(labelDir, actor, { expectedHash } = {}) {
  if (!mayDo(actor?.domain, RESOURCES.SEALED_LABELS, 'read')) return denied('CUSTODY_DENIED', `domain '${actor?.domain}' may not read sealed labels`);
  let data;
  try { data = JSON.parse(fs.readFileSync(path.join(labelDir, LABEL_FILE), 'utf8')); } catch (e) { return denied('LABELS_UNREADABLE', `cannot read labels: ${e.code || e.message}`); }
  const defects = Array.isArray(data?.defects) ? data.defects : []; const negatives = Array.isArray(data?.negatives) ? data.negatives : [];
  const labelsHash = sealLabels(defects, negatives);
  if (expectedHash && labelsHash !== expectedHash) return denied('LABELS_HASH_MISMATCH', 'labels changed after they were sealed');
  return { ok: true, errors: [], defects, negatives, labelsHash };
}

// realpath of the nearest existing ancestor plus the not-yet-existing remainder, so a path that does not exist
// yet still compares correctly against one reached through a symlinked parent (macOS /var -> /private/var).
function real(p) {
  let cur = path.resolve(p); const rest = [];
  for (;;) {
    try { return path.join(fs.realpathSync(cur), ...rest.reverse()); } catch { /* climb */ }
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(p);
    rest.push(path.basename(cur)); cur = parent;
  }
}

/** A workspace that contains, or sits inside, the label directory would hand the engine the answer key by construction. */
export function assertCustodyIsolation(labelDir, workspaceDir) {
  const a = real(labelDir); const b = real(workspaceDir);
  if (a === b || a.startsWith(b + path.sep) || b.startsWith(a + path.sep)) {
    return denied('CUSTODY_OVERLAP', `workspace ${workspaceDir} overlaps the label directory ${labelDir}`);
  }
  return { ok: true, errors: [] };
}

/** Environment for the engine under test: secret-looking variables, evaluation variables and anything naming the label directory are removed. */
export function engineEnvironment(base, { labelDir } = {}) {
  const scrubbed = scrubEnv(base || {});
  const out = {};
  const labelReal = labelDir ? real(labelDir) : null;
  for (const [k, v] of Object.entries(scrubbed)) {
    if (/^AGENTIC_(SECURITY_)?EVAL/i.test(k)) continue;
    if (labelDir && typeof v === 'string' && (v.includes(labelDir) || v.includes(labelReal))) continue;
    out[k] = v;
  }
  return out;
}
