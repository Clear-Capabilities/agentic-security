// Dataset manifest for the Eval Lab (PRD 6, requirements 1, 3 and 4).
//
// A dataset is the thing a model is measured on, so everything that could make a score meaningless is a validation error here,
// not a default:
//   * `leakagePolicy.mode` must be `enforce`. There is no `off`; a dataset cannot opt out of the leakage controls.
//   * a real-code dataset (`git-pairs`) must name a license that permits use. An unknown license refuses the dataset.
//   * every vulnerable entry carries the exact span the defect occupies (`expectedSpan`), so detection is scored on LOCATION, not
//     on "a finding of the right class exists somewhere in the file".
//   * every hard negative says what it resembles and which kind of safe code it is (sanitization, authorization, ...), because a
//     negative that does not look like a vulnerability measures nothing.
//
// Labels (kind, cwe, span, category, reproducer) live in the manifest and are NEVER written into a workspace an arm can read.
// A workspace reference is a directory inside the manifest's own folder, or a revision of a local git repository.
//
// Pure except `loadDatasetFile`, which reads one bounded file.
import fs from 'node:fs';
import path from 'node:path';
import { load as loadYaml } from '../../../util/yaml.js';
import { digestOf } from '../../assurance/identity.js';

const DATASET_SCHEMA = 'agentic-security/eval-dataset';
export const SPLITS = Object.freeze(['dev', 'validation', 'sealed']);
const ENTRY_KINDS = Object.freeze(['vulnerable', 'fixed', 'hard-negative']);
export const HARD_NEGATIVE_CATEGORIES = Object.freeze(['sanitization', 'authorization', 'parameterization', 'bounds-check', 'correct-crypto', 'safe-wrapper']);
const SOURCE_KINDS = Object.freeze(['directory', 'git-pairs', 'sard']);
const PERMITTED_LICENSES = Object.freeze(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', '0BSD', 'Unlicense', 'CC0-1.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later']);
const MAX_MANIFEST_BYTES = 5 * 1024 * 1024;
const MAX_ENTRIES = 20000;
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,79}$/;
const CWE_RE = /^CWE-\d{1,5}$/;
const REV_RE = /^[0-9a-f]{7,64}$/i;

export const normalizeCwe = (c) => { const m = /(\d{1,5})/.exec(String(c ?? '')); return m ? `CWE-${Number(m[1])}` : null; };

function spanErrors(span, where) {
  const errs = [];
  if (!span || typeof span !== 'object') return [`${where} is required`];
  if (typeof span.file !== 'string' || !span.file || span.file.includes('\0') || span.file.startsWith('/') || span.file.split(/[\\/]/).includes('..')) errs.push(`${where}.file must be a relative path inside the workspace`);
  if (!Number.isInteger(span.startLine) || span.startLine < 1) errs.push(`${where}.startLine must be a positive integer`);
  if (!Number.isInteger(span.endLine) || span.endLine < span.startLine) errs.push(`${where}.endLine must be an integer at or after startLine`);
  return errs;
}

const argvOk = (a) => Array.isArray(a) && a.length > 0 && a.length <= 64 && a.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'));

/** @returns {{ok: boolean, errors: string[]}} */
export function validateDatasetManifest(m) {
  const errors = [];
  const bad = (msg) => errors.push(msg);
  if (!m || typeof m !== 'object' || Array.isArray(m)) return { ok: false, errors: ['manifest must be an object'] };
  const d = m.dataset;
  if (!d || typeof d !== 'object') return { ok: false, errors: ['manifest needs a "dataset" object'] };
  if (typeof d.id !== 'string' || !ID_RE.test(d.id)) bad('dataset.id must be a lower-case identifier');
  if (typeof d.version !== 'string' || !/^[0-9A-Za-z][0-9A-Za-z._+-]{0,39}$/.test(d.version)) bad('dataset.version is required');
  const langs = Array.isArray(d.language) ? d.language : [d.language];
  if (!langs.length || !langs.every((l) => typeof l === 'string' && /^[a-z][a-z0-9+#-]{0,19}$/.test(l))) bad('dataset.language must name one or more languages');
  if (!d.source || typeof d.source !== 'object' || !SOURCE_KINDS.includes(d.source.kind)) bad(`dataset.source.kind must be one of ${SOURCE_KINDS.join(', ')}`);
  if (!SPLITS.includes(d.split)) bad(`dataset.split must be one of ${SPLITS.join(', ')}`);
  if (typeof d.license !== 'string' || !d.license.trim()) bad('dataset.license is required');
  else if (d.source?.kind === 'git-pairs' && !PERMITTED_LICENSES.includes(d.license)) bad(`a real-code dataset needs a license that permits use (one of ${PERMITTED_LICENSES.slice(0, 6).join(', ')}, ...); "${d.license}" is not accepted`);
  if (!Array.isArray(d.cwe) || !d.cwe.length || !d.cwe.every((c) => CWE_RE.test(String(c)))) bad('dataset.cwe must list CWE ids such as CWE-89');
  const lp = d.leakagePolicy;
  if (!lp || typeof lp !== 'object') bad('dataset.leakagePolicy is required');
  else {
    if (lp.mode !== 'enforce') bad('dataset.leakagePolicy.mode must be "enforce"; a dataset cannot turn the leakage controls off');
    for (const k of ['stripComments', 'renameFiles']) if (lp[k] !== undefined && typeof lp[k] !== 'boolean') bad(`dataset.leakagePolicy.${k} must be a boolean`);
    if (lp.removePaths !== undefined && !(Array.isArray(lp.removePaths) && lp.removePaths.every((g) => typeof g === 'string' && g.length >= 1 && g.length <= 120 && !g.includes('\0')))) bad('dataset.leakagePolicy.removePaths must be a list of simple globs');
    if (lp.protectedTerms !== undefined && !(Array.isArray(lp.protectedTerms) && lp.protectedTerms.every((t) => typeof t === 'string' && t.length >= 4 && t.length <= 200))) bad('dataset.leakagePolicy.protectedTerms must be a list of strings of at least 4 characters');
  }
  if (d.build !== undefined && !argvOk(d.build)) bad('dataset.build must be an argv array');
  if (d.test !== undefined && !argvOk(d.test)) bad('dataset.test must be an argv array');

  const entries = m.entries;
  if (!Array.isArray(entries) || !entries.length) bad('entries must be a non-empty list');
  else if (entries.length > MAX_ENTRIES) bad(`entries is limited to ${MAX_ENTRIES}`);
  else {
    const seen = new Set();
    entries.forEach((e, i) => {
      const w = `entries[${i}]`;
      if (!e || typeof e !== 'object') { bad(`${w} must be an object`); return; }
      if (typeof e.id !== 'string' || !ID_RE.test(e.id)) bad(`${w}.id must be a lower-case identifier`);
      else if (seen.has(e.id)) bad(`${w}.id "${e.id}" is duplicated`);
      else seen.add(e.id);
      if (!ENTRY_KINDS.includes(e.kind)) bad(`${w}.kind must be one of ${ENTRY_KINDS.join(', ')}`);
      if (!e.workspace || typeof e.workspace !== 'object') bad(`${w}.workspace is required`);
      else if (typeof e.workspace.dir === 'string') {
        if (e.workspace.dir.startsWith('/') || e.workspace.dir.includes('\0') || e.workspace.dir.split(/[\\/]/).includes('..')) bad(`${w}.workspace.dir must stay inside the manifest folder`);
      } else if (e.workspace.git && typeof e.workspace.git === 'object') {
        if (typeof e.workspace.git.repo !== 'string' || !e.workspace.git.repo) bad(`${w}.workspace.git.repo is required`);
        if (typeof e.workspace.git.rev !== 'string' || !REV_RE.test(e.workspace.git.rev)) bad(`${w}.workspace.git.rev must be a commit id (a moving ref such as a branch is not reproducible)`);
      } else bad(`${w}.workspace needs "dir" or "git"`);
      if (e.kind === 'vulnerable') {
        if (!CWE_RE.test(String(e.cwe))) bad(`${w}.cwe is required for a vulnerable entry`);
        errors.push(...spanErrors(e.expectedSpan, `${w}.expectedSpan`));
        if (e.category !== undefined || e.lookalikeSpan !== undefined) bad(`${w}: category and lookalikeSpan belong to negative entries`);
      } else if (e.kind === 'hard-negative') {
        if (!HARD_NEGATIVE_CATEGORIES.includes(e.category)) bad(`${w}.category must be one of ${HARD_NEGATIVE_CATEGORIES.join(', ')}`);
        if (!CWE_RE.test(String(e.resemblesCwe))) bad(`${w}.resemblesCwe must name the weakness it looks like`);
        errors.push(...spanErrors(e.lookalikeSpan, `${w}.lookalikeSpan`));
        if (e.expectedSpan !== undefined) bad(`${w}: a hard negative has no expectedSpan; it is not vulnerable`);
      } else if (e.kind === 'fixed') {
        if (!CWE_RE.test(String(e.resemblesCwe ?? e.cwe))) bad(`${w}.resemblesCwe must name the weakness that was fixed`);
        if (e.lookalikeSpan !== undefined) errors.push(...spanErrors(e.lookalikeSpan, `${w}.lookalikeSpan`));
      }
      if (e.reproducer !== undefined && (typeof e.reproducer !== 'string' || e.reproducer.startsWith('/') || e.reproducer.split(/[\\/]/).includes('..'))) bad(`${w}.reproducer must be a relative path inside the manifest folder`);
      if (e.test !== undefined && !argvOk(e.test)) bad(`${w}.test must be an argv array`);
    });
    if (!entries.some((e) => e?.kind === 'vulnerable')) bad('a dataset needs at least one vulnerable entry');
    if (!entries.some((e) => e?.kind === 'hard-negative' || e?.kind === 'fixed')) bad('a dataset needs at least one negative entry (fixed or hard-negative); without one, precision cannot be measured');
  }
  return { ok: errors.length === 0, errors };
}

/** Content hash of everything that defines what is measured. Key order does not matter. */
export const datasetHash = (m) => digestOf({ dataset: m.dataset, entries: m.entries });

/** Read and validate a manifest (JSON or YAML), bounded. Entry paths resolve against the manifest's own folder. */
export function loadDatasetFile(file) {
  let st;
  try { st = fs.statSync(file); } catch { return { ok: false, errors: [`cannot read ${file}`] }; }
  if (!st.isFile() || st.size > MAX_MANIFEST_BYTES) return { ok: false, errors: [`${file} is not a regular file under ${MAX_MANIFEST_BYTES} bytes`] };
  let doc;
  try {
    const text = fs.readFileSync(file, 'utf8');
    doc = /\.json$/i.test(file) ? JSON.parse(text) : loadYaml(text);
  } catch (e) { return { ok: false, errors: [`cannot parse ${path.basename(file)}: ${String(e.message).split('\n')[0]}`] }; }
  const v = validateDatasetManifest(doc);
  if (!v.ok) return { ok: false, errors: v.errors };
  return { ok: true, manifest: doc, baseDir: path.dirname(path.resolve(file)), hash: datasetHash(doc) };
}

/** Resolve a manifest-relative path and confirm it did not escape (symlinks included). Returns null when it did. */
export function resolveInside(baseDir, rel) {
  const target = path.resolve(baseDir, rel);
  let real;
  try { real = fs.realpathSync(target); } catch { return null; }
  const root = fs.realpathSync(baseDir);
  return real === root || real.startsWith(root + path.sep) ? real : null;
}
