// Haskell and Nix analysis metadata as registered state artifacts (X-016).
//
// An ordinary scan already leaves last-scan.json. Two things a reviewer, auditor or retention policy needs about the
// Haskell/Nix side were not artifacts of their own: WHAT analysed the sources (parser/resolver outcomes, capability
// status, limitations, optional modes) and WHICH components the language BOM recorded. They are written beside
// last-scan.json as `language-analysis.json` and `language-bom.json`, each with a detached signature, registered in
// posture/artifact-registry.js (so export, retention, legal hold and `reset` all see them), and described by a record
// that carries sha256 digests of every input and of the artifact bodies. No source text is ever written: paths and
// digests only, so the file is metadata, not a copy of customer code.

import crypto from 'node:crypto';
import { statePath, safeWriteState } from '../posture/state-dir.js';
import { signLastScan } from '../posture/integrity.js';
import { loadLanguageProject } from './context.js';

export const LANGUAGE_ANALYSIS_FILE = 'language-analysis.json';
export const LANGUAGE_BOM_FILE = 'language-bom.json';
export const LANGUAGE_ARTIFACT_SCHEMA = 'agentic-security/language-analysis@1';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v === undefined ? null : v);
}

/** True when the scan has anything Haskell/Nix to record. */
export function hasLanguageContent(scan) {
  const lc = scan && scan.scanHealth && scan.scanHealth.languageCoverage;
  const files = lc && lc.totals && Number(lc.totals.files || lc.totals.analyzed || 0);
  return !!((lc && (files > 0 || (lc.capabilities && Object.keys(lc.capabilities).length))) || (scan && scan.languageBom && (scan.languageBom.components || []).length));
}

/**
 * The analysis record for `scan`, plus the BOM body. `inputs` is [{path, sha256}] over the Haskell/Nix sources and
 * manifests (digests only). Pure: no I/O.
 */
export function buildLanguageArtifacts(scan, inputs = []) {
  const lc = (scan && scan.scanHealth && scan.scanHealth.languageCoverage) || null;
  const bom = (scan && scan.languageBom) || null;
  const bridges = (scan && scan.languageBridges) || null;
  const bomBody = bom ? JSON.stringify(bom, null, 2) : null;
  const record = {
    schema: LANGUAGE_ARTIFACT_SCHEMA,
    classification: { class: 'scan-metadata', containsSourceText: false, containsSecrets: false },
    inputs: inputs.map((i) => ({ path: String(i.path), sha256: String(i.sha256) })).sort((a, b) => (a.path < b.path ? -1 : 1)),
    analysis: lc ? { totals: lc.totals, byKind: lc.byKind, conditions: lc.conditions, limitations: lc.limitations, capabilities: lc.capabilities, optionalModes: lc.optionalModes } : null,
    bom: bom ? { file: LANGUAGE_BOM_FILE, sha256: sha256(bomBody), components: (bom.components || []).length } : null,
    bridges: bridges ? { sha256: sha256(canonical(bridges)) } : null,
  };
  return { record, bomBody };
}

/**
 * Writes the artifacts under the project's state directory, each with a `.sig`. Returns {written:[{name, sha256}], skipped}.
 * Never throws and never blocks a scan; a project that disallows state writes gets `skipped: 'state-writes-disabled'`.
 */
export function persistLanguageArtifacts(root, scan) {
  if (!hasLanguageContent(scan)) return { written: [], skipped: 'no-language-content' };
  let inputs = [];
  try {
    const proj = loadLanguageProject(root);
    inputs = [...Object.entries(proj.files), ...Object.entries(proj.manifests)].map(([path, text]) => ({ path, sha256: sha256(text) }));
  } catch { /* the record then says it has no input digests */ }
  const { record, bomBody } = buildLanguageArtifacts(scan, inputs);
  const out = [];
  const put = (name, body) => {
    const fp = statePath(root, name);
    if (!safeWriteState(fp, body)) return false;
    try { safeWriteState(`${fp}.sig`, signLastScan(body)); } catch { /* the signature is best effort, as for last-scan.json */ }
    out.push({ name, sha256: sha256(body) });
    return true;
  };
  const body = JSON.stringify(record, null, 2);
  if (!put(LANGUAGE_ANALYSIS_FILE, body)) return { written: [], skipped: 'state-writes-disabled' };
  if (bomBody) put(LANGUAGE_BOM_FILE, bomBody);
  return { written: out, skipped: null };
}
