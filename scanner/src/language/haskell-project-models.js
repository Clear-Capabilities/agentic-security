// Declarative project models for Haskell wrappers (PRD FR 03).
//
// A wrapper the shipped registry does not know (a project's own `runQuery`, a vendored HTTP helper) can be declared in
// `.agentic-security/haskell-models.json`. A suggestive function name is never enough: every model must carry provenance (who
// reviewed it and why), the argument position it concerns, and a paired positive and negative test that exist in the scanned
// source. A model that lacks any of these is rejected, with the reason, and has no effect on the scan.
//
// File shape:
//   { "schema": "haskell-project-models/1",
//     "models": [ { "id": "app-runquery", "role": "sink", "module": "App.Db", "name": "runQuery",
//                   "family": "sql", "cwe": "CWE-89", "argIndex": 0,
//                   "provenance": { "reviewer": "…", "reviewedAt": "2026-11-01", "reason": "…" },
//                   "tests": { "positive": "test/RunQueryVuln.hs", "negative": "test/RunQuerySafe.hs" } } ] }
//
// Roles: `source` (its result is untrusted input), `sink` (argument `argIndex` is dangerous for `family`), `sanitizer`
// (its result is safe for the families in `appliesTo`, and only those; `*` is not accepted).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath } from '../posture/state-dir.js';

export const PROJECT_MODEL_SCHEMA = 'haskell-project-models/1';

const FAMILIES = Object.freeze({
  sql: 'CWE-89', cmd: 'CWE-78', path: 'CWE-22', ssrf: 'CWE-918', xss: 'CWE-79', log: 'CWE-532', code: 'CWE-94', redirect: 'CWE-601',
});
const SEVERITY = { sql: 'high', cmd: 'high', path: 'high', ssrf: 'high', xss: 'high', log: 'medium', code: 'critical', redirect: 'medium' };
const MODULE_RE = /^[A-Z][A-Za-z0-9_']*(?:\.[A-Z][A-Za-z0-9_']*)*$/;
const NAME_RE = /^[a-z_][A-Za-z0-9_']*$/;

function check(m, exists) {
  if (!m || typeof m !== 'object') return 'not an object';
  if (!m.id || typeof m.id !== 'string') return 'missing id';
  if (!['source', 'sink', 'sanitizer'].includes(m.role)) return `role must be source, sink or sanitizer, got ${JSON.stringify(m.role)}`;
  if (!MODULE_RE.test(String(m.module || ''))) return 'module must be a qualified module name such as App.Db';
  if (!NAME_RE.test(String(m.name || ''))) return 'name must be a function name';
  const pv = m.provenance;
  if (!pv || !pv.reviewer || !pv.reviewedAt || !pv.reason) return 'provenance needs reviewer, reviewedAt and reason: a function name alone is not a model';
  const t = m.tests;
  if (!t || !t.positive || !t.negative) return 'a paired positive and negative test is required';
  if (t.positive === t.negative) return 'the positive and negative tests must be different files';
  for (const k of ['positive', 'negative']) {
    if (!exists(String(t[k]))) return `${k} test "${t[k]}" does not exist inside the project`;
  }
  if (m.role === 'sink') {
    if (!FAMILIES[m.family]) return `family must be one of ${Object.keys(FAMILIES).join(', ')}`;
    if (!(Number.isInteger(m.argIndex) && m.argIndex >= 0) && m.argIndex !== 'all') return 'a sink needs argIndex (a non-negative integer or "all")';
  }
  if (m.role === 'sanitizer') {
    if (!Array.isArray(m.appliesTo) || !m.appliesTo.length) return 'a sanitizer needs appliesTo, the families it neutralises';
    if (m.appliesTo.includes('*')) return 'a project sanitizer may not claim every family';
    const bad = m.appliesTo.find((f) => !FAMILIES[f]);
    if (bad) return `unknown family in appliesTo: ${bad}`;
  }
  if (m.role === 'source' && !m.label) return 'a source needs a label saying what it returns';
  return null;
}

/** A predicate for 'this relative path is a regular file inside the project root'. */
export function projectFileExists(scanRoot) {
  const root = path.resolve(scanRoot);
  return (rel) => {
    try {
      if (path.isAbsolute(rel)) return false;
      const abs = path.resolve(root, rel);
      if (abs !== root && !abs.startsWith(root + path.sep)) return false;
      return fs.lstatSync(abs).isFile();
    } catch { return false; }
  };
}

/** Read the model file from the scan root (an exact path, never a traversal). Returns the parsed document or null. */
export function readProjectModelFile(scanRoot) {
  try {
    const fp = statePath(scanRoot, 'haskell-models.json');
    return JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch { return null; }
}

/**
 * @returns {{present: boolean, accepted: object[], rejected: {id: string, reason: string}[], catalog: object[]}}
 */
export function loadProjectModels(doc, exists = () => false) {
  if (!doc) return { present: false, accepted: [], rejected: [], catalog: [] };
  if (doc.schema !== PROJECT_MODEL_SCHEMA || !Array.isArray(doc.models)) {
    return { present: true, accepted: [], rejected: [{ id: '(file)', reason: `expected schema ${PROJECT_MODEL_SCHEMA} with a models array` }], catalog: [] };
  }
  const accepted = []; const rejected = []; const seen = new Set();
  for (const m of doc.models) {
    const id = String(m && m.id || '(no id)');
    const why = seen.has(id) ? 'duplicate id' : check(m, exists);
    seen.add(id);
    if (why) rejected.push({ id, reason: why }); else accepted.push(m);
  }
  const catalog = accepted.map((m) => {
    const callee = `${m.module}.${m.name}`;
    const base = { id: `hs-project-${m.id}`.toLowerCase(), language: 'hs', framework: 'haskell', match: { type: 'call', callee }, projectModel: m.id };
    if (m.role === 'source') return { ...base, kind: 'source', label: m.label, provenance: 'project-model' };
    if (m.role === 'sink') return {
      ...base, kind: 'sink', argIndex: m.argIndex,
      vuln: { name: m.vuln || `${m.family} sink (project model ${m.id})`, severity: SEVERITY[m.family], cwe: m.cwe || FAMILIES[m.family], remediation: m.remediation || 'See the project model that declares this wrapper.' },
      hs: { family: m.family, shell: m.shell === true, argv: false, package: 'project', htmlSkeleton: false },
    };
    return { ...base, kind: 'sanitizer', effect: 'strip', appliesTo: m.appliesTo, note: `project model ${m.id}` };
  });
  return { present: true, accepted, rejected, catalog };
}
