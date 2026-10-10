// Shared helpers for the evaluation suites. SYNTHETIC data only: see
// src/posture/evaluation/synthetic.js. Not a test file (no `.test.js`).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSyntheticSuite, syntheticResolver } from '../../src/posture/evaluation/synthetic.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.join(HERE, '..', 'fixtures', 'evaluation-synthetic');

let cached = null;
export function suite() {
  if (!cached) cached = buildSyntheticSuite({ fixturesDir: FIXTURES });
  return cached;
}
export const resolver = () => syntheticResolver(FIXTURES);

export const SYN_FINDING = (over = {}) => ({ id: 'f1', file: 'app.js', line: 8, family: 'sql-injection', cwe: 'CWE-89', severity: 'high', parser: 'IR-TAINT', vuln: 'SQL Injection', ...over });

/** A scan function that returns the same canned findings per workspace, never touching the engine. */
export function stubScan(byTarget, calls = []) {
  return async (dir, opts) => {
    calls.push({ dir, opts });
    const key = Object.keys(byTarget).find((k) => dir.includes(k.replace(/[^\w.-]/g, '_')));
    const v = key ? byTarget[key] : [];
    if (v instanceof Error) throw v;
    return { findings: v };
  };
}

export const timeoutError = () => Object.assign(new Error('no result within 1 ms'), { code: 'TIMEOUT' });

/** A deep clone of the suite's draft with overrides, re-frozen. */
export function clone(v) { return JSON.parse(JSON.stringify(v)); }
