// Shared harness for the DAG-05 incremental-analysis acceptance tests. Not a test file.
//
// Everything here drives the REAL entry points (`buildProjectIR` + `runDeepAnalysis`, and `runScan`
// for the language fixtures); the cache under test is the one on disk in a temporary project root.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { buildProjectIR } from '../../src/ir/index.js';
import { runDeepAnalysis } from '../../src/dataflow/index.js';

/** A temporary scan root that state may be written into (it has a project marker). */
export function tempRoot(label = 'inc') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `dag05-${label}-`));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"fixture","version":"1.0.0"}');
  return root;
}

export function cleanup(...roots) { for (const r of roots) fs.rmSync(r, { recursive: true, force: true }); }

/** Run the deep stage on `files`. `incremental` switches the cache on for this call only. */
export function deep(files, root, { incremental = true, opts = {}, env = {} } = {}) {
  const saved = {};
  const set = (k, v) => { saved[k] = process.env[k]; if (v === undefined || v === null) delete process.env[k]; else process.env[k] = v; };
  set('AGENTIC_SECURITY_INCREMENTAL', incremental ? '1' : null);
  for (const [k, v] of Object.entries(env)) set(k, v);
  try {
    const { perFile, callGraph } = buildProjectIR(files);
    return runDeepAnalysis(perFile, callGraph, { scanRoot: root, fileContents: files, ...opts });
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

/**
 * Comparable form of an engine result: every field of every finding except the cache provenance
 * (which differs by design), sorted. Equal arrays mean equal findings, not merely equal locations.
 */
export function normalized(findings) {
  return findings.map((f) => JSON.stringify({ ...f, cacheProvenance: undefined })).sort();
}

export function incompleteReasons(findings) {
  return (findings.analysisIncomplete || []).map((x) => `${x.reason}:${x.count}`).sort();
}

/** Parse the persisted incremental files of a root (for assertions about what was stored). */
export function storedState(root) {
  const dir = path.join(root, '.agentic-security', 'incremental');
  const rd = (n) => { try { return JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8')); } catch { return undefined; } };
  return { dir, manifest: rd('version.json'), files: rd('files.json'), deps: rd('deps.json'), replay: rd('replay.json') };
}

export const stateDirOf = (root) => path.join(root, '.agentic-security', 'incremental');
