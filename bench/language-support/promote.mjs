// Measures the frozen holdout ONCE, runs the capability test suites, evaluates support, and writes the registry.
//
//   node bench/language-support/promote.mjs [--reuse]      # --reuse evaluates the stored results without measuring again
//
// Promotion is a pure consequence of the measurement: `evaluateSupport` decides every row, `checkPromotion` re-checks each proposed
// `supported` row, and the registry (docs/language-support.json) plus its rendered table (docs/language-support.md) are written from
// that and nothing else. A row can only move to `supported` by passing evidence of its own metric kind.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO, DATA, readJson, read, sha } from './lib.mjs';
import { runAll, probeTools, CAPABILITY_SUITES } from './suites.mjs';
import { buildRegistry, renderTable } from './registry-build.mjs';

const RESULTS = path.join(REPO, 'bench', 'language-support', 'results');
export const HOLDOUT = path.join(RESULTS, 'holdout.json');
export const UNSEEN = path.join(RESULTS, 'unseen.json');
export const loadUnseen = () => { if (!fs.existsSync(UNSEEN)) return null; const u = JSON.parse(fs.readFileSync(UNSEEN, 'utf8')); return { ...u, unseenRollup: (u.hashes || {}).unseenRollup || null }; };
export const SUITES = path.join(RESULTS, 'suites.json');
export const REGISTRY = path.join(REPO, 'docs', 'language-support.json');
export const TABLE = path.join(REPO, 'docs', 'language-support.md');

export function currentFrozen() {
  const manifest = readJson('manifest.json');
  return { holdoutRollup: manifest.holdoutRollup, labelsSha256: sha(read(path.join(DATA, 'labels', 'cases.json'))), privacyLabelsSha256: sha(read(path.join(DATA, 'labels', 'privacy.json'))), corpusVersion: manifest.version };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const reuse = process.argv.includes('--reuse');
  fs.mkdirSync(RESULTS, { recursive: true });
  if (!reuse || !fs.existsSync(HOLDOUT)) {
    const r = spawnSync(process.execPath, [path.join(REPO, 'bench', 'language-support', 'measure.mjs'), '--split', 'holdout', '--out', HOLDOUT], { cwd: path.join(REPO, 'scanner'), encoding: 'utf8', timeout: 3_600_000 });
    if (r.status !== 0) { process.stderr.write(`measurement failed:\n${r.stderr}\n`); process.exit(2); }
  }
  if (!reuse || !fs.existsSync(SUITES)) {
    const results = runAll();
    fs.writeFileSync(SUITES, `${JSON.stringify({ schema: 'agentic-security/language-support-suites@1', ranAt: new Date().toISOString().slice(0, 10), node: process.version, tools: probeTools(), capabilitySuites: CAPABILITY_SUITES, results }, null, 2)}\n`);
  }
  const measurement = JSON.parse(fs.readFileSync(HOLDOUT, 'utf8'));
  const suites = JSON.parse(fs.readFileSync(SUITES, 'utf8'));
  const { registry, allSupported } = buildRegistry(measurement, suites, currentFrozen(), probeTools(), loadUnseen());
  fs.writeFileSync(REGISTRY, `${JSON.stringify(registry, null, 2)}\n`);
  fs.writeFileSync(TABLE, renderTable(registry));
  process.stdout.write(`registry written: ${path.relative(REPO, REGISTRY)}\nall required rows supported: ${allSupported}\n`);
  for (const [lang, entry] of Object.entries(registry.languages)) process.stdout.write(`${lang}: ${entry.summary.supported}/${entry.summary.required} supported; not supported: ${entry.summary.notSupported.join(', ') || 'none'}\n`);
}
