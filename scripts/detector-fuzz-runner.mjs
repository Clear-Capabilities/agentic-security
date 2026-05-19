#!/usr/bin/env node
// FR-ADV-6 — Detector-fuzz runner.
//
// Mutates known-vuln fixtures with the strategies in adversarial-self-test
// and records per-family escape rate via detector-fuzz.js. Distinct from
// self-test-runner.mjs in two ways:
//   1. Per-family escape rate is the primary output, not the gap list.
//   2. Designed to run on every release as a CI gate (escape rate above the
//      family's threshold fails the run).
//
// Usage:
//   node scripts/detector-fuzz-runner.mjs [--fixtures <dir>] \
//                                          [--threshold 0.30] \
//                                          [--output <file>]
//
// Exit 0 if every family's escape rate is below threshold; 1 otherwise.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { prepareFuzzCorpus, recordOutcome, summarize } from '../scanner/src/posture/detector-fuzz.js';
import { runScan } from '../scanner/src/runScan.js';

function parseArgs(argv) {
  const opts = { fixtures: 'scanner/test/fixtures', threshold: 0.30, output: 'detector-fuzz-results.json' };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--fixtures') opts.fixtures = argv[++i];
    else if (argv[i] === '--threshold') opts.threshold = parseFloat(argv[++i]);
    else if (argv[i] === '--output') opts.output = argv[++i];
  }
  return opts;
}

const FAMILY_FROM_DIR = {
  'sql-injection': 'sql-injection',
  'sqli': 'sql-injection',
  'command-injection': 'command-injection',
  'xss': 'xss',
  'path-traversal': 'path-traversal',
  'ssrf': 'ssrf',
  'webhook': 'webhook-no-signature',
  'prototype-pollution': 'prototype-pollution',
};

function discoverFixtures(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  for (const e of fs.readdirSync(root, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const family = FAMILY_FROM_DIR[e.name];
    if (!family) continue;
    const dir = path.join(root, e.name, 'vulnerable');
    if (!fs.existsSync(dir)) continue;
    for (const ff of fs.readdirSync(dir)) {
      const fp = path.join(dir, ff);
      try {
        const stat = fs.statSync(fp);
        if (!stat.isFile() || stat.size > 32_000) continue;
        out.push({ id: `${e.name}/${ff}`, family, file: fp, code: fs.readFileSync(fp, 'utf8') });
      } catch {}
    }
  }
  return out;
}

async function scanMutationCode(family, code) {
  const tmp = path.join('/tmp', `as-fuzz-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'm.js'), code, 'utf8');
  try {
    const { scan } = await runScan(tmp);
    const findings = scan.findings || [];
    const matched = findings.some(f => {
      const fam = String(f.family || f.vuln || '').toLowerCase();
      return fam.includes(family) || fam.includes(family.split('-')[0]);
    });
    return matched;
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
}

async function main() {
  const opts = parseArgs(process.argv);
  const fixtures = discoverFixtures(path.resolve(opts.fixtures));
  if (!fixtures.length) { process.stderr.write(`no fixtures under ${opts.fixtures}\n`); process.exit(2); }
  const matrix = prepareFuzzCorpus(fixtures);
  process.stderr.write(`detector-fuzz: ${matrix.length} mutations to run\n`);
  for (const entry of matrix) {
    const detected = await scanMutationCode(entry.family, entry.mutatedCode);
    recordOutcome(entry, detected);
  }
  const summary = summarize(matrix);
  fs.writeFileSync(opts.output, JSON.stringify({ summary, matrix }, null, 2));
  let fail = false;
  process.stdout.write(`\nDetector-fuzz per-family escape rates (threshold ${opts.threshold}):\n`);
  for (const [fam, stats] of Object.entries(summary.perFamily)) {
    const flag = stats.escapeRate > opts.threshold ? ' ❌ ABOVE THRESHOLD' : '';
    if (stats.escapeRate > opts.threshold) fail = true;
    process.stdout.write(`  ${fam}: ${(stats.escapeRate * 100).toFixed(1)}% (${stats.escaped}/${stats.run})${flag}\n`);
  }
  process.exit(fail ? 1 : 0);
}

main().catch(e => { process.stderr.write(`detector-fuzz runner: ${e.stack || e.message}\n`); process.exit(2); });
