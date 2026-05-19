#!/usr/bin/env node
// FR-LEARN-8 — Adversarial self-test runner.
//
// Drives the closed-loop: take known-vuln fixtures, mutate them across the
// strategies in posture/adversarial-self-test.js, run the scanner against
// each variant, record whether the scanner caught the mutation.
//
// Usage:
//   node scripts/self-test-runner.mjs [--fixtures <dir>] [--output <file>]
//
// Default fixtures source: scanner/test/fixtures/ (subdirs map family name).
// Output: ./self-test-results.json + a per-family escape-rate summary to stdout.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { mutateSnippet, summarizeSelfTest } from '../scanner/src/posture/adversarial-self-test.js';
import { runScan } from '../scanner/src/runScan.js';

function parseArgs(argv) {
  const opts = { fixtures: 'scanner/test/fixtures', output: 'self-test-results.json' };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--fixtures') opts.fixtures = argv[++i];
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
  const fixtures = [];
  if (!fs.existsSync(root)) return fixtures;
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
        const code = fs.readFileSync(fp, 'utf8');
        fixtures.push({ id: `${e.name}/${ff}`, family, file: fp, code });
      } catch {}
    }
  }
  return fixtures;
}

async function scanMutation(family, mutationCode) {
  // Write to a temp dir as a single .js/.py file and scan that root.
  const tmp = path.join('/tmp', `as-selftest-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
  fs.mkdirSync(tmp, { recursive: true });
  const ext = family === 'webhook-no-signature' || /sql|command|xss|ssrf|webhook|prototype/.test(family) ? '.js' : '.py';
  const fp = path.join(tmp, `m${ext}`);
  fs.writeFileSync(fp, mutationCode, 'utf8');
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
  const root = path.resolve(opts.fixtures);
  const fixtures = discoverFixtures(root);
  if (!fixtures.length) {
    process.stderr.write(`no fixtures found under ${root}\n`);
    process.exit(2);
  }
  process.stderr.write(`self-test: found ${fixtures.length} fixtures\n`);
  const runs = [];
  for (const fx of fixtures) {
    const muts = mutateSnippet(fx.code, fx.family);
    for (let i = 0; i < muts.length; i++) {
      const mutationCode = muts[i];
      let detected = false;
      try { detected = await scanMutation(fx.family, mutationCode); } catch (e) { detected = false; }
      runs.push({ fixtureId: fx.id, family: fx.family, mutation: { strategy: `mut-${i + 1}` }, detectedByScanner: detected });
      process.stderr.write(`  ${fx.family} mut-${i + 1} on ${fx.id}: ${detected ? 'caught' : 'ESCAPED'}\n`);
    }
  }
  const summary = summarizeSelfTest(runs);
  fs.writeFileSync(opts.output, JSON.stringify({ summary, runs }, null, 2));
  process.stdout.write(`Self-test summary: ${summary.totalRuns} runs, ${summary.gaps.length} escapes, ${summary.confirmed.length} confirmed.\n`);
  process.stdout.write(`Detailed results: ${opts.output}\n`);
  process.exit(summary.gaps.length ? 1 : 0);
}

main().catch(e => { process.stderr.write(`self-test runner: ${e.stack || e.message}\n`); process.exit(2); });
