#!/usr/bin/env node
// Calibration seed expansion script.
//
// Runs the scanner against OWASP Benchmark v1.2 and/or Juliet Java
// test cases, compares findings against answer keys, computes per-family
// TP/FP/FN, and updates calibration-seed.json with expanded counts.
//
// Prerequisites:
//   1. OWASP Benchmark v1.2 test cases in bench/owasp-benchmark-v1.2/src/ (or under AGENTIC_SECURITY_OWASP_BENCHMARK_DIR)
//      Download from: https://github.com/OWASP-Benchmark/BenchmarkJava/releases
//   2. Expected results CSV at bench/owasp-benchmark-v1.2/expectedresults-1.2.csv
//
// Usage:
//   node scripts/calibration-expand.mjs [--owasp] [--juliet] [--dry-run]
//
// With --dry-run, prints the updated counts but does not write the file.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { disableStateWrites } from '../bench/_lib/tree-integrity.mjs';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const SEED_PATH = path.join(ROOT, 'scanner/src/posture/calibration-seed.json');

const CWE_TO_FAMILY = {
  'CWE-78':  'command-injection',
  'CWE-79':  'xss',
  'CWE-89':  'sql-injection',
  'CWE-90':  'ldap-injection',
  'CWE-22':  'path-traversal',
  'CWE-327': 'weak-crypto',
  'CWE-328': 'weak-crypto',
  'CWE-330': 'weak-rng',
  'CWE-501': 'trust-boundary',
  'CWE-614': 'insecure-http',
  'CWE-643': 'xpath-injection',
};

async function loadOwaspExpectedResults(csvPath) {
  if (!fs.existsSync(csvPath)) {
    console.error(`Expected results CSV not found: ${csvPath}`);
    console.error('Download OWASP Benchmark v1.2 and place expectedresults-1.2.csv there.');
    return null;
  }
  const lines = fs.readFileSync(csvPath, 'utf8').split('\n').filter(l => l.trim() && !l.startsWith('#'));
  const entries = [];
  for (const line of lines.slice(1)) { // skip header
    const parts = line.split(',');
    if (parts.length < 4) continue;
    // the 1.2 file's header: `# test name, category, real vulnerability, cwe, ...` (the two last columns were read the other way round before
    // 2026-11-15, so no row ever matched a family and the script re-measured nothing)
    const testName = parts[0].trim();
    const category = parts[1].trim();
    const real = parts[2].trim().toLowerCase() === 'true';
    const cwe = parts[3].trim();
    entries.push({ testName, category, cwe: `CWE-${cwe}`, real });
  }
  return entries;
}

async function runScanOnBenchmark(benchDir) {
  const { runScan } = await import(path.join(ROOT, 'scanner/src/runScan.js'));
  const { normalizeFindings } = await import(path.join(ROOT, 'scanner/src/report/index.js'));
  console.log(`Scanning ${benchDir}...`);
  const t0 = Date.now();
  const { scan } = await runScan(benchDir);
  const findings = normalizeFindings(scan);
  console.log(`Scan completed in ${((Date.now() - t0) / 1000).toFixed(1)}s — ${findings.length} findings`);
  return findings;
}

function computePerFamily(expectedResults, findings) {
  const counts = {};
  for (const entry of expectedResults) {
    const family = CWE_TO_FAMILY[entry.cwe];
    if (!family) continue;
    if (!counts[family]) counts[family] = { tp: 0, fp: 0, fn: 0, tn: 0 };
    const found = findings.some(f =>
      f.file && f.file.includes(entry.testName) &&
      f.family === family
    );
    if (entry.real && found) counts[family].tp++;
    else if (entry.real && !found) counts[family].fn++;
    else if (!entry.real && found) counts[family].fp++;
    else counts[family].tn++;
  }
  return counts;
}

function mergeSeed(existingSeed, newCounts) {
  const merged = JSON.parse(JSON.stringify(existingSeed));
  for (const [family, counts] of Object.entries(newCounts)) {
    if (counts.tp + counts.fp === 0) continue;   // a family the engine reported nothing for carries no rate (its misses are printed above, not stored)
    if (!merged.families[family]) {
      merged.families[family] = { tp: counts.tp, fp: counts.fp };
    } else {
      merged.families[family].tp += counts.tp;
      merged.families[family].fp += counts.fp;
    }
  }
  return merged;
}

async function main() {
  // STATE_SEAM_COMPLETION_PRD M3 — a harness that scans must not write into
  // what it scans. These scripts were outside bench/ and so outside the first
  // sweep; they were still creating .agentic-security/ in fixture trees.
  await disableStateWrites();
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const doOwasp = args.includes('--owasp') || args.length === 0;

  const seed = JSON.parse(fs.readFileSync(SEED_PATH, 'utf8'));
  console.log('Current seed families:', Object.keys(seed.families).length);
  for (const [f, c] of Object.entries(seed.families)) {
    const n = c.tp + c.fp;
    if (n < 30) console.log(`  [LOW] ${f}: n=${n} (needs ${30 - n} more)`);
  }

  if (doOwasp) {
    // AGENTIC_SECURITY_OWASP_BENCHMARK_DIR names a checkout of the benchmark (its `src/` and `expectedresults-1.2.csv`) kept outside the
    // repository; the default is the gitignored bench directory as before.
    const owaspRoot = process.env.AGENTIC_SECURITY_OWASP_BENCHMARK_DIR || path.join(ROOT, 'bench/owasp-benchmark-v1.2');
    const benchDir = path.join(owaspRoot, 'src');
    const csvPath = path.join(owaspRoot, 'expectedresults-1.2.csv');

    if (!fs.existsSync(benchDir)) {
      console.error(`\nOWASP Benchmark source dir not found: ${benchDir}`);
      console.error('Download and extract the test cases first.');
      process.exit(1);
    }

    const expected = await loadOwaspExpectedResults(csvPath);
    if (!expected) process.exit(1);

    console.log(`\nLoaded ${expected.length} expected results`);
    const findings = await runScanOnBenchmark(benchDir);
    const perFamily = computePerFamily(expected, findings);

    console.log('\nPer-family results from OWASP Benchmark:');
    for (const [family, counts] of Object.entries(perFamily).sort()) {
      const n = counts.tp + counts.fp;
      const tpRate = n > 0 ? (counts.tp / n * 100).toFixed(1) : 'N/A';
      console.log(`  ${family}: TP=${counts.tp} FP=${counts.fp} FN=${counts.fn} (TP rate: ${tpRate}%)`);
    }

    const merged = mergeSeed(seed, perFamily);
    console.log('\nMerged seed families:', Object.keys(merged.families).length);
    let allAbove30 = true;
    for (const [f, c] of Object.entries(merged.families)) {
      const n = c.tp + c.fp;
      if (n < 30) { allAbove30 = false; console.log(`  [STILL LOW] ${f}: n=${n}`); }
    }
    if (allAbove30) console.log('  All families have n >= 30');

    if (!dryRun) {
      const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'scanner/package.json'), 'utf8')).version;
      const day = new Date().toISOString().slice(0, 10);
      merged._source = seed._source.replace(/ \+ OWASP Benchmark v1\.2 (?:expansion|re-measured on [^(]*)\(calibration-expand\.mjs\)$/, '') + ` + OWASP Benchmark v1.2 re-measured on ${day} with the engine at ${version} (calibration-expand.mjs)`;
      // FR-207: the freshness age is computed from this field; it is the time of the measurement that produced the counts
      merged._generatedAt = new Date().toISOString();
      merged._generatedAtNote = 'FR-207: the time of the measurement that produced the family counts (written by scripts/calibration-expand.mjs), read by posture/calibration.js calibrationFreshness(). It moves only when the counts are re-measured.';
      fs.writeFileSync(SEED_PATH, JSON.stringify(merged, null, 2) + '\n');
      console.log(`\nWritten updated seed to ${SEED_PATH}`);
    } else {
      console.log('\n[DRY RUN] Would write:', JSON.stringify(merged.families, null, 2));
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
