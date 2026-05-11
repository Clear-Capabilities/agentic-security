#!/usr/bin/env node
// F1 benchmark for the agentic-security scanner.
//
// Reads scanner/test/benchmark/expected.json (per-fixture expected findings),
// runs the scanner against each fixture, and computes precision/recall/F1
// per family and overall.
//
// Match key: (file, line ± LINE_TOLERANCE, family). Family is derived from
// the scanner's `vuln` string via expected.json#_familyMap. Unknown vulns are
// auto-categorized via prefix matching, falling back to a slug.
//
// Exit codes:
//   0 — F1 unchanged or improved relative to baseline (or no baseline)
//   1 — F1 regressed
//   2 — invalid manifest / no fixtures matched

import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname;
const FIX_ROOT = path.join(__dirname, '..', 'fixtures');
const LINE_TOLERANCE = 2;

const args = new Set(process.argv.slice(2));
const VERBOSE = args.has('--verbose') || args.has('-v');
const JSON_OUT = args.has('--json');
const UPDATE_BASELINE = args.has('--update-baseline');
const STRICT_NO_UNKNOWN = args.has('--strict-no-unknown');

// Mirrors familyForBench in bench-realworld.js. SCA findings frequently lack a
// `vuln` string but carry osvId / cveAliases — collapse them to vulnerable-dep
// so they don't all slug to 'unknown'.
function familyFor(vuln, familyMap, finding) {
  if (!vuln) {
    if (finding && (finding.type === 'vulnerable_dep' || finding.osvId || (finding.cveAliases && finding.cveAliases.length))) {
      return 'vulnerable-dep';
    }
    return 'unknown';
  }
  if (familyMap.exact?.[vuln]) return familyMap.exact[vuln];
  for (const [prefix, fam] of Object.entries(familyMap.prefix || {})) {
    if (vuln.startsWith(prefix)) return fam;
  }
  return vuln.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40);
}

function withinTolerance(a, b) {
  return Math.abs(a - b) <= LINE_TOLERANCE;
}

async function scanFixture(fixDir) {
  const { scan } = await runScan(fixDir);
  // Aggregate everything the user-facing report shows: SAST taint + logic +
  // structural findings + secrets + supply-chain. Each finding shape varies
  // but bench only needs file/line/vuln, all read via lineOf/fileOf below.
  return [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []),
  ];
}

function score(actual, expected, familyMap, expectedNone) {
  const tps = []; const fps = []; const fns = [];
  const actualConsumed = new Set();
  function lineOf(a) { return a.sink?.line ?? a.line ?? a.source?.line ?? 0; }
  function fileOf(a) { return a.file || a.sink?.file || a.source?.file || ''; }
  for (const e of expected) {
    const tol = typeof e.lineTolerance === 'number' ? e.lineTolerance : LINE_TOLERANCE;
    let matched = false;
    for (let i = 0; i < actual.length; i++) {
      if (actualConsumed.has(i)) continue;
      const a = actual[i];
      const aFile = fileOf(a);
      if (aFile !== e.file && !aFile.endsWith('/' + e.file)) continue;
      if (Math.abs(lineOf(a) - e.line) > tol) continue;
      const aFam = familyFor(a.vuln, familyMap, a);
      if (aFam !== e.family) continue;
      actualConsumed.add(i);
      tps.push({ ...e, matchedVuln: a.vuln });
      matched = true;
      // matchAny: one expected entry consumes ALL matching actuals (for
      // package.json carrying many CVEs — credit any/all of them as TPs).
      if (!e.matchAny) break;
    }
    if (!matched) fns.push(e);
  }
  for (let i = 0; i < actual.length; i++) {
    if (actualConsumed.has(i)) continue;
    const a = actual[i];
    fps.push({ file: fileOf(a), line: lineOf(a), family: familyFor(a.vuln, familyMap, a), vuln: a.vuln });
  }
  return { tps, fps, fns };
}

function f1(p, r) {
  if (p + r === 0) return 0;
  return (2 * p * r) / (p + r);
}

function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

async function main() {
  const manifestPath = path.join(ROOT, 'expected.json');
  let manifest;
  try {
    manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  } catch (e) {
    console.error(`bench: cannot read ${manifestPath}: ${e.message}`);
    process.exit(2);
  }
  const familyMap = manifest._familyMap || {};
  const fixtures = manifest.fixtures || {};
  const fixtureNames = Object.keys(fixtures);
  if (!fixtureNames.length) { console.error('bench: no fixtures in manifest'); process.exit(2); }

  let totalTP = 0, totalFP = 0, totalFN = 0;
  const perFamily = {};
  const perFixture = {};

  for (const name of fixtureNames) {
    const fixDir = path.join(FIX_ROOT, name);
    let exists = true;
    try { await fs.access(fixDir); } catch { exists = false; }
    if (!exists) {
      console.error(`bench: fixture missing: ${fixDir}`);
      continue;
    }
    const actual = await scanFixture(fixDir);
    const cfg = fixtures[name];
    const { tps, fps, fns } = score(actual, cfg.expected || [], familyMap, !!cfg.expectedNone);

    perFixture[name] = { tp: tps.length, fp: fps.length, fn: fns.length, fps, fns };
    totalTP += tps.length; totalFP += fps.length; totalFN += fns.length;

    for (const t of tps) {
      perFamily[t.family] ??= { tp: 0, fp: 0, fn: 0 };
      perFamily[t.family].tp++;
    }
    for (const f of fps) {
      perFamily[f.family] ??= { tp: 0, fp: 0, fn: 0 };
      perFamily[f.family].fp++;
    }
    for (const f of fns) {
      perFamily[f.family] ??= { tp: 0, fp: 0, fn: 0 };
      perFamily[f.family].fn++;
    }
  }

  const precision = totalTP + totalFP === 0 ? 1 : totalTP / (totalTP + totalFP);
  const recall    = totalTP + totalFN === 0 ? 1 : totalTP / (totalTP + totalFN);
  const overallF1 = f1(precision, recall);

  if (JSON_OUT) {
    console.log(JSON.stringify({
      overall: { tp: totalTP, fp: totalFP, fn: totalFN, precision, recall, f1: overallF1 },
      perFamily, perFixture,
    }, null, 2));
  } else {
    console.log('');
    console.log(`Fixtures: ${fixtureNames.length}   TP: ${totalTP}   FP: ${totalFP}   FN: ${totalFN}`);
    console.log(`Precision: ${(precision*100).toFixed(1)}%   Recall: ${(recall*100).toFixed(1)}%   F1: ${(overallF1*100).toFixed(1)}%`);
    console.log('');
    console.log('Per-fixture:');
    console.log(`  ${pad('fixture', 28)} ${pad('TP', 4)} ${pad('FP', 4)} ${pad('FN', 4)}  P     R     F1`);
    for (const [name, s] of Object.entries(perFixture)) {
      const p = s.tp+s.fp===0?1:s.tp/(s.tp+s.fp);
      const r = s.tp+s.fn===0?1:s.tp/(s.tp+s.fn);
      const fOne = f1(p, r);
      console.log(`  ${pad(name, 28)} ${pad(s.tp,4)} ${pad(s.fp,4)} ${pad(s.fn,4)}  ${(p*100).toFixed(0).padStart(4)}  ${(r*100).toFixed(0).padStart(4)}  ${(fOne*100).toFixed(1)}%`);
    }
    console.log('');
    console.log('Per-family:');
    console.log(`  ${pad('family', 24)} ${pad('TP', 4)} ${pad('FP', 4)} ${pad('FN', 4)}  P     R     F1`);
    for (const [fam, s] of Object.entries(perFamily).sort()) {
      const p = s.tp+s.fp===0?1:s.tp/(s.tp+s.fp);
      const r = s.tp+s.fn===0?1:s.tp/(s.tp+s.fn);
      const fOne = f1(p, r);
      console.log(`  ${pad(fam, 24)} ${pad(s.tp,4)} ${pad(s.fp,4)} ${pad(s.fn,4)}  ${(p*100).toFixed(0).padStart(4)}  ${(r*100).toFixed(0).padStart(4)}  ${(fOne*100).toFixed(1)}%`);
    }
    if (VERBOSE) {
      console.log('');
      console.log('False positives:');
      for (const [name, s] of Object.entries(perFixture)) {
        if (!s.fps.length) continue;
        console.log(`  ${name}:`);
        for (const f of s.fps) console.log(`    ${f.file}:${f.line}  ${f.family}  ${f.vuln}`);
      }
      console.log('');
      console.log('False negatives:');
      for (const [name, s] of Object.entries(perFixture)) {
        if (!s.fns.length) continue;
        console.log(`  ${name}:`);
        for (const f of s.fns) console.log(`    ${f.file}:${f.line}  ${f.family}  expected (severity=${f.severity || '?'})`);
      }
    }
  }

  // Disk-backed FP/FN registry for diff-against-previous-run analysis.
  const fpRegistry = [];
  const fnRegistry = [];
  for (const [name, s] of Object.entries(perFixture)) {
    for (const f of s.fps) fpRegistry.push({ fixture: name, ...f });
    for (const f of s.fns) fnRegistry.push({ fixture: name, ...f });
  }
  await fs.writeFile(path.join(ROOT, 'bench-fps.json'), JSON.stringify(fpRegistry, null, 2));
  await fs.writeFile(path.join(ROOT, 'bench-fns.json'), JSON.stringify(fnRegistry, null, 2));

  // --strict-no-unknown: any actual finding mapping to family 'unknown' fails
  // the bench. Forces taxonomy upkeep when a new vuln string lands.
  if (STRICT_NO_UNKNOWN) {
    const unknowns = fpRegistry.filter(f => f.family === 'unknown');
    if (unknowns.length) {
      console.error(`\nFAIL (--strict-no-unknown): ${unknowns.length} finding(s) map to family 'unknown'. Add them to expected.json#_familyMap.`);
      for (const u of unknowns.slice(0, 10)) console.error(`  ${u.fixture}: ${u.file}:${u.line}  vuln="${u.vuln}"`);
      process.exit(1);
    }
  }

  // Baseline tracking
  const baselinePath = path.join(ROOT, 'baseline.json');
  let baseline = null;
  try { baseline = JSON.parse(await fs.readFile(baselinePath, 'utf8')); } catch {}
  const current = { precision, recall, f1: overallF1, tp: totalTP, fp: totalFP, fn: totalFN, perFamily, ts: new Date().toISOString() };

  if (UPDATE_BASELINE) {
    await fs.writeFile(baselinePath, JSON.stringify(current, null, 2));
    console.log(`\nBaseline updated → ${baselinePath}`);
    process.exit(0);
  }

  // Per-family floors enforcement. Reads expected.json#floors as
  // { "<family>": { "minPrecision": 0.9, "minRecall": 0.95 } }. Families with
  // TP+FN < minSampleSize (default 5) are skipped to avoid statistical noise.
  const floors = manifest.floors || {};
  const FLOOR_MIN_SAMPLE = manifest.floorMinSample || 5;
  const floorBreaches = [];
  for (const [fam, gates] of Object.entries(floors)) {
    const s = perFamily[fam] || { tp: 0, fp: 0, fn: 0 };
    if (s.tp + s.fn < FLOOR_MIN_SAMPLE) continue;
    const p = s.tp+s.fp===0 ? 1 : s.tp/(s.tp+s.fp);
    const r = s.tp+s.fn===0 ? 1 : s.tp/(s.tp+s.fn);
    if (typeof gates.minPrecision === 'number' && p < gates.minPrecision - 1e-6) {
      floorBreaches.push(`${fam}: precision ${(p*100).toFixed(1)}% < floor ${(gates.minPrecision*100).toFixed(1)}%`);
    }
    if (typeof gates.minRecall === 'number' && r < gates.minRecall - 1e-6) {
      floorBreaches.push(`${fam}: recall ${(r*100).toFixed(1)}% < floor ${(gates.minRecall*100).toFixed(1)}%`);
    }
  }
  if (floorBreaches.length) {
    console.error(`\nFAIL: per-family floor breaches:`);
    for (const b of floorBreaches) console.error(`  ${b}`);
    process.exit(1);
  }

  if (baseline) {
    const delta = overallF1 - baseline.f1;
    const deltaPct = (delta * 100).toFixed(2);
    console.log(`\nBaseline F1: ${(baseline.f1*100).toFixed(1)}%   Δ: ${delta >= 0 ? '+' : ''}${deltaPct}pp`);
    if (delta < -0.001) {
      console.error(`\nFAIL: F1 regressed (${(baseline.f1*100).toFixed(1)}% → ${(overallF1*100).toFixed(1)}%)`);
      process.exit(1);
    }
  } else {
    console.log('\nNo baseline yet. Run with --update-baseline to set one.');
  }
}

main().catch(e => { console.error(e); process.exit(2); });
