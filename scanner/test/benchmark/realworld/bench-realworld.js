#!/usr/bin/env node
// F1 benchmark against real-world vulnerable apps (OWASP Benchmark, NodeGoat,
// etc.). Source code is NEVER committed: each app is shallow-cloned to
// .bench-cache/{name}-{sha}/ on demand and re-used across runs.
//
// Usage:
//   node bench-realworld.js --all                  # all apps in manifest
//   node bench-realworld.js --app nodegoat         # one app
//   node bench-realworld.js --app nodegoat --refresh-cache
//   node bench-realworld.js --json                 # machine-readable
//
// Reports per-app precision/recall/F1. Per-app, never combined — different
// apps test different rule families and a combined number is misleading.

import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(__dirname, 'manifest.json');
const CACHE_ROOT = path.join(__dirname, '.bench-cache');
const EXPECTED_DIR = path.join(__dirname, 'expected');
const LINE_TOLERANCE = 2;

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const value = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i+1] : null; };

const ALL = flag('--all');
const APP = value('--app');
const JSON_OUT = flag('--json');
const REFRESH = flag('--refresh-cache');
const VERBOSE = flag('--verbose') || flag('-v');

if (!ALL && !APP) {
  console.error('Usage: bench-realworld.js [--all | --app <name>] [--refresh-cache] [--json] [--verbose]');
  process.exit(2);
}

function sh(cmd, args, opts = {}) {
  const r = cp.spawnSync(cmd, args, { encoding: 'utf8', stdio: ['ignore','pipe','pipe'], ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr || r.stdout}`);
  return r.stdout;
}

async function ensureClone(name, repo, sha) {
  const dest = path.join(CACHE_ROOT, `${name}-${sha}`);
  let exists = true;
  try { await fs.access(dest); } catch { exists = false; }
  if (exists && REFRESH) {
    console.error(`  refreshing cache: ${dest}`);
    await fs.rm(dest, { recursive: true, force: true });
    exists = false;
  }
  if (!exists) {
    await fs.mkdir(CACHE_ROOT, { recursive: true });
    console.error(`  cloning ${repo} @ ${sha.slice(0,7)} → ${dest}`);
    sh('git', ['clone', '--quiet', '--depth', '50', repo, dest]);
    sh('git', ['-C', dest, 'checkout', '--quiet', sha]);
  } else if (VERBOSE) {
    console.error(`  cache hit: ${dest}`);
  }
  return dest;
}

// Build expected[] for OWASP Benchmark from upstream's expectedresults-*.csv.
// Each row: testcase, category, real-vuln (true|false), cwe.
async function buildOwaspBenchmarkExpected(repoRoot, gt) {
  const csvPath = path.join(repoRoot, gt.path);
  const raw = await fs.readFile(csvPath, 'utf8');
  const lines = raw.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  const expected = [];
  for (const line of lines) {
    const [test, cat, real, cwe] = line.split(',').map(s => s && s.trim());
    if (!test || !cat) continue;
    if (real !== 'true') continue;   // only declared TPs become expected entries
    const family = gt.categoryToFamily[cat] || cat;
    expected.push({
      file: `${test}.java`,
      line: 1,
      lineTolerance: 9999, // file-level granularity — ground truth is per-test-file, not per-line
      matchAny: true,      // multiple Java rules can fire on the same file (e.g., scanJavaSAST + structural sink+source pairing); credit them all to the single expected entry rather than counting in-file duplicates as FPs.
      family,
      cwe: cwe ? `CWE-${cwe}` : null,
    });
  }
  return expected;
}

async function loadCuratedExpected(name, gtPath) {
  const p = path.join(__dirname, gtPath);
  return JSON.parse(await fs.readFile(p, 'utf8'));
}

// Build expected[] for a SARD/Juliet-style test suite. Each test file lives in
// `juliet-cweN/.../<TestFile>.java`. The CWE in the directory name maps to a
// scanner family via gt.cweToFamily. We walk the cloned repo, find every test
// file under a known CWE, and emit one expected entry per file (matchAny so
// multiple rules firing on the same file don't double-count).
async function buildJulietExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const ignoredDirs = new Set(['juliet-support', 'gradle', 'build']);
  // Walk top-level dirs.
  const entries = await fs.readdir(repoRoot, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory() || ignoredDirs.has(e.name)) continue;
    const m = e.name.match(/^juliet-cwe(\d+)$/i);
    if (!m) continue;
    const cwe = `CWE${m[1]}`;
    const family = cweMap[cwe];
    if (!family) continue; // CWE not covered by our scanner — skip entirely.
    // Walk this CWE's src/main/java for *.java files. Skip anything under
    // /test/ or that names a Test* (gradle harness).
    const srcRoot = path.join(repoRoot, e.name, 'src', 'main', 'java');
    let exists = true;
    try { await fs.access(srcRoot); } catch { exists = false; }
    if (!exists) continue;
    async function walk(dir) {
      let dEntries;
      try { dEntries = await fs.readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const f of dEntries) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) {
          if (f.name === 'test' || f.name === 'utils') continue;
          await walk(p);
          continue;
        }
        if (!/\.java$/i.test(f.name)) continue;
        // Filter out helper / gradle / Test* harness.
        if (/^Test|TestCase\.java$/.test(f.name)) continue;
        // Path relative to repoRoot.
        const rel = path.relative(repoRoot, p);
        expected.push({
          file: rel,
          line: 1,
          lineTolerance: 9999,
          matchAny: true,
          family,
          cwe,
        });
      }
    }
    await walk(srcRoot);
  }
  return expected;
}

function familyForBench(vuln, vulnFamilyMap, finding) {
  // Reuse the synthetic bench's taxonomy so cross-bench numbers are comparable.
  // SCA findings (vulnerable_dep) frequently lack a `vuln` string but carry
  // osvId/CVE aliases — collapse them under a single 'vulnerable-dep' family
  // so they don't all slug to 'unknown'.
  if (!vuln) {
    if (finding && (finding.type === 'vulnerable_dep' || finding.osvId || (finding.cveAliases && finding.cveAliases.length))) {
      return 'vulnerable-dep';
    }
    return 'unknown';
  }
  for (const [exact, fam] of Object.entries(vulnFamilyMap.exact || {})) if (vuln === exact) return fam;
  for (const [pre, fam] of Object.entries(vulnFamilyMap.prefix || {})) if (vuln.startsWith(pre)) return fam;
  return String(vuln).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40);
}

async function loadFamilyMap() {
  const synth = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'expected.json'), 'utf8'));
  return synth._familyMap || {};
}

function lineOf(a) { return a.sink?.line ?? a.line ?? a.source?.line ?? 0; }
function fileOf(a) { return a.file || a.sink?.file || a.source?.file || ''; }

function score(actual, expected, vulnFamilyMap, scanRoot, wildcardFamilies) {
  const tps = []; const fps = []; const fns = [];
  const consumed = new Set();
  const wildSet = new Set(wildcardFamilies || []);
  // First pass: wildcardFamilies — credit every actual finding whose family is
  // listed (advisory rules that fire correctly across many files; we don't
  // track them per-line).
  if (wildSet.size) {
    for (let i = 0; i < actual.length; i++) {
      const a = actual[i];
      const fam = familyForBench(a.vuln, vulnFamilyMap, a);
      if (wildSet.has(fam)) {
        consumed.add(i);
        tps.push({ family: fam, file: fileOf(a), line: lineOf(a), wildcard: true, matchedVuln: a.vuln });
      }
    }
  }
  // Second pass: match expected entries normally.
  for (const e of expected) {
    const tol = typeof e.lineTolerance === 'number' ? e.lineTolerance : LINE_TOLERANCE;
    let matched = false;
    for (let i = 0; i < actual.length; i++) {
      if (consumed.has(i)) continue;
      const a = actual[i];
      const aFile = fileOf(a);
      const baseE = e.file.replace(/\\/g,'/').split('/').slice(-1)[0];
      const baseA = aFile.replace(/\\/g,'/').split('/').slice(-1)[0];
      // Match either by basename or by suffix path.
      if (baseA !== baseE && !aFile.endsWith('/' + e.file)) continue;
      if (Math.abs(lineOf(a) - e.line) > tol) continue;
      const fam = familyForBench(a.vuln, vulnFamilyMap, a);
      if (fam !== e.family) continue;
      consumed.add(i);
      tps.push({ ...e, matchedVuln: a.vuln });
      matched = true;
      // matchAny: one expected entry consumes ALL matching actuals (used for
      // "the famous vuln-deps" case — package.json carries dozens of CVEs and
      // we credit the scanner for finding any/all of them).
      if (!e.matchAny) break;
    }
    if (!matched && !wildSet.has(e.family)) fns.push(e);
  }
  for (let i = 0; i < actual.length; i++) {
    if (consumed.has(i)) continue;
    const a = actual[i];
    fps.push({ file: fileOf(a), line: lineOf(a), family: familyForBench(a.vuln, vulnFamilyMap, a), vuln: a.vuln });
  }
  return { tps, fps, fns };
}

function f1(p, r) { return p+r === 0 ? 0 : (2*p*r)/(p+r); }
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

async function runOne(name, app, vulnFamilyMap) {
  console.error(`\n=== ${name} (${app.language}) ===`);
  const repoRoot = await ensureClone(name, app.repo, app.sha);
  const scanRoot = path.join(repoRoot, app.scanRoot || '.');

  // Apply per-app excludePaths via a generated rules.yml under the scan root.
  // runScan() honors `<scanRoot>/.agentic-security/rules.yml#ignorePaths`. We
  // generate it fresh on every run so manifest changes propagate immediately,
  // and clean up after to leave the cache reusable.
  let rulesPath = null;
  if (Array.isArray(app.excludePaths) && app.excludePaths.length) {
    const rulesDir = path.join(scanRoot, '.agentic-security');
    rulesPath = path.join(rulesDir, 'rules.yml');
    await fs.mkdir(rulesDir, { recursive: true });
    // Quote each path so leading `*` isn't parsed as a YAML alias.
    const yml = 'ignorePaths:\n' + app.excludePaths.map(p => `  - ${JSON.stringify(p)}`).join('\n') + '\n';
    await fs.writeFile(rulesPath, yml);
  }

  let expected;
  let wildcardFamilies = [];
  if (app.groundTruth.kind === 'csv') {
    expected = await buildOwaspBenchmarkExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'juliet') {
    expected = await buildJulietExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else {
    const curated = await loadCuratedExpected(name, app.groundTruth.path);
    if (Array.isArray(curated)) { expected = curated; }
    else { expected = curated.expected || []; wildcardFamilies = curated.wildcardFamilies || []; }
  }

  console.error(`  scanning ${scanRoot} (expected: ${expected.length} TPs)`);
  const t0 = Date.now();
  const { scan } = await runScan(scanRoot);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  if (rulesPath) { try { await fs.rm(path.dirname(rulesPath), { recursive: true, force: true }); } catch {} }

  const actual = [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []),
  ];

  const { tps, fps, fns } = score(actual, expected, vulnFamilyMap, scanRoot, wildcardFamilies);
  const tp = tps.length, fp = fps.length, fn = fns.length;
  const precision = tp+fp === 0 ? 1 : tp/(tp+fp);
  const recall    = tp+fn === 0 ? 1 : tp/(tp+fn);
  const fOne      = f1(precision, recall);

  // Per-family breakdown
  const perFamily = {};
  const bump = (fam, k) => { (perFamily[fam] ??= {tp:0,fp:0,fn:0})[k]++; };
  for (const t of tps) bump(t.family, 'tp');
  for (const x of fps) bump(x.family, 'fp');
  for (const x of fns) bump(x.family, 'fn');

  return { name, language: app.language, scanned: actual.length, tp, fp, fn, precision, recall, f1: fOne, perFamily, fps, fns, elapsedSec: parseFloat(elapsed), expectedTotal: expected.length };
}

function printResult(r) {
  console.log(`\n${r.name} (${r.language})`);
  console.log(`  P: ${(r.precision*100).toFixed(1)}%   R: ${(r.recall*100).toFixed(1)}%   F1: ${(r.f1*100).toFixed(1)}%`);
  console.log(`  TP: ${r.tp} / FP: ${r.fp} / FN: ${r.fn}   (expected: ${r.expectedTotal}, scan emitted: ${r.scanned}, ${r.elapsedSec}s)`);
  if (Object.keys(r.perFamily).length) {
    console.log(`  per-family:`);
    for (const [fam, s] of Object.entries(r.perFamily).sort()) {
      const p = s.tp+s.fp===0?1:s.tp/(s.tp+s.fp);
      const rr = s.tp+s.fn===0?1:s.tp/(s.tp+s.fn);
      console.log(`    ${pad(fam, 24)} TP:${pad(s.tp,4)} FP:${pad(s.fp,4)} FN:${pad(s.fn,4)} P:${(p*100).toFixed(0).padStart(3)}%  R:${(rr*100).toFixed(0).padStart(3)}%  F1:${(f1(p,rr)*100).toFixed(0).padStart(3)}%`);
    }
  }
  if (VERBOSE) {
    if (r.fns.length) {
      console.log(`  false negatives (first 20):`);
      for (const f of r.fns.slice(0,20)) console.log(`    ${f.file}:${f.line}  ${f.family}`);
      if (r.fns.length > 20) console.log(`    … and ${r.fns.length - 20} more`);
    }
    if (r.fps.length) {
      const fpLimit = parseInt(process.env.FP_LIMIT || '20');
      console.log(`  false positives (first ${fpLimit}):`);
      for (const f of r.fps.slice(0,fpLimit)) console.log(`    ${f.file}:${f.line}  ${f.family}  ${f.vuln}`);
      if (r.fps.length > fpLimit) console.log(`    … and ${r.fps.length - fpLimit} more`);
    }
  }
}

async function main() {
  const manifest = JSON.parse(await fs.readFile(MANIFEST, 'utf8'));
  const familyMap = await loadFamilyMap();
  const apps = manifest.apps;
  const targets = ALL ? Object.keys(apps) : [APP];
  for (const t of targets) {
    if (!apps[t]) { console.error(`unknown app: ${t} (have: ${Object.keys(apps).join(', ')})`); process.exit(2); }
  }

  const results = [];
  for (const t of targets) {
    try {
      results.push(await runOne(t, apps[t], familyMap));
    } catch (e) {
      console.error(`  FAILED: ${e.message}`);
      results.push({ name: t, error: e.message });
    }
  }

  if (JSON_OUT) {
    console.log(JSON.stringify({ results }, null, 2));
  } else {
    console.log(`\n${'='.repeat(50)}\nReal-world benchmark — ${results.length} app(s)\n${'='.repeat(50)}`);
    for (const r of results) {
      if (r.error) { console.log(`\n${r.name}: ERROR — ${r.error}`); continue; }
      printResult(r);
    }
  }
}

main().catch(e => { console.error(e); process.exit(2); });
