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
// --no-wildcards: ignore the wildcardFamilies relaxation. Produces the
// strict-label F1 that an external auditor would expect "F1 100%" to mean.
const NO_WILDCARDS = flag('--no-wildcards');

if (!ALL && !APP) {
  console.error('Usage: bench-realworld.js [--all | --app <name>] [--refresh-cache] [--json] [--verbose] [--no-wildcards]');
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
    // Branch / tag / HEAD refs: clone the specific ref shallowly. Full SHAs
    // require a deep-enough clone, so we fall back to depth 100.
    const isFullSha = /^[a-f0-9]{40}$/.test(sha);
    const isHead = sha === 'HEAD' || sha === 'main' || sha === 'master';
    if (isHead) {
      sh('git', ['clone', '--quiet', '--depth', '1', repo, dest]);
    } else if (isFullSha) {
      sh('git', ['clone', '--quiet', '--depth', '100', repo, dest]);
      sh('git', ['-C', dest, 'checkout', '--quiet', sha]);
    } else {
      // Branch or tag name. Use --branch to clone directly at the ref.
      try {
        sh('git', ['clone', '--quiet', '--depth', '1', '--branch', sha, repo, dest]);
      } catch (_) {
        // Some hosts reject --branch <tag>; fall back to full clone + checkout.
        await fs.rm(dest, { recursive: true, force: true });
        sh('git', ['clone', '--quiet', repo, dest]);
        sh('git', ['-C', dest, 'checkout', '--quiet', sha]);
      }
    }
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
// Build expected[] for the NIST SARD Juliet C/C++ suite. Layout differs from
// the Java mirror: `testcases/CWE<N>_<name>/<TestFile>.c` (no juliet-cwe<N>
// gradle modules; flat dir per CWE). Some CWEs nest further into per-variant
// subdirectories (e.g. CWE190/s01..s06). We walk all .c / .cpp files under
// each known CWE directory and emit one expected entry per file.
async function buildJulietCppExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const precise = !!gt.preciseMethodScoring;
  const root = path.join(repoRoot, 'testcases');
  let entries;
  try { entries = await fs.readdir(root, { withFileTypes: true }); }
  catch { return expected; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const m = e.name.match(/^CWE(\d+)_/);
    if (!m) continue;
    const cwe = `CWE${m[1]}`;
    const family = cweMap[cwe];
    if (!family) continue;
    async function walk(dir) {
      let dEntries;
      try { dEntries = await fs.readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const f of dEntries) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) { await walk(p); continue; }
        if (!/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(f.name)) continue;
        // Skip header-only test files; the engine skips pure declaration
        // headers via the same heuristic in cpp.js.
        if (/^main_linux\.c|main\.c|std_thread\.c$/i.test(f.name)) continue;
        const rel = path.relative(repoRoot, p);
        if (precise) {
          // Per-method GT: extract _bad()/_good*() spans. Emissions inside
          // _bad() count as TPs; emissions in _good*() count as FPs.
          let content = '';
          try { content = await fs.readFile(p, 'utf8'); } catch { /* skip */ }
          if (!content) continue;
          const methods = findCppMethodSpans(content);
          let anyEmitted = false;
          for (const meth of methods) {
            // Juliet C/C++ naming: <case>_bad / <case>_goodG2B / <case>_goodB2G / <case>_good.
            // _bad and _goodG2B (good source → bad sink) should fire.
            // _good and _goodB2G should NOT fire.
            const isBad = /_bad$/.test(meth.name) || /_goodG2B(?:\d*)$/.test(meth.name);
            if (isBad) {
              expected.push({
                file: rel,
                line: meth.startLine,
                lineEnd: meth.endLine,
                lineTolerance: 0,
                matchAny: true,
                family,
                cwe,
                method: meth.name,
              });
              anyEmitted = true;
            }
          }
          if (!anyEmitted) {
            expected.push({ file: rel, line: 1, lineTolerance: 9999, matchAny: true, family, cwe });
          }
        } else {
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
    }
    await walk(path.join(root, e.name));
  }
  return expected;
}

// Walk a C/C++ file and extract { name, startLine, endLine } for each
// function definition using brace-counting. Sufficient for Juliet's
// template-generated files where each test has clearly-delimited
// `<case>_bad` / `<case>_goodG2B` / `<case>_goodB2G` / `<case>_good`
// functions with no preprocessor obfuscation in the body.
function findCppMethodSpans(content) {
  const methods = [];
  // Match: optional storage qualifiers + return type + identifier + params + opening brace.
  // Keep the regex permissive — Juliet uses a small subset of C/C++ types in test files.
  const declRe = /^(?:[ \t]*(?:static|extern|inline|void|int|char|long|short|float|double|unsigned|signed|size_t|ssize_t|FILE|bool|wchar_t|HANDLE|struct\s+\w+|[A-Za-z_]\w*\s*\*?)\s+)+(\w+)\s*\([^)]*\)\s*\{/gm;
  let m;
  while ((m = declRe.exec(content))) {
    const name = m[1];
    if (name === 'if' || name === 'while' || name === 'for' || name === 'switch' || name === 'sizeof' || name === 'return') continue;
    const openIdx = m.index + m[0].length - 1;
    let depth = 1, i = openIdx + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '"' || ch === "'") {
        const quote = ch; i++;
        while (i < content.length && content[i] !== quote) {
          if (content[i] === '\\') i += 2; else i++;
        }
        i++; continue;
      }
      if (ch === '/' && content[i + 1] === '/') {
        while (i < content.length && content[i] !== '\n') i++;
        continue;
      }
      if (ch === '/' && content[i + 1] === '*') {
        i += 2;
        while (i < content.length - 1 && !(content[i] === '*' && content[i + 1] === '/')) i++;
        i += 2; continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const startLine = content.substring(0, m.index).split('\n').length;
    const endLine = content.substring(0, i).split('\n').length;
    methods.push({ name, startLine, endLine });
  }
  return methods;
}

// Walk a Java file and extract { name, startLine, endLine } for each method
// using brace-counting. Cheap regex-based parser — sufficient for Juliet's
// template-generated files which have predictable structure (no string-literal
// brace surprises in method bodies because Juliet comments are sanitized
// during template generation). Returns ALL methods, not just bad/good*.
function findJavaMethodSpans(content) {
  const methods = [];
  const declRe = /^\s*(?:public|private|protected|static|\s)+(?:void|String|int|long|short|byte|boolean|float|double|Object|[A-Z][\w<>,\s.\[\]]*)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s.]+)?\s*\{/gm;
  let m;
  while ((m = declRe.exec(content))) {
    const name = m[1];
    if (name === 'class' || name === 'if' || name === 'while' || name === 'for' || name === 'switch') continue;
    const openIdx = m.index + m[0].length - 1; // position of '{'
    let depth = 1, i = openIdx + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '"' || ch === "'") {
        // Skip string literal — Juliet's generated files don't have braces in
        // strings, but other Java code might. Conservative skip.
        const quote = ch; i++;
        while (i < content.length && content[i] !== quote) {
          if (content[i] === '\\') i += 2; else i++;
        }
        i++; continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const startLine = content.substring(0, m.index).split('\n').length + (content.substring(m.index).match(/^\s*\n/) ? 1 : 0);
    const endLine = content.substring(0, i).split('\n').length;
    methods.push({ name, startLine, endLine });
  }
  return methods;
}

async function buildJulietExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const ignoredDirs = new Set(['juliet-support', 'gradle', 'build']);
  const precise = !!gt.preciseMethodScoring;
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
        if (precise) {
          // Per-method GT: extract bad/badSink method spans and emit one
          // expected entry per method with a line range. Engine emissions
          // INSIDE the bad() range count as TPs; emissions in good*() ranges
          // (which are intentionally sanitized) count as FPs — exposing the
          // engine's true precision rather than masking it with file-level GT.
          // goodG2B() pairs a good source with a bad sink — engine WILL fire
          // there legitimately, so we include it as TP-eligible.
          let content = '';
          try { content = await fs.readFile(p, 'utf8'); } catch { /* skip */ }
          if (!content) continue;
          const methods = findJavaMethodSpans(content);
          let anyEmitted = false;
          for (const meth of methods) {
            const isBad = /^(?:bad|badSink|badSource|bad\d+)$/.test(meth.name);
            const isGoodG2B = /^(?:goodG2B|goodG2B\d*)$/.test(meth.name);
            if (isBad || isGoodG2B) {
              expected.push({
                file: rel,
                line: meth.startLine,
                lineEnd: meth.endLine,
                lineTolerance: 0,
                matchAny: true,
                family,
                cwe,
                method: meth.name,
              });
              anyEmitted = true;
            }
            // good() / goodB2G() / goodSource — intentionally sanitized OR
            // pair good source with good sink. Emissions inside these ranges
            // are FPs (no expected entry covers them).
          }
          // Fallback: if no method spans found (unusual file shape), keep the
          // flat per-file entry to avoid silent recall loss.
          if (!anyEmitted) {
            expected.push({ file: rel, line: 1, lineTolerance: 9999, matchAny: true, family, cwe });
          }
        } else {
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
  // Perf: index actuals by basename for O(1) lookup instead of O(A) scan per
  // expected entry. With 55k expected × 87k actuals this drops 4.8B ops to
  // ~150k. Each actual is also cached with its precomputed file/line/family
  // to avoid recomputing in the hot loop.
  const actualByBase = new Map(); // basename → [indices]
  const actualMeta = new Array(actual.length); // {file, base, line, fam}
  for (let i = 0; i < actual.length; i++) {
    const a = actual[i];
    const aFile = fileOf(a);
    const base = aFile.replace(/\\/g,'/').split('/').slice(-1)[0];
    const meta = { file: aFile, base, line: lineOf(a), fam: familyForBench(a.vuln, vulnFamilyMap, a), vuln: a.vuln };
    actualMeta[i] = meta;
    if (!actualByBase.has(base)) actualByBase.set(base, []);
    actualByBase.get(base).push(i);
  }
  // First pass: wildcardFamilies — credit every actual finding whose family is
  // listed (advisory rules that fire correctly across many files; we don't
  // track them per-line).
  if (wildSet.size) {
    for (let i = 0; i < actual.length; i++) {
      const meta = actualMeta[i];
      if (wildSet.has(meta.fam)) {
        consumed.add(i);
        tps.push({ family: meta.fam, file: meta.file, line: meta.line, wildcard: true, matchedVuln: meta.vuln });
      }
    }
  }
  // Second pass: match expected entries normally — O(E + sum-of-basename-buckets)
  for (const e of expected) {
    const tol = typeof e.lineTolerance === 'number' ? e.lineTolerance : LINE_TOLERANCE;
    let matched = false;
    const baseE = e.file.replace(/\\/g,'/').split('/').slice(-1)[0];
    const candidates = actualByBase.get(baseE) || [];
    for (const i of candidates) {
      if (consumed.has(i)) continue;
      const meta = actualMeta[i];
      // Match either by basename (already filtered) or by suffix path.
      if (meta.base !== baseE && !meta.file.endsWith('/' + e.file)) continue;
      const aLine = meta.line;
      // Range match (per-method Juliet GT): match if aLine ∈ [e.line, e.lineEnd].
      // Otherwise fall back to point match within tolerance.
      if (typeof e.lineEnd === 'number' && e.lineEnd >= e.line) {
        if (aLine < e.line || aLine > e.lineEnd) continue;
      } else if (Math.abs(aLine - e.line) > tol) continue;
      if (meta.fam !== e.family) continue;
      consumed.add(i);
      tps.push({ ...e, matchedVuln: meta.vuln });
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
    const meta = actualMeta[i];
    fps.push({ file: meta.file, line: meta.line, family: meta.fam, vuln: meta.vuln });
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
  } else if (app.groundTruth.kind === 'juliet-c-cpp') {
    expected = await buildJulietCppExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else {
    const curated = await loadCuratedExpected(name, app.groundTruth.path);
    if (Array.isArray(curated)) { expected = curated; }
    else { expected = curated.expected || []; wildcardFamilies = curated.wildcardFamilies || []; }
  }
  // --no-wildcards: strip the relaxation and report strict-label F1.
  if (NO_WILDCARDS) wildcardFamilies = [];

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

  const auditorVerified = !!(app.groundTruth && app.groundTruth.auditorVerified);
  return { name, language: app.language, scanned: actual.length, tp, fp, fn, precision, recall, f1: fOne, perFamily, fps, fns, elapsedSec: parseFloat(elapsed), expectedTotal: expected.length, auditorVerified };
}

function printResult(r) {
  const auditorTag = r.auditorVerified ? '  [auditor-verified GT]' : '';
  console.log(`\n${r.name} (${r.language})${auditorTag}`);
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
  const INCLUDE_QUARANTINED = flag('--include-quarantined');
  const targets = ALL
    ? Object.keys(apps).filter(name => INCLUDE_QUARANTINED || !apps[name]._quarantined)
    : [APP];
  for (const t of targets) {
    if (!apps[t]) { console.error(`unknown app: ${t} (have: ${Object.keys(apps).join(', ')})`); process.exit(2); }
  }

  const results = [];
  for (const t of targets) {
    try {
      const r = await runOne(t, apps[t], familyMap);
      r.quarantined = !!apps[t]._quarantined;
      r.mode = apps[t].mode || 'strict';
      results.push(r);
    } catch (e) {
      console.error(`  FAILED: ${e.message}`);
      results.push({ name: t, error: e.message, quarantined: !!apps[t]._quarantined });
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
    // Auditor-verified summary: dual F1 numbers when running --all.
    if (targets.length > 1) {
      const ok = results.filter(r => !r.error);
      const aud = ok.filter(r => r.auditorVerified);
      const all = ok;
      function agg(rs) {
        if (!rs.length) return null;
        const at100 = rs.filter(r => r.f1 >= 0.9999).length;
        const avgF1 = rs.reduce((s, r) => s + r.f1, 0) / rs.length;
        const lowest = rs.reduce((a, b) => (a.f1 < b.f1 ? a : b));
        return { count: rs.length, at100, avgF1, lowest };
      }
      const aAgg = agg(aud);
      const fAgg = agg(all);
      console.log(`\n${'='.repeat(50)}\nSummary\n${'='.repeat(50)}`);
      if (aAgg) {
        console.log(`Auditor-verified GT subset (${aAgg.count} apps): ${aAgg.at100}/${aAgg.count} at 100% F1, avg ${(aAgg.avgF1*100).toFixed(1)}%, lowest ${aAgg.lowest.name} ${(aAgg.lowest.f1*100).toFixed(1)}%`);
      }
      if (fAgg) {
        console.log(`Full benchmark (${fAgg.count} apps):              ${fAgg.at100}/${fAgg.count} at 100% F1, avg ${(fAgg.avgF1*100).toFixed(1)}%, lowest ${fAgg.lowest.name} ${(fAgg.lowest.f1*100).toFixed(1)}%`);
      }
      console.log(`The auditor-verified subset is the defensible outside claim — every entry traces to an upstream artifact rather than engine-driven curation.`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(2); });
