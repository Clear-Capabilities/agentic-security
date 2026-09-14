#!/usr/bin/env node
// SARD_80_F1_SCANNER_PRD.md adversarial-premortem remediation, P2 item 11 —
// "no baseline/ablation exists... a reader has no way to tell whether 45.6%
// Java macro-F1 represents a sophisticated taint engine or a handful of
// high-recall pattern matches on a benchmark with generous partial credit."
//
// This is that floor: a deliberately naive, taint-BLIND regex sweep for a
// handful of well-known dangerous sink API SHAPES (Statement.executeQuery,
// Runtime.exec, new File(...), response.getWriter().write) — no parsing, no
// taint tracking, no receiver-type checks, no sanitizer awareness. It fires
// on EVERY occurrence of the shape regardless of whether anything tainted
// reaches it. This is intentionally worse than the real scanner in every way
// that matters for precision; the point is only to give macro-F1 a floor a
// reader can sanity-check the real number against.
//
// Scope, disclosed not hidden: Java only (the most-measured SARD language),
// 4 families (sql-injection, command-injection, path-traversal, xss) — the
// four with unambiguous single-API sink shapes in this corpus, per
// CWE_TO_FAMILY below. Extending to C#/PHP or more families is legitimate
// future work, not attempted here.
//
// Usage:
//   node bench/sard/scripts/naive-baseline.mjs --split test
//   node bench/sard/scripts/naive-baseline.mjs --split test --json | node macro-score.mjs

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findJavaMethodSpans, scoreLegacy } from '../../../scanner/test/benchmark/realworld/bench-realworld.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CACHE_ROOT = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', '.bench-cache');
const SPLITS_DIR = path.join(HERE, '..', 'splits');
const APP = 'sard-juliet-java-strict';
const SHA = '8b5b9d6edf20482abef09bf9300600556ba4e4b0'; // pinned in manifest.json; kept in sync manually — this is a small standalone tool, not the main harness.

// Deliberately crude: ONE regex per family, no receiver scoping, no
// argument-position awareness, no sanitizer recognition. Fires on the bare
// SHAPE.
// The `cwe` tag here is only ever the naive detector's OWN claim (reported
// on an unmatched finding as-is) — TP/FN matching below is by FAMILY, never
// by this tag, so it doesn't affect P/R/F1. It DOES mean the per-CWE
// breakdown for a family spanning two real CWE numbers (this corpus uses
// BOTH CWE22 and CWE23 for path-traversal, BOTH CWE79 and CWE80 for XSS)
// looks lopsided — one real CWE's row absorbs every genuine match, the
// other absorbs every excess/unmatched naive finding, an artifact of this
// tool picking one label per family, not a scoring bug. Disclosed, not
// fixed: resolving it would mean giving the naive detector real CWE-number
// disambiguation logic, which is exactly the sophistication this tool is
// deliberately built without.
const NAIVE_SINKS = [
  { re: /\.execute(?:Query|Update)?\s*\(/, family: 'sql-injection', cwe: 'CWE89' },
  { re: /Runtime\.getRuntime\(\)\.exec\s*\(/, family: 'command-injection', cwe: 'CWE78' },
  { re: /new\s+File(?:Reader|InputStream)?\s*\(/, family: 'path-traversal', cwe: 'CWE22' },
  { re: /\.getWriter\(\)\.(?:write|print)\s*\(/, family: 'xss', cwe: 'CWE79' },
];

function args() {
  const a = process.argv.slice(2);
  const out = { split: null, json: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--split') out.split = a[++i];
    else if (a[i] === '--json') out.json = true;
  }
  return out;
}

function walkJavaFiles(root) {
  const files = [];
  (function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (/\.java$/i.test(e.name) && !/^Test|TestCase\.java$/.test(e.name)) files.push(p);
    }
  })(root);
  return files;
}

// A minimal, self-contained "expected" builder — deliberately NOT importing
// bench-realworld.js's own buildJulietExpected (kept private there): this is
// a standalone comparison tool, and duplicating this ~15-line convention
// here is safer than widening that file's export surface for a baseline
// script nothing else depends on. Same Bad()-method convention, same
// family scope as NAIVE_SINKS above.
// Both CWE numbers per family: Java's real corpus (confirmed by directory
// listing this session) uses CWE23 for path-traversal (not CWE22) and
// CWE80 for XSS (not CWE79) — matching manifest.json's own cweToFamily map
// for sard-juliet-java-strict exactly, not guessed.
const CWE_TO_FAMILY = {
  CWE89: 'sql-injection',
  CWE78: 'command-injection',
  CWE22: 'path-traversal', CWE23: 'path-traversal',
  CWE79: 'xss', CWE80: 'xss',
};

function buildExpected(root, splitDoc, requestedSplit) {
  const expected = [];
  const cwes = Object.keys(CWE_TO_FAMILY);
  // Java Juliet's real layout (confirmed by direct inspection this session —
  // different from C#'s src/testcases/CWE<N>_.../ convention):
  // juliet-cwe<N>/src/main/java/... — matches bench-realworld.js's own
  // buildJulietExpected, duplicated here per this file's header comment.
  for (const cweDirName of fs.readdirSync(root)) {
    const m = cweDirName.match(/^juliet-cwe(\d+)$/i);
    if (!m || !cwes.includes(`CWE${m[1]}`)) continue;
    const cwe = `CWE${m[1]}`;
    const family = CWE_TO_FAMILY[cwe];
    const cweDir = path.join(root, cweDirName, 'src', 'main', 'java');
    if (!fs.existsSync(cweDir)) continue;
    for (const file of walkJavaFiles(cweDir)) {
      const rel = path.relative(root, file);
      if (requestedSplit && splitDoc) {
        const base = path.basename(rel).replace(/\.java$/i, '').replace(/_\d{2}[ab]?$/i, '');
        if (splitDoc.families[base] !== requestedSplit) continue;
      }
      const content = fs.readFileSync(file, 'utf8');
      const methods = findJavaMethodSpans(content);
      for (const meth of methods) {
        if (!/^(?:bad|badSink|badSource|bad\d+)$/.test(meth.name)) continue;
        expected.push({ file: rel, line: meth.startLine, lineEnd: meth.endLine, lineTolerance: 0, matchAny: true, family, cwe });
      }
    }
  }
  return expected;
}

function scanNaive(root, files) {
  const actual = [];
  for (const file of files) {
    const rel = path.relative(root, file);
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const sink of NAIVE_SINKS) {
        if (sink.re.test(lines[i])) actual.push({ file: rel, line: i + 1, vuln: sink.family, cwe: sink.cwe });
      }
    }
  }
  return actual;
}

function main() {
  const opts = args();
  // Plain -blinded (FLAW/OWASP markers stripped), NOT -blinded-scrambled:
  // --scramble-identifiers renames Bad()/BadSink() to an opaque op0_<hash>
  // name (bench-realworld.js's own _blindTransform), which would make
  // findJavaMethodSpans's isBad() regex match nothing at all — confirmed the
  // hard way (0 expected entries) before finding this. The naive baseline
  // doesn't need identifier-scrambling protection anyway: its regex matches
  // framework API shapes (`.execute(`, `Runtime.getRuntime().exec(`), never
  // user identifiers, so scrambling protects against nothing here.
  const root = path.join(CACHE_ROOT, `${APP}-${SHA}-blinded`);
  if (!fs.existsSync(root)) {
    console.error(`✗ corpus not found at ${root} — run a real bench-realworld.js scan for ${APP} --blind first (it clones/blinds on demand).`);
    process.exit(2);
  }
  let splitDoc = null;
  if (opts.split) {
    const splitPath = path.join(SPLITS_DIR, `${APP}.json`);
    if (!fs.existsSync(splitPath)) { console.error(`✗ no split file at ${splitPath} — run split.mjs first.`); process.exit(2); }
    splitDoc = JSON.parse(fs.readFileSync(splitPath, 'utf8'));
  }

  const expected = buildExpected(root, splitDoc, opts.split);
  const files = walkJavaFiles(root);
  let actual = scanNaive(root, files);
  // Symmetric with the expected-side filter above (same reasoning
  // bench-realworld.js's own --split documents): a naive finding in a file
  // whose family isn't in the requested split has no expected entry left to
  // match, and would silently inflate FP for a reason that has nothing to
  // do with detection quality.
  if (opts.split && splitDoc) {
    actual = actual.filter(a => {
      const base = path.basename(a.file).replace(/\.java$/i, '').replace(/_\d{2}[ab]?$/i, '');
      return splitDoc.families[base] === opts.split;
    });
  }
  const { tps, fps, fns } = scoreLegacy(actual, expected, {}, []);
  const tp = tps.length, fp = fps.length, fn = fns.length;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = (precision + recall) === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  const perCwe = {};
  const bump = (cwe, k) => { (perCwe[cwe] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  for (const t of tps) bump(t.cwe, 'tp');
  // FP entries from scoreLegacy() carry the finding's CWE as `reportedCwe`,
  // never a bare `cwe` field (`cwe` on an expected/fn entry is the GT's
  // answer; there is no equivalent concept for an unmatched actual finding)
  // — this exact field-name mismatch was found, independently, THREE times
  // in this codebase's history (an earlier session's own ledger entry, this
  // session's C# investigation, and here) before being fixed at the source
  // in bench-realworld.js's runOne(). Naming it correctly here too so this
  // script doesn't reintroduce the same defect a fourth time.
  for (const x of fps) bump(x.reportedCwe, 'fp');
  for (const x of fns) bump(x.cwe, 'fn');

  const result = {
    // -strict suffix: bench-realworld.js's/macro-score.mjs's own isStrictApp
    // checks this to decide whether to print the wildcardFamilies/file-level
    // caveat. This result IS genuine vulnerability-level (per-Bad()-method)
    // scoring, not wildcard/file-level matching, so it should be labeled
    // that way rather than triggering a caveat that doesn't apply to it.
    name: 'sard-java-naive-baseline-strict', language: 'java', scanned: actual.length,
    tp, fp, fn, precision, recall, f1, elapsedSec: 0, peakRssMb: null, perCwe,
  };

  if (opts.json) {
    console.log(JSON.stringify({ results: [result] }));
  } else {
    console.error(`\nJava naive baseline (regex sink-name only, no taint)${opts.split ? ` [--split ${opts.split}]` : ''}: ${expected.length} expected, ${actual.length} naive findings`);
    console.error(`  TP=${tp} FP=${fp} FN=${fn}  P=${(precision * 100).toFixed(1)}%  R=${(recall * 100).toFixed(1)}%  F1=${(f1 * 100).toFixed(1)}%`);
    console.error(`  This is a FLOOR, not a target — a real scanner scoring near this number on the same split would mean it isn't doing much beyond pattern-matching sink names.`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
