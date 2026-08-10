#!/usr/bin/env node
// Polyglot benchmark runner (P1.4 / G3).
//
// For each case under ./cases/<id>/:
//   1. Parse manifest.yaml
//   2. Run the scanner against the case's services/ directory
//   3. Score actual findings vs expected entries (file, line ± tol, family)
//   4. Aggregate per-case and overall F1
//
// CLI:
//   node bench/polyglot/runner.mjs                # all cases
//   node bench/polyglot/runner.mjs --case 01-rest-node-to-python-sql
//   node bench/polyglot/runner.mjs --json         # machine-readable

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../scanner/src/runScan.js';

import { disableStateWrites } from '../_lib/tree-integrity.mjs';
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const CASES_DIR  = path.join(__dirname, 'cases');
const RESULTS_DIR = path.join(__dirname, 'results');

const args = process.argv.slice(2);
const ONE_CASE = (() => { const i = args.indexOf('--case'); return i >= 0 ? args[i + 1] : null; })();
const JSON_OUT = args.includes('--json');
const TOL = 3;  // line tolerance: ±3 lines between expected and actual

// ─── Minimal YAML parser ────────────────────────────────────────────────────
//
// Just enough YAML to parse our manifest.yaml — single document, no anchors,
// no flow style beyond what we write. Keeps the bench dependency-free.

// Minimal YAML parser. Two-pass: first lex into (indent, kind, text), then
// build a tree. This is small + auditable. Handles only the manifest shapes
// we use; do not extend beyond what the bench needs.
function parseYamlSimple(text) {
  const tokens = [];
  for (const raw of text.split(/\r?\n/)) {
    const noComment = raw.replace(/#.*$/, '').trimEnd();
    if (!noComment.trim()) continue;
    const indent = noComment.length - noComment.trimStart().length;
    const stripped = noComment.trim();
    if (stripped.startsWith('- ')) {
      tokens.push({ indent, kind: 'item', text: stripped.slice(2) });
    } else {
      const m = stripped.match(/^([\w.-]+)\s*:\s*(.*)$/);
      if (m) tokens.push({ indent, kind: 'kv', key: m[1], val: m[2] });
    }
  }
  let i = 0;
  function readValue(parentIndent) {
    // Look ahead: array of items OR object of kvs OR scalar (already consumed).
    if (i >= tokens.length) return null;
    const t = tokens[i];
    if (t.indent <= parentIndent) return null;
    if (t.kind === 'item') {
      const arr = [];
      while (i < tokens.length && tokens[i].kind === 'item' && tokens[i].indent === t.indent) {
        const it = tokens[i++];
        const obj = {};
        if (it.text && it.text.includes(':')) {
          const [k, ...rest] = it.text.split(':');
          obj[k.trim()] = _coerceScalar(rest.join(':').trim());
        }
        // Read further kvs nested under this item (indent > it.indent).
        while (i < tokens.length && tokens[i].kind === 'kv' && tokens[i].indent > it.indent) {
          const kv = tokens[i++];
          if (kv.val === '' || kv.val === undefined) {
            obj[kv.key] = readValue(kv.indent);
          } else {
            obj[kv.key] = _coerceScalar(kv.val);
          }
        }
        arr.push(obj);
      }
      return arr;
    }
    if (t.kind === 'kv') {
      const obj = {};
      while (i < tokens.length && tokens[i].kind === 'kv' && tokens[i].indent === t.indent) {
        const kv = tokens[i++];
        if (kv.val === '' || kv.val === undefined) {
          obj[kv.key] = readValue(kv.indent);
        } else {
          obj[kv.key] = _coerceScalar(kv.val);
        }
      }
      return obj;
    }
    return null;
  }
  // Top level: a sequence of kvs at indent 0.
  const root = {};
  while (i < tokens.length && tokens[i].kind === 'kv' && tokens[i].indent === 0) {
    const kv = tokens[i++];
    if (kv.val === '' || kv.val === undefined) {
      root[kv.key] = readValue(kv.indent);
    } else {
      root[kv.key] = _coerceScalar(kv.val);
    }
  }
  return root;
}

function _coerceScalar(s) {
  if (s === undefined || s === null) return null;
  s = String(s).trim();
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d*\.\d+$/.test(s)) return parseFloat(s);
  // Strip surrounding quotes
  if (/^".*"$/.test(s)) return s.slice(1, -1);
  if (/^'.*'$/.test(s)) return s.slice(1, -1);
  return s;
}

// ─── Per-case scoring ───────────────────────────────────────────────────────

function familyOf(f) {
  return f.family || _slug(f.vuln || '');
}
function _slug(v) {
  return String(v).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40);
}

function score(actual, expected) {
  const tps = []; const fps = []; const fns = [];
  const consumed = new Set();
  for (const e of expected) {
    let matched = false;
    for (let i = 0; i < actual.length; i++) {
      if (consumed.has(i)) continue;
      const a = actual[i];
      const aFile = a.file || a.sink?.file || '';
      const aLine = a.line || a.sink?.line || 0;
      if (!aFile.endsWith(e.file) && aFile !== e.file) continue;
      if (Math.abs(aLine - e.line) > TOL) continue;
      const aFam = familyOf(a);
      if (aFam !== e.family) continue;
      // cross_language is an optional gate: if expected requires it, actual must agree.
      if (e.cross_language === true && a.cross_language !== true) continue;
      consumed.add(i);
      tps.push(e);
      matched = true;
      break;
    }
    if (!matched) fns.push(e);
  }
  for (let i = 0; i < actual.length; i++) {
    if (consumed.has(i)) continue;
    const a = actual[i];
    fps.push({ file: a.file || a.sink?.file || '', line: a.line || a.sink?.line || 0, family: familyOf(a), vuln: a.vuln });
  }
  return { tps, fps, fns };
}

function f1(p, r) { if (p + r === 0) return 0; return (2 * p * r) / (p + r); }

// ─── Driver ──────────────────────────────────────────────────────────────────

async function listCases() {
  const entries = await fs.readdir(CASES_DIR, { withFileTypes: true });
  return entries.filter(e => e.isDirectory()).map(e => e.name).sort();
}

async function runCase(caseName) {
  const dir = path.join(CASES_DIR, caseName);
  const manifestPath = path.join(dir, 'manifest.yaml');
  const yaml = await fs.readFile(manifestPath, 'utf8').catch(() => null);
  if (!yaml) return { case: caseName, error: `manifest.yaml missing at ${manifestPath}` };
  const manifest = parseYamlSimple(yaml);
  const expected = Array.isArray(manifest.expected) ? manifest.expected : [];
  // Polyglot bench measures CROSS-LANGUAGE propagation — does the chain fire
  // where it should? Incidental single-language findings (header-hardening,
  // CSRF on test routes, body-parser DoS warnings) are noise for this bench's
  // purpose. By default, `mode: 'recall-only'` makes the bench score recall
  // (did we find every expected entry?) and ignore unmatched extras. Set
  // `mode: 'strict'` in the manifest to count extras as FPs.
  const mode = manifest.mode || 'recall-only';
  // Scan the case's directory.
  const { scan } = await runScan(dir);
  const actual = [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
  ];
  const { tps, fps, fns } = score(actual, expected);
  const effectiveFps = mode === 'strict' ? fps : [];
  const precision = tps.length + effectiveFps.length === 0 ? 1 : tps.length / (tps.length + effectiveFps.length);
  const recall    = tps.length + fns.length === 0 ? 1 : tps.length / (tps.length + fns.length);
  return {
    case: caseName,
    description: manifest.description || '',
    mode,
    expectedTotal: expected.length,
    tp: tps.length, fp: effectiveFps.length, fn: fns.length,
    incidental: mode === 'strict' ? 0 : fps.length,
    precision, recall, f1: f1(precision, recall),
    fps: effectiveFps, fns,
  };
}

async function main() {
  // STATE_SEAM_COMPLETION_PRD M3 — a benchmark must not mutate what it measures.
  // Every runner disables state writing; runners with a well-defined corpus
  // directory additionally assert byte-identity (see bench/cve-replay/runner.mjs).
  await disableStateWrites();
  await fs.mkdir(RESULTS_DIR, { recursive: true });
  const all = await listCases();
  const targets = ONE_CASE ? [ONE_CASE] : all;
  if (ONE_CASE && !all.includes(ONE_CASE)) {
    console.error(`bench:polyglot: no case named ${ONE_CASE}. Known: ${all.join(', ')}`);
    process.exit(2);
  }
  const results = [];
  for (const c of targets) {
    const r = await runCase(c);
    results.push(r);
  }
  // Aggregate
  let TP = 0, FP = 0, FN = 0;
  for (const r of results) {
    if (r.error) continue;
    TP += r.tp; FP += r.fp; FN += r.fn;
  }
  const overall = {
    cases: results.length,
    tp: TP, fp: FP, fn: FN,
    precision: TP + FP === 0 ? 1 : TP / (TP + FP),
    recall:    TP + FN === 0 ? 1 : TP / (TP + FN),
  };
  overall.f1 = f1(overall.precision, overall.recall);

  // Persist
  const out = { ts: new Date().toISOString(), overall, results };
  await fs.writeFile(path.join(RESULTS_DIR, 'latest.json'), JSON.stringify(out, null, 2));

  if (JSON_OUT) {
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log('');
    console.log(`Polyglot benchmark — ${results.length} case(s)`);
    console.log(`Overall: TP=${TP} FP=${FP} FN=${FN}  P=${(overall.precision*100).toFixed(1)}%  R=${(overall.recall*100).toFixed(1)}%  F1=${(overall.f1*100).toFixed(1)}%`);
    console.log('');
    for (const r of results) {
      if (r.error) { console.log(`  ${r.case}: ERROR ${r.error}`); continue; }
      console.log(`  ${r.case.padEnd(40)}  TP=${r.tp} FP=${r.fp} FN=${r.fn}  F1=${(r.f1*100).toFixed(1)}%`);
      if (r.fps.length || r.fns.length) {
        for (const fp of r.fps) console.log(`    [FP] ${fp.file}:${fp.line} ${fp.family} — ${fp.vuln}`);
        for (const fn of r.fns) console.log(`    [FN] ${fn.file}:${fn.line} ${fn.family} (expected)`);
      }
    }
  }
  // Floor enforcement. The PRD G3 TARGET is F1 ≥ 0.85, achievable once Phase
  // 2 cross-asset detectors and Python SAST coverage land. v1 ships with a
  // softer floor so the bench can run on every PR without false-failing the
  // build while the detectors are still being filled in. Override via
  // POLYGLOT_F1_FLOOR=0.85 (or any other threshold).
  const FLOOR = parseFloat(process.env.POLYGLOT_F1_FLOOR || '0.30');
  const G3_TARGET = 0.85;
  if (overall.f1 + 1e-6 < FLOOR) {
    console.error(`\nFAIL: polyglot F1 ${(overall.f1*100).toFixed(1)}% below floor ${(FLOOR*100).toFixed(0)}%`);
    process.exit(1);
  }
  if (overall.f1 + 1e-6 < G3_TARGET) {
    console.error(`\nWARN: polyglot F1 ${(overall.f1*100).toFixed(1)}% below PRD G3 target ${(G3_TARGET*100).toFixed(0)}% — gaps:`);
    for (const r of results) {
      if (r.error || r.f1 >= G3_TARGET) continue;
      for (const fn of r.fns) console.error(`  [MISS] ${r.case}: ${fn.file}:${fn.line} ${fn.family}`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(2); });
