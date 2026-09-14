#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 3 — score the ingested PHP SARD corpus.
// Reads bench/sard/gold/php.json (trusted-only) and bench/sard/workspace/php/
// (scanner-visible, neutralized — see ingest-php.mjs), runs the real scanner
// against each case, and computes TP/FP/FN per CWE + macro/micro F1. Mirrors
// bench-realworld.js's own scoring shape (per-CWE {tp,fp,fn}) so
// macro-score.mjs can consume this output identically to a bench-realworld
// --json run — one report format for both corpora, not two.
//
// Usage:
//   node bench/sard/scripts/score-php.mjs [--deep] [--limit N] [--json] [--split train|dev|test] [--cwe CWE-89,CWE-78]
//   node bench/sard/scripts/score-php.mjs --deep --json | node bench/sard/scripts/macro-score.mjs
//
// --deep enables the IR-taint engine for the run (runScan's own `deep` option,
// the same thing bench-realworld.js's --deep passes for Java/C#). Without it
// the run measures only the regex/structural layers, which is NOT what
// bench:sard:java / bench:sard:csharp measure, so every cross-language
// comparison must pass it. --cwe restricts scoring to the listed CWEs (both
// the bad cases with that CWE and, for FP accounting, the good cases whose
// family set intersects them), mirroring bench-realworld.js's --cwe.
//
// Adversarial-premortem remediation (finding F1.2): every PHP number reported
// anywhere in this ledger to date was fit-and-report on the same undivided
// sample — no split existed for this corpus at all (unlike bench-realworld.js's
// `--split` for Java/C#). ingest-php.mjs now assigns a `split` field per case
// at ingest time (see its own header comment for the family-key derivation,
// which differs from Juliet's since this corpus has no `_NN[ab]` convention);
// `--split` here is the consuming half — filters BEFORE `--limit` so a limited
// run still samples only from the requested split, not the whole corpus.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../../scanner/src/runScan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SARD_ROOT = path.resolve(HERE, '..');
const GOLD_PATH = path.join(SARD_ROOT, 'gold', 'php.json');
const WORKSPACE_ROOT = path.join(SARD_ROOT, 'workspace', 'php');

function args() {
  const a = process.argv.slice(2);
  const out = { limit: null, json: false, split: null, deep: false, cwe: null, fpDetail: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--limit') out.limit = parseInt(a[++i], 10);
    else if (a[i] === '--json') out.json = true;
    else if (a[i] === '--split') out.split = a[++i];
    else if (a[i] === '--deep') out.deep = true;
    else if (a[i] === '--cwe') out.cwe = new Set(String(a[++i]).split(',').map(s => s.trim()).filter(Boolean));
    else if (a[i] === '--fp-detail') out.fpDetail = true;
  }
  if (out.split && !['train', 'dev', 'test'].includes(out.split)) {
    console.error(`✗ --split must be train|dev|test, got: ${out.split}`);
    process.exit(2);
  }
  return out;
}

// Pure, exported for direct unit testing — mirrors bench-realworld.js's own
// `inRequestedSplit` shape (a dedicated testable filter function rather than
// inline logic in main()). An entry with no `split` field is always excluded
// when a split is requested: it was ingested before this feature existed, so
// its bucket is genuinely unknown, not merely unset.
export function filterBySplit(gold, split) {
  if (!split) return gold;
  return gold.filter(g => g.split === split);
}

// Same taxonomy the scanner's own detectors use for `finding.family` /
// `finding.vuln` — best-effort classification from whatever the finding
// carries, mirroring bench-realworld.js's familyForBench() fallback.
function familyOf(finding) {
  if (finding.family) return finding.family;
  const v = String(finding.vuln || finding.cwe || '').toLowerCase();
  if (v.includes('sql')) return 'sql-injection';
  if (v.includes('command') || v.includes('cmdi')) return 'command-injection';
  if (v.includes('xss') || v.includes('cross-site-script')) return 'xss';
  if (v.includes('ldap')) return 'ldap-injection';
  if (v.includes('path') || v.includes('traversal')) return 'path-traversal';
  if (v.includes('redirect')) return 'open-redirect';
  if (v.includes('xpath')) return 'xpath-injection';
  if (v.includes('eval') || v.includes('code-injection') || v.includes('rfi') || v.includes('include')) return 'code-injection';
  if (v.includes('authz') || v.includes('access-control') || v.includes('authorization')) return 'missing-authz';
  return v.replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'unknown';
}

async function main() {
  const opts = args();
  if (!fs.existsSync(GOLD_PATH)) {
    console.error(`✗ ${path.relative(process.cwd(), GOLD_PATH)} not found — run ingest-php.mjs first.`);
    process.exit(2);
  }
  let gold = JSON.parse(fs.readFileSync(GOLD_PATH, 'utf8'));

  if (opts.split) {
    const before = gold.length;
    const noSplitField = gold.filter(g => !g.split).length;
    gold = filterBySplit(gold, opts.split);
    console.error(`  --split ${opts.split}: ${gold.length}/${before} cases kept` +
      (noSplitField ? ` (${noSplitField} of the excluded cases have no split field at all — re-ingest to backfill)` : ''));
  }

  if (opts.cwe) {
    // A good case carries no CWE of its own (state=good has no ruleId), so the
    // CWE filter keeps every good case whose FAMILY is one of the requested
    // CWEs' families: those are the safe variants of exactly the vulnerability
    // classes being scored, which is where the FPs that matter come from.
    const wantedFamilies = new Set(gold.filter(g => g.cwe && opts.cwe.has(g.cwe)).map(g => g.family).filter(Boolean));
    const before = gold.length;
    gold = gold.filter(g => g.state === 'bad' ? opts.cwe.has(g.cwe) : (g.family ? wantedFamilies.has(g.family) : true));
    console.error(`  --cwe ${[...opts.cwe].join(',')}: ${gold.length}/${before} cases kept`);
  }

  if (opts.limit) gold = gold.slice(0, opts.limit);

  // Families this corpus actually exercises: a good case's finding only counts
  // as an FP when it belongs to one of them, so an unrelated detector (e.g.
  // hardcoded-secret firing on an incidental literal) doesn't inflate FP for a
  // family this case was never testing.
  const coveredFamilies = new Set(gold.map(x => x.family).filter(Boolean));

  const perCwe = {};
  const bump = (cwe, k) => { if (!cwe) return; (perCwe[cwe] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  let tp = 0, fp = 0, fn = 0;
  // FP attribution: which detector produced the spurious finding, and what
  // sanitizer (if any) the taint walk saw on the path. A good case in this
  // corpus is almost always a sanitized variant of a bad one, so the
  // sanitizer-on-path breakdown says exactly which sanitizer semantics the
  // engine is getting wrong.
  const fpByParser = {};
  const fpBySanitizer = {};
  const fpDetail = [];
  let deepTierSeen = false;
  const t0 = Date.now();

  for (const g of gold) {
    const caseDir = path.join(WORKSPACE_ROOT, g.caseId);
    if (!fs.existsSync(caseDir)) continue;
    let findings = [];
    try {
      const { scan } = await runScan(caseDir, opts.deep ? { deep: true } : {});
      findings = scan.findings || [];
      if (opts.deep && scan.analysisTier && scan.analysisTier.irTaint) deepTierSeen = true;
    } catch (e) {
      console.error(`  ⚠ ${g.caseId}: scan failed (${e.message})`);
      continue;
    }
    const fams = new Set(findings.map(familyOf));
    if (g.state === 'bad') {
      if (g.family && fams.has(g.family)) { tp++; bump(g.cwe, 'tp'); }
      else { fn++; bump(g.cwe, 'fn'); }
    } else {
      // 'good' case: any covered-family finding at all is a false positive.
      const spurious = findings.filter(f => coveredFamilies.has(familyOf(f)));
      const spuriousFams = new Set(spurious.map(familyOf));
      fp += spuriousFams.size;
      for (const fam of spuriousFams) {
        const first = spurious.find(f => familyOf(f) === fam);
        const parser = first.parser || 'unknown';
        fpByParser[parser] = (fpByParser[parser] || 0) + 1;
        const san = Array.isArray(first._sanitizersOnPath) && first._sanitizersOnPath.length
          ? first._sanitizersOnPath.join('+')
          : (first.sanitized ? 'sanitized-unnamed' : '(none)');
        fpBySanitizer[san] = (fpBySanitizer[san] || 0) + 1;
        if (opts.fpDetail) fpDetail.push({ caseId: g.caseId, family: fam, parser, id: first.id, line: first.line, sanitizers: first._sanitizersOnPath || [], sanitized: !!first.sanitized, proof: first.proof && first.proof.verdict });
      }
    }
  }

  if (opts.deep && !deepTierSeen) {
    console.error('  ⚠ --deep was requested but no scan reported analysisTier.irTaint: the taint engine did not run.');
  }

  const elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : (tp === 0 ? 1 : 0);
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : (tp === 0 ? 1 : 0);
  const f1v = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const result = {
    name: 'sard-php-strict', language: 'php', scanned: gold.length,
    tp, fp, fn, precision, recall, f1: f1v, elapsedSec: parseFloat(elapsedSec), peakRssMb: null,
    perCwe, deep: opts.deep, fpByParser, fpBySanitizer,
    ...(opts.fpDetail ? { fpDetail } : {}),
  };

  if (opts.json) {
    console.log(JSON.stringify({ results: [result] }, null, 2));
  } else {
    console.error(`\nSARD PHP scoring: ${gold.length} cases, ${elapsedSec}s${opts.deep ? ' (deep)' : ''}`);
    console.error(`  TP=${tp} FP=${fp} FN=${fn}  P=${(precision * 100).toFixed(1)}%  R=${(recall * 100).toFixed(1)}%  F1=${(f1v * 100).toFixed(1)}%`);
    console.error(`  per-CWE: ${JSON.stringify(perCwe)}`);
    console.error(`  FP by parser: ${JSON.stringify(fpByParser)}`);
    console.error(`  FP by sanitizer on path: ${JSON.stringify(fpBySanitizer)}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
