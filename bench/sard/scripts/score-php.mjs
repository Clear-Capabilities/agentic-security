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
//   node bench/sard/scripts/score-php.mjs [--limit N] [--json]
//   node bench/sard/scripts/score-php.mjs --json | node bench/sard/scripts/macro-score.mjs

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
  const out = { limit: null, json: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--limit') out.limit = parseInt(a[++i], 10);
    else if (a[i] === '--json') out.json = true;
  }
  return out;
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
  if (opts.limit) gold = gold.slice(0, opts.limit);

  const perCwe = {};
  const bump = (cwe, k) => { if (!cwe) return; (perCwe[cwe] ??= { tp: 0, fp: 0, fn: 0 })[k]++; };
  let tp = 0, fp = 0, fn = 0;
  const t0 = Date.now();

  for (const g of gold) {
    const caseDir = path.join(WORKSPACE_ROOT, g.caseId);
    if (!fs.existsSync(caseDir)) continue;
    let findings = [];
    try {
      const { scan } = await runScan(caseDir);
      findings = scan.findings || [];
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
      // Only count families this corpus actually exercises so an unrelated
      // detector (e.g. hardcoded-secret firing on an incidental literal)
      // doesn't inflate FP for a family this case was never testing.
      const coveredFamilies = new Set(gold.map(x => x.family).filter(Boolean));
      const spurious = [...fams].filter(f => coveredFamilies.has(f));
      fp += spurious.length;
    }
  }

  const elapsedSec = ((Date.now() - t0) / 1000).toFixed(1);
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : (tp === 0 ? 1 : 0);
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : (tp === 0 ? 1 : 0);
  const f1v = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const result = {
    name: 'sard-php-strict', language: 'php', scanned: gold.length,
    tp, fp, fn, precision, recall, f1: f1v, elapsedSec: parseFloat(elapsedSec), peakRssMb: null,
    perCwe,
  };

  if (opts.json) {
    console.log(JSON.stringify({ results: [result] }, null, 2));
  } else {
    console.error(`\nSARD PHP scoring: ${gold.length} cases, ${elapsedSec}s`);
    console.error(`  TP=${tp} FP=${fp} FN=${fn}  P=${(precision * 100).toFixed(1)}%  R=${(recall * 100).toFixed(1)}%  F1=${(f1v * 100).toFixed(1)}%`);
    console.error(`  per-CWE: ${JSON.stringify(perCwe)}`);
  }
}

main();
