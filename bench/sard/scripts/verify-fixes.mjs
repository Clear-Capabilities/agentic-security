#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 8 (§28-33) — fix generation + independent
// verification for real Juliet Java findings.
//
// FIX ISOLATION (PRD §29), by construction, not by discipline: the only
// input to fix synthesis is `synthesizeDeterministicPatch(finding,
// fileContent)` — the finding this session's own fresh scan produced, and
// the CURRENT (vulnerable) file content. Nothing here ever reads a Juliet
// `good()`/`goodG2B()` method, an expected-patch answer key, or any gold
// data — those aren't even loaded by this script. This is the same
// deterministic autofix path `synthesize_fix`/`apply_fix` (scanner/src/mcp/)
// use in production, exercised directly rather than duplicated.
//
// WHY DETERMINISTIC-FIX, NOT AN LLM: this environment has no
// AGENTIC_SECURITY_LLM_ENDPOINT configured, so LLM-based fix generation is
// not available to exercise here (and would not be reproducible/offline if
// it were). `deterministic-fix.js` covered ZERO Java findings before this
// session (its `applies()` gates matched Java CWEs but `transform()` had no
// Java branch at all — a real, general gap, now fixed for weak-hash). This
// script can therefore only produce PROVEN_FIXED/PROVEN_VULNERABLE verdicts
// for the CWE families deterministic-fix.js actually covers (today:
// weak-hash, CWE-327/328); everything else is honestly UNSUPPORTED, not
// silently skipped or miscounted as a failure.
//
// Verdict states (PRD §32), STATIC proof only — no dynamic PoC exists for
// weak-crypto in this codebase's PoC generator (posture/poc-generator.js's
// five proof classes are command/code-injection, webhook-signature,
// sql-injection, path-traversal — weak-crypto isn't among them, so "dynamic
// exploit neutralized" is UNSUPPORTED for this family specifically, honestly,
// not silently converted to PROVEN_FIXED per PRD §32's explicit rule):
//   PROVEN_FIXED       — patch applied, parses, original finding gone,
//                        no new medium+ finding introduced.
//   PROVEN_VULNERABLE  — patch applied but the original finding (or an
//                        equivalent one) is still present after rescan.
//   INDETERMINATE      — patch applied but parse failed, or scanning
//                        errored — never silently promoted to PROVEN_FIXED.
//   UNSUPPORTED        — no deterministic fix rule covers this
//                        finding's CWE/family at all.
//
// Usage:
//   node bench/sard/scripts/verify-fixes.mjs --app sard-juliet-java-strict --cwe 89,78,23,80,327 --limit 60

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../../scanner/src/runScan.js';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';
import { synthesizeDeterministicPatch } from '../../../scanner/src/posture/deterministic-fix.js';
import { parseJavaFile } from '../../../scanner/src/ir/parser-java.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');
const CACHE_ROOT = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', '.bench-cache');
const REPORTS_DIR = path.join(HERE, '..', 'reports');

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function args() {
  const a = process.argv.slice(2);
  const out = { app: null, cwes: null, limit: 60 };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--app') out.app = a[++i];
    else if (a[i] === '--cwe') out.cwes = a[++i].split(',').map(s => s.trim());
    else if (a[i] === '--limit') out.limit = parseInt(a[++i], 10);
  }
  return out;
}

function resolveRoot(appName) {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const app = manifest.apps?.[appName];
  if (!app) throw new Error(`unknown manifest app: ${appName}`);
  return { app, root: path.join(CACHE_ROOT, `${appName}-${app.sha}`) };
}

function sampleFiles(root, cwes, limit) {
  const perCwe = Math.max(1, Math.ceil(limit / (cwes?.length || 1)));
  const samples = [];
  const dirs = fs.readdirSync(root, { withFileTypes: true }).filter(e => e.isDirectory() && /^juliet-cwe\d+$/i.test(e.name));
  for (const d of dirs) {
    const m = d.name.match(/^juliet-cwe(\d+)$/i);
    const cweNum = m[1];
    if (cwes && !cwes.includes(cweNum)) continue;
    const srcRoot = path.join(root, d.name, 'src', 'main', 'java');
    if (!fs.existsSync(srcRoot)) continue;
    let count = 0;
    (function walk(dir) {
      if (count >= perCwe) return;
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (count >= perCwe) return;
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { walk(p); continue; }
        if (!/\.java$/i.test(e.name) || /^Test|TestCase\.java$/.test(e.name)) continue;
        samples.push(p);
        count++;
      }
    })(srcRoot);
  }
  return samples.slice(0, limit);
}

async function scanFile(fileBaseName, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sard-fixverify-'));
  const target = path.join(dir, fileBaseName);
  fs.writeFileSync(target, content);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

async function main() {
  await disableStateWrites();
  const opts = args();
  if (!opts.app) { console.error('Usage: verify-fixes.mjs --app <manifest-app-name> [--cwe 89,78,...] [--limit N]'); process.exit(2); }
  const { root } = resolveRoot(opts.app);
  if (!fs.existsSync(root)) { console.error(`✗ corpus not cloned yet: ${root}`); process.exit(2); }

  const files = sampleFiles(root, opts.cwes, opts.limit);
  console.error(`  sampled ${files.length} files`);

  const results = [];
  for (const file of files) {
    const base = path.basename(file);
    let content;
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }

    // Baseline: real findings from a fresh scan of THIS file, this run.
    const baselineFindings = await scanFile(base, content);
    if (!baselineFindings.length) continue; // nothing to fix in this file

    for (const finding of baselineFindings) {
      const patchResult = synthesizeDeterministicPatch(finding, content);
      if (!patchResult) {
        results.push({ file: path.relative(root, file), cwe: finding.cwe, family: finding.family, verdict: 'UNSUPPORTED', reason: 'no deterministic fix rule covers this finding' });
        continue;
      }
      const patched = patchResult.patch[finding.file] ?? patchResult.patch[base];
      if (typeof patched !== 'string') {
        results.push({ file: path.relative(root, file), cwe: finding.cwe, family: finding.family, verdict: 'INDETERMINATE', reason: 'patch result did not key by expected filename' });
        continue;
      }

      // Validation: PARSES.
      let parsed;
      try { parsed = await parseJavaFile(base, patched); } catch { parsed = null; }
      if (!parsed || !Array.isArray(parsed.functions) || parsed.functions.length === 0) {
        results.push({ file: path.relative(root, file), cwe: finding.cwe, family: finding.family, ruleId: patchResult.ruleId, verdict: 'INDETERMINATE', reason: 'patched file failed to parse' });
        continue;
      }

      // Rescan the patched content.
      const afterFindings = await scanFile(base, patched);
      const stillPresent = afterFindings.some(f => (f.family || '').toLowerCase() === (finding.family || '').toLowerCase() && (f.cwe || '') === (finding.cwe || ''));
      const newMediumPlus = afterFindings.filter(f => {
        const isOriginalFamily = (f.family || '').toLowerCase() === (finding.family || '').toLowerCase();
        const rank = SEVERITY_RANK[f.severity] ?? 0;
        return !isOriginalFamily && rank >= SEVERITY_RANK.medium;
      });

      let verdict;
      let reason;
      if (stillPresent) { verdict = 'PROVEN_VULNERABLE'; reason = 'original finding (or an equivalent) still present after rescan'; }
      else if (newMediumPlus.length > 0) { verdict = 'PROVEN_VULNERABLE'; reason = `fix removed the original finding but introduced ${newMediumPlus.length} new medium+ finding(s): ${newMediumPlus.map(f=>f.family).join(', ')}`; }
      else { verdict = 'PROVEN_FIXED'; reason = 'original finding gone, no new medium+ finding, patch parses'; }

      results.push({ file: path.relative(root, file), cwe: finding.cwe, family: finding.family, ruleId: patchResult.ruleId, verdict, reason });
    }
  }

  const byVerdict = {};
  for (const r of results) byVerdict[r.verdict] = (byVerdict[r.verdict] || 0) + 1;
  const attempted = results.filter(r => r.verdict !== 'UNSUPPORTED');
  const provenFixed = byVerdict.PROVEN_FIXED || 0;
  // Fully Verified Fix Rate (PRD §33): over ATTEMPTED fixes (a rule existed),
  // never over the full sample — UNSUPPORTED isn't a failed attempt, it's no
  // attempt at all, and folding it into the denominator would make "we have
  // no fix rule for this" look identical to "we tried and failed."
  const fullyVerifiedFixRate = attempted.length ? provenFixed / attempted.length : null;

  const report = {
    generatedAt: new Date().toISOString(), app: opts.app, sampled: files.length,
    totalFindingsConsidered: results.length,
    byVerdict,
    fullyVerifiedFixRate,
    attemptedCount: attempted.length,
    results,
  };
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, 'fix-verification-report.json'), JSON.stringify(report, null, 2) + '\n');

  console.log(`\nFully Verified Fix Rate: ${fullyVerifiedFixRate === null ? 'N/A (no rule covered any sampled finding)' : (fullyVerifiedFixRate*100).toFixed(1) + '%'} (${provenFixed}/${attempted.length} attempted fixes)`);
  for (const [v, c] of Object.entries(byVerdict)) console.log(`  ${v}: ${c}`);
  console.log(`\nWritten: ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'fix-verification-report.json'))}`);
}

main();
