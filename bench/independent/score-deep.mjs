#!/usr/bin/env node
// One-off, ad-hoc verification script (not part of the harness, not wired
// into any npm script) — scores the full independent population WITH
// AGENTIC_SECURITY_DEEP=1 forced, to answer a direct question: how much does
// the deep taint engine actually contribute on real-world code, given that
// bench/independent/runner.mjs's own scanDir() never sets deep mode and no
// caller of it ever has?
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchesCwe, localiseToAdvisory, scoreCounts, purgeScanState } from './runner.mjs';
import { entryDir, entryComplete } from './fetch.mjs';
import { disableStateWrites, snapshotTree, assertTreeUnchanged } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MANIFEST = path.join(HERE, 'manifest.json');

async function scanDirDeep(dir) {
  purgeScanState(dir);
  const before = snapshotTree(dir);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  const findings = (normalizeFindings(scan) || []).filter(f => !String(f.file || '').includes('.agentic-security'));
  assertTreeUnchanged(before, snapshotTree(dir), `independent-deep entry ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  const irTaintCount = findings.filter(f => f.parser === 'IR-TAINT').length;
  return { findings, irTaintCount, analysisTier: scan._scanMeta?.analysisTier || null };
}

async function main() {
  await disableStateWrites();
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const perEntry = [];
  let processed = 0;
  for (const e of manifest.entries) {
    if (!entryComplete(e)) continue;
    const dir = entryDir(e.id);
    let pre, post;
    try {
      pre = await scanDirDeep(path.join(dir, 'pre'));
      post = await scanDirDeep(path.join(dir, 'post'));
    } catch (err) {
      process.stderr.write(`  SKIP ${e.id}: ${err.message}\n`);
      continue;
    }
    const hitPre = matchesCwe(pre.findings, e.cwe, e.files);
    const hitPost = matchesCwe(post.findings, e.cwe, e.files);
    // Which finding matched, and was it IR-TAINT specifically?
    const scoped = localiseToAdvisory(pre.findings, e.files);
    const want = String(e.cwe).toUpperCase();
    const matchFinding = scoped.find(f => String(f.cwe || '').toUpperCase() === want);
    perEntry.push({
      id: e.id, cwe: e.cwe, language: e.language,
      tp: hitPre ? 1 : 0, fn: hitPre ? 0 : 1,
      fp: hitPost ? 1 : 0, tn: hitPost ? 0 : 1,
      matchedParser: matchFinding ? (matchFinding.parser || 'unknown') : null,
      preIrTaintCount: pre.irTaintCount,
      preAnalysisTier: pre.analysisTier,
    });
    processed++;
    process.stderr.write(`  [${processed}] ${e.id}  tp=${hitPre ? 1 : 0}  irTaintFindings=${pre.irTaintCount}  matchedParser=${matchFinding ? matchFinding.parser : '-'}\n`);
  }
  const sum = perEntry.reduce((a, r) => ({ tp: a.tp + r.tp, fp: a.fp + r.fp, fn: a.fn + r.fn, tn: a.tn + r.tn }), { tp: 0, fp: 0, fn: 0, tn: 0 });
  const overall = scoreCounts(sum);
  const taintCaught = perEntry.filter(r => r.tp === 1 && r.matchedParser === 'IR-TAINT').length;
  const out = { scoredEntries: perEntry.length, overall, taintCaughtCount: taintCaught, perEntry };
  fs.writeFileSync(path.join(HERE, 'RESULT-deep.json'), JSON.stringify(out, null, 2) + '\n');
  process.stderr.write(`\nDONE. scored=${perEntry.length} tp=${overall.tp} fn=${overall.fn} recall=${overall.recall.value} taintCaught=${taintCaught}\n`);
}

main();
