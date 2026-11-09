// Pilot capture and replay (PRD M0 "Reproduce and baseline", and the coverage-accounting release target).
//
//   capture  scan a pinned snapshot and record everything M0 asks for: the command, the scanner version and revision, the snapshot's
//            revision and dirty state (the scan record), the ignore policy and scope, the parse budgets, the full report JSON, and the
//            coverage measure: every eligible Haskell file has a status, at least 95% of eligible .hs files parse, at least 90% complete
//            the semantic passes, with failures in the denominator and every incomplete entry point named.
//   compare  replay: diff two reports of the same snapshot (the pilot's original report and a capture with the current release),
//            finding by finding. This is a finding diff, not recall: without adjudicated labels a lost finding may be a fixed false
//            positive or a lost true positive, and the output says which ones need a reviewer.
//
// Pilot exclusions are frozen: the first capture into an output directory records the exclusions file's digest, and a later capture
// with different exclusions is refused, so the denominator cannot be changed after the fact.
//
// usage: node bench/haskell-pilot/pilot.mjs capture --root <snapshot> --out <dir> [--label <name>] [--exclusions <file.json>]
//        node bench/haskell-pilot/pilot.mjs compare <before-report.json> <after-report.json>
//
// exclusions file: { "exclusions": [ { "path": "vendor/legacy", "reason": "..." } ] }   (every entry needs a reason)
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
export const PARSE_TARGET = 0.95;
export const SEMANTIC_TARGET = 0.9;

/** Validate and digest an exclusions document. */
export function readExclusions(doc) {
  const list = doc && Array.isArray(doc.exclusions) ? doc.exclusions : null;
  if (!list) return { ok: false, reason: 'the exclusions file must be { "exclusions": [ { "path", "reason" } ] }' };
  for (const e of list) if (!e || !e.path || !String(e.reason || '').trim()) return { ok: false, reason: `exclusion ${e && e.path ? e.path : '?'} has no reason` };
  const canonical = JSON.stringify(list.map((e) => ({ path: e.path, reason: e.reason })).sort((a, b) => a.path.localeCompare(b.path)));
  return { ok: true, paths: list.map((e) => e.path), digest: sha(canonical) };
}

/** Why a capture must be refused because the exclusions changed after the first capture, or null. */
export function exclusionRefusal(frozen, digest) {
  if (!frozen) return null;
  return frozen.digest === digest ? null : `the pilot exclusions changed after they were frozen (${frozen.digest.slice(0, 12)} then, ${digest.slice(0, 12)} now): the denominator must not move`;
}

/** The coverage measure from a scan's Haskell coverage record. */
export function coverageMeasure(hs) {
  if (!hs || !hs.present) return { present: false, pass: false, reasons: ['no Haskell files were found in the snapshot'] };
  const files = Object.entries(hs.byFile || {}).filter(([, r]) => r.eligible);
  const noStatus = files.filter(([, r]) => !r.parse || !r.flowAnalysis).map(([f]) => f);
  const eligibleHs = hs.totals?.eligibleHs ?? 0;
  const parseRate = hs.stages?.parse?.rate ?? null;
  const semanticRate = hs.stages?.semantic?.rate ?? null;
  const reasons = [];
  if (noStatus.length) reasons.push(`${noStatus.length} eligible file(s) have no status`);
  if (parseRate === null || parseRate < PARSE_TARGET) reasons.push(`parse rate ${parseRate === null ? 'unknown' : `${(parseRate * 100).toFixed(1)}%`} is below ${PARSE_TARGET * 100}%`);
  if (semanticRate === null || semanticRate < SEMANTIC_TARGET) reasons.push(`semantic completion ${semanticRate === null ? 'unknown' : `${(semanticRate * 100).toFixed(1)}%`} is below ${SEMANTIC_TARGET * 100}%`);
  return {
    present: true, eligible: files.length, eligibleHs, parseRate, semanticRate, filesWithoutStatus: noStatus,
    parseFailed: hs.stages?.parse?.failed ?? null, semanticCompleted: hs.stages?.semantic?.completed ?? null,
    incompleteEntries: hs.incompleteEntries || [], incompleteMains: hs.incompleteMains || [],
    budgetRemaining: hs.budget?.remaining || [], pass: reasons.length === 0, reasons,
  };
}

const keyOf = (f) => f.stableId || `${f.file}:${f.line}:${f.cwe}`;

/** Finding-level diff of two reports of the same snapshot. */
export function compareReports(before, after) {
  const b = new Map((before.findings || []).map((f) => [keyOf(f), f]));
  const a = new Map((after.findings || []).map((f) => [keyOf(f), f]));
  const lost = [...b].filter(([k]) => !a.has(k)).map(([, f]) => f);
  const added = [...a].filter(([k]) => !b.has(k)).map(([, f]) => f);
  const byCwe = {};
  for (const [side, m] of [['before', b], ['after', a]]) for (const f of m.values()) { const c = f.cwe || 'none'; (byCwe[c] ||= { before: 0, after: 0 })[side]++; }
  const brief = (f) => ({ key: keyOf(f), file: f.file, line: f.line, cwe: f.cwe, severity: f.severity, vuln: f.vuln });
  return {
    before: b.size, after: a.size, kept: b.size - lost.length,
    lost: lost.map(brief), added: added.map(brief), byCwe,
    lostCriticalOrHigh: lost.filter((f) => f.severity === 'critical' || f.severity === 'high').map(brief),
    note: 'a finding diff, not recall: each lost finding needs a reviewer to say whether a false positive was fixed or a true positive was lost',
  };
}

async function capture(argv) {
  const opt = (n, d = null) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };
  const root = opt('root'); const out = opt('out');
  if (!root || !out) { console.error('capture needs --root <snapshot> and --out <dir>'); return 2; }
  const label = opt('label', 'capture');
  let excl = { ok: true, paths: [], digest: sha('[]') };
  if (opt('exclusions')) {
    excl = readExclusions(JSON.parse(fs.readFileSync(opt('exclusions'), 'utf8')));
    if (!excl.ok) { console.error(`refused: ${excl.reason}`); return 2; }
  }
  fs.mkdirSync(out, { recursive: true });
  const frozenPath = path.join(out, 'FROZEN-exclusions.json');
  const frozen = fs.existsSync(frozenPath) ? JSON.parse(fs.readFileSync(frozenPath, 'utf8')) : null;
  const refusal = exclusionRefusal(frozen, excl.digest);
  if (refusal) { console.error(`refused: ${refusal}`); return 2; }
  if (!frozen) fs.writeFileSync(frozenPath, JSON.stringify({ schema: 'pilot-exclusions-freeze/1', frozenAt: new Date().toISOString(), digest: excl.digest, paths: excl.paths }, null, 1) + '\n');

  // the snapshot is evidence: the scan must not write scan state into it
  await disableStateWrites();
  const { runScan } = await import(pathToFileURL(path.join(REPO, 'scanner', 'src', 'runScan.js')).href);
  const options = { deep: true, gitScope: true, scope: { respectGitignore: true, excludePaths: excl.paths } };
  const t0 = Date.now();
  const { scan } = await runScan(path.resolve(root), options);
  const ms = Date.now() - t0;
  const hs = scan.scanHealth?.languageCoverage?.haskell || null;
  const measure = coverageMeasure(hs);
  const dir = path.join(out, label);
  fs.mkdirSync(dir, { recursive: true });
  const { fc, depFileContents, ...report } = scan;   // file contents are the snapshot itself, not part of the report
  fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report) + '\n');
  const record = {
    schema: 'pilot-capture/1', label, capturedAt: new Date().toISOString(), durationMs: ms,
    command: `node bench/haskell-pilot/pilot.mjs ${argv.join(' ')}`, scanOptions: options, node: process.version,
    scanRecord: scan.scanRecord || null, scope: scan.scope || null, budgets: hs?.budget?.budgets || null,
    exclusions: { digest: excl.digest, paths: excl.paths }, coverage: measure,
    findings: { total: (scan.findings || []).length, dispositions: scan.dispositionCounts || null, reconciliation: scan.candidateReconciliation || null },
  };
  fs.writeFileSync(path.join(dir, 'capture.json'), JSON.stringify(record, null, 1) + '\n');
  const pct = (x) => (x == null ? 'n/a' : `${(x * 100).toFixed(1)}%`);
  console.log(`captured ${label}: ${record.findings.total} finding(s) in ${(ms / 1000).toFixed(1)} s -> ${dir}`);
  console.log(`coverage: ${measure.eligibleHs ?? 0} eligible .hs, parse ${pct(measure.parseRate)} (target ${PARSE_TARGET * 100}%), semantic ${pct(measure.semanticRate)} (target ${SEMANTIC_TARGET * 100}%)`);
  for (const e of measure.incompleteEntries || []) console.log(`  incomplete entry: ${typeof e === 'string' ? e : JSON.stringify(e)}`);
  for (const r of measure.reasons) console.log(`  not met: ${r}`);
  return measure.pass ? 0 : 1;
}

function compareCli(argv) {
  const [b, a] = argv;
  if (!b || !a) { console.error('compare needs <before-report.json> <after-report.json>'); return 2; }
  const d = compareReports(JSON.parse(fs.readFileSync(b, 'utf8')), JSON.parse(fs.readFileSync(a, 'utf8')));
  console.log(`before ${d.before}, after ${d.after}, kept ${d.kept}, lost ${d.lost.length}, new ${d.added.length}`);
  for (const [c, n] of Object.entries(d.byCwe).sort()) if (n.before !== n.after) console.log(`  ${c}: ${n.before} -> ${n.after}`);
  for (const f of d.lostCriticalOrHigh) console.log(`  LOST ${f.severity}: ${f.file}:${f.line} ${f.cwe} ${f.vuln}`);
  console.log(d.note);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const code = cmd === 'capture' ? await capture(rest) : cmd === 'compare' ? compareCli(rest) : (console.error('usage: pilot.mjs capture|compare ...'), 2);
  process.exit(code);
}
