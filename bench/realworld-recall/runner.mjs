#!/usr/bin/env node
// Addition #6 — self-improving recall harness: CLI runner.
//
// Orchestrates one recall measurement end-to-end:
//   load corpus (known vulns) → gather emitted findings → for each known vuln,
//   ask the semantic judge (judge.mjs; null offline) then fall back to the
//   deterministic matcher (score.mjs) → scoreRecall → analyze every miss.
//
// It measures RECALL / detection-rate: of the vulnerabilities we KNOW are in the
// corpus, what fraction did the scanner surface? (Precision is independent-eval's
// job.) The judge is BENCH-ONLY and degrades deterministically offline, so this
// runner is fully offline-safe: with no LLM endpoint and no --scan, `--smoke`
// runs the whole pipeline against a bundled synthetic corpus with no network.
//
// Emitted-findings source (pick one; default = bundled smoke set):
//   --emitted <file.json>  bring-your-own: a JSON array (or {findings:[...]}) of
//                          findings you produced by scanning the corpus repos.
//   --scan <dir>           run the in-repo scanner over a local checkout (copied
//                          to a temp dir so no scan state is written into it).
//   (neither)              bundled SMOKE_EMITTED — a synthetic set matched to
//                          corpus/EXAMPLE.json so the harness self-exercises.
//
// Usage:
//   node bench/realworld-recall/runner.mjs --smoke
//   node bench/realworld-recall/runner.mjs --corpus mycorpus.json --emitted out.json
//   node bench/realworld-recall/runner.mjs --scan ./checkout --gate default
//   node bench/realworld-recall/runner.mjs --json
//   node bench/realworld-recall/runner.mjs --update-baseline
//   node bench/realworld-recall/runner.mjs --check-baseline
//
// Exit codes: 0 = ran (gate/baseline passed); 1 = gate/baseline drift; 2 = usage/no data.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchExpected, scoreRecall, checkGate, sharesLocation, sharesClass } from './score.mjs';
import { judgeDetection } from './judge.mjs';
import { analyzeMiss, DEFAULT_STAGES } from './analyze-misses.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXAMPLE_CORPUS = path.join(HERE, 'corpus', 'EXAMPLE.json');
const BASELINE_PATH = path.join(HERE, 'baseline.json');
const RESULTS_DIR = path.join(HERE, 'results');

const STAGES = DEFAULT_STAGES;

// Bundled synthetic emitted findings, matched to corpus/EXAMPLE.json:
//   EX-001 sql-injection @ src/db/users.js:42     → detected
//   EX-002 command-injection @ src/exec/run.js:88 → detected
//   EX-003 path-traversal @ src/files/read.js:15  → MISSED (nothing emitted there → detector gap)
//   EX-004 ssrf @ src/net/fetch.js:20             → MISSED (a finding is there, but wrong class → detector gap)
const SMOKE_EMITTED = [
  { id: 'F1', file: 'src/db/users.js', line: 42, family: 'sql-injection', cwe: 'CWE-89', vuln: 'SQL injection', confidence: 0.92 },
  { id: 'F2', file: 'src/exec/run.js', line: 88, family: 'command-injection', cwe: 'CWE-78', vuln: 'OS command injection', confidence: 0.88 },
  { id: 'F3', file: 'src/net/fetch.js', line: 20, family: 'open-redirect', cwe: 'CWE-601', vuln: 'Open redirect', confidence: 0.55 },
];

function parseArgs(argv) {
  const out = { corpus: null, emitted: null, scan: null, smoke: false, json: false,
    updateBaseline: false, checkBaseline: false, endpoint: null, gate: null };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--corpus') out.corpus = argv[++i];
    else if (t === '--emitted') out.emitted = argv[++i];
    else if (t === '--scan') out.scan = argv[++i];
    else if (t === '--smoke') out.smoke = true;
    else if (t === '--json') out.json = true;
    else if (t === '--update-baseline') out.updateBaseline = true;
    else if (t === '--check-baseline') out.checkBaseline = true;
    else if (t === '--endpoint') out.endpoint = argv[++i];
    else if (t === '--gate') { const n = argv[i + 1]; out.gate = (n && !n.startsWith('--')) ? argv[++i] : 'default'; }
  }
  return out;
}

/** Load a corpus JSON: { entries: [...] } | { corpus, entries } | bare array. */
function loadCorpus(fp) {
  const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
  const entries = Array.isArray(raw) ? raw : (Array.isArray(raw.entries) ? raw.entries : []);
  return entries.filter((e) => e && (e.finding_id || e.id) && (e.type || e.family));
}

/** Load emitted findings: bare array | { findings: [...] }. */
function loadEmitted(fp) {
  const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
  const arr = Array.isArray(raw) ? raw : (Array.isArray(raw.findings) ? raw.findings : []);
  return arr;
}

/** Run the in-repo scanner over a temp COPY of a checkout (no scan state leaks). */
async function scanDir(dir) {
  const { runScan } = await import('../../scanner/src/runScan.js');
  const { normalizeFindings } = await import('../../scanner/src/report/index.js');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-recall-'));
  fs.cpSync(dir, tmp, { recursive: true, filter: (s) => !s.includes('.agentic-security') && !s.includes('node_modules') });
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  try {
    const { scan } = await runScan(tmp);
    return (normalizeFindings(scan) || []).map((f) => ({
      id: f.id || f.stableId, file: f.file, line: f.line, family: f.family, cwe: f.cwe, vuln: f.vuln,
      confidence: typeof f.confidence === 'number' ? f.confidence : (typeof f.calibratedConfidence === 'number' ? f.calibratedConfidence : 0.5),
    }));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** Infer the pipeline signals for a MISS from the corpus entry + emitted set.
 *  Offline we can only see location/class overlap, so we distinguish a total
 *  detector blank (nothing at the location) from a wrong-class candidate (rule
 *  gap) from a semantic override (judge said no on a location+class match →
 *  posture/proof). A BYO corpus may pre-annotate richer signals; those win. */
function inferMissSignals(expected, emitted) {
  const atLocation = (emitted || []).filter((f) => sharesLocation(expected, f));
  const sameClassHere = atLocation.filter((f) => sharesClass(expected, f));
  const base = {};
  if (sameClassHere.length > 0) base.postureFiltered = true;   // matched loc+class yet judged a miss
  else base.detectorFired = false;                             // no right-class candidate emitted here
  if (atLocation.length > 0) base.candidateAtLocation = true;
  // Explicit annotations on the corpus entry override inference.
  return { ...base, ...pickSignals(expected) };
}

function pickSignals(e) {
  const out = {};
  for (const k of ['entrypointFound', 'fileScanned', 'reachedStage', 'detectorFired', 'candidateEmitted',
    'candidateAtLocation', 'taintConnected', 'taintReached', 'postureFiltered', 'suppressed',
    'proofFailed', 'demotedUnreachable', 'unreachable', 'lostAtStage', 'stage']) {
    if (e && Object.prototype.hasOwnProperty.call(e, k)) out[k] = e[k];
  }
  return out;
}

function entryVerdict(detected) {
  return detected === true ? 'detected' : detected === null ? 'judge-error' : 'missed';
}

async function evaluate(opts) {
  const corpusPath = opts.smoke ? EXAMPLE_CORPUS : path.resolve(opts.corpus || EXAMPLE_CORPUS);
  const corpus = loadCorpus(corpusPath);

  let emitted, emittedSource;
  if (opts.emitted) { emitted = loadEmitted(path.resolve(opts.emitted)); emittedSource = `--emitted ${opts.emitted}`; }
  else if (opts.scan) { emitted = await scanDir(path.resolve(opts.scan)); emittedSource = `--scan ${opts.scan}`; }
  else { emitted = SMOKE_EMITTED; emittedSource = 'bundled SMOKE_EMITTED (synthetic)'; }

  const results = corpus.map((expected) => {
    const verdict = judgeDetection({ expectedFinding: expected, emittedFindings: emitted, endpoint: opts.endpoint });
    const m = matchExpected(expected, emitted, verdict);
    return {
      id: expected.finding_id || expected.id,
      type: expected.type || expected.family || 'unknown',
      location: expected.location || expected.file || null,
      detected: m.detected, matched: m.matched, confidence: m.confidence,
      judged: verdict.detected !== null, judgeReasoning: verdict.reasoning,
      expected,
    };
  });

  const score = scoreRecall(results);
  const misses = results.filter((r) => r.detected === false).map((r) =>
    analyzeMiss({ id: r.id, type: r.type, location: r.location, root_cause: r.expected.root_cause,
      ...inferMissSignals(r.expected, emitted) }, { stages: STAGES }));

  return { corpusPath, emittedSource, corpusSize: corpus.length, results, score, misses };
}

function verdictMap(results) {
  return Object.fromEntries(results.map((r) => [r.id, entryVerdict(r.detected)]).sort(([a], [b]) => a.localeCompare(b)));
}

function fmtRate(r) { return r == null ? '  —  (unmeasured)' : `${(r * 100).toFixed(1)}%`; }

function printReport(ev) {
  const { score, misses } = ev;
  process.stdout.write('\nReal-world recall harness — detection-rate on a known-vuln corpus\n');
  process.stdout.write(`  corpus:  ${ev.corpusPath}  (${ev.corpusSize} known vulns)\n`);
  process.stdout.write(`  emitted: ${ev.emittedSource}\n\n`);
  process.stdout.write(`  detection-rate  ${fmtRate(score.detectionRate)}  (detected ${score.detected} / measured ${score.total - score.judgeErrors})\n`);
  process.stdout.write(`  detected ${score.detected}   missed ${score.missed}   judge-errors ${score.judgeErrors}   total ${score.total}\n\n`);
  process.stdout.write('  by type:\n');
  for (const [t, m] of Object.entries(score.byType).sort((a, b) => a[0].localeCompare(b[0]))) {
    process.stdout.write(`    ${t.padEnd(20)} ${fmtRate(m.detectionRate).padStart(16)}   (${m.detected}/${m.total - m.judgeErrors})\n`);
  }
  process.stdout.write('\n  per known-vuln:\n');
  for (const r of ev.results) {
    const flag = r.detected === true ? '✓ detected' : r.detected === null ? '? judge-err' : '✗ MISSED  ';
    process.stdout.write(`    ${flag} ${String(r.id).padEnd(10)} ${r.type.padEnd(18)} ${r.matched ? '→ ' + r.matched : ''}\n`);
  }
  if (misses.length) {
    process.stdout.write('\n  miss analysis (stage that dropped it → proposed fix):\n');
    for (const m of misses) {
      process.stdout.write(`    · ${String(m.missId).padEnd(10)} lost at [${m.lostAtStage}]\n`);
      process.stdout.write(`      ↳ ${m.proposedFix}\n`);
    }
  }
  if (ev.corpusPath === EXAMPLE_CORPUS) {
    process.stdout.write('\n  ⚠  This is the SYNTHETIC smoke corpus — not a real recall number. Wire\n');
    process.stdout.write('     your own corpus (--corpus) + emitted findings (--emitted/--scan). See README.\n');
  }
  process.stdout.write('\n');
}

/** Append a compact cross-run history record (best-effort; never fatal). */
function recordHistory(ev) {
  try {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const when = new Date().toISOString();
    const row = { when, corpus: path.basename(ev.corpusPath), corpusSize: ev.corpusSize,
      detectionRate: ev.score.detectionRate, detected: ev.score.detected, missed: ev.score.missed,
      judgeErrors: ev.score.judgeErrors, total: ev.score.total };
    fs.appendFileSync(path.join(RESULTS_DIR, 'history.jsonl'), JSON.stringify(row) + '\n');
    fs.writeFileSync(path.join(RESULTS_DIR, `${when.replace(/[:.]/g, '-')}.json`),
      JSON.stringify({ ...row, byType: ev.score.byType, misses: ev.misses }, null, 2));
  } catch { /* history is advisory */ }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const ev = await evaluate(opts);

  if (opts.json && !opts.updateBaseline && !opts.checkBaseline) {
    const { results, ...rest } = ev;
    process.stdout.write(JSON.stringify({ generatedAt: new Date().toISOString().slice(0, 10), ...rest,
      results: results.map(({ expected, ...r }) => r) }, null, 2) + '\n');
    process.exit(0);
  }

  // --update-baseline: record each known-vuln's detected|missed|judge-error verdict.
  if (opts.updateBaseline) {
    const entries = verdictMap(ev.results);
    const baseline = {
      generatedAt: new Date().toISOString().slice(0, 10),
      corpus: path.basename(ev.corpusPath),
      total: ev.results.length,
      detected: Object.values(entries).filter((v) => v === 'detected').length,
      detectionRate: ev.score.detectionRate,
      entries,
    };
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
    process.stdout.write(`\n✓ baseline updated: ${baseline.detected}/${baseline.total} known vulns detected → ${path.relative(process.cwd(), BASELINE_PATH)}\n`);
    return;
  }

  // --check-baseline: recall gate. Fails on ANY drift from baseline.json:
  //   REGRESSED         — a known vuln that WAS detected no longer is
  //   NEW ENTRY MISSED  — a new known vuln is not detected (added unverified)
  //   BASELINED MISSING — a baselined entry vanished without a refresh
  // A newly-detected entry is allowed (recall growth) and reported as a nudge.
  if (opts.checkBaseline) {
    if (!fs.existsSync(BASELINE_PATH)) {
      process.stderr.write(`✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run --update-baseline first.\n`);
      process.exit(2);
    }
    const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
    const now = verdictMap(ev.results);
    const regressed = [], newMissed = [], missing = [], newDetected = [];
    for (const [id, v] of Object.entries(now)) {
      const base = baseline.entries[id];
      if (base === undefined) { (v === 'detected' ? newDetected : newMissed).push(id); }
      else if (base === 'detected' && v !== 'detected') regressed.push(id);
    }
    for (const id of Object.keys(baseline.entries)) if (now[id] === undefined) missing.push(id);

    process.stdout.write('\nReal-world recall baseline check:\n');
    if (regressed.length) process.stdout.write(`  ✗ REGRESSED to a miss (${regressed.length}): ${regressed.join(', ')}\n`);
    if (newMissed.length) process.stdout.write(`  ✗ NEW ENTRY NOT DETECTED (${newMissed.length}): ${newMissed.join(', ')}\n`);
    if (missing.length) process.stdout.write(`  ✗ BASELINED ENTRY MISSING (${missing.length}): ${missing.join(', ')}\n`);
    if (newDetected.length) process.stdout.write(`  + new detected entries (${newDetected.length}, refresh baseline): ${newDetected.join(', ')}\n`);
    if (regressed.length || newMissed.length || missing.length) {
      process.stderr.write('\n✗ recall baseline drift — failing build. If intentional, run --update-baseline.\n');
      process.exit(1);
    }
    process.stdout.write(`  ✓ no drift — ${baseline.detected}/${baseline.total} baselined known vulns still detected\n`);
    return;
  }

  printReport(ev);
  recordHistory(ev);

  if (opts.gate) {
    const thresholds = opts.gate === 'default'
      ? { minDetectionRate: 0.5, minSamples: 1 }
      : JSON.parse(opts.gate);
    const violations = checkGate(ev.score, thresholds);
    process.stdout.write(`Gate (${JSON.stringify(thresholds)}):\n`);
    if (!violations.length) process.stdout.write('  ✓ passed\n');
    else {
      for (const vio of violations) process.stdout.write(`  ✗ ${vio}\n`);
      process.exit(1);
    }
  }
  process.exit(0);
}

main().catch((e) => { process.stderr.write(String((e && e.stack) || e) + '\n'); process.exit(2); });
