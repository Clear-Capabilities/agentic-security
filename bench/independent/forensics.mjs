#!/usr/bin/env node
// Miss forensics for the independent population (E1-05): why was each labelled defect not found?
//
// Every localized false negative of a run is re-scanned with the engine's own diagnostics and named for the EARLIEST pipeline stage that
// lost it, using the same classifier the evaluation protocol uses (posture/evaluation/why-missed.js). The stage is then mapped to the PRD's
// ten categories. A classification is a verdict about the engine's own evidence, not a guess from the label: its `evidence` field carries
// the ledger entry, the parse failure, the mislocated finding or the counts that justify it, and when no diagnostic exists the answer is
// `unlabelled_ambiguity`, never a plausible-sounding stage.
//
//   node bench/independent/forensics.mjs --run <runId>        re-scan the misses of a finished run and write forensics.json / FORENSICS.md
//
// The totals reconcile by construction and are checked: scored = localized true positives + localized false negatives, and every false
// negative is classified exactly once. Entries that were never scored are reported by cause and are never counted as misses.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyMiss } from '../../scanner/src/posture/evaluation/why-missed.js';
import { defaultScanFn } from '../../scanner/src/posture/evaluation/runner.js';
import { engineEnvironment } from '../../scanner/src/posture/evaluation/custody.js';
import { atomicWriteJson, atomicWriteFile } from '../../scripts/loop-engineering/lib/util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export const CATEGORIES = Object.freeze([
  'no_detector_candidate', 'parse_ir_gap', 'missing_source_or_sink', 'alias_or_callgraph_gap', 'sanitizer_misclassification',
  'guard_or_suppression', 'reachability_demotion', 'wrong_file_or_cwe', 'tool_or_setup_incomplete', 'unlabelled_ambiguity',
]);

const REACHABILITY = /unreachab|reachab|dead[- ]?code|not[- ]called/i;
const SANITIZER = /^(?:sanitized:|sanitizer-gate|sanitizer)/i;

/** Map the classifier's (stage, reason) onto the PRD's categories. Total: every stage and every reason lands somewhere. */
export function categoryOf({ stage, reason = '' }) {
  switch (stage) {
    case 'scan-execution': return 'tool_or_setup_incomplete';
    case 'parser-ir': return 'parse_ir_gap';
    case 'source-modelling': return 'missing_source_or_sink';
    case 'sink-modelling': return /no-detector-rule|no-pattern-rule/.test(reason) ? 'no_detector_candidate' : 'missing_source_or_sink';
    case 'propagation': return 'alias_or_callgraph_gap';
    case 'filters': return REACHABILITY.test(reason) ? 'reachability_demotion' : SANITIZER.test(reason) ? 'sanitizer_misclassification' : 'guard_or_suppression';
    case 'suppression': return REACHABILITY.test(reason) ? 'reachability_demotion' : 'guard_or_suppression';
    case 'deduplication': case 'attribution': return 'wrong_file_or_cwe';
    default: return 'unlabelled_ambiguity';
  }
}

/** A label the classifier understands, from a manifest entry, the file the fix changed and the changed line range. */
export function labelFromEntry(entry, { file, startLine, endLine, family }) {
  return { id: `lbl:${entry.id}`, targetId: entry.id, language: entry.language, family: family ?? null, cwe: entry.cwe, location: { file, startLine, endLine } };
}

/**
 * Classify one false negative.
 * @param {object} o
 * @param {object} o.entry          manifest entry
 * @param {object} o.location       { file, startLine, endLine, family }
 * @param {object[]} o.preFindings  findings of the vulnerable tree
 * @param {object|null} o.diagnostics the diagnostics block of a diagnosing re-scan, or null
 * @param {string} [o.scanStatus]   'completed' unless the re-scan itself failed
 */
export function classifyIndependentMiss({ entry, location, preFindings, diagnostics, scanStatus = 'completed', failureReason = null, layer = 'deep-taint' }) {
  const label = labelFromEntry(entry, location);
  const outcome = { status: scanStatus, findings: preFindings || [], failureReason };
  const c = classifyMiss({ label, outcome, diagnostics, policy: { lineWindow: 3 }, layer });
  return { entryId: entry.id, language: entry.language, cwe: entry.cwe, repo: entry.repo, stage: c.stage, reason: c.reason, category: categoryOf(c), evidence: c.evidence, location: label.location };
}

/**
 * Totals, clusters and reconciliation.
 * @param {object} o
 * @param {object[]} o.rows          scored rows of the run
 * @param {object[]} o.classified    classifications, one per localized false negative
 * @param {object[]} o.unscored      [{ id, reason, class }]
 */
export function buildForensics({ rows, classified, unscored = [], runId = null, command = null }) {
  const misses = rows.filter((r) => r.fnLocal === 1).map((r) => r.id).sort();
  const hits = rows.filter((r) => r.tpLocal === 1).length;
  const byEntry = new Map();
  const duplicates = [];
  for (const c of classified) { if (byEntry.has(c.entryId)) duplicates.push(c.entryId); byEntry.set(c.entryId, c); }
  const unclassified = misses.filter((id) => !byEntry.has(id));
  const stray = [...byEntry.keys()].filter((id) => !misses.includes(id));
  const reconciliation = {
    scored: rows.length, localizedTruePositives: hits, localizedFalseNegatives: misses.length, classified: byEntry.size,
    unclassified, classifiedButNotAMiss: stray, duplicateClassifications: duplicates,
    reconciles: rows.length === hits + misses.length && !unclassified.length && !stray.length && !duplicates.length,
    rule: 'scored = localized true positives + localized false negatives; every false negative is classified exactly once',
  };
  const groups = new Map();
  for (const c of byEntry.values()) {
    const key = `${c.category}|${c.stage}:${c.reason}`;
    if (!groups.has(key)) groups.set(key, { category: c.category, stage: c.stage, reason: c.reason, count: 0, entries: [], languages: {}, cwes: {} });
    const g = groups.get(key);
    g.count++; g.entries.push(c.entryId);
    g.languages[c.language] = (g.languages[c.language] || 0) + 1;
    g.cwes[c.cwe] = (g.cwes[c.cwe] || 0) + 1;
  }
  const clusters = [...groups.values()].map((g) => ({ ...g, entries: undefined, sampleIds: g.entries.sort().slice(0, 5), share: misses.length ? g.count / misses.length : null }))
    .sort((a, b) => b.count - a.count || (`${a.category}${a.reason}` < `${b.category}${b.reason}` ? -1 : 1));
  const byCategory = Object.fromEntries(CATEGORIES.map((k) => [k, 0]));
  for (const c of byEntry.values()) byCategory[c.category]++;
  return {
    schemaVersion: 1, runId, reconciliation, byCategory, clusters,
    unscored: { count: unscored.length, byClass: unscored.reduce((m, u) => ({ ...m, [u.class || 'other']: (m[u.class || 'other'] || 0) + 1 }), {}), note: 'never scored, so never a miss; the cause is a tool or setup limitation' },
    reproduce: command,
    classifications: [...byEntry.values()].sort((a, b) => (a.entryId < b.entryId ? -1 : 1)),
  };
}

export function renderMarkdown(f) {
  const L = ['# Miss forensics', ''];
  L.push(`Run \`${f.runId}\`. Localized false negatives: **${f.reconciliation.localizedFalseNegatives}** of ${f.reconciliation.scored} scored; localized true positives: ${f.reconciliation.localizedTruePositives}. Reconciles: **${f.reconciliation.reconciles}**.`, '');
  L.push('| Category | Misses |', '|---|---|');
  for (const [k, v] of Object.entries(f.byCategory)) L.push(`| ${k} | ${v} |`);
  L.push('', '## Ranked clusters', '', '| # | Category | Stage: reason | Count | Share | Sample ids |', '|---|---|---|---|---|---|');
  f.clusters.forEach((c, i) => L.push(`| ${i + 1} | ${c.category} | ${c.stage}: ${c.reason} | ${c.count} | ${c.share === null ? '' : `${(c.share * 100).toFixed(1)}%`} | ${c.sampleIds.join(', ')} |`));
  L.push('', `Unscored entries (${f.unscored.count}) are not misses: ${Object.entries(f.unscored.byClass).map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}.`, '', f.reproduce ? `Reproduce: \`${f.reproduce}\`` : '');
  return L.join('\n');
}

// ---- the re-scan ---------------------------------------------------------------------------------------------------------------

async function inferFamily(cwe) {
  const mod = await import('../../scanner/src/posture/finding-defaults.js');
  return mod._internals._inferFamily({ cwe });
}

/** Re-scan the vulnerable tree of one entry with diagnostics and classify the miss. */
export async function diagnoseEntry(entry, { cache, timeoutMs = 10 * 60 * 1000, scanFn = defaultScanFn, ranges }) {
  const pre = join(cache, entry.id, 'pre');
  const file = (entry.files || []).find((f) => existsSync(join(pre, f))) || (entry.files || [])[0];
  const family = await inferFamily(entry.cwe);
  const r = ranges ? ranges(entry, file) : [[1, 1]];
  const startLine = Math.min(...r.map((x) => x[0])); const endLine = Math.max(...r.map((x) => x[1]));
  const location = { file, startLine, endLine, family };
  if (!existsSync(pre)) return classifyIndependentMiss({ entry, location, preFindings: [], diagnostics: null, scanStatus: 'unavailable', failureReason: 'the vulnerable tree is not materialised' });
  const work = mkdtempSync(join(os.tmpdir(), 'ee-forensics-'));
  try {
    const copy = join(work, 'tree');
    cpSync(pre, copy, { recursive: true, filter: (p) => !/(^|\/)(\.git|\.agentic-security)(\/|$)/.test(p) });
    const env = engineEnvironment({ PATH: process.env.PATH, LANG: 'C', HOME: work, AGENTIC_SECURITY_DIAG_FILES: JSON.stringify([file]) });
    let res;
    try { res = await scanFn(copy, { layer: 'deep-taint', timeoutMs, env, diagnose: true }); } catch (e) {
      return classifyIndependentMiss({ entry, location, preFindings: [], diagnostics: null, scanStatus: String(e.code || 'error').toLowerCase() === 'timeout' ? 'timeout' : 'error', failureReason: String(e.message).slice(0, 200) });
    }
    return classifyIndependentMiss({ entry, location, preFindings: res.findings || [], diagnostics: res.diagnostics || null });
  } finally { rmSync(work, { recursive: true, force: true }); }
}

export async function forensicsForRun(runDir, { cache = join(HERE, 'cache'), diagnose = diagnoseEntry, onEntry = () => {} } = {}) {
  const result = JSON.parse(readFileSync(join(runDir, 'RESULT.json'), 'utf8'));
  const manifest = JSON.parse(readFileSync(join(HERE, 'manifest.json'), 'utf8')).entries;
  const byId = new Map(manifest.map((e) => [e.id, e]));
  const misses = result.perEntry.filter((r) => r.fnLocal === 1);
  const classified = [];
  const { rangesFromTrees } = await import('./runner.mjs');
  for (const r of misses) {
    const entry = byId.get(r.id);
    const c = await diagnose(entry, { cache, ranges: (e, file) => { try { return rangesFromTrees(join(cache, e.id)).local(file); } catch { return [[1, 1]]; } } });
    classified.push(c); onEntry(c);
  }
  const f = buildForensics({ rows: result.perEntry, classified, unscored: result.scoring.denominators ? (result.unscored || []).map((u) => ({ ...u, class: result.scoring ? classifyUnscoredLite(u.reason) : 'other' })) : [], runId: result.runId, command: `node bench/independent/forensics.mjs --run ${result.runId}` });
  atomicWriteJson(join(runDir, 'forensics.json'), f);
  atomicWriteFile(join(runDir, 'FORENSICS.md'), `${renderMarkdown(f)}\n`, 0o644);
  return f;
}

function classifyUnscoredLite(reason) {
  const r = String(reason || '');
  if (/not fetched|acquisition/i.test(r)) return 'acquisition';
  if (/timed? ?out|exceeded/i.test(r)) return 'timeout';
  if (/parse/i.test(r)) return 'parse';
  if (/scan failed/i.test(r)) return 'scan_failure';
  if (/absent/i.test(r)) return 'scope_file_absent';
  return 'other';
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const a = process.argv.slice(2);
  const i = a.indexOf('--run');
  if (i < 0) { console.error('usage: forensics.mjs --run <runId>'); process.exit(2); }
  const runDir = join(HERE, 'runs', a[i + 1]);
  forensicsForRun(runDir, { onEntry: (c) => console.error(`  ${c.entryId}: ${c.category} (${c.stage}: ${c.reason})`) })
    .then((f) => { console.log(`forensics: ${f.reconciliation.classified} misses classified; reconciles=${f.reconciliation.reconciles}`); process.exit(f.reconciliation.reconciles ? 0 : 1); })
    .catch((e) => { console.error(`forensics failed: ${e.stack || e.message}`); process.exit(2); });
}
void resolve; void mkdirSync; void writeFileSync;
