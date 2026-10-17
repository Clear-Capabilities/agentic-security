// E1-05 on the real baseline run: every miss is classified once, with a concrete trace, totals that reconcile exactly, ranked clusters, and sample ids that reproduce.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const read = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const pointer = read('bench/independent/runs/BASELINE.json'); const RUN = `bench/independent/runs/${pointer.runId}`;
const result = read(`${RUN}/RESULT.json`); const f = read(`${RUN}/forensics.json`);
const CATEGORIES = ['no_detector_candidate', 'parse_ir_gap', 'missing_source_or_sink', 'alias_or_callgraph_gap', 'sanitizer_misclassification', 'guard_or_suppression', 'reachability_demotion', 'wrong_file_or_cwe', 'tool_or_setup_incomplete', 'unlabelled_ambiguity'];

test('TOTALS RECONCILE EXACTLY with the scored population: scored = localized hits + localized misses, and every miss is classified once', () => {
  const tp = result.perEntry.reduce((a, r) => a + r.tpLocal, 0); const fn = result.perEntry.reduce((a, r) => a + r.fnLocal, 0);
  assert.equal(f.reconciliation.scored, result.coverage.scored); assert.equal(f.reconciliation.localizedTruePositives, tp); assert.equal(f.reconciliation.localizedFalseNegatives, fn);
  assert.equal(tp + fn, result.coverage.scored); assert.equal(f.classifications.length, fn); assert.equal(f.reconciliation.classified, fn);
  assert.equal(f.reconciliation.reconciles, true); assert.deepEqual([f.reconciliation.unclassified, f.reconciliation.classifiedButNotAMiss, f.reconciliation.duplicateClassifications], [[], [], []]);
  assert.deepEqual(Object.keys(f.byCategory), CATEGORIES); assert.equal(Object.values(f.byCategory).reduce((a, b) => a + b, 0), fn);
  const missedIds = new Set(result.perEntry.filter((r) => r.fnLocal > 0).map((r) => r.id)); const classifiedIds = f.classifications.map((c) => c.entryId);
  assert.equal(new Set(classifiedIds).size, classifiedIds.length, 'no entry classified twice'); assert.deepEqual([...new Set(classifiedIds)].sort(), [...missedIds].sort(), 'exactly the missed entries');
  assert.deepEqual(f.unscored, { count: result.coverage.unscored, byClass: { timeout: 5 }, note: f.unscored.note }, 'unscored entries are reported by cause and are not misses');
});

test('EVERY CLASSIFICATION REFERENCES A CONCRETE TRACE: a stage, a reason, a location in the defect file, and the evidence that justifies the category', () => {
  for (const c of f.classifications) {
    assert.ok(CATEGORIES.includes(c.category), c.entryId); assert.ok(c.stage && c.reason, c.entryId);
    assert.ok(c.location && typeof c.location.file === 'string' && Number.isInteger(c.location.startLine), `${c.entryId} points at the fix's location`);
    assert.ok(c.evidence && Object.keys(c.evidence).length >= 1, `${c.entryId} carries evidence`);
    const e = c.evidence;
    // the family no rule fired for, or an explicit null when the engine has no family for this CWE at all (94 of 148): both are recorded, neither is a guess
    if (c.category === 'no_detector_candidate') assert.ok('family' in e, 'records the family question');
    if (c.category === 'guard_or_suppression' || c.category === 'sanitizer_misclassification') assert.ok(e.ledger, 'cites the ledger entry that dropped it');
    if (c.category === 'wrong_file_or_cwe') assert.ok(e.reported && typeof e.reported === 'object' && Object.keys(e.reported).length >= 1, 'cites what was reported instead');
    if (c.category === 'parse_ir_gap') assert.ok(e.file, 'names the file that did not lower');
    if (c.category === 'tool_or_setup_incomplete') assert.ok(e.failureReason, 'names the failure');
  }
  assert.equal(f.byCategory.unlabelled_ambiguity, 0, 'no answer was a plausible-sounding guess: where no diagnostic existed it would say so, and none was needed');
});

test('THE SCAN-OUTPUT LOSS IS GONE: only a genuine timeout remains under tool or setup limitations (62 re-scans were lost to a truncated child output before the fix)', () => {
  assert.equal(f.byCategory.tool_or_setup_incomplete, 1); const t = f.classifications.find((c) => c.category === 'tool_or_setup_incomplete');
  assert.equal(t.reason, 'scan-timeout');
  assert.ok(!f.classifications.some((c) => (c.evidence && c.evidence.failureReason) === 'scan produced no result block'));
});

test('RANKED CLUSTERS: largest first, shares add up, sample ids are the first five by id and therefore reproduce', () => {
  const total = f.classifications.length; let prev = Infinity; let sum = 0;
  for (const c of f.clusters) {
    assert.ok(c.count <= prev, 'ranked by size'); prev = c.count; sum += c.count;
    const members = f.classifications.filter((x) => x.category === c.category && x.stage === c.stage && x.reason === c.reason).map((x) => x.entryId).sort();
    assert.equal(members.length, c.count, `${c.stage}: ${c.reason}`); assert.deepEqual(c.sampleIds ?? c.samples, members.slice(0, (c.sampleIds ?? c.samples).length), 'samples are the first by id');
  }
  assert.equal(sum, total); assert.equal(f.clusters[0].category, 'no_detector_candidate');
  const md = fs.readFileSync(path.join(ROOT, RUN, 'FORENSICS.md'), 'utf8'); assert.ok(md.includes(pointer.runId)); assert.ok(md.includes(f.clusters[0].sampleIds ? f.clusters[0].sampleIds[0] : f.clusters[0].samples[0])); assert.match(md, new RegExp(`Reproduce: \`${f.reproduce.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\``));
});
