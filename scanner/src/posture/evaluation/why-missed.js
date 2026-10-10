// Why-missed instrumentation across the analysis pipeline (QA-005.AC01, QA-005.AC03).
//
// For a labelled DEVELOPMENT miss, name the EARLIEST stage that lost the defect, or say `unknown` and why. The stages, in the
// order a defect travels through the engine:
//
//   scan-execution   the scan never completed (timeout, error, unavailable, quarantined): nothing downstream ran
//   parser-ir        the file did not lower to an IR function, or the parser failed on it
//   source-modelling no untrusted source was recognised anywhere the flow could start
//   propagation      a source and a sink were both recognised near the defect, and no flow joined them
//   sink-modelling   no sink (or, for non-flow families, no detector rule) was recognised at the defect
//   filters          a candidate existed and a precision filter (guard recognition, safe-shape, sanitized) dropped it
//   suppression      a candidate existed and policy dropped it (ignore pragma, custom rule, learned feedback, validator)
//   deduplication    a candidate existed and was collapsed into a finding that carries a different location
//   attribution      a finding for this defect was REPORTED, at a location or under a family that does not match the label
//
// The order of DETERMINATION differs from the order of travel, deliberately: a candidate observed downstream (a dropped finding,
// a deduplicated loser, a mislocated report) PROVES every earlier stage worked, so those are checked first and name the stage that
// lost it. Only when no candidate was observed anywhere do the early stages explain the miss, and among them the first failed
// stage wins. Sources are checked before sinks, and propagation is blamed only when BOTH endpoints were recognised.
//
// Honesty rules: evidence is the engine's own diagnostics (a suppression ledger entry carries file, line, id, cwe and family), not
// a guess from the label; when there is no diagnostic evidence the answer is `unknown`, never a plausible-sounding stage. The
// instrument only runs over the DEVELOPMENT split: the sealed split's per-case outcomes are not available to detector work.

import { stageWorkspace, engineEnvironment } from './custody.js';
import { defaultScanFn } from './runner.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const STAGES = Object.freeze(['scan-execution', 'parser-ir', 'source-modelling', 'propagation', 'sink-modelling', 'filters', 'suppression', 'deduplication', 'attribution']);
export const UNKNOWN = 'unknown';

// Families whose detection is a source-to-sink flow; the rest (weak crypto, hardcoded secrets, misconfiguration) are pattern rules.
const FLOW_FAMILIES = new Set([
  'sql-injection', 'nosql-injection', 'command-injection', 'path-traversal', 'xss', 'ssrf', 'deserialization', 'insecure-deserialization',
  'open-redirect', 'code-injection', 'xxe', 'ldap-injection', 'xpath-injection', 'ssti', 'prototype-pollution', 'response-splitting', 'log-injection',
]);
const IR_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|java|cs|kt|kts|go|php|rb|rs|c|cc|cpp|cxx|h|hpp)$/i;

// A ledger reason names its mechanism by prefix. Filters judge a candidate not to be a real flow; suppressions are policy.
const FILTER_REASON = /^(?:guard-recognized:|sanitized:|universal-|bench-safe-shape|bench-category|primary-cwe|safe-sink-shape|sanitizer-gate)/;
const SUPPRESSION_REASON = /^(?:inline[- ]pragma|custom-rule|llm-validator|learned|rules-disable|no-vuln-name)/;

const norm = (p) => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');

function windowOf(label, policy) {
  const w = Number.isInteger(policy?.lineWindow) ? policy.lineWindow : 3;
  return { lo: label.location.startLine - w, hi: label.location.endLine + w };
}
const inWindow = (line, win) => Number.isInteger(line) && line >= win.lo && line <= win.hi;

function familyOf(entry) { return entry.family ?? null; }
function sameKind(entry, label) {
  // A ledger entry or finding agrees with the label by family or CWE. With neither recorded the identity is location-only.
  if (familyOf(entry) && familyOf(entry) === label.family) return 'family';
  if (entry.cwe && label.cwe && String(entry.cwe).toUpperCase() === String(label.cwe).toUpperCase()) return 'cwe';
  if (!familyOf(entry) && !entry.cwe) return 'location-only';
  return null;
}

/**
 * Classify ONE labelled miss.
 * @param {object} o
 * @param {object} o.label       an adjudicated defect label
 * @param {object|null} o.outcome the run outcome for the label's target (variant 'pre')
 * @param {object|null} o.diagnostics the scan child's diagnostics block for that target, or null
 * @param {object} [o.policy]    the protocol's matching policy
 * @param {string} [o.layer]     the configuration that produced the outcome
 */
export function classifyMiss({ label, outcome, diagnostics, policy, layer = 'deep-taint' }) {
  const base = { labelId: label.id, targetId: label.targetId, language: label.language, family: label.family, location: label.location };
  const done = (stage, reason, evidence = {}) => ({ ...base, stage, reason, evidence, deterministic: true });
  if (!outcome) return done('scan-execution', 'no-outcome-recorded');
  if (outcome.status !== 'completed') return done('scan-execution', `scan-${outcome.status}`, { failureReason: outcome.failureReason || null });
  if (!diagnostics) return done(UNKNOWN, 'no-diagnostic-evidence', { note: 'the target was not re-scanned with diagnostics, so no stage can be named' });

  const win = windowOf(label, policy);
  const file = norm(label.location.file);
  const here = (e) => norm(e.file) === file;

  // ---- a candidate was REPORTED but does not match: attribution
  const reported = (outcome.findings || []).filter(here);
  let best = null;
  for (const f of reported) {
    const kind = sameKind(f, label);
    if (!kind || kind === 'location-only') continue;
    const inRange = inWindow(f.line, win);
    if (inRange) continue; // would have matched; not a miss caused by attribution
    if (!Number.isInteger(f.line)) { best = best || { f, distance: Infinity, why: 'finding-has-no-line' }; continue; }
    const distance = f.line < win.lo ? win.lo - f.line : f.line - win.hi;
    if (!best || distance < best.distance) best = { f, distance, why: 'right-file-and-family-wrong-line' };
  }
  if (best) return done('attribution', best.why, { reported: { id: best.f.id ?? null, line: best.f.line ?? null, family: best.f.family ?? null, cwe: best.f.cwe ?? null }, distanceLines: Number.isFinite(best.distance) ? best.distance : null });

  // ---- a candidate was COLLAPSED into a winner elsewhere: deduplication
  // Only the FINAL winner of a bucket counts: a winner that was itself collapsed into a later one is not where the candidate ended up.
  const allDedupes = diagnostics.stageEvidence?.dedupe || [];
  const laterLosers = new Set(allDedupes.map((d) => d.loser?.id).filter(Boolean));
  const dedupes = allDedupes.filter((d) => !laterLosers.has(d.winner?.id) && norm(d.loser?.file || d.file) === file && inWindow(d.loser?.line, win) && (d.family === label.family || !d.family));
  const dedupeHit = dedupes.find((d) => !(norm(d.winner?.file) === file && inWindow(d.winner?.line, win)));
  if (dedupeHit) return done('deduplication', 'collapsed-into-winner-at-other-location', { loser: dedupeHit.loser, winner: dedupeHit.winner });

  // ---- a candidate was DROPPED with a recorded reason: filters or suppression
  const dropped = (diagnostics.suppressions || [])
    .filter((s) => here(s) && inWindow(s.line, win) && sameKind(s, label))
    .sort((a, b) => String(a.reason).localeCompare(String(b.reason)) || (a.line ?? 0) - (b.line ?? 0));
  if (dropped.length) {
    const d = dropped[0];
    const stage = SUPPRESSION_REASON.test(d.reason) ? 'suppression' : FILTER_REASON.test(d.reason) ? 'filters' : 'filters';
    return done(stage, d.reason.split(':').slice(0, 2).join(':'), { ledger: { id: d.id ?? null, line: d.line, family: d.family ?? null, cwe: d.cwe ?? null, reason: d.reason, identity: sameKind(d, label) }, alsoDropped: dropped.length - 1 });
  }

  // ---- a finding of ANOTHER family sits at the defect's location and no candidate of this family was observed anywhere: it was reported under the wrong family
  const wrongFamily = reported.find((f) => inWindow(f.line, win) && !sameKind(f, label));
  if (wrongFamily) return done('attribution', 'right-location-wrong-family', { reported: { id: wrongFamily.id ?? null, line: wrongFamily.line, family: wrongFamily.family ?? null, cwe: wrongFamily.cwe ?? null } });

  // ---- nothing observed anywhere: the early stages explain it
  const flow = FLOW_FAMILIES.has(label.family) && layer !== 'deterministic-only';
  if (!flow) {
    return done('sink-modelling', layer === 'deterministic-only' && FLOW_FAMILIES.has(label.family) ? 'no-pattern-rule-fired-and-taint-layer-not-run' : 'no-detector-rule-fired', { family: label.family });
  }
  const ir = diagnostics.ir || {};
  const entry = ir.files ? ir.files[label.location.file] ?? ir.files[file] : undefined;
  const ext = (/\.[A-Za-z0-9]+$/.exec(file) || [''])[0].replace('.', '').toLowerCase();
  if (IR_EXT.test(file)) {
    if (ir.parseFailures?.byLanguage && ir.parseFailures.byLanguage[ext] > 0) return done('parser-ir', 'ir-parse-failure', { parseFailures: ir.parseFailures.byLanguage[ext], firstError: ir.parseFailures.firstError ?? null });
    if (entry && (!entry.lowered || (entry.functions || []).length === 0)) return done('parser-ir', 'no-function-lowered', { file: label.location.file });
  }
  const sources = (diagnostics.sources || []);
  const sinks = (diagnostics.sinks || []);
  const sourcesInFile = sources.filter(here);
  if (sourcesInFile.length === 0 && sources.length === 0) return done('source-modelling', 'no-source-recognized', { sourcesRecognized: 0 });
  if (sourcesInFile.length === 0) return done('source-modelling', 'no-source-in-defect-file', { sourcesRecognizedElsewhere: sources.length });
  const wide = { lo: win.lo - 10, hi: win.hi + 10 };
  const sinkNear = sinks.some((s) => here(s) && inWindow(s.line, wide));
  if (!sinkNear) return done('sink-modelling', 'no-sink-recognized-near-defect', { sourcesInFile: sourcesInFile.length });
  return done('propagation', 'source-and-sink-recognized-no-flow', { sourcesInFile: sourcesInFile.length });
}

/** Classify every miss in a score. `diagnosticsFor(targetId)` returns that target's diagnostics or null. */
export function classifyMisses({ score, defects, run, diagnosticsFor, policy, layer }) {
  const byId = new Map(defects.map((d) => [d.id, d]));
  const outcomeOf = new Map((run?.outcomes || []).map((o) => [`${o.targetId}|${o.variant}`, o]));
  const classified = [];
  for (const miss of score.misses || []) {
    const label = byId.get(miss.labelId);
    if (!label) { classified.push({ labelId: miss.labelId, targetId: miss.targetId, stage: UNKNOWN, reason: 'label-not-supplied', evidence: {}, deterministic: true }); continue; }
    classified.push(classifyMiss({ label, outcome: outcomeOf.get(`${miss.targetId}|pre`) || null, diagnostics: diagnosticsFor ? diagnosticsFor(miss.targetId) : null, policy, layer }));
  }
  classified.sort((a, b) => String(a.labelId).localeCompare(String(b.labelId)));
  return classified;
}

export function stageCounts(classified) {
  const byStage = Object.fromEntries([...STAGES, UNKNOWN].map((s) => [s, 0]));
  const byReason = {};
  for (const c of classified) {
    byStage[c.stage] = (byStage[c.stage] || 0) + 1;
    byReason[`${c.stage}:${c.reason}`] = (byReason[`${c.stage}:${c.reason}`] || 0) + 1;
  }
  return { total: classified.length, byStage, byReason };
}

/**
 * Before/after view of a fix (QA-005.AC03). Recovered defects are labels that were misses before and are not after; each is
 * listed with the stage that lost it and the finding that now matches. New false positives are named, never netted away.
 */
export function compareMisses({ before, after, scoreBefore, scoreAfter }) {
  const afterMissed = new Set(after.map((c) => c.labelId));
  const recovered = before.filter((c) => !afterMissed.has(c.labelId));
  const fpKey = (x) => `${x.targetId}|${x.finding?.file}|${x.finding?.family}|${x.finding?.line}`;
  const fpBefore = new Set((scoreBefore.falsePositives || []).map(fpKey));
  const newFalsePositives = (scoreAfter.falsePositives || []).filter((x) => !fpBefore.has(fpKey(x)));
  const verdict = recovered.length === 0 ? 'no-recovery' : newFalsePositives.length ? 'recovered-with-new-false-positives' : 'recovered-without-new-false-positives';
  return {
    verdict,
    stageCounts: { before: stageCounts(before), after: stageCounts(after) },
    recovered: recovered.map((c) => ({ labelId: c.labelId, targetId: c.targetId, lostAtStage: c.stage, reason: c.reason })),
    falsePositives: { before: (scoreBefore.falsePositives || []).length, after: (scoreAfter.falsePositives || []).length, newFalsePositives },
    precisionNote: 'a recovery that adds a false positive is reported as such and does not count as a clean improvement',
  };
}

/**
 * Re-scan the DEVELOPMENT targets that have a miss, with diagnostics on, and return `Map(targetId -> diagnostics)`.
 * The sealed split is refused outright: its per-case outcomes are not material for detector work.
 */
export async function collectDiagnostics({ protocol, score, defects, resolveTarget, protectedTerms = [], scanFn = defaultScanFn, layer = 'deep-taint', timeoutMs }) {
  const sealed = new Set(protocol.splits.sealed);
  const missTargets = [...new Set((score.misses || []).map((m) => m.targetId))];
  const refused = missTargets.filter((t) => sealed.has(t));
  if (refused.length) return { ok: false, errors: [{ code: 'SEALED_ACCESS', path: 'score.misses', message: `why-missed analysis is for development misses; ${refused.length} sealed target(s) refused` }], diagnostics: new Map() };
  const byTarget = new Map();
  for (const d of defects) { if (!byTarget.has(d.targetId)) byTarget.set(d.targetId, []); byTarget.get(d.targetId).push(d); }
  const out = new Map();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-diag-'));
  try {
    for (const targetId of missTargets.sort()) {
      const target = protocol.targets.find((t) => t.id === targetId);
      if (!target) continue;
      const r = await resolveTarget(target, 'pre');
      if (!r?.dir) continue;
      const staged = stageWorkspace({ srcDir: r.dir, destDir: path.join(root, targetId.replace(/[^\w.-]/g, '_')), terms: protectedTerms });
      if (!staged.ok) continue;
      try {
        const files = [...new Set((byTarget.get(targetId) || []).map((d) => d.location.file))];
        const env = engineEnvironment({ PATH: process.env.PATH, LANG: 'C', HOME: root, AGENTIC_SECURITY_DIAG_FILES: JSON.stringify(files) });
        const res = await scanFn(staged.destDir, { layer, timeoutMs: timeoutMs || protocol.limits.perTargetTimeoutMs, env, diagnose: true });
        if (res?.diagnostics) out.set(targetId, res.diagnostics);
      } catch { /* a target that cannot be diagnosed stays `unknown`, which is the honest answer */ } finally {
        fs.rmSync(staged.destDir, { recursive: true, force: true });
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  return { ok: true, errors: [], diagnostics: out };
}
