// FR-806 (assurance-hardening PRD): "Validate model calibration against
// accepted and realized incidents where customers opt in | Calibration
// reports are aggregated and privacy-preserving."
//
// SCOPE, stated explicitly because the PRD's own wording is terse: this
// codebase has no SaaS control plane and takes no runtime cloud calls
// (root CLAUDE.md's own "No runtime cloud calls" rule, and E10's own goal
// of "consistent policy... without requiring a SaaS control plane") — so
// "aggregated" here means aggregated WITHIN one installation, across every
// feedback event an operator has recorded over time, never aggregated
// ACROSS installations on some central server. An operator who wants a
// cross-organization rollup can feed this module's own report output into
// their own aggregation, the same way `fleet.js` composes many single-repo
// scans without a hosted backend.
//
// TWO OUTCOMES, matching the PRD's own two named cases:
//   'accepted-risk'    — an operator/customer reviewed a finding, accepted
//                        the risk, and (later, of their own accord) reports
//                        that no incident occurred. A well-calibrated model
//                        should have predicted LOW confidence/risk for
//                        these.
//   'realized-incident' — an operator reports that a finding's
//                        vulnerability WAS actually exploited or otherwise
//                        caused a real incident. A well-calibrated model
//                        should have predicted HIGH confidence/risk for
//                        these — a realized incident on a LOW-predicted
//                        finding is exactly the miscalibration this
//                        requirement exists to surface.
//
// PRIVACY-PRESERVING AT THE SOURCE, not just at the report layer: a
// feedback record snapshots only the model's OWN prediction signals
// (confidence, severity, riskDollars.ev) plus the operator's outcome and
// optional free-text note — never file path, line, vuln title, or code
// snippet. This mirrors this codebase's existing privacy modules' own
// discipline (dataflow/privacy-*.js) of never persisting more than a
// report needs to answer its one question.
//
// OPT-IN, genuinely: nothing here is ever auto-populated by a scan. A
// record exists only when an operator explicitly calls
// `recordCalibrationFeedback` (via the CLI's `calibration-feedback record`
// command) — the file simply does not exist for every project that never
// opts in, and every read degrades to "no data" rather than throwing.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { statePath, stateDir, isSafeStateDir, stateWritesEnabled } from './state-dir.js';

export const CALIBRATION_FEEDBACK_FILE = 'calibration-feedback.jsonl';
export const OUTCOMES = Object.freeze(['accepted-risk', 'realized-incident']);

// Below this many samples, a rate is an artifact of the sample, not a
// property of the model — same precedent as fix-metrics.js's RELIABLE_N.
const RELIABLE_N = 10;

function _findFinding(scanRoot, findingId) {
  try {
    const raw = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8'));
    const findings = Array.isArray(raw.findings) ? raw.findings : [];
    return findings.find(f => f && (f.id === findingId || f.stableId === findingId)) || null;
  } catch { return null; }
}

// FR-806 privacy fix: the caller-supplied findingId is routinely a finding's
// plain `.id` (e.g. "client-side:DANGEROUS_INNERHTML:src/billing/secret.js:142"),
// which embeds the exact file path and line this module's own docstring
// promises never to persist. Never write the caller's raw string to disk:
// prefer the matched finding's own privacy-safe `.stableId` (a hash, by
// construction elsewhere in this codebase), and otherwise hash the input
// ourselves so a stale/removed finding's id can never leak path/line either.
function _privacySafeFindingId(findingId, finding) {
  if (finding && typeof finding.stableId === 'string' && finding.stableId) return finding.stableId;
  return crypto.createHash('sha256').update(findingId).digest('hex').slice(0, 16);
}

/**
 * Record one opt-in calibration-feedback event. Snapshots ONLY the
 * model's own prediction signals for the named finding (if it is still
 * present in the last scan — a finding fixed/removed since is still
 * recordable, just without a fresh snapshot) plus the outcome and an
 * optional note. Never throws; returns {ok, record} or {ok:false, reason}.
 */
export function recordCalibrationFeedback(scanRoot, { findingId, outcome, note } = {}) {
  if (!findingId || typeof findingId !== 'string') return { ok: false, reason: '--finding-id is required' };
  if (!OUTCOMES.includes(outcome)) return { ok: false, reason: `--outcome must be one of: ${OUTCOMES.join(', ')}` };
  const finding = _findFinding(scanRoot, findingId);
  const record = {
    at: new Date().toISOString(),
    findingId: _privacySafeFindingId(findingId, finding),
    outcome,
    predictedConfidence: finding && typeof finding.confidence === 'number' ? finding.confidence : null,
    predictedConfidenceTier: finding?.confidenceTier || null,
    predictedSeverity: finding?.severity || null,
    predictedRiskEv: finding?.riskDollars && typeof finding.riskDollars.ev === 'number' ? finding.riskDollars.ev : null,
    note: note ? String(note).slice(0, 280) : null,
  };
  // Append-only, same primitives as fix-metrics.js/triage-memory.js's own
  // JSONL writers — a single fs.appendFileSync, never a read-modify-write
  // of the whole file (which would also reintroduce a TOCTOU between an
  // existence check and the write, the exact anti-pattern this codebase's
  // own conventions forbid).
  const dir = stateDir(scanRoot);
  if (!isSafeStateDir(dir)) return { ok: false, reason: 'no safe state directory' };
  if (!stateWritesEnabled()) return { ok: false, reason: 'state writes are disabled (--no-state)' };
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(statePath(scanRoot, CALIBRATION_FEEDBACK_FILE), JSON.stringify(record) + '\n', 'utf8');
  } catch (e) { return { ok: false, reason: e.message }; }
  return { ok: true, record };
}

/**
 * Every well-formed feedback event ever recorded. A line that fails to
 * parse or lacks a valid outcome is skipped, not fatal.
 */
export function loadCalibrationFeedback(scanRoot) {
  let fp;
  try { fp = statePath(scanRoot, CALIBRATION_FEEDBACK_FILE); } catch { return []; }
  let raw;
  try { raw = fs.readFileSync(fp, 'utf8'); } catch { return []; }
  const out = [];
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line);
      if (rec && OUTCOMES.includes(rec.outcome)) out.push(rec);
    } catch { /* torn or hand-edited line — drop it, keep the rest */ }
  }
  return out;
}

function _avg(nums) {
  const v = nums.filter(n => typeof n === 'number' && Number.isFinite(n));
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
}

function _summarizeOutcome(records) {
  const withConfidence = records.map(r => r.predictedConfidence).filter(c => typeof c === 'number');
  return {
    n: records.length,
    reliable: records.length >= RELIABLE_N,
    avgPredictedConfidence: _avg(withConfidence),
    withoutPrediction: records.length - withConfidence.length,
  };
}

/**
 * Aggregate ALL recorded feedback (this installation only — see the
 * module header for why cross-installation aggregation is out of scope)
 * into a privacy-preserving report: rates and averages only, never a
 * per-finding breakdown, never file/line/vuln text (none of that was ever
 * stored in the first place).
 */
export function buildCalibrationReport(scanRoot) {
  const records = loadCalibrationFeedback(scanRoot);
  const acceptedRisk = records.filter(r => r.outcome === 'accepted-risk');
  const realizedIncident = records.filter(r => r.outcome === 'realized-incident');
  return {
    schema: 'agentic-security/calibration-report@1',
    generatedAt: new Date().toISOString(),
    totalEvents: records.length,
    acceptedRisk: _summarizeOutcome(acceptedRisk),
    realizedIncident: _summarizeOutcome(realizedIncident),
    // The calibration question itself: accepted-risk events SHOULD skew
    // toward low predicted confidence; realized-incident events SHOULD
    // skew toward high. This flag is a coarse, disclosed-uncertainty
    // signal, not a verdict — it only ever fires when BOTH buckets have
    // enough samples to say anything at all (RELIABLE_N each).
    possibleMiscalibration: (() => {
      const a = _summarizeOutcome(acceptedRisk);
      const r = _summarizeOutcome(realizedIncident);
      if (!a.reliable || !r.reliable || a.avgPredictedConfidence == null || r.avgPredictedConfidence == null) return null;
      return r.avgPredictedConfidence <= a.avgPredictedConfidence;
    })(),
  };
}

/**
 * One block of human-readable summary, or null when nothing has ever been
 * recorded — genuinely opt-in, so "nothing recorded" is the expected
 * default state for almost every project, not an error.
 */
export function renderCalibrationReportSummary(report) {
  if (!report || report.totalEvents === 0) return null;
  const lines = [
    'Calibration feedback (this installation, opt-in):',
    `  accepted-risk:     n=${report.acceptedRisk.n}${report.acceptedRisk.reliable ? '' : ' (below reliable sample size)'}` +
      (report.acceptedRisk.avgPredictedConfidence != null ? `  avg predicted confidence=${report.acceptedRisk.avgPredictedConfidence.toFixed(2)}` : ''),
    `  realized-incident: n=${report.realizedIncident.n}${report.realizedIncident.reliable ? '' : ' (below reliable sample size)'}` +
      (report.realizedIncident.avgPredictedConfidence != null ? `  avg predicted confidence=${report.realizedIncident.avgPredictedConfidence.toFixed(2)}` : ''),
  ];
  if (report.possibleMiscalibration === true) {
    lines.push('  ⚠ realized incidents were NOT predicted with higher confidence than accepted risks — possible miscalibration.');
  } else if (report.possibleMiscalibration === false) {
    lines.push('  ✓ realized incidents were predicted with higher confidence than accepted risks, as expected.');
  } else {
    lines.push('  (not enough samples in both buckets yet to assess calibration — this is not a pass or fail.)');
  }
  return lines.join('\n');
}

export const _internals = { RELIABLE_N, _findFinding };
