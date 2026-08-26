// FR-907 (assurance-hardening PRD): "Add longitudinal production feedback
// measurement | Metrics separate user suppression, accepted risk, invalid
// finding, fixed finding, and verification outcome."
//
// Read-only aggregation over 5 ALREADY-BUILT, separate mechanisms — this
// module invents no new storage of its own, only a unified view:
//
//   user-suppression     -> triage-memory.jsonl (decision:'wont-fix'),
//                            accepted.json (vibecoder soft-accept, dated),
//                            suppressions.yml (pro exception, undated)
//   invalid-finding       -> triage-memory.jsonl (decision:'false-positive')
//   accepted-risk         -> sca-policy.yml's accept-risk[] (undated snapshot
//                            — the policy file has no per-entry creation
//                            timestamp, only an optional future `expires`)
//   fixed-finding          -> fix-history/log.json (dated via `appliedAt`,
//                            status-tagged: applied/pending/reverted/failed)
//   verification-outcome  -> fix-metrics.jsonl (dated via `at`, ok-tagged)
//
// "Longitudinal" means: every event that HAS a real timestamp is usable in
// a time-bucketed trend; every event that does NOT (accept-risk entries,
// pro suppressions — neither schema records when the entry was added) is
// still counted in its category total but reported separately as
// "undated" rather than silently smeared across the time window or
// silently dropped. Same disclosed-gap discipline this codebase already
// uses elsewhere (privacy-framework.js's engine-gap bucket, accuracy-
// scorecard.js's excluded-from-denominator entries) — a number without
// its caveat is not a measurement.
//
// Never throws (posture convention): each of the 5 reads is wrapped
// independently, so a missing or malformed source degrades only that ONE
// category to empty, never blocks the other four. Every underlying reader
// (loadSoftAccepted, loadProSuppressions, loadMemory, loadScaPolicy,
// readLog, loadFixAttempts) already degrades gracefully on its own; the
// wrapping here is defense in depth against a reader whose contract
// changes later, not a claim that today's readers can throw.

import { loadSoftAccepted, loadProSuppressions } from './suppressions.js';
import { loadMemory } from './triage-memory.js';
import { loadScaPolicy } from './sca-policy.js';
import { readLog } from './fix-history.js';
import { loadFixAttempts } from './fix-metrics.js';

const MS_PER_DAY = 86400000;

// The 5 categories named verbatim in FR-907's own acceptance criterion.
export const CATEGORIES = Object.freeze([
  'user-suppression', 'accepted-risk', 'invalid-finding', 'fixed-finding', 'verification-outcome',
]);

function _safe(fn) {
  try { return fn(); } catch { return []; }
}

/**
 * One unified event per underlying record, tagged with which of the 5
 * PRD-named categories it belongs to. `at` is an ISO timestamp or null
 * when the source schema has no per-entry creation date. `raw` keeps the
 * original record for drill-down — never re-derived from the unified
 * shape, so nothing is lost in translation.
 */
export function collectFeedbackEvents(scanRoot) {
  const events = [];

  for (const e of _safe(() => loadSoftAccepted(scanRoot))) {
    events.push({
      category: 'user-suppression', source: 'suppressions.js:accepted.json',
      at: e.accepted_at || null, findingId: e.id || null, file: e.file || null,
      line: e.line ?? null, outcome: 'soft-accepted', raw: e,
    });
  }
  for (const e of _safe(() => loadProSuppressions(scanRoot))) {
    events.push({
      category: 'user-suppression', source: 'suppressions.js:suppressions.yml',
      at: null, findingId: e.finding_id || null, file: e.file || null,
      line: null, outcome: 'pro-exception', raw: e,
    });
  }
  for (const e of _safe(() => loadMemory(scanRoot))) {
    if (e.decision === 'wont-fix') {
      events.push({
        category: 'user-suppression', source: 'triage-memory.js',
        at: e.at || null, findingId: e.id || null, file: e.file || null,
        line: e.line ?? null, outcome: 'wont-fix', raw: e,
      });
    } else if (e.decision === 'false-positive') {
      events.push({
        category: 'invalid-finding', source: 'triage-memory.js',
        at: e.at || null, findingId: e.id || null, file: e.file || null,
        line: e.line ?? null, outcome: 'false-positive', raw: e,
      });
    }
  }
  const scaPolicy = _safe(() => loadScaPolicy(scanRoot));
  const acceptRisk = scaPolicy && Array.isArray(scaPolicy.acceptRisk) ? scaPolicy.acceptRisk : [];
  for (const e of acceptRisk) {
    events.push({
      category: 'accepted-risk', source: 'sca-policy.js',
      at: null, findingId: e.cve || e.package || null, file: null,
      line: null, outcome: 'accept-risk', raw: e,
    });
  }
  for (const e of _safe(() => readLog(scanRoot))) {
    events.push({
      category: 'fixed-finding', source: 'fix-history.js',
      at: e.appliedAt || null, findingId: e.findingId || e.stableId || null,
      file: e.file || null, line: null, outcome: e.status || 'unknown', raw: e,
    });
  }
  for (const e of _safe(() => loadFixAttempts(scanRoot))) {
    events.push({
      category: 'verification-outcome', source: 'fix-metrics.js',
      at: e.at || null, findingId: e.stableId || null, file: null,
      line: null, outcome: e.ok ? 'verified' : 'not-verified', raw: e,
    });
  }

  return events;
}

/**
 * Bucket events by day within a rolling `sinceDays`-day window — the same
 * cutoff-window shape as posture/triage.js's own trend(). An event with no
 * timestamp (or an unparseable one) cannot be placed on a time axis: it is
 * counted once in `undated` per category rather than silently dropped or
 * silently smeared into the window.
 */
export function summarizeFeedbackTrend(events, { sinceDays = 30, now = Date.now() } = {}) {
  const cutoff = now - sinceDays * MS_PER_DAY;
  const byCategory = {};
  for (const cat of CATEGORIES) byCategory[cat] = { total: 0, inWindow: 0, undated: 0 };

  const dayBuckets = new Map(); // 'YYYY-MM-DD' -> { category: count }
  for (const ev of Array.isArray(events) ? events : []) {
    if (!ev || !CATEGORIES.includes(ev.category)) continue;
    byCategory[ev.category].total++;
    const t = ev.at ? Date.parse(ev.at) : NaN;
    if (!Number.isFinite(t)) { byCategory[ev.category].undated++; continue; }
    if (t < cutoff) continue;
    byCategory[ev.category].inWindow++;
    const dayKey = new Date(t).toISOString().slice(0, 10);
    if (!dayBuckets.has(dayKey)) dayBuckets.set(dayKey, {});
    const bucket = dayBuckets.get(dayKey);
    bucket[ev.category] = (bucket[ev.category] || 0) + 1;
  }

  const series = [...dayBuckets.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([day, counts]) => ({ day, counts }));
  return { sinceDays, byCategory, series };
}

/**
 * Convenience wrapper: collect + summarize in one call — same pattern as
 * fix-metrics.js's fixDurationReport(scanRoot).
 */
export function productionFeedbackReport(scanRoot, opts) {
  const events = collectFeedbackEvents(scanRoot);
  return { events, ...summarizeFeedbackTrend(events, opts) };
}

/**
 * One block of human-readable summary, or null when nothing was measured
 * at all — same "null when nothing measured" contract as
 * renderFixDurationSummary, so a caller can skip the section entirely
 * rather than print an empty header.
 */
export function renderProductionFeedbackSummary(report) {
  if (!report || !Array.isArray(report.events) || !report.events.length) return null;
  const lines = [`Production feedback (last ${report.sinceDays}d):`];
  for (const cat of CATEGORIES) {
    const c = report.byCategory[cat];
    if (!c || c.total === 0) continue;
    const undatedNote = c.undated ? `, ${c.undated} undated` : '';
    lines.push(`  ${cat}: ${c.inWindow} in window / ${c.total} total${undatedNote}`);
  }
  return lines.length > 1 ? lines.join('\n') : null;
}

export const _internals = { MS_PER_DAY };
