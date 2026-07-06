// 0.8.0 Feat-11: MTTR / finding-age tracking — per-finding firstSeenAt/lastSeenAt with SLA breach detection.
//
// Stamps every finding with `firstSeenAt` (preserved from the baseline if the
// finding existed previously) and `lastSeenAt` (the current scan time). Surfaces
// findings exceeding an SLA threshold per severity.
//
// Pure function — does not write to disk. The caller (CLI / fix workflow) decides
// when to persist firstSeenAt back into the baseline.

import * as crypto from 'node:crypto';

// Stable fingerprint for cross-scan finding identity. Mirrors the dedupe key.
function _fingerprint(f) {
  const file = (f.file || '').split(' -> ').pop();
  const line = f.line || f.source?.line || f.sink?.line || 0;
  const vuln = (f.vuln || f.type || '').replace(/\W+/g, '_').toLowerCase();
  const cwe = (f.cwe || '').toUpperCase();
  return crypto.createHash('sha256').update(`${file}:${line}:${vuln}:${cwe}`).digest('hex').slice(0, 16);
}

// Stamp findings in-place with firstSeenAt / lastSeenAt / ageDays.
// `findings` — current scan findings (will be mutated).
// `baselineMap` — optional Map of fingerprint → { firstSeenAt }. Pass an empty Map for first run.
// `now` — Date.now() at scan time (allow injection for tests).
export function stampFindingTimestamps(findings, baselineMap = new Map(), now = Date.now()) {
  const nowIso = new Date(now).toISOString();
  for (const f of findings) {
    const fp = _fingerprint(f);
    f._fp = fp;
    const prev = baselineMap.get(fp);
    f.firstSeenAt = prev?.firstSeenAt || nowIso;
    f.lastSeenAt = nowIso;
    const firstMs = Date.parse(f.firstSeenAt);
    f.ageDays = Math.max(0, Math.floor((now - firstMs) / 86400000));
  }
  return findings;
}

// Build a baseline map from an existing baseline JSON (or scan JSON shape).
// Recognised top-level: { findings, secrets, supplyChain }. Each entry retains
// firstSeenAt if it had one previously.
export function buildBaselineMap(baselineJson) {
  const map = new Map();
  const all = [
    ...(baselineJson?.findings || []),
    ...(baselineJson?.secrets || []),
    ...(baselineJson?.supplyChain || []).filter(s => s.type === 'vulnerable_dep'),
  ];
  for (const f of all) {
    const fp = _fingerprint(f);
    if (f.firstSeenAt) map.set(fp, { firstSeenAt: f.firstSeenAt });
  }
  return map;
}

// Identify findings exceeding an SLA threshold.
// slaDays: { critical: 7, high: 30, medium: 60, low: 90, info: 180 } (default).
export function findingsExceedingSLA(findings, slaDays = null) {
  const SLA = slaDays || { critical: 7, high: 30, medium: 60, low: 90, info: 180 };
  return findings.filter(f => {
    const limit = SLA[f.severity] ?? 90;
    return (f.ageDays || 0) > limit;
  });
}

// Median age (days) of the currently-open findings — a single-scan proxy for
// "how long has this debt been sitting". True MTTR (computeMTTR) needs the set
// of findings that were FIXED; this reports the open backlog's median age so a
// scan can show whether debt is getting older. Returns null on empty input.
// Local — surfaced only through renderSlaSummary (its sole consumer).
function medianOpenAgeDays(findings) {
  const ages = (findings || []).map(f => f.ageDays || 0).sort((a, b) => a - b);
  if (!ages.length) return null;
  return ages[Math.floor(ages.length / 2)];
}

// One-line SLA-breach summary for surfacing after a scan (#10). Returns null
// when nothing is past its per-severity SLA. Pairs with medianOpenAgeDays for a
// "is my security debt aging" readout that the vibecoder can act on.
export function renderSlaSummary(findings, slaDays = null) {
  const breached = findingsExceedingSLA(findings || [], slaDays);
  if (!breached.length) return null;
  const bySev = {};
  for (const f of breached) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  const parts = ['critical', 'high', 'medium', 'low', 'info'].filter(s => bySev[s]).map(s => `${bySev[s]} ${s}`);
  const median = medianOpenAgeDays(findings);
  const ageNote = median != null ? ` (median open age ${median}d)` : '';
  return `${breached.length} finding(s) past remediation SLA: ${parts.join(', ')}${ageNote}`;
}

// Compute MTTR statistics from a series of saved scans (each with firstSeen/lastSeen).
// Useful for trend reporting.
export function computeMTTR(removedFindings) {
  // removedFindings: findings that existed in baseline but no longer in current
  // (i.e., were fixed). Each carries firstSeenAt and lastSeenAt from the baseline.
  if (!removedFindings.length) return { count: 0, meanDays: null, medianDays: null, perSeverity: {} };
  const ages = removedFindings.map(f => {
    const first = Date.parse(f.firstSeenAt || 0);
    const last = Date.parse(f.lastSeenAt || 0);
    return Math.max(0, (last - first) / 86400000);
  }).sort((a, b) => a - b);
  const meanDays = ages.reduce((s, x) => s + x, 0) / ages.length;
  const medianDays = ages[Math.floor(ages.length / 2)];
  const perSeverity = {};
  for (const f of removedFindings) {
    const sev = f.severity || 'medium';
    (perSeverity[sev] = perSeverity[sev] || []).push(
      Math.max(0, (Date.parse(f.lastSeenAt || 0) - Date.parse(f.firstSeenAt || 0)) / 86400000)
    );
  }
  for (const k of Object.keys(perSeverity)) {
    const a = perSeverity[k];
    perSeverity[k] = { count: a.length, meanDays: a.reduce((s,x)=>s+x,0)/a.length };
  }
  return { count: removedFindings.length, meanDays, medianDays, perSeverity };
}
