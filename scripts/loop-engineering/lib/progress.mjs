// Completion accounting. The numerator is only fresh, fully-passing, independently
// issued evidence; everything else, including stale-but-implemented, blocked
// and failed work, stays in the denominator.
import { assessRequirement } from './evidence.mjs';

export function formatPercent(num, den) {
  if (den <= 0) return 0;
  if (num >= den) return 100;
  return Math.min(99.9, Math.floor((num / den) * 1000) / 10);
}

export const CATEGORY_LABEL = { haskell: 'Haskell', nix: 'Nix/NixOS', shared: 'Shared', loop: 'Loop', quality: 'Quality', documentation: 'Documentation', release: 'Release' };

export function assessAll({ L, manifest, tree, key, checkLogs = false }) {
  const map = new Map();
  for (const r of manifest.requirements) map.set(r.id, assessRequirement(L, r, { key, manifest, tree, checkLogs }));
  return map;
}

export function computeProgress(manifest, assessMap, runReqState = {}) {
  const byId = new Map(manifest.requirements.map((r) => [r.id, r]));
  const verifiedIds = new Set([...assessMap].filter(([, a]) => a.verified).map(([id]) => id));
  const rows = [];
  const counts = { verified: 0, stale: 0, blocked: 0, failed: 0, 'timed-out': 0, running: 0, verifying: 0, 'retry-wait': 0, ready: 0, pending: 0, paused: 0 };
  let num = 0, den = 0, critPass = 0, critTotal = 0;
  const cat = {};
  for (const r of manifest.requirements) {
    const a = assessMap.get(r.id);
    const st = runReqState[r.id] || {};
    const depsOk = r.dependencies.every((d) => verifiedIds.has(d));
    let state;
    if (a.verified) state = 'verified';
    else if (a.stale) state = 'stale';
    else if (st.state && ['running', 'verifying', 'retry-wait', 'blocked', 'failed', 'timed-out', 'paused'].includes(st.state)) state = st.state;
    else state = depsOk ? 'ready' : 'pending';
    counts[state] = (counts[state] || 0) + 1;
    const c = (cat[r.category] ||= { num: 0, den: 0, requirements: 0, verified: 0 });
    c.den += r.weight; c.requirements += 1;
    den += r.weight;
    critTotal += r.criteria.length;
    // Criteria count as passed only when the evidence carrying them is fresh.
    if (a.latest && a.fresh) critPass += a.passedCriteria;
    if (state === 'verified') { num += r.weight; c.num += r.weight; c.verified += 1; }
    const failing = a.latest ? (a.latest.ev.criteria || []).filter((x) => x.state !== 'pass').map((x) => x.id) : r.criteria.map((x) => x.id);
    rows.push({
      id: r.id, title: r.title, category: r.category, weight: r.weight, state,
      dependencies: r.dependencies, dependenciesVerified: depsOk,
      criteria: { passed: a.latest && a.fresh ? a.passedCriteria : 0, total: r.criteria.length },
      implementedButStale: state === 'stale',
      unmetCriteria: state === 'verified' ? [] : failing,
      staleReasons: a.staleReasons || [],
      attempts: st.attempts || 0,
      blockers: st.blockers || [],
      lastFailure: st.lastFailure || null,
      nextEligibleAt: st.nextEligibleAt || null,
      evidence: a.latest ? { id: a.latest.ev.evidenceId, result: a.latest.ev.result, at: a.latest.ev.createdAt, fresh: a.fresh, file: a.latest.file } : null,
      rejectedEvidence: (a.rejected || []).length,
    });
  }
  void byId;
  const categories = Object.fromEntries(Object.entries(cat).map(([k, c]) => [k, { label: CATEGORY_LABEL[k] || k, verifiedPercent: formatPercent(c.num, c.den), verifiedWeight: c.num, totalWeight: c.den, verifiedRequirements: c.verified, totalRequirements: c.requirements }]));
  return {
    verifiedPercent: formatPercent(num, den),
    verifiedWeight: num, totalWeight: den,
    verifiedRequirements: counts.verified, totalRequirements: manifest.requirements.length,
    passedCriteria: critPass, totalCriteria: critTotal,
    counts, categories, requirements: rows,
  };
}

export function nextReady(manifest, progress, now = Date.now()) {
  const row = progress.requirements.find((r) => (r.state === 'ready' || r.state === 'stale' || r.state === 'retry-wait') && r.dependenciesVerified
    && (!r.nextEligibleAt || r.nextEligibleAt <= now));
  return row || null;
}
