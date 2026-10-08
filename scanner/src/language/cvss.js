// CVSS v3.x base-score calculator and advisory-severity selection for the Haskell and Nix SCA matchers.
// Pure: no I/O. Never invents a rating: a vector that cannot be parsed, or a CVSS version this module does not compute
// (v4 needs lookup tables that are not shipped), yields no score and says why.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };
const REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

// CVSS 3.1 Roundup (spec appendix A, integer arithmetic so float error cannot move a score across a boundary).
function roundUp31(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
const roundUp30 = (x) => Math.ceil(x * 10) / 10;

/** @returns {{ok:true, version:string, score:number, vector:string}|{ok:false, reason:string}} */
export function cvssV3BaseScore(vector) {
  if (typeof vector !== 'string') return { ok: false, reason: 'the CVSS vector is not a string' };
  const parts = vector.trim().split('/');
  const m = /^CVSS:(3\.[01])$/.exec(parts[0] || '');
  if (!m) return { ok: false, reason: /^CVSS:4/.test(parts[0] || '') ? 'CVSS v4 vectors are not scored by this tool' : 'the vector is not a CVSS v3.0/v3.1 vector' };
  const version = m[1];
  const metrics = {};
  for (const p of parts.slice(1)) {
    const kv = /^([A-Za-z]+):([A-Za-z])$/.exec(p);
    if (!kv || kv[1] in metrics) return { ok: false, reason: `malformed or repeated metric "${p}"` };
    metrics[kv[1]] = kv[2];
  }
  for (const k of REQUIRED) if (!(k in metrics)) return { ok: false, reason: `missing base metric ${k}` };
  if (metrics.S !== 'C' && metrics.S !== 'U') return { ok: false, reason: `invalid scope value "${metrics.S}"` };
  const changed = metrics.S === 'C';
  const av = W.AV[metrics.AV], ac = W.AC[metrics.AC], ui = W.UI[metrics.UI];
  const c = W.CIA[metrics.C], i = W.CIA[metrics.I], a = W.CIA[metrics.A];
  const pr = PR[metrics.S][metrics.PR];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined)) return { ok: false, reason: 'an unknown value in a base metric' };
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  const up = version === '3.1' ? roundUp31 : roundUp30;
  const score = impact <= 0 ? 0 : changed ? up(Math.min(1.08 * (impact + expl), 10)) : up(Math.min(impact + expl, 10));
  return { ok: true, version, score, vector: vector.trim() };
}

export function levelFromScore(score) {
  if (!(score > 0)) return null;
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
}

const NAMED = { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' };
export const normalizeSeverityName = (s) => (typeof s === 'string' ? NAMED[s.trim().toLowerCase()] || null : null);

export const NO_RATING_BASIS = 'the advisory carries no severity rating';

/**
 * Pick the advisory's own severity from an OSV record: CVSS vectors at record level and on each affected entry, then
 * database_specific.severity (record, then affected). The highest parseable CVSS score wins; a named severity is used
 * only when no vector could be scored. Returns {level:null, basis} when nothing usable exists.
 */
export function advisorySeverity(rec) {
  const vectors = [];
  const named = [];
  const take = (sevArr, dbs) => {
    for (const s of Array.isArray(sevArr) ? sevArr : []) if (s && typeof s.score === 'string') vectors.push(s.score);
    if (dbs && typeof dbs.severity === 'string') named.push(dbs.severity);
  };
  if (rec && typeof rec === 'object') {
    take(rec.severity, rec.database_specific);
    for (const a of Array.isArray(rec.affected) ? rec.affected : []) if (a && typeof a === 'object') take(a.severity, a.database_specific);
  }
  let best = null; const why = [];
  for (const v of vectors) {
    const r = cvssV3BaseScore(v);
    if (r.ok) { if (!best || r.score > best.score) best = r; } else why.push(r.reason);
  }
  if (best) {
    const level = levelFromScore(best.score);
    if (level) return { level, score: best.score, vector: best.vector, basis: `CVSS v${best.version} base score ${best.score.toFixed(1)} from the advisory` };
    why.push('the CVSS base score is 0.0 (no impact)');
  }
  for (const n of named) {
    const level = normalizeSeverityName(n);
    if (level) return { level, score: null, vector: null, basis: `severity "${n}" stated by the advisory (database_specific)` };
    why.push(`unrecognised severity "${String(n).slice(0, 40)}"`);
  }
  return { level: null, score: null, vector: null, basis: why.length ? `${NO_RATING_BASIS} that could be used (${[...new Set(why)].join('; ')})` : NO_RATING_BASIS };
}
