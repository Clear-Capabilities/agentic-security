// Haskell and Nix support registry and promotion gate (HS-011, QA-002).
//
// A capability row says what is SUPPORTED, from MEASURED evidence only. The registry never grants support from an installed parser,
// a structural-only detection, a metric of another kind, or labels that changed after the measurement. `evaluateSupport` is pure:
// it takes a measurement (bench/language-support/measure.mjs output) plus the results of the named test suites and returns each
// capability's status with the reasons it is or is not supported. Nothing here runs a scan or reads the corpus.
//
//   supported      every criterion for the row has passing evidence of the row's OWN metric kind, on the frozen corpus
//   partial        measured, some criteria met and some not (the unmet ones are listed)
//   failed         measured and below target
//   not-measured   no evidence of the right kind (a zero or absent denominator is never 100%)
//   blocked        a required tool or host is absent (a compiler, nix, a NixOS host): the criterion could not run, which is a
//                  failed criterion for support, never a skip

export const SUPPORT_REGISTRY_VERSION = 'language-support/1';

/** The section 9.2 numerical gates. */
export const TARGETS = Object.freeze({ precision: 0.9, recall: 0.85, f1: 0.8, perFamilyF1: 0.8, minHoldoutPerLabelPerFamily: 5, minPrivacyPositives: 100, minPrivacyNegatives: 100 });

/** The pairs gate is this project's own (the PRD sets none): semantics-changing pairs must ALL flip; preserving pairs may not drift much. */
export const PAIR_GATE = Object.freeze({ change: 1, preserve: 0.9 });

/** Required capabilities per ecosystem, with the metric kind each one may be promoted from. */
export const REQUIRED_CAPABILITIES = Object.freeze({
  haskell: Object.freeze({
    parser: 'parse-fixtures', sast: 'sast-holdout', taint: 'taint-holdout', 'privacy-lineage': 'privacy-holdout',
    auth: 'auth-detection', sca: 'sca-fixtures', bom: 'test-suite', fix: 'fix-fixtures', integration: 'test-suite',
  }),
  nix: Object.freeze({
    parser: 'parse-fixtures', 'config-sast': 'sast-holdout', 'config-taint': 'taint-holdout', 'privacy-lineage': 'privacy-holdout',
    sca: 'sca-fixtures', bom: 'test-suite', fix: 'fix-fixtures', integration: 'test-suite', 'nix-eval': 'test-suite', 'nixos-host': 'host-run',
  }),
});

/**
 * Authentication and authorization are rated on DETECTION of the families that carry them (measured on the frozen holdout, gated like
 * any other layer) AND on the web-model test suite passing. A pass/fail test run alone is not a measurement of how well missing or
 * broken authentication is found, so it can never promote this row by itself.
 */
export const AUTH_FAMILIES = Object.freeze(['route-authentication', 'object-authorization']);

/** Capabilities that need an external tool or host to be exercised at all: absent, the row is BLOCKED whatever its tests say. */
export const REQUIRES_TOOL = Object.freeze({
  haskell: Object.freeze({ auth: Object.freeze({ tool: 'ghc', why: 'the route fixtures are compiled by GHC (HS-006.AC01)' }) }),
  nix: Object.freeze({
    'nix-eval': Object.freeze({ tool: 'nix', why: 'a successful controlled evaluation needs a real nix binary (NIX-011.AC04)' }),
    'nixos-host': Object.freeze({ tool: 'nixos', why: 'the complete scanner must run on a NixOS host (NIX-012)' }),
  }),
});

/** Metric kinds that can NEVER promote a row, whatever their value. */
export const NON_PROMOTING_EVIDENCE = Object.freeze(['installation', 'grammar-present', 'structural-only', 'documentation', 'model-assertion', 'taint-as-privacy', 'unknown']);

const ratio = (n, d) => (d > 0 ? n / d : null);

/**
 * Exact (Clopper-Pearson) two-sided confidence interval for k successes in n trials. A rate of 30/30 is NOT "100%": its 95% lower
 * bound is about 0.88, and a table that prints 1.000 without it invites exactly that misreading.
 */
export function clopperPearson(k, n, alpha = 0.05) {
  if (!(n > 0)) return null;
  const binomTail = (p, from) => { // P(X >= from) for X ~ Bin(n, p), computed in log space
    let sum = 0;
    for (let i = from; i <= n; i++) {
      let lc = 0; for (let j = 1; j <= i; j++) lc += Math.log((n - i + j) / j);
      sum += Math.exp(lc + (p > 0 ? i * Math.log(p) : (i === 0 ? 0 : -Infinity)) + (p < 1 ? (n - i) * Math.log(1 - p) : (n - i === 0 ? 0 : -Infinity)));
    }
    return sum;
  };
  const bisect = (f, lo, hi) => { for (let i = 0; i < 80; i++) { const mid = (lo + hi) / 2; if (f(mid)) hi = mid; else lo = mid; } return (lo + hi) / 2; };
  const lower = k === 0 ? 0 : bisect((p) => binomTail(p, k) >= alpha / 2, 0, 1);
  const upper = k === n ? 1 : bisect((p) => binomTail(p, k + 1) >= 1 - alpha / 2, 0, 1);
  return [lower, upper];
}
// Every unseen shape is instantiated with TWO near-identical nouns, so those two cases are one observation, not two. The interval over
// cases would be too narrow; this one is over shapes (counts halved, rounded), and is labelled so.
const SHAPE_CLUSTER = 2;
const ciShapes = (k, n) => { const r = clopperPearson(Math.round(k / SHAPE_CLUSTER), Math.max(1, Math.round(n / SHAPE_CLUSTER))); return r ? [Number(r[0].toFixed(4)), Number(r[1].toFixed(4))] : null; };
const ci = (k, n) => { const r = clopperPearson(k, n); return r ? [Number(r[0].toFixed(4)), Number(r[1].toFixed(4))] : null; };
const withInterval = (e) => (e && Number.isFinite(e.tp) ? { ...e, ci: { precision: ci(e.tp, e.tp + (e.fp || 0)), recall: ci(e.tp, e.tp + (e.fn || 0)), level: 0.95, method: 'Clopper-Pearson' } } : e);
const pct = (x) => (x == null ? 'not measured' : `${(x * 100).toFixed(1)}%`);

function rate(layer) {
  if (!layer || !layer.measured) return { precision: null, recall: null, f1: null };
  return { precision: layer.precision, recall: layer.recall, f1: layer.f1 };
}

/** Section 9.2 gate for one scored layer. Returns {ok, reasons}. `perFamilyCases` supplies the holdout denominators per family. */
export function gateLayer(layer, perFamilyCases, { kind }) {
  const reasons = [];
  if (!layer || !layer.measured) return { ok: false, reasons: [`${kind}: not measured (a zero or absent denominator is never 100%)`] };
  const r = rate(layer);
  if (!(r.precision >= TARGETS.precision)) reasons.push(`precision ${pct(r.precision)} < ${pct(TARGETS.precision)} (${layer.tp} TP, ${layer.fp} FP)`);
  if (!(r.recall >= TARGETS.recall)) reasons.push(`recall ${pct(r.recall)} < ${pct(TARGETS.recall)} (${layer.tp} TP, ${layer.fn} FN)`);
  if (!(r.f1 >= TARGETS.f1)) reasons.push(`F1 ${pct(r.f1)} < ${pct(TARGETS.f1)}`);
  const fams = layer.families || {};
  for (const [name, m] of Object.entries(fams)) {
    // a family absent from the holdout cannot pass; a family with too few examples of either label cannot pass
    const f1 = m.f1 == null ? null : m.f1;
    if (!(f1 >= TARGETS.perFamilyF1)) reasons.push(`family ${name}: F1 ${pct(f1)} < ${pct(TARGETS.perFamilyF1)}`);
  }
  for (const [name, c] of Object.entries(perFamilyCases || {})) {
    if (!(c.vulnerable >= TARGETS.minHoldoutPerLabelPerFamily && c.safe >= TARGETS.minHoldoutPerLabelPerFamily)) reasons.push(`family ${name}: holdout has ${c.vulnerable} vulnerable / ${c.safe} safe (< ${TARGETS.minHoldoutPerLabelPerFamily} each)`);
  }
  return { ok: reasons.length === 0, reasons };
}

function suiteStatus(results, names) {
  // suites are keyed by file base name; a capability lists the files (paths) that back it
  const rows = (names || []).map((n) => results && results[String(n).split('/').pop()]);
  if (!(names || []).length || rows.some((r) => !r)) return { ok: false, status: 'not-measured', reasons: ['no test-suite evidence was recorded for this capability'] };
  const reasons = [];
  for (const r of rows) {
    if (r.blocked) reasons.push(`${r.name}: blocked (${r.blocked})`);
    else if (r.fail > 0) reasons.push(`${r.name}: ${r.fail} failing test(s)`);
    if (r.skipped > 0) reasons.push(`${r.name}: ${r.skipped} skipped test(s) (a skip is not a pass)`);
    if (!(r.tests > 0)) reasons.push(`${r.name}: no tests ran`);
  }
  if (reasons.some((x) => /blocked/.test(x))) return { ok: false, status: 'blocked', reasons };
  return { ok: reasons.length === 0, status: reasons.length ? 'failed' : 'supported', reasons };
}

/**
 * @param {string} language 'haskell' | 'nix'
 * @param {{measurement: object, suites?: Record<string,object>, capabilitySuites?: Record<string,string[]>, frozen?: object}} input
 *   measurement: the holdout measurement; suites: test-suite results by name; capabilitySuites: which suites back each capability;
 *   frozen: {holdoutRollup, labelsSha256, privacyLabelsSha256} of the corpus AS IT IS NOW (a measurement on other data cannot promote).
 */
export function evaluateSupport(language, input) {
  const required = REQUIRED_CAPABILITIES[language];
  if (!required) throw new Error(`unknown language ${language}`);
  const m = input.measurement || {};
  const eco = (m.ecosystems && m.ecosystems[language]) || {};
  const out = { language, version: SUPPORT_REGISTRY_VERSION, rows: {}, summary: {} };
  const dataOk = (() => {
    if (!input.frozen) return { ok: false, reasons: ['no frozen corpus hashes were supplied to check the measurement against'] };
    const h = m.hashes || {};
    const reasons = [];
    if (m.split !== 'holdout') reasons.push(`the measurement is on the "${m.split}" split, not the frozen holdout`);
    if (h.holdoutRollup !== input.frozen.holdoutRollup) reasons.push('the measured holdout hash is not the current frozen holdout');
    if (h.labelsSha256 !== input.frozen.labelsSha256) reasons.push('the measured labels are not the current labels (changed benchmark labels cannot promote a row)');
    if (h.privacyLabelsSha256 !== input.frozen.privacyLabelsSha256) reasons.push('the measured privacy labels are not the current privacy labels');
    return { ok: reasons.length === 0, reasons };
  })();

  const row = (capability, status, reasons, evidence) => { out.rows[capability] = { capability, status, reasons, evidence: evidence || null }; };
  const detection = eco.detection || {};
  const layerKey = (cap) => (/taint/.test(cap) ? 'taint' : 'sast');

  for (const [cap, kind] of Object.entries(required)) {
    if (kind === 'parse-fixtures') {
      const p = eco.parser;
      if (!p || !(p.validFixtures > 0)) { row(cap, 'not-measured', ['no parse-fixture measurement']); continue; }
      const reasons = [];
      if (p.validFixturesParsedCleanly !== p.validFixtures) reasons.push(`${p.validFixturesParsedCleanly}/${p.validFixtures} valid fixtures parsed cleanly`);
      if ((p.crashed || []).length) reasons.push(`${p.crashed.length} crash(es)`);
      const u = detection.unknownOutcomes;
      if (u && (u.silentClean > 0 || u.requiredDisclosureMissing > 0)) reasons.push(`unknown cases: ${u.silentClean} silent-clean, ${u.requiredDisclosureMissing} undisclosed required boundary`);
      row(cap, reasons.length ? 'failed' : 'supported', reasons, { metric: 'parse-fixtures', files: p.files, parsed: p.parsed, validFixtures: p.validFixtures, crashed: (p.crashed || []).length });
    } else if (kind === 'sast-holdout' || kind === 'taint-holdout') {
      const key = layerKey(cap);
      const layer = (detection.layers || {})[key];
      const g = gateLayer(layer, filterFamilies(detection.perFamilyCases, layer), { kind: key });
      const reasons = [...g.reasons, ...dataOk.reasons];
      const u = detection.unknownOutcomes;
      if (u && u.silentClean > 0) reasons.push(`${u.silentClean} unknown case(s) came back with neither a finding nor a disclosure (false assurance)`);
      row(cap, !layer || !layer.measured ? 'not-measured' : reasons.length ? 'failed' : 'supported', reasons, layer ? { metric: kind, layer: key, tp: layer.tp, fp: layer.fp, fn: layer.fn, tn: layer.tn, precision: layer.precision, recall: layer.recall, f1: layer.f1, cases: layer.cases, families: layer.families, strictPrecision: layer.strict && layer.strict.precision } : null);
    } else if (kind === 'auth-detection') {
      const sast = detection.layers && detection.layers.sast;
      const fams = Object.fromEntries(AUTH_FAMILIES.filter((f) => sast && sast.families && sast.families[f]).map((f) => [f, sast.families[f]]));
      if (!Object.keys(fams).length) { row(cap, 'not-measured', [`no measured authentication families (${AUTH_FAMILIES.join(', ')}): a passing test run is not a detection measurement`]); continue; }
      const sum = (k) => Object.values(fams).reduce((n, x) => n + (x[k] || 0), 0);
      const tp = sum('tp'); const fp = sum('fp'); const fn = sum('fn');
      const precision = ratio(tp, tp + fp); const recall = ratio(tp, tp + fn);
      const f1 = precision != null && recall != null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
      const pseudo = { measured: true, tp, fp, fn, tn: sum('tn'), precision, recall, f1, families: fams };
      const g = gateLayer(pseudo, filterFamilies(detection.perFamilyCases, pseudo), { kind: 'auth' });
      const ts = suiteStatus(input.suites, (input.capabilitySuites || {})[cap]);
      const reasons = [...g.reasons, ...dataOk.reasons, ...(ts.ok ? [] : ts.reasons)];
      row(cap, reasons.length ? (ts.status === 'blocked' ? 'blocked' : 'failed') : 'supported', reasons, { metric: 'auth-detection', layer: 'sast', families: Object.keys(fams), tp, fp, fn, precision, recall, f1, suites: ((input.capabilitySuites || {})[cap] || []) });
    } else if (kind === 'privacy-holdout') {
      const p = eco.privacy;
      if (!p || !(p.positives > 0 && p.negatives > 0)) { row(cap, 'not-measured', ['no privacy field-to-sink measurement (a security finding or a taint metric is never a privacy metric)']); continue; }
      const reasons = [...dataOk.reasons];
      if (!(p.precision >= TARGETS.precision)) reasons.push(`precision ${pct(p.precision)} < ${pct(TARGETS.precision)}`);
      if (!(p.recall >= TARGETS.recall)) reasons.push(`recall ${pct(p.recall)} < ${pct(TARGETS.recall)}`);
      if (!(p.f1 >= TARGETS.f1)) reasons.push(`F1 ${pct(p.f1)} < ${pct(TARGETS.f1)}`);
      const tot = (m.corpusTotals && m.corpusTotals[language] && m.corpusTotals[language].privacy) || null;
      if (!tot || !(tot.positives >= TARGETS.minPrivacyPositives && tot.negatives >= TARGETS.minPrivacyNegatives)) reasons.push(`the corpus has ${tot ? `${tot.positives} positive / ${tot.negatives} negative` : 'unknown'} field-to-sink expectations (< ${TARGETS.minPrivacyPositives} each)`);
      row(cap, reasons.length ? 'failed' : 'supported', reasons, { metric: 'privacy-holdout', positives: p.positives, negatives: p.negatives, tp: p.tp, fp: p.fp, fn: p.fn, tn: p.tn, precision: p.precision, recall: p.recall, f1: p.f1, byKind: p.byKind });
    } else if (kind === 'sca-fixtures') {
      const s = m.supply || {};
      const reasons = [];
      const man = s.manifests; const rng = s.advisoryRanges;
      if (!man || !man.total) reasons.push('no manifest-resolution measurement');
      else if (man.exact !== man.total) reasons.push(`${man.exact}/${man.total} manifest fixtures exact`);
      if (language === 'haskell') { if (!rng || !rng.total) reasons.push('no advisory-range replay'); else if (rng.correct !== rng.total) reasons.push(`${rng.correct}/${rng.total} advisory range checks correct`); }
      const ts = suiteStatus(input.suites, (input.capabilitySuites || {})[cap]);
      if (!ts.ok) reasons.push(...ts.reasons);
      row(cap, reasons.length ? (ts.status === 'blocked' ? 'blocked' : 'failed') : 'supported', reasons, { metric: 'sca-fixtures', manifests: man ? `${man.exact}/${man.total}` : null, advisoryRanges: rng ? `${rng.correct}/${rng.total}` : null });
    } else if (kind === 'fix-fixtures') {
      const f = eco.fixes;
      if (!f) { row(cap, 'not-measured', ['no fix-fixture measurement']); continue; }
      const reasons = [];
      if (f.accept.correct !== f.accept.total) reasons.push(`${f.accept.correct}/${f.accept.total} valid proposals accepted`);
      if (f.reject.correct !== f.reject.total) reasons.push(`${f.reject.correct}/${f.reject.total} bad proposals rejected`);
      if (f.advertised.verified !== f.advertised.planned) reasons.push(`${f.advertised.verified}/${f.advertised.planned} advertised deterministic fixes verified`);
      const ts = suiteStatus(input.suites, (input.capabilitySuites || {})[cap]);
      if (!ts.ok) reasons.push(...ts.reasons);
      const pairs = eco.pairs;
      row(cap, reasons.length ? (ts.status === 'blocked' ? 'blocked' : 'failed') : 'supported', reasons, { metric: 'fix-fixtures', accepted: `${f.accept.correct}/${f.accept.total}`, rejected: `${f.reject.correct}/${f.reject.total}`, advertised: `${f.advertised.verified}/${f.advertised.planned}`, unsupportedShapes: f.advertised.unsupported, pairs: pairs ? { preserve: `${pairs.preserve.held}/${pairs.preserve.total}`, change: `${pairs.change.held}/${pairs.change.total}` } : null });
    } else if (kind === 'test-suite' || kind === 'host-run') {
      const ts = suiteStatus(input.suites, (input.capabilitySuites || {})[cap]);
      row(cap, ts.status === 'supported' ? 'supported' : ts.status, ts.reasons, { metric: kind, suites: ((input.capabilitySuites || {})[cap] || []) });
    }
  }
  // 95% intervals beside every measured rate, and the strict precision (which counts findings of other families) beside the scoped one
  for (const r of Object.values(out.rows)) {
    if (!r.evidence || !Number.isFinite(r.evidence.tp)) continue;
    const key = /taint/.test(r.capability) ? 'taint' : 'sast';
    const strict = r.evidence.metric === 'sast-holdout' || r.evidence.metric === 'taint-holdout' ? (detection.layers || {})[key] && (detection.layers[key].strict || null) : null;
    r.evidence = withInterval({ ...r.evidence, ...(strict && Number.isFinite(strict.precision) ? { strictPrecision: strict.precision } : {}) });
  }
  // Generalisation: the SAME layers measured on shapes absent from train, validation and holdout. It never changes a row's status (the
  // PRD's gates are defined on the frozen holdout); it is stated beside it, with the shortfalls named, so "supported" is not read as more.
  const un = input.unseen && input.unseen.ecosystems && input.unseen.ecosystems[language] && input.unseen.ecosystems[language].detection;
  out.generalizationGaps = [];
  for (const r of Object.values(out.rows)) {
    if (!r.evidence || !/^(sast|taint)-holdout$/.test(r.evidence.metric || '')) continue;
    const key = /taint/.test(r.capability) ? 'taint' : 'sast';
    const u = un && un.layers && un.layers[key];
    if (!u || !u.measured) { r.generalization = { status: 'not-measured' }; continue; }
    const shortfalls = [];
    if (!(u.precision >= TARGETS.precision)) shortfalls.push(`precision ${pct(u.precision)} < ${pct(TARGETS.precision)}`);
    if (!(u.recall >= TARGETS.recall)) shortfalls.push(`recall ${pct(u.recall)} < ${pct(TARGETS.recall)}`);
    if (!(u.f1 >= TARGETS.f1)) shortfalls.push(`F1 ${pct(u.f1)} < ${pct(TARGETS.f1)}`);
    r.generalization = { status: shortfalls.length ? 'below-target' : 'meets-targets', shortfalls, cases: u.cases, tp: u.tp, fp: u.fp, fn: u.fn, tn: u.tn, precision: u.precision, recall: u.recall, f1: u.f1, strictPrecision: u.strict && u.strict.precision, ci: { precision: ciShapes(u.tp, u.tp + u.fp), recall: ciShapes(u.tp, u.tp + u.fn), level: 0.95, method: `Clopper-Pearson over shapes (${SHAPE_CLUSTER} near-identical cases per shape)` } };
    if (shortfalls.length) out.generalizationGaps.push(`${r.capability}: ${shortfalls.join(', ')}`);
  }
  // a capability whose tool is absent is blocked, not passed and not skipped
  const tools = input.tools || {};
  for (const [cap, req] of Object.entries(REQUIRES_TOOL[language] || {})) {
    const r = out.rows[cap];
    if (r && !tools[req.tool]) out.rows[cap] = { ...r, status: 'blocked', reasons: [`${req.tool} is not available on the measuring host: ${req.why}`, ...r.reasons] };
  }
  const rows = Object.values(out.rows);
  out.summary = { required: rows.length, supported: rows.filter((r) => r.status === 'supported').length, notSupported: rows.filter((r) => r.status !== 'supported').map((r) => `${r.capability}:${r.status}`), dataOk: dataOk.ok };
  const pairs = eco.pairs;
  if (pairs) {
    const pr = pairs.preserve.total ? pairs.preserve.held / pairs.preserve.total : null; const ch = pairs.change.total ? pairs.change.held / pairs.change.total : null;
    out.metamorphic = { preserve: pr, change: ch, gate: PAIR_GATE, ok: pr != null && ch != null && pr >= PAIR_GATE.preserve && ch >= PAIR_GATE.change, broken: [...pairs.preserve.broken, ...pairs.change.broken] };
  }
  return out;
}

// Only the families the layer actually scored are held to the holdout-denominator rule.
function filterFamilies(perFamilyCases, layer) {
  if (!layer || !layer.families) return perFamilyCases;
  const wanted = new Set(Object.keys(layer.families));
  return Object.fromEntries(Object.entries(perFamilyCases || {}).filter(([k]) => wanted.has(k)));
}

/**
 * The promotion check applied to one proposed registry row. A row may be marked `supported` only if `evidence.metric` is the kind
 * the capability requires, the evidence is not of a non-promoting kind, and `evaluateSupport` agrees. Returns {ok, reasons}.
 */
export function checkPromotion(language, capability, proposedStatus, evidence, evaluated) {
  const required = REQUIRED_CAPABILITIES[language];
  const reasons = [];
  if (!required || !(capability in required)) return { ok: false, reasons: [`${capability} is not a required capability of ${language}`] };
  if (proposedStatus !== 'supported') return { ok: true, reasons: [] };
  const metric = evidence && evidence.metric;
  if (!metric) reasons.push('no evidence metric was named');
  else if (NON_PROMOTING_EVIDENCE.includes(metric)) reasons.push(`evidence of kind "${metric}" can never promote a row`);
  else if (metric !== required[capability]) reasons.push(`the row needs "${required[capability]}" evidence, not "${metric}" (a metric of another kind is not a measurement of this capability)`);
  const actual = evaluated && evaluated.rows[capability];
  if (!actual) reasons.push('the evaluated measurement has no such row');
  else if (actual.status !== 'supported') reasons.push(`the measurement does not support it: ${actual.status}${actual.reasons.length ? ` (${actual.reasons[0]})` : ''}`);
  return { ok: reasons.length === 0, reasons };
}

/**
 * Re-checks a stored registry against the corpus as it is now: a row whose recorded hashes no longer match is demoted to
 * `unverified` (changed labels never keep a promotion).
 */
export function verifyRegistry(registry, frozen) {
  const stale = [];
  for (const [lang, entry] of Object.entries((registry && registry.languages) || {})) {
    const f = entry.frozen || {};
    for (const k of ['holdoutRollup', 'labelsSha256', 'privacyLabelsSha256']) if (f[k] !== (frozen || {})[k]) { stale.push({ language: lang, field: k }); }
  }
  return { ok: stale.length === 0, stale };
}
