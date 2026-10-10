// projection.js: the one place a boundary context becomes something a person or another tool reads (X-307).
//
// It follows the verification projection (`posture/verification/projection.js`): the JSON report, the Markdown and terminal
// reports and the MCP finding explanation all call this module, so none of them formats its own boundary text and the
// surfaces cannot disagree. Rules it keeps:
//   - It is a VIEW. It reads a context produced by `analyzeFindingBoundaries` and invents nothing; a context that fails
//     validation yields `{ ok: false, errors }`, never a guessed state.
//   - Closed world. A context with a field this module does not know, or a string shaped like a credential or carrying control
//     characters, is refused rather than shown. Imported secrets and raw trace payloads cannot reach a report through here.
//   - Ids are shared. The view carries the context id, the hypothesis id, path ids, edge ids and verification record ids
//     unchanged, so a boundary record can be joined to a verification record by id.
//   - Filtering never hides the caveats. A filter narrows the paths shown; the scope, the uncovered boundaries and every
//     warning stay, and a warning says how many paths the filter hid.
//   - The text states what was established and what was not. It never calls a partial result safe or protected, and it does
//     not call a finding unreachable: no path found is "not shown to exist".
//   - Deterministic: no clock, no randomness, fixed key order.
//
// The presentation is additive and off by default. `attachBoundaryContext` is the only producer and it is gated by the
// `deployment-boundaries` feature; with the feature off no finding carries a context, so no output changes.

import { featureStatus } from '../../posture/assurance/config.js';
import { analyzeFindingBoundaries, BOUNDARY_CONTEXT_SCHEMA } from './attack-paths.js';

export const VIEW_SCHEMA = 'agentic-security/boundary-view';
export const VIEW_VERSION = '1.0.0';
export const COVERAGE_SCHEMA = 'agentic-security/boundary-coverage';
export const BOUNDARY_FEATURE = 'deployment-boundaries';

const CONTEXT_KEYS = ['schema', 'schemaVersion', 'id', 'hypothesisId', 'finding', 'binding', 'graph', 'exposure', 'paths', 'truncated', 'verification', 'uncovered', 'warnings'];
const FILTER_KEYS = ['service', 'repository', 'environment', 'tenant'];
const MAX_STRING = 600;

const STATE_TEXT = Object.freeze({
  possible: 'POSSIBLE (configured; not exercised)',
  blocked: 'BLOCKED (an explicit deny in configuration; the deny was not tested)',
  unresolved: 'UNRESOLVED (depends on something the configuration does not establish)',
  'runtime-supported': 'OBSERVED (seen in the supplied traces; traffic coverage is not established)',
});
const EXPOSURE_TEXT = Object.freeze({
  'runtime-supported': 'OBSERVED', possible: 'POSSIBLE', unresolved: 'UNRESOLVED', blocked: 'BLOCKED', 'none-found': 'NO PATH FOUND', 'not-assessed': 'NOT ASSESSED',
});
const EXPLOIT_TEXT = Object.freeze({
  'not-established': 'not established',
  'exploitable-confirmed': 'confirmed by a trusted oracle in its declared scenario',
  'oracle-confirmed-path-blocked': 'oracle-confirmed effect, but the path is blocked by configuration',
  'oracle-confirmed-path-unresolved': 'oracle-confirmed effect, but deployment reachability is unresolved',
});

// Credential and payload shapes that must never appear in a context.
const SENSITIVE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:password|passwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*\S+/i,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./,
];
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function scanStrings(value, path, errors, depth = 0) {
  if (depth > 12) { errors.push({ code: 'RULE_VIOLATION', path, message: 'context nests deeper than the contract allows' }); return; }
  if (typeof value === 'string') {
    if (value.length > MAX_STRING) errors.push({ code: 'RULE_VIOLATION', path, message: `a string is over ${MAX_STRING} characters` });
    else if (CONTROL.test(value)) errors.push({ code: 'RULE_VIOLATION', path, message: 'a string carries control characters' });
    else if (SENSITIVE.some((re) => re.test(value))) errors.push({ code: 'RULE_VIOLATION', path, message: 'a string is shaped like a credential or a raw payload and is refused' });
  } else if (Array.isArray(value)) value.forEach((v, i) => scanStrings(v, `${path}[${i}]`, errors, depth + 1));
  else if (value && typeof value === 'object') for (const k of Object.keys(value)) scanStrings(value[k], `${path}.${k}`, errors, depth + 1);
}

/** Closed-world check of a context. Never throws. */
export function validateBoundaryContext(ctx) {
  const errors = [];
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) return { ok: false, errors: [{ code: 'BAD_TYPE', path: '', message: 'a boundary context must be an object' }] };
  if (ctx.schema !== BOUNDARY_CONTEXT_SCHEMA) errors.push({ code: 'BAD_SCHEMA', path: 'schema', message: `schema must be '${BOUNDARY_CONTEXT_SCHEMA}'` });
  for (const k of Object.keys(ctx)) if (!CONTEXT_KEYS.includes(k)) errors.push({ code: 'UNKNOWN_FIELD', path: k, message: `field '${k}' is not part of a boundary context` });
  for (const k of CONTEXT_KEYS) if (!(k in ctx)) errors.push({ code: 'MISSING_FIELD', path: k, message: `field '${k}' is required` });
  if (errors.length) return { ok: false, errors };
  if (typeof ctx.id !== 'string' || !ctx.id) errors.push({ code: 'BAD_TYPE', path: 'id', message: 'id must be a non-empty string' });
  if (!Array.isArray(ctx.paths)) errors.push({ code: 'BAD_TYPE', path: 'paths', message: 'paths must be an array' });
  if (!Array.isArray(ctx.warnings) || !Array.isArray(ctx.uncovered) || !Array.isArray(ctx.verification)) errors.push({ code: 'BAD_TYPE', path: '', message: 'warnings, uncovered and verification must be arrays' });
  if (errors.length) return { ok: false, errors };
  scanStrings(ctx, '', errors);
  return { ok: errors.length === 0, errors };
}

// ------------------------------------------------------------ view

function pathView(p) {
  const services = [...new Set(p.hops.flatMap((h) => [h.from, h.to]).concat(p.hops.length ? [] : [p.entry]).filter((n) => n.kind === 'service').map((n) => n.name))].sort();
  const repositories = [...new Set(p.hops.flatMap((h) => [h.from.repository, h.to.repository]).concat([p.entry.repository, p.target.repository]).filter(Boolean))].sort();
  const unobserved = new Set(p.coverage.unobservedHops);
  const uncovered = p.crossings.filter((c) => c.type === 'identity' || unobserved.has(c.hop)).map((c) => ({ type: c.type, detail: c.detail, hop: c.hop }));
  return {
    id: p.id, kind: p.kind, state: p.state, conditional: p.conditional,
    environments: p.environments, tenants: p.tenants, services, repositories, provenance: p.provenance,
    entry: p.entry, target: p.target,
    hops: p.hops.map((h) => ({
      index: h.index, from: h.from, to: h.to, relations: h.relations, state: h.state,
      edges: h.edges.map((e) => ({
        id: e.id, relation: e.relation, provenance: e.provenance, effect: e.effect, confidence: e.confidence, pathState: e.pathState,
        sourceRevision: e.sourceRevision, source: e.source, observationInterval: e.observationInterval, completeness: e.completeness,
      })),
    })),
    supportingEdgeIds: p.supportingEdgeIds, conditions: p.conditions, blockers: p.blockers, assumptions: p.assumptions,
    crossings: p.crossings, uncoveredBoundaries: uncovered,
    freshness: {
      observedFrom: p.coverage.observedFrom, observedUntil: p.coverage.observedUntil, staleHops: p.coverage.staleHops,
      sampledHops: p.coverage.sampledHops, staleEvaluated: p.coverage.staleEvaluated,
      statement: p.coverage.observedHops.length
        ? `${p.coverage.observedHops.length} network hop(s) were observed${p.coverage.observedUntil ? ` up to ${p.coverage.observedUntil}` : ''}${p.coverage.staleEvaluated ? '' : '; staleness was not evaluated (no clock supplied)'}; the rest are configuration only`
        : 'no network hop was observed; this path is configuration only',
    },
    coverage: p.coverage, exploitability: p.exploitability,
  };
}

function textLines(view) {
  const L = [];
  L.push(`Deployment boundaries: exposure ${EXPOSURE_TEXT[view.exposure.state] ?? view.exposure.state}. ${view.exposure.statement}`);
  L.push(view.binding.service
    ? `  Service: ${view.binding.service.name} (environment ${view.binding.service.environment ?? 'none'}, tenant ${view.binding.service.tenant ?? 'none'})`
    : `  Service: not bound (${view.binding.reason})`);
  L.push(`  Graph: repository ${view.graph.repository ?? 'unknown'}, revision ${view.graph.revision ? view.graph.revision.slice(0, 12) : 'unknown'}, digest ${view.graph.digest.slice(0, 12)}`);
  const f = view.filter;
  const filterText = f ? ` (filter ${FILTER_KEYS.filter((k) => f[k]).map((k) => `${k}=${f[k]}`).join(', ') || 'none'}; ${view.scope.hiddenPathCount} hidden)` : '';
  L.push(`  Paths: ${view.paths.length} shown of ${view.scope.totalPathCount}${filterText}`);
  for (const p of view.paths) {
    const chain = p.hops.length ? [p.hops[0].from.name, ...p.hops.map((h) => h.to.name)].join(' -> ') : p.entry.name;
    L.push(`    ${p.id} [${p.kind}] ${STATE_TEXT[p.state]}: ${chain}`);
    L.push(`      environment: ${p.environments.join(', ') || 'none'}; tenants: ${p.tenants.join(', ') || 'none'}; provenance: ${p.provenance.join(', ') || 'none'}`);
    const files = [...new Set(p.hops.flatMap((h) => h.edges.map((e) => (e.source ? `${e.source.file}@${e.source.digest.slice(0, 8)}` : null))).filter(Boolean))].sort();
    L.push(`      supporting edges: ${p.supportingEdgeIds.length}${files.length ? ` from ${files.join(', ')}` : ''}`);
    L.push(`      freshness: ${p.freshness.statement}`);
    for (const c of p.conditions) L.push(`      condition: ${c.detail}`);
    for (const b of p.blockers) L.push(`      blocker: ${b.detail}`);
    if (p.uncoveredBoundaries.length) L.push(`      not covered by observation: ${p.uncoveredBoundaries.map((u) => `${u.type} (${u.detail})`).join('; ')}`);
    L.push(`      exploitability: ${EXPLOIT_TEXT[p.exploitability.label] ?? p.exploitability.label}. ${p.exploitability.reason}`);
  }
  if (view.verification.length) L.push(`  Verification records: ${view.verification.map((v) => `${v.recordId} (${v.applicable ? 'applicable' : 'not applicable'})`).join(', ')}`);
  if (view.uncovered.length) {
    L.push('  Not established:');
    for (const u of view.uncovered) L.push(`    ${u.type}: ${u.detail}`);
  }
  L.push('  Caveats:');
  for (const w of view.warnings) L.push(`    ${w}`);
  return L;
}

/**
 * Project a boundary context.
 * @returns {{ ok: boolean, view: object|null, errors: object[] }} never throws
 */
export function projectBoundaryContext(ctx) {
  try {
    const v = validateBoundaryContext(ctx);
    if (!v.ok) return { ok: false, view: null, errors: v.errors };
    const paths = ctx.paths.map(pathView);
    const view = {
      schema: VIEW_SCHEMA, schemaVersion: VIEW_VERSION,
      contextId: ctx.id, hypothesisId: ctx.hypothesisId, finding: ctx.finding, binding: ctx.binding,
      graph: ctx.graph, exposure: ctx.exposure, paths,
      verification: ctx.verification.map((r) => ({ recordId: r.recordId, outcome: r.outcome, applicable: r.applicable })),
      verificationRecordIds: ctx.verification.map((r) => r.recordId).filter(Boolean),
      uncovered: ctx.uncovered,
      warnings: [...ctx.warnings],
      scope: {
        totalPathCount: paths.length, hiddenPathCount: 0, truncated: ctx.truncated,
        repositories: ctx.graph.repositories, environments: ctx.graph.environments, tenants: ctx.graph.tenants,
        services: [...new Set(paths.flatMap((p) => p.services))].sort(),
      },
      filter: null,
    };
    view.text = textLines(view);
    return { ok: true, view, errors: [] };
  } catch (e) {
    return { ok: false, view: null, errors: [{ code: 'RULE_VIOLATION', path: '', message: `boundary projection failed: ${String(e?.message || e).slice(0, 160)}` }] };
  }
}

/**
 * Narrow a view by service, repository, environment and tenant (all given criteria must match). The scope, the uncovered
 * boundaries and every warning are kept, and a warning says how many paths were hidden. A filter that matches nothing says so
 * and does not claim that nothing exists.
 */
export function filterBoundaryView(view, filter = {}) {
  const f = {};
  for (const k of FILTER_KEYS) f[k] = typeof filter[k] === 'string' && filter[k] ? filter[k] : null;
  const match = (p) => (!f.service || p.services.includes(f.service))
    && (!f.repository || p.repositories.includes(f.repository))
    && (!f.environment || p.environments.includes(f.environment))
    && (!f.tenant || p.tenants.includes(f.tenant));
  const total = view.scope.totalPathCount;
  const shown = view.paths.filter(match);
  const hidden = total - shown.length;
  const warnings = [...view.warnings.filter((w) => !w.startsWith('Filter: '))];
  if (hidden > 0) warnings.push(`Filter: ${hidden} of ${total} path(s) are hidden by the filter; hidden paths are not shown to be absent.`);
  if (!shown.length && total > 0) warnings.push('Filter: no path matches the filter; that says nothing about paths outside it.');
  const out = { ...view, paths: shown, warnings, scope: { ...view.scope, hiddenPathCount: hidden }, filter: f };
  out.text = textLines(out);
  return out;
}

/**
 * The additive report fields for a finding that carries a context. Mirrors `verificationFields`, with one difference: the
 * context itself is returned only when it validated, so a refused context (a credential-shaped string, a made-up field) is not
 * echoed into a report by the very surface that refused to show it.
 */
export function boundaryFields(ctx, o = {}) {
  if (!ctx || typeof ctx !== 'object') return {};
  const p = projectBoundaryContext(ctx);
  if (!p.ok) return { boundaryView: null, boundaryViewErrors: p.errors };
  return { boundaryContext: ctx, boundaryView: o.filter ? filterBoundaryView(p.view, o.filter) : p.view };
}

/** Run-level accounting for the findings that carry a context. */
export function boundaryCoverage(contexts) {
  const list = (Array.isArray(contexts) ? contexts : []).filter((c) => c && typeof c === 'object');
  const valid = list.filter((c) => validateBoundaryContext(c).ok);
  const bound = valid.filter((c) => c.binding.status === 'bound').length;
  const byExposure = {};
  for (const c of valid) byExposure[c.exposure.state] = (byExposure[c.exposure.state] || 0) + 1;
  const invalid = list.length - valid.length;
  const why = Object.entries(byExposure).sort(([a], [b]) => a.localeCompare(b)).map(([k, n]) => `${k}: ${n}`).join(', ');
  const line = `Deployment boundaries: ${list.length} finding(s) with context; ${bound} bound to a service, ${valid.length - bound} not bound${invalid ? `, ${invalid} invalid` : ''}${why ? ` (${why})` : ''}; traffic coverage is not established`;
  return { schema: COVERAGE_SCHEMA, schemaVersion: VIEW_VERSION, total: list.length, bound, unbound: valid.length - bound, invalid, byExposure, lines: [line] };
}

/**
 * Attach a boundary context to each finding. This is the only producer and it is feature gated: with the feature off the
 * same array is returned untouched, so scan and report output do not change.
 *
 * @returns {{ status: string, code?: string, reason?: string, findings: object[], errors: object[] }}
 */
export function attachBoundaryContext({ config, findings, graph, bindings = [], records = [], now } = {}) {
  const gate = featureStatus(config, BOUNDARY_FEATURE);
  if (gate.status !== 'ok') return { ...gate, findings, errors: [] };
  const out = [], errors = [];
  for (const f of Array.isArray(findings) ? findings : []) {
    const r = analyzeFindingBoundaries({ graph, finding: f, bindings, records, now });
    if (!r.ok) { errors.push(...r.errors); out.push(f); continue; }
    out.push({ ...f, boundaryContext: r.context });
  }
  return { status: 'ok', code: null, reason: gate.reason, findings: out, errors };
}
