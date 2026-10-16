// First-class security invariants for Deterministic Context Intelligence (E4-02).
//
// An invariant is a rule a team states once, in a versioned file, and the analysis then checks on every entry point it applies to:
// "every /orders route must be authenticated and owner-scoped", "the health check is public by design". It replaces the reviewer's unwritten
// expectation with something that can be validated, scoped, expired and audited.
//
// FILE      context-intelligence-invariants.json at the project root (or a path the caller passes)
// SCHEMA    { schema: 'agentic-security/dci-invariants', schemaVersion: '1.0.0', invariants: [ ... ] }
// RULES     'requires'         the matching entry points must carry every listed control before their first sensitive operation
//           'public-by-design' the matching entry points are deliberately open on the listed dimensions; this is the only way a missing control
//                              is accepted, and it needs a reason, an owner and a review date
// SCOPE     appliesTo.routes / methods choose entry points by label; validity.paths limits the invariant to handlers in those files
//           (path-scoped validity); validity.from / until bound it in time. An invariant that is out of scope for an entry point says
//           `not_applicable`, never `satisfied`.
//
// VERDICTS  satisfied | violated | unknown (the analysis could not resolve enough to say) | not_applicable | public_by_policy | expired
// A verdict never rests on a model. It reads the protection states DCI already computed, so it is as strong as that evidence and says so.
//
// The validator is closed-world: an unknown field, a duplicate id, an empty control list, a glob that is not a glob, a public-by-design with no
// reason, or an invariant already past its `until` date is reported with a path and a code, never silently dropped.
import { existsSync, readFileSync } from 'node:fs';
import { join as pathJoin } from 'node:path';

export const INVARIANTS_SCHEMA = 'agentic-security/dci-invariants';
export const INVARIANTS_VERSION = '1.0.0';
export const INVARIANTS_FILE = 'context-intelligence-invariants.json';
export const CONTROL_DIMENSIONS = Object.freeze(['authentication', 'authorization-role', 'ownership', 'tenant-scope']);
export const VERDICTS = Object.freeze(['satisfied', 'violated', 'unknown', 'not_applicable', 'public_by_policy', 'expired']);
const RULES = ['requires', 'public-by-design'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ANY'];
const ID_RE = /^[A-Z][A-Z0-9-]{2,63}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TOP = ['schema', 'schemaVersion', 'invariants'];
const INV = ['id', 'title', 'rule', 'appliesTo', 'requires', 'waives', 'public', 'validity', 'severity'];
const APPLIES = ['routes', 'methods'];
const VALID = ['paths', 'from', 'until'];
const PUB = ['reason', 'owner', 'reviewBy'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const validGlob = (g) => typeof g === 'string' && g.length > 0 && g.length <= 200 && !/[\0\r\n]/.test(g) && !/\*\*\*/.test(g) && !g.includes('..');

/** Glob to RegExp: `**` any characters, `*` any characters except `/`, everything else literal. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') { if (glob[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; } else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/** @returns {{ok:boolean, errors:{code:string,path:string,message:string}[], warnings:{code:string,path:string,message:string}[]}} */
export function validateInvariants(doc, { now = new Date() } = {}) {
  const errors = []; const warnings = [];
  const err = (code, path, message) => errors.push({ code, path, message });
  const warn = (code, path, message) => warnings.push({ code, path, message });
  if (!isObj(doc)) { err('NOT_AN_OBJECT', '', 'the invariants file must be a JSON object'); return { ok: false, errors, warnings }; }
  for (const k of Object.keys(doc)) if (!TOP.includes(k)) err('UNKNOWN_FIELD', k, `field '${k}' is not part of this schema`);
  if (doc.schema !== INVARIANTS_SCHEMA) { err('SCHEMA_MISMATCH', 'schema', `expected ${INVARIANTS_SCHEMA}`); return { ok: false, errors, warnings }; }
  const m = typeof doc.schemaVersion === 'string' ? /^(\d+)\.(\d+)\.(\d+)$/.exec(doc.schemaVersion) : null;
  if (!m) { err('BAD_VERSION', 'schemaVersion', 'must be a semantic version'); return { ok: false, errors, warnings }; }
  if (Number(m[1]) !== 1) { err('UNSUPPORTED_MAJOR', 'schemaVersion', `major ${m[1]} is not supported (supported: 1)`); return { ok: false, errors, warnings }; }
  if (!Array.isArray(doc.invariants)) { err('MISSING_FIELD', 'invariants', 'must be a list'); return { ok: false, errors, warnings }; }
  if (doc.invariants.length > 500) err('TOO_MANY', 'invariants', 'at most 500 invariants');
  const today = new Date(now); const iso = (d) => d.toISOString().slice(0, 10);
  const seen = new Set();
  doc.invariants.forEach((inv, i) => {
    const p = `invariants[${i}]`;
    if (!isObj(inv)) { err('BAD_TYPE', p, 'an invariant is an object'); return; }
    for (const k of Object.keys(inv)) if (!INV.includes(k)) err('UNKNOWN_FIELD', `${p}.${k}`, `field '${k}' is not part of an invariant`);
    if (typeof inv.id !== 'string' || !ID_RE.test(inv.id)) err('BAD_ID', `${p}.id`, 'id must look like ORDERS-001: capitals, digits and hyphens, 3 to 64 characters');
    else if (seen.has(inv.id)) err('DUPLICATE_ID', `${p}.id`, `duplicate id ${inv.id}`); else seen.add(inv.id);
    if (typeof inv.title !== 'string' || !inv.title.trim()) err('MISSING_FIELD', `${p}.title`, 'a title is required');
    if (!RULES.includes(inv.rule)) err('UNKNOWN_ENUM', `${p}.rule`, `rule must be one of ${RULES.join(', ')}`);
    if (inv.severity !== undefined && !SEVERITIES.includes(inv.severity)) err('UNKNOWN_ENUM', `${p}.severity`, `severity must be one of ${SEVERITIES.join(', ')}`);
    const a = inv.appliesTo;
    if (!isObj(a)) err('MISSING_FIELD', `${p}.appliesTo`, 'appliesTo is required');
    else {
      for (const k of Object.keys(a)) if (!APPLIES.includes(k)) err('UNKNOWN_FIELD', `${p}.appliesTo.${k}`, `field '${k}' is not part of appliesTo`);
      if (!Array.isArray(a.routes) || !a.routes.length) err('MISSING_FIELD', `${p}.appliesTo.routes`, 'at least one route glob is required');
      else a.routes.forEach((g, j) => { if (!validGlob(g)) err('BAD_GLOB', `${p}.appliesTo.routes[${j}]`, 'not a usable glob'); else if (g === '**' || g === '/**') warn('BROAD_SCOPE', `${p}.appliesTo.routes[${j}]`, 'matches every route'); });
      if (a.methods !== undefined && (!Array.isArray(a.methods) || !a.methods.length || a.methods.some((x) => !METHODS.includes(x)))) err('UNKNOWN_ENUM', `${p}.appliesTo.methods`, `methods must be a non-empty list of ${METHODS.join(', ')}`);
    }
    const dimList = (field, value) => {
      if (!Array.isArray(value) || !value.length) { err('MISSING_FIELD', `${p}.${field}`, `${field} must list at least one control`); return; }
      if (new Set(value).size !== value.length) err('DUPLICATE_ID', `${p}.${field}`, 'a control is listed twice');
      value.forEach((d, j) => { if (!CONTROL_DIMENSIONS.includes(d)) err('UNKNOWN_ENUM', `${p}.${field}[${j}]`, `control must be one of ${CONTROL_DIMENSIONS.join(', ')}`); });
    };
    if (inv.rule === 'requires') {
      dimList('requires', inv.requires);
      if (inv.waives !== undefined || inv.public !== undefined) err('RULE_VIOLATION', `${p}`, "'requires' does not take waives or public");
    } else if (inv.rule === 'public-by-design') {
      dimList('waives', inv.waives);
      if (inv.requires !== undefined) err('RULE_VIOLATION', `${p}.requires`, "'public-by-design' does not take requires");
      const pub = inv.public;
      if (!isObj(pub)) err('MISSING_FIELD', `${p}.public`, 'a public-by-design invariant needs { reason, owner, reviewBy }');
      else {
        for (const k of Object.keys(pub)) if (!PUB.includes(k)) err('UNKNOWN_FIELD', `${p}.public.${k}`, `field '${k}' is not part of public`);
        if (typeof pub.reason !== 'string' || pub.reason.trim().length < 10) err('MISSING_FIELD', `${p}.public.reason`, 'a reason of at least 10 characters is required: openness must be justified');
        if (typeof pub.owner !== 'string' || !pub.owner.trim()) err('MISSING_FIELD', `${p}.public.owner`, 'an owner is required');
        if (typeof pub.reviewBy !== 'string' || !DATE_RE.test(pub.reviewBy) || Number.isNaN(Date.parse(pub.reviewBy))) err('BAD_DATE', `${p}.public.reviewBy`, 'reviewBy must be a YYYY-MM-DD date');
        else if (pub.reviewBy < iso(today)) err('EXPIRED', `${p}.public.reviewBy`, `the review date ${pub.reviewBy} has passed: public-by-design must be re-approved`);
      }
    }
    const v = inv.validity;
    if (v !== undefined) {
      if (!isObj(v)) err('BAD_TYPE', `${p}.validity`, 'validity is an object');
      else {
        for (const k of Object.keys(v)) if (!VALID.includes(k)) err('UNKNOWN_FIELD', `${p}.validity.${k}`, `field '${k}' is not part of validity`);
        if (v.paths !== undefined) { if (!Array.isArray(v.paths) || !v.paths.length) err('BAD_TYPE', `${p}.validity.paths`, 'paths must be a non-empty list of globs'); else v.paths.forEach((g, j) => { if (!validGlob(g)) err('BAD_GLOB', `${p}.validity.paths[${j}]`, 'not a usable glob'); }); }
        for (const f of ['from', 'until']) if (v[f] !== undefined && (typeof v[f] !== 'string' || !DATE_RE.test(v[f]) || Number.isNaN(Date.parse(v[f])))) err('BAD_DATE', `${p}.validity.${f}`, `${f} must be a YYYY-MM-DD date`);
        if (v.from && v.until && v.from > v.until) err('RULE_VIOLATION', `${p}.validity`, 'from is after until');
        if (v.until && v.until < iso(today)) warn('PAST_UNTIL', `${p}.validity.until`, `until ${v.until} has passed: the invariant is reported as expired`);
      }
    }
  });
  return { ok: errors.length === 0, errors, warnings };
}

const norm = (s) => String(s || '').trim();
function routeMatches(a, label, method) {
  if (Array.isArray(a.methods) && method && !a.methods.includes('ANY') && !a.methods.includes(method) && method !== 'ANY') return false;
  // the label is `METHOD /path`; route globs name the path
  const path = norm(label).replace(/^[A-Z]+\s+/, '');
  return a.routes.some((g) => globToRegExp(g).test(path));
}
function handlerFile(ep) { return ep?.rootSpan?.file || ep?.registrationSite?.file || ''; }

/** Control state of one dimension for a bundle: present / absent / unresolved / none-to-protect. */
function dimensionState(bundle, dim) {
  const prot = bundle.manifest?.protection || {};
  if (dim === 'tenant-scope') {
    const facts = bundle.reach?.facts || [];
    const sens = facts.filter((f) => f.category === 'sensitive');
    if (!sens.length) return { state: 'none-to-protect', why: 'no sensitive operation was seen' };
    const first = Math.min(...sens.map((f) => f.effLine));
    const ctl = facts.filter((f) => f.category === 'control' && f.kind === 'tenant-scope' && (f.effLine < first || (f.basis === 'query-filter' && f.effLine <= first)));
    if (ctl.length) return { state: 'present', why: 'a tenant scope precedes the first sensitive operation', evidence: ctl.slice(0, 4).map((f) => ({ file: f.file, line: f.line, basis: f.basis })) };
    const unresolved = (bundle.manifest?.unknowns || []).some((u) => u.material);
    return unresolved ? { state: 'unresolved', why: 'an unresolved call could hide a tenant scope' } : { state: 'absent', why: 'the resolved context contains no tenant scope' };
  }
  const d = prot[dim];
  if (!d) return { state: 'unresolved', why: 'the bundle carries no protection verdict for this dimension' };
  if (d.state === 'present') return { state: 'present', why: d.why, evidence: d.evidence };
  if (d.state === 'not_seen') return { state: 'none-to-protect', why: d.why };
  if (d.state === 'not_present' || d.state === 'evaluated_and_ineffective') return { state: 'absent', why: d.why, evidence: d.evidence };
  return { state: 'unresolved', why: d.why };
}

/**
 * @param {object} doc a validated invariants document
 * @param {{entrypoint:object, manifest:object, reach:object}[]} bundles the bundles buildContext returned (those with a manifest)
 * @returns {{results:object[], problems:string[]}}
 */
export function evaluateInvariants(doc, bundles, { now = new Date() } = {}) {
  const v = validateInvariants(doc, { now });
  if (!v.ok) return { results: [], problems: v.errors.map((e) => `${e.path}: ${e.code}`) };
  const today = now.toISOString().slice(0, 10);
  const results = [];
  const publics = doc.invariants.filter((i) => i.rule === 'public-by-design');
  for (const b of bundles.filter((x) => x.manifest)) {
    const ep = b.entrypoint; const file = handlerFile(ep);
    for (const inv of doc.invariants) {
      if (inv.rule !== 'requires') continue;
      const base = { invariantId: inv.id, title: inv.title, entrypointId: ep.id, label: ep.label, file, ...(inv.severity ? { severity: inv.severity } : {}) };
      if (!routeMatches(inv.appliesTo, ep.label, ep.method)) continue;
      const val = inv.validity || {};
      if (Array.isArray(val.paths) && !val.paths.some((g) => globToRegExp(g).test(file))) { results.push({ ...base, verdict: 'not_applicable', reasons: [`the handler file ${file} is outside this invariant's validity paths`] }); continue; }
      if (val.from && today < val.from) { results.push({ ...base, verdict: 'not_applicable', reasons: [`the invariant is valid from ${val.from}`] }); continue; }
      if (val.until && today > val.until) { results.push({ ...base, verdict: 'expired', reasons: [`the invariant expired on ${val.until}`] }); continue; }
      const dims = inv.requires.map((d) => ({ dim: d, ...dimensionState(b, d) }));
      const waivedBy = (dim) => publics.find((p) => p.waives.includes(dim) && routeMatches(p.appliesTo, ep.label, ep.method) && (!p.validity?.paths || p.validity.paths.some((g) => globToRegExp(g).test(file))) && !(p.public.reviewBy < today));
      const missing = dims.filter((x) => x.state === 'absent');
      const unresolved = dims.filter((x) => x.state === 'unresolved');
      const allNone = dims.every((x) => x.state === 'none-to-protect');
      if (allNone) { results.push({ ...base, verdict: 'not_applicable', reasons: ['no sensitive operation was seen, so there is nothing for a control to protect'], controls: dims }); continue; }
      const unwaived = missing.filter((x) => !waivedBy(x.dim));
      const waived = missing.filter((x) => waivedBy(x.dim));
      if (unwaived.length) results.push({ ...base, verdict: 'violated', reasons: unwaived.map((x) => `${x.dim}: ${x.why}`), controls: dims });
      else if (waived.length) results.push({ ...base, verdict: 'public_by_policy', reasons: waived.map((x) => `${x.dim} is waived by ${waivedBy(x.dim).id}: ${waivedBy(x.dim).public.reason}`), waivedBy: [...new Set(waived.map((x) => waivedBy(x.dim).id))], controls: dims });
      else if (unresolved.length) results.push({ ...base, verdict: 'unknown', reasons: unresolved.map((x) => `${x.dim}: ${x.why}`), controls: dims });
      else results.push({ ...base, verdict: 'satisfied', reasons: dims.filter((x) => x.state === 'present').map((x) => `${x.dim}: ${x.why}`), controls: dims });
    }
  }
  results.sort((a, b) => (a.invariantId + a.entrypointId < b.invariantId + b.entrypointId ? -1 : 1));
  return { results, problems: [] };
}

/** Read and validate the invariants file of a project. A missing file is "no invariants", not an error; a malformed one reports every problem. */
export function loadInvariants(root, { file = INVARIANTS_FILE, now } = {}) {
  const full = pathJoin(root, file);
  if (!existsSync(full)) return { present: false, doc: null, validation: { ok: true, errors: [], warnings: [] } };
  let doc;
  try { doc = JSON.parse(readFileSync(full, 'utf8')); } catch (e) { return { present: true, doc: null, validation: { ok: false, errors: [{ code: 'BAD_JSON', path: '', message: String(e.message).slice(0, 200) }], warnings: [] } }; }
  return { present: true, doc, validation: validateInvariants(doc, now ? { now } : undefined) };
}
