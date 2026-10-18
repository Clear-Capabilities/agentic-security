// The one evaluator behind every detection output. Validation (synthetic events), hunting (historical logs) and the
// rendered rules' described behavior all call `evaluateEvent`, so a rule that passes validation is the same rule that
// searches the logs. An event is the NORMALIZED request record produced by log-reader.js or by the validator.
//
//   event = { time, method, path, query: {name: [values]}, bodyParams: {name: [values]} | null, headers: {name: value} | null,
//             status, authPresent: boolean | null }
//
// A missing field is `undefined`/`null`, never an empty string: "the log did not record this" and "the value was empty" are
// different facts, and only the first makes an event undecidable.
import { PAYLOAD_CLASSES, matchesClass } from './payload-classes.js';

const norm = (p) => (p.length > 1 ? p.replace(/\/+$/, '') : p);

/** `/api/users/:id` and `/api/users/{id}` match any single non-empty segment in that position. */
export function pathMatches(template, actual) {
  if (typeof actual !== 'string' || !actual.startsWith('/')) return false;
  const t = norm(template).split('/');
  const a = norm(actual.split('?')[0]).split('/');
  if (t.length !== a.length) return false;
  return t.every((seg, i) => (/^(?::[A-Za-z_]\w*|\{[A-Za-z_]\w*\})$/.test(seg) ? a[i].length > 0 : seg === a[i]));
}

/** Fields an event must have for a detection to be able to say "no" about it. */
export function requiredFields(ir) {
  const need = new Set();
  if (ir.endpoint) { need.add('method'); need.add('path'); }
  if (ir.payloadClass === 'auth-bypass') { need.add('status'); need.add('auth'); return [...need]; }
  const loc = ir.parameter?.location;
  if (loc === 'body') need.add('body');
  else if (loc === 'header' || loc === 'cookie') need.add('headers');
  else if (loc === 'path') need.add('path');
  else need.add('query');
  if (!ir.endpoint) need.add('path');
  return [...need];
}

function candidateValues(ir, event) {
  const out = [];
  const p = ir.parameter;
  const take = (bag, name) => { for (const v of (bag?.[name] ?? [])) out.push([`${name}`, v]); };
  if (!p) {
    for (const [k, vs] of Object.entries(event.query ?? {})) for (const v of vs) out.push([`query:${k}`, v]);
    for (const [k, vs] of Object.entries(event.bodyParams ?? {})) for (const v of vs) out.push([`body:${k}`, v]);
    return { values: out, decidable: event.query != null };
  }
  if (p.location === 'query') { take(event.query, p.name); return { values: out.map(([k, v]) => [`query:${k}`, v]), decidable: event.query != null }; }
  if (p.location === 'body') { take(event.bodyParams, p.name); return { values: out.map(([k, v]) => [`body:${k}`, v]), decidable: event.bodyParams != null }; }
  if (p.location === 'header' || p.location === 'cookie') {
    const v = event.headers?.[p.name.toLowerCase()];
    return { values: v == null ? [] : [[`${p.location}:${p.name}`, v]], decidable: event.headers != null };
  }
  // path parameter: the segment where the template has the parameter
  if (p.location === 'path' && ir.endpoint) {
    const t = norm(ir.endpoint.path).split('/');
    const a = norm(String(event.path).split('?')[0]).split('/');
    t.forEach((seg, i) => { if (seg === `:${p.name}` || seg === `{${p.name}}`) out.push([`path:${p.name}`, a[i] ?? '']); });
  }
  return { values: out, decidable: typeof event.path === 'string' };
}

/**
 * @returns {{match: boolean, undecidable: boolean, missing: string[], matchedOn: string|null, value: string|null}}
 * `undecidable` means "this event lacks a field the detection needs", which is different from "this event does not match".
 */
export function evaluateEvent(ir, event) {
  const res = { match: false, undecidable: false, missing: [], matchedOn: null, value: null };
  if (ir.endpoint) {
    if (!event.method) res.missing.push('method');
    if (typeof event.path !== 'string') res.missing.push('path');
    if (res.missing.length) { res.undecidable = true; return res; }
    if (String(event.method).toUpperCase() !== ir.endpoint.method) return res;
    if (!pathMatches(ir.endpoint.path, event.path)) return res;
  } else if (typeof event.path !== 'string') { res.missing.push('path'); res.undecidable = true; return res; }

  if (ir.payloadClass === 'auth-bypass') {
    if (event.status == null) res.missing.push('status');
    if (event.authPresent == null) res.missing.push('auth');
    if (res.missing.length) { res.undecidable = true; return res; }
    if (event.status >= 200 && event.status < 300 && event.authPresent === false) { res.match = true; res.matchedOn = 'unauthenticated-success'; res.value = `${event.status}`; }
    return res;
  }

  if (!PAYLOAD_CLASSES[ir.payloadClass]) { res.undecidable = true; res.missing.push('payload-class'); return res; }
  const { values, decidable } = candidateValues(ir, event);
  for (const [where, v] of values) {
    if (matchesClass(ir.payloadClass, v)) { res.match = true; res.matchedOn = where; res.value = String(v).slice(0, 200); return res; }
  }
  if (!decidable) { res.undecidable = true; res.missing.push(ir.parameter?.location === 'body' ? 'body' : ir.parameter?.location === 'header' || ir.parameter?.location === 'cookie' ? 'headers' : 'query'); }
  return res;
}
