// The request-level facts a proof can carry about HOW the vulnerable operation is reached: `POST /api/export`, parameter
// `filename`, sink `exec()`. They are optional and ride on the reproducer (as `reproducer.attack`) because only the person or
// agent who wrote the reproducer knows them; the runner never reads them, so adding them cannot change a proof's result.
//
// Closed-world on purpose. There is no field for an attacker address, a domain, a file hash or a user agent: a detection that
// is built only from these facts cannot contain an invented indicator, because there is nowhere to put one.
import { PAYLOAD_CLASS_NAMES } from './payload-classes.js';

const ATTACK_FACT_KEYS = Object.freeze(['method', 'path', 'parameter', 'location', 'payloadClass', 'sink']);
export const HTTP_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
export const PARAM_LOCATIONS = Object.freeze(['query', 'body', 'header', 'path', 'cookie']);

const PATH_RE = /^\/[A-Za-z0-9/_\-.:{}~%]{0,199}$/;
const PARAM_RE = /^[A-Za-z_][A-Za-z0-9_.\-[\]]{0,63}$/;
const SINK_RE = /^[A-Za-z0-9_.()\- /$]{1,80}$/;

/** Returns a list of problems; empty means the facts are acceptable. Unknown keys are refused, never ignored. */
export function validateAttackFacts(a) {
  if (a == null) return [];
  if (typeof a !== 'object' || Array.isArray(a)) return ['attack must be an object'];
  const errs = [];
  for (const k of Object.keys(a)) if (!ATTACK_FACT_KEYS.includes(k)) errs.push(`attack.${k} is not a recognised fact`);
  if (a.method != null && !HTTP_METHODS.includes(a.method)) errs.push('attack.method must be an HTTP method in upper case');
  if (a.path != null && (typeof a.path !== 'string' || !PATH_RE.test(a.path) || a.path.includes('..'))) errs.push('attack.path must be an absolute URL path without a query string');
  if (a.parameter != null && (typeof a.parameter !== 'string' || !PARAM_RE.test(a.parameter))) errs.push('attack.parameter must be a plain parameter name');
  if (a.location != null && !PARAM_LOCATIONS.includes(a.location)) errs.push(`attack.location must be one of ${PARAM_LOCATIONS.join(', ')}`);
  if (a.payloadClass != null && !PAYLOAD_CLASS_NAMES.includes(a.payloadClass)) errs.push(`attack.payloadClass must be one of ${PAYLOAD_CLASS_NAMES.join(', ')}`);
  if (a.sink != null && (typeof a.sink !== 'string' || !SINK_RE.test(a.sink))) errs.push('attack.sink must be a short operation name');
  if ((a.parameter != null) !== (a.location != null)) errs.push('attack.parameter and attack.location go together');
  return errs;
}
