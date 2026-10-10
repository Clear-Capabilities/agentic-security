// The closed grammar of forbidden outcomes (X-401).
//
// Kept apart from `schema.js` so the oracle adapter can validate the expressions it is handed without importing the schema
// (the schema imports the oracle registry, which imports the adapters). Every expression is data: an `op` from the table below
// plus parameters whose strings are restricted to a conservative charset, so no declarative field can carry executable content.
// An op that is not in the table is an unsupported expression and is rejected, never interpreted.
const LIST_LIMIT = 8;

// Letters, digits and a few separators. No spaces, quotes, braces, parentheses, operators or template syntax.
const SAFE_TEXT = /^[A-Za-z0-9_.:/-]{1,64}$/;
export const isSafeText = (v) => typeof v === 'string' && SAFE_TEXT.test(v);
const safeList = (v, max = LIST_LIMIT) => Array.isArray(v) && v.length >= 1 && v.length <= max && v.every(isSafeText);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export const EXPRESSIONS = Object.freeze({
  'cross-tenant-write': { classes: ['tenant-isolation'], keys: ['op', 'bind', 'id', 'prefix'], check: (e) => (e.prefix === undefined || isSafeText(e.prefix) ? null : 'prefix must be a short safe string') },
  'cross-tenant-read': { classes: ['tenant-isolation'], keys: ['op', 'bind', 'id'], check: () => null },
  'unauthorized-role-change': {
    classes: ['privilege-constraint'], keys: ['op', 'bind', 'id', 'actions', 'allowedRoles'],
    check: (e) => (safeList(e.actions) && safeList(e.allowedRoles) ? null : 'actions and allowedRoles must be short lists of safe strings'),
  },
  'sum-not-conserved': {
    classes: ['value-conservation'], keys: ['op', 'bind', 'id', 'prefix', 'field', 'allowedActions'],
    check: (e) => (isSafeText(e.prefix) && isSafeText(e.field) && (e.allowedActions === undefined || (Array.isArray(e.allowedActions) && e.allowedActions.length <= LIST_LIMIT && e.allowedActions.every(isSafeText))) ? null : 'prefix and field are required safe strings; allowedActions is a short list'),
  },
  'transition-outside': {
    classes: ['workflow-order'], keys: ['op', 'bind', 'id', 'prefix', 'field', 'allowed'],
    check: (e) => (isSafeText(e.prefix) && isSafeText(e.field) && Array.isArray(e.allowed) && e.allowed.length >= 1 && e.allowed.length <= 16
      && e.allowed.every((t) => isObj(t) && Object.keys(t).every((k) => k === 'from' || k === 'to') && isSafeText(t.from) && isSafeText(t.to)) ? null : 'prefix, field and a list of { from, to } transitions are required'),
  },
  'duplicate-effect': {
    classes: ['idempotency'], keys: ['op', 'bind', 'id', 'event', 'max'],
    check: (e) => (isSafeText(e.event) && (e.max === undefined || (Number.isInteger(e.max) && e.max >= 1 && e.max <= 5)) ? null : 'event must be a safe string and max an integer 1 to 5'),
  },
});

/** Problems with one expression (empty list when it is supported and well formed). Does not check class or oracle binding. */
export function expressionProblems(expr) {
  if (!isObj(expr) || !isSafeText(expr.id)) return ['a forbidden outcome needs a safe id'];
  const spec = EXPRESSIONS[expr.op];
  if (!spec) return [`'${String(expr.op).slice(0, 40)}' is not a supported expression (supported: ${Object.keys(EXPRESSIONS).join(', ')})`];
  const out = Object.keys(expr).filter((k) => !spec.keys.includes(k)).map((k) => `'${k}' is not a parameter of ${expr.op}`);
  const why = spec.check(expr);
  if (why) out.push(why);
  return out;
}
