// Pre-computed taint summaries for popular npm/pip packages.
//
// When the taint engine encounters a call to an external function that
// the call graph can't resolve (e.g., lodash.merge from node_modules),
// it checks this registry as a fallback. Each entry describes whether
// the function's return value carries taint and whether any parameters
// are mutated (tainted by reference).
//
// Format: same as SummaryCache entries.
//   { returnTainted: bool, mutatedParams: Set<paramIndex-as-string> }
//
// Convention: param indices are STRING keys ('0', '1', ...) because
// SummaryCache uses param names, and for external functions we don't
// know names — we use positional indices instead.

const S = (returnTainted, mutatedIndices = []) => ({
  returnTainted,
  mutatedParams: new Set(mutatedIndices.map(String)),
  taintedGlobals: new Set(),
  findings: [],
  _builtin: true,
});

export const BUILTIN_SUMMARIES = new Map([
  // ── Lodash ──────────────────────────────────────────────────────────────
  ['_.merge',           S(true, [0])],
  ['_.defaultsDeep',    S(true, [0])],
  ['_.defaults',        S(true, [0])],
  ['_.extend',          S(true, [0])],
  ['_.assign',          S(true, [0])],
  ['_.assignIn',        S(true, [0])],
  ['_.set',             S(false, [0])],
  ['_.get',             S(true)],
  ['_.pick',            S(true)],
  ['_.omit',            S(true)],
  ['_.cloneDeep',       S(true)],
  ['_.clone',           S(true)],
  ['_.map',             S(true)],
  ['_.filter',          S(true)],
  ['_.find',            S(true)],
  ['_.reduce',          S(true)],
  ['_.flatten',         S(true)],
  ['_.compact',         S(true)],
  ['_.uniq',            S(true)],
  ['_.groupBy',         S(true)],
  ['_.keyBy',           S(true)],
  ['_.values',          S(true)],
  ['_.keys',            S(false)],
  ['_.identity',        S(true)],

  // ── Node.js core ────────────────────────────────────────────────────────
  ['JSON.parse',        S(true)],
  ['JSON.stringify',    S(true)],
  ['Buffer.from',       S(true)],
  ['Buffer.concat',     S(true)],
  ['querystring.parse', S(true)],
  ['url.parse',         S(true)],
  ['path.join',         S(true)],
  ['path.resolve',      S(true)],
  ['util.format',       S(true)],

  // ── Express / HTTP ──────────────────────────────────────────────────────
  ['express.json',      S(false)],
  ['express.urlencoded',S(false)],
  ['bodyParser.json',   S(false)],
  ['cors',              S(false)],

  // ── Database clients ────────────────────────────────────────────────────
  ['pool.query',        S(true)],
  ['client.query',      S(true)],
  ['db.query',          S(true)],
  ['db.all',            S(true)],
  ['db.get',            S(true)],
  ['db.run',            S(false)],
  ['knex.raw',          S(true)],
  ['knex.select',       S(true)],

  // ── HTTP clients ────────────────────────────────────────────────────────
  ['axios.get',         S(true)],
  ['axios.post',        S(true)],
  ['axios.put',         S(true)],
  ['axios.patch',       S(true)],
  ['axios.delete',      S(true)],
  ['axios.request',     S(true)],
  ['fetch',             S(true)],
  ['got',               S(true)],
  ['got.get',           S(true)],
  ['got.post',          S(true)],
  ['superagent.get',    S(true)],
  ['superagent.post',   S(true)],

  // ── Crypto / hashing (return is derived, not tainted) ───────────────────
  ['crypto.createHash', S(false)],
  ['crypto.randomBytes',S(false)],
  ['bcrypt.hash',       S(false)],
  ['bcrypt.compare',    S(false)],

  // ── Sanitizers (return is clean) ────────────────────────────────────────
  ['parseInt',          S(false)],
  ['parseFloat',        S(false)],
  ['Number',            S(false)],
  ['Boolean',           S(false)],
  ['encodeURIComponent',S(false)],
  ['encodeURI',         S(false)],
  ['DOMPurify.sanitize',S(false)],
  ['validator.escape',  S(false)],
  ['he.encode',         S(false)],

  // ── Python stdlib (matched by callee name) ──────────────────────────────
  ['json.loads',        S(true)],
  ['json.dumps',        S(true)],
  ['int',               S(false)],
  ['float',             S(false)],
  ['str',               S(true)],
  ['shlex.quote',       S(false)],
  ['html.escape',       S(false)],
  ['bleach.clean',      S(false)],
]);

export function lookupBuiltinSummary(calleeName) {
  if (!calleeName || typeof calleeName !== 'string') return null;
  const direct = BUILTIN_SUMMARIES.get(calleeName);
  if (direct) return direct;
  const lastDot = calleeName.lastIndexOf('.');
  if (lastDot > 0) {
    const short = calleeName.slice(lastDot + 1);
    const fallback = BUILTIN_SUMMARIES.get(short);
    if (fallback) return fallback;
  }
  return null;
}
