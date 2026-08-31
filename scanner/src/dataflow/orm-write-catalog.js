// Milestone 2, Sub-project E, increment 1 (ORM-write sink recognition).
// Per docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e1-plan.md
// and its own referenced scoping doc's Finding 3 (the precision-mechanism
// gap): a catalog of ORM row-write call shapes (`Model.create({...})`,
// `Model.save({...})`, `Model.update({...})`, `Model.upsert({...})`) for
// `src/lineage/`'s Data Flow Explorer only.
//
// DELIBERATELY NOT ADDED TO `dataflow/catalog.js`'s own `CATALOG`, and NOT
// wired into `matchSinkOrSanitizer`/`runTaintEngine` — the exact same
// isolation reasoning `privacy-catalog.js`'s own header comment gives for
// itself (see that file, lines 12-32), reapplied here for a stronger
// reason: `CATALOG` is a shared, always-active singleton consulted for
// EVERY scan, with no per-family filtering, so merging these entries in
// would make every already-tainted general source (`req.body`, etc.)
// immediately produce a new, unreviewed SAST finding class the moment it
// reached an ORM `.create()`/`.save()`/`.update()`/`.upsert()` call — a
// real, unintended expansion of the general SAST pipeline's output as a
// side effect of a Data Flow Explorer feature, not something this
// increment is chartered to decide. Unlike `privacy-catalog.js` (which
// shares its entry shape with something that COULD wire into `CATALOG`
// later), this catalog's own precision gate — "the call's first argument
// must be an object-literal expression" — cannot be expressed inside
// `matchSinkOrSanitizer`'s existing `(calleeExpr, file, receiverType)`
// signature at all, since that signature never receives the call's
// arguments. Making that check work requires a caller with `site.args`
// (`src/lineage/graph-builder.js`'s own site enumeration), so the
// isolation here is closer to structural than a mere policy choice.
//
// Keeping this catalog in its own file, imported ONLY by `src/lineage/`'s
// own registry/graph-builder modules, is what makes it genuinely inert to
// every other scan surface.
//
// TWO signals gate a real match, and only one lives in this file:
//   1. Callee shape (HERE, in `ORM_WRITE_CATALOG` + `matchOrmWrite`):
//      method name is one of create/save/update/upsert, receiver is a
//      BARE, CAPITALIZED identifier (`^[A-Z]\w*$`) — the SAME shape
//      `sast/mass-assignment.js` (line 27) and `posture/cross-lang-orm.js`
//      (`findOrmWrites`) already use in production as real SAST
//      detectors; this is not a new or untested heuristic, it is the
//      established one, reused here for a lower-stakes (candidate-tier,
//      disclosed) purpose than either of those two modules' own
//      full-confidence findings.
//   2. Argument shape (NOT here — lineage-side, in `graph-builder.js`'s
//      site enumeration): the matched call's first argument must be an
//      object-literal expression (`kind: 'object'`). A call whose first
//      argument is not an object literal (a bare variable, a spread, a
//      positional string — e.g. `User.create(req.body)`) never becomes an
//      ORM-write sink candidate at all; this file cannot express that gate
//      itself, since `matchOrmWrite`'s signature (mirroring
//      `matchPrivacySink`'s) never receives the call's arguments.
//
// `coverageStatus` for every site this catalog recognizes is the literal
// string 'candidate', unconditionally, computed nowhere — see
// `sink-registry.js`'s `reclassifyOrmWrite`. Even with both signals
// present, this is real, disclosed uncertainty: an arbitrary
// capitalized-identifier receiver could still be a non-ORM builder
// pattern that happens to take an object-literal argument.
//
// Scope boundary, disclosed rather than silently assumed: JS/TS only.
// Python/Java/Go/Ruby/PHP ORM shapes (Django `.objects.create()`, GORM,
// ActiveRecord, Eloquent) are real, common shapes this catalog does not
// recognize — out of scope for this increment, per the plan's own
// "Explicitly deferred" list. Table/column/operation extraction, and
// Prisma's distinctive `data: {...}` wrapper form's own precise handling,
// are likewise deferred (the object-literal-argument check as specified
// sees Prisma's OUTER `{ data: {...} }` literal and passes, which is
// consistent for the callee-match gate, but this file makes no claim
// about extracting the inner Prisma shape — that's E2's job).
//
// `category: 'database'` reuses the existing `SINK_CATEGORIES` value
// (schema.js) rather than minting a new `orm-write`-style category — a
// genuine, lower-confidence detection of the same kind of destination a
// raw-SQL sink already models. Whether a dedicated category is warranted
// is an open question left to a future increment, not decided here.

import { _languageFamilyExtensions } from './catalog.js';

// The method-name vocabulary is verified against `cross-lang-orm.js`'s own
// `findOrmWrites` regex (`create|save|update|build|insert|upsert`) and
// `mass-assignment.js`'s own JS pattern (`create|update|build|save`) —
// this catalog uses the plan's suggested starting set (create/save/update/
// upsert), a subset of both, not the full union: `build`/`insert` are
// real ORM-adjacent method names too, but the plan's own "starting point,
// not a mandate" framing leaves widening this list to a future increment.
export const ORM_WRITE_CATALOG = [
  { kind: 'sink', id: 'orm-write-js-create', language: 'js', framework: 'orm', category: 'database',
    match: { type: 'call', callee: 'create' }, argIndex: 0,
    vuln: { name: 'ORM Write (create)', severity: 'info', cwe: null,
            remediation: 'Heuristic ORM row-write recognition for the Data Flow Explorer only — not a SAST finding. No remediation is implied.' } },
  { kind: 'sink', id: 'orm-write-js-save', language: 'js', framework: 'orm', category: 'database',
    match: { type: 'call', callee: 'save' }, argIndex: 0,
    vuln: { name: 'ORM Write (save)', severity: 'info', cwe: null,
            remediation: 'Heuristic ORM row-write recognition for the Data Flow Explorer only — not a SAST finding. No remediation is implied.' } },
  { kind: 'sink', id: 'orm-write-js-update', language: 'js', framework: 'orm', category: 'database',
    match: { type: 'call', callee: 'update' }, argIndex: 0,
    vuln: { name: 'ORM Write (update)', severity: 'info', cwe: null,
            remediation: 'Heuristic ORM row-write recognition for the Data Flow Explorer only — not a SAST finding. No remediation is implied.' } },
  { kind: 'sink', id: 'orm-write-js-upsert', language: 'js', framework: 'orm', category: 'database',
    match: { type: 'call', callee: 'upsert' }, argIndex: 0,
    vuln: { name: 'ORM Write (upsert)', severity: 'info', cwe: null,
            remediation: 'Heuristic ORM row-write recognition for the Data Flow Explorer only — not a SAST finding. No remediation is implied.' } },
];

function _ormLanguageAllowed(entry, file) {
  if (!file) return true;
  const res = _languageFamilyExtensions(entry.language);
  if (!res.length) return true; // unmapped language stays permissive
  return res.some((re) => re.test(file));
}

// Small, local copy of the callee-name extraction shape `privacy-catalog.js`'s
// own `_privacyCalleeNames` establishes — not imported from that file (it's
// private/unexported there), matching this package's established precedent
// of a small local duplicate over an awkward cross-module dependency on
// another module's private helper (see `src/lineage/handling-analyzer.js`'s
// own disclosed `calleeDescriptorOf` duplicate).
function _ormCalleeNames(calleeExpr) {
  let last = null;
  let full = null;
  if (typeof calleeExpr === 'string') {
    full = calleeExpr;
    last = calleeExpr.includes('.') ? calleeExpr.slice(calleeExpr.lastIndexOf('.') + 1) : calleeExpr;
  } else if (calleeExpr && calleeExpr.kind === 'member' && calleeExpr.prop) {
    last = calleeExpr.prop;
    if (calleeExpr.object && calleeExpr.object.kind === 'ident') full = `${calleeExpr.object.name}.${calleeExpr.prop}`;
  } else if (calleeExpr && calleeExpr.kind === 'ident') {
    last = calleeExpr.name || null;
  }
  return { last, full };
}

// Bare, capitalized receiver identifier — a SHAPE regex on the receiver's
// own name, not a `receiverTypeIn` exact-alias lookup (unrelated to the
// IR's CHA-resolved `receiverType`). Only a `kind: 'member'` calleeExpr
// whose `object` is itself a plain `kind: 'ident'` can satisfy this — a
// computed or chained receiver (`db.models.User.create(...)`) does not,
// by design (the same conservative shape `mass-assignment.js`/
// `cross-lang-orm.js` already use in production).
const CAPITALIZED_IDENT_RE = /^[A-Z]\w*$/;

function _ormReceiverIsCapitalizedIdent(calleeExpr) {
  return Boolean(
    calleeExpr && typeof calleeExpr === 'object' &&
    calleeExpr.kind === 'member' &&
    calleeExpr.object && calleeExpr.object.kind === 'ident' &&
    typeof calleeExpr.object.name === 'string' &&
    CAPITALIZED_IDENT_RE.test(calleeExpr.object.name),
  );
}

/**
 * Signal 1 only (callee shape) — the argument-shape signal (signal 2) is
 * NOT checked here; see this file's own header for why it structurally
 * cannot be. Mirrors `matchPrivacySink`'s `(calleeExpr, file, receiverType)`
 * contract, minus the unused third parameter (this catalog's receiver
 * constraint is a name-shape regex, not a `receiverTypeIn` lookup, so no
 * `receiverType` input is ever consulted). Returns an array of hits, or
 * `null` — same "array of hits, or null" contract `matchSinkOrSanitizer`/
 * `matchPrivacySink` already establish.
 */
export function matchOrmWrite(calleeExpr, file) {
  if (!calleeExpr) return null;
  if (!_ormReceiverIsCapitalizedIdent(calleeExpr)) return null;
  const { last, full } = _ormCalleeNames(calleeExpr);
  if (!last && !full) return null;
  const hits = ORM_WRITE_CATALOG.filter((e) => {
    if (!e || e.kind !== 'sink') return false;
    const cName = e.match && e.match.callee;
    if (!cName) return false;
    if (cName !== last && cName !== full) return false;
    if (!_ormLanguageAllowed(e, file)) return false;
    return true;
  });
  return hits.length ? hits : null;
}
