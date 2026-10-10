export const id = 5014;
export const ids = [5014,5144];
export const modules = {

/***/ 45144:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   addLegalHold: () => (/* binding */ addLegalHold),
/* harmony export */   isUnderHold: () => (/* binding */ isUnderHold),
/* harmony export */   listLegalHolds: () => (/* binding */ listLegalHolds),
/* harmony export */   loadLegalHolds: () => (/* binding */ loadLegalHolds),
/* harmony export */   removeLegalHold: () => (/* binding */ removeLegalHold)
/* harmony export */ });
/* unused harmony export LEGAL_HOLD_FILE */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31174);
/* harmony import */ var _artifact_registry_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(70471);
// FR-707 (assurance-hardening PRD): "Support legal hold and policy-
// authorized retention exceptions | Legal hold is identity-bound, reasoned,
// time-bounded where applicable, and auditable."
//
// A third instance of the recurring {owner, reason, expires_at} exception
// shape this codebase already uses twice — `posture/suppressions.js`'s
// pro-tier exception (scoped to a FINDING) and `posture/compliance-policy.js`'s
// structured `not-applicable` (scoped to a COMPLIANCE CONTROL). Per D-0025,
// these are deliberately distinct mechanisms serving different subjects, not
// one shared module — this file is the third subject: a STATE ARTIFACT.
//
// Field naming matches the existing two schemas' snake_case convention
// (`owner`, `reason`, `expires_at`) rather than inventing a fourth style.
//
//   identity-bound   -> `owner` (required, who placed the hold and is
//                        accountable for lifting it)
//   reasoned         -> `reason` (required — "we might need this later" is
//                        not a reason; same discipline suppressions.js
//                        already enforces for its own exceptions)
//   time-bounded
//     where applicable -> `expires_at` is OPTIONAL: a null/absent value is
//                        an INDEFINITE hold, which the acceptance
//                        criterion's own "where applicable" phrase
//                        explicitly allows (a genuine legal matter may have
//                        no known end date) — an ISO date value behaves
//                        exactly like FR-506/FR-1004's own expiring
//                        exceptions: once past, the hold is no longer
//                        active and the artifact is exposed to its normal
//                        retention TTL again.
//   auditable        -> persisted as a single JSON array under
//                        `.agentic-security/legal-holds.json` (itself
//                        registered as operator-config — an operator/legal
//                        team's own input, never scanner-written from scan
//                        results), readable via `listLegalHolds`.
//
// Consulted from TWO places, not one: `retention-policy.js#findExpiredArtifacts`
// (defense in depth for any caller reaching it directly) AND `cmdReset`
// itself for its PLAIN (non-`--expired`) path, which deletes every
// registered 'generated' artifact unconditionally and would otherwise blow
// through a hold that only gated TTL expiry.





const LEGAL_HOLD_FILE = 'legal-holds.json';

function _loadRaw(scanRoot) {
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE); } catch { return []; }
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return []; }
  try {
    const doc = JSON.parse(raw);
    return Array.isArray(doc) ? doc : [];
  } catch { return []; }
}

/**
 * All legal holds ever recorded for this project, malformed entries
 * dropped rather than throwing. Never filters by expiry — see
 * `isUnderHold`/`listLegalHolds` for that.
 */
function loadLegalHolds(scanRoot) {
  return _loadRaw(scanRoot).filter(h => h && typeof h === 'object' && typeof h.artifact === 'string' && typeof h.owner === 'string' && typeof h.reason === 'string');
}

/**
 * Is `artifactName` currently protected by an active (non-expired) hold?
 * Returns the matching hold record, or null. Multiple holds on the same
 * artifact are permitted (e.g. two independent legal matters); the first
 * still-active one found is returned.
 */
function isUnderHold(artifactName, holds, now = Date.now()) {
  for (const h of holds) {
    if (h.artifact !== artifactName) continue;
    if (!h.expires_at) return h; // indefinite hold — always active
    const t = Date.parse(h.expires_at);
    if (!Number.isFinite(t) || t >= now) return h;
  }
  return null;
}

/**
 * Active (non-expired) holds only, unless `includeExpired`. For
 * `legal-hold list` / auditing.
 */
function listLegalHolds(scanRoot, { includeExpired = false, now = Date.now() } = {}) {
  const holds = loadLegalHolds(scanRoot);
  if (includeExpired) return holds;
  return holds.filter(h => {
    if (!h.expires_at) return true;
    const t = Date.parse(h.expires_at);
    return !Number.isFinite(t) || t >= now;
  });
}

/**
 * Add a legal hold. Validates identity-bound + reasoned up front (both
 * required, non-empty) and that `expires_at`, if given, is a parseable
 * date in the future — an already-expired hold would be a hold that
 * protects nothing, which is never a legitimate request. `artifact` must
 * name a real registered artifact (artifact-registry.js) — a hold on an
 * unrecognised name can never protect anything and almost always means a
 * typo. Returns `{ok:true, hold}` or `{ok:false, reason}`; never throws.
 */
function addLegalHold(scanRoot, { artifact, owner, reason, expires_at } = {}) {
  if (!artifact || typeof artifact !== 'string') return { ok: false, reason: '--artifact is required' };
  if (!(0,_artifact_registry_js__WEBPACK_IMPORTED_MODULE_2__/* .isRegisteredArtifact */ .Jl)(artifact)) return { ok: false, reason: `"${artifact}" is not a registered state artifact` };
  if (!owner || typeof owner !== 'string') return { ok: false, reason: '--owner is required (identity-bound)' };
  if (!reason || typeof reason !== 'string') return { ok: false, reason: '--reason is required (reasoned)' };
  if (expires_at) {
    const t = Date.parse(expires_at);
    if (!Number.isFinite(t)) return { ok: false, reason: 'expires_at must be a parseable date' };
    if (t < Date.now()) return { ok: false, reason: 'expires_at is in the past — a hold that already expired protects nothing' };
  }
  const hold = { artifact, owner, reason, expires_at: expires_at || null, created_at: new Date().toISOString() };
  const holds = _loadRaw(scanRoot);
  holds.push(hold);
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .safeWriteState */ .Ep)(fp, JSON.stringify(holds, null, 2) + '\n')) {
    return { ok: false, reason: 'state writes are disabled (--no-state) or this is not a safe state directory' };
  }
  return { ok: true, hold };
}

/**
 * Remove every hold on `artifact` (lifting a hold, not letting it expire).
 * Returns the number removed. A no-op (0) if none existed — never an error.
 */
function removeLegalHold(scanRoot, artifact) {
  const holds = _loadRaw(scanRoot);
  const remaining = holds.filter(h => !(h && h.artifact === artifact));
  const removedCount = holds.length - remaining.length;
  if (removedCount > 0) {
    const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE);
    (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .safeWriteState */ .Ep)(fp, JSON.stringify(remaining, null, 2) + '\n');
  }
  return removedCount;
}


/***/ }),

/***/ 25014:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runPortfolioCommand: () => (/* binding */ runPortfolioCommand)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/posture/portfolio/wording.js
var wording = __webpack_require__(9886);
// EXTERNAL MODULE: ./src/posture/portfolio/work-units.js
var work_units = __webpack_require__(90987);
// EXTERNAL MODULE: ./src/posture/portfolio/scheduler.js
var scheduler = __webpack_require__(34563);
// EXTERNAL MODULE: ./src/posture/portfolio/progress.js
var progress = __webpack_require__(67439);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./src/posture/legal-hold.js
var legal_hold = __webpack_require__(45144);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
;// CONCATENATED MODULE: ./src/posture/portfolio/retention.js
// Evidence retention for portfolio artifacts (X-708.AC01).
//
// `posture/retention-policy.js` ages the scanner's own registered state files. A portfolio keeps a different population: replay
// evidence that lets someone re-run a check, metadata that describes a release, traces of model calls, and secrets that must not
// outlive their use. They differ in how long they should live, so a record here has a CLASS, and the policy sets a retention per class:
//
//   replay-evidence  replay manifests and verification receipts. Kept longest: they are what makes a claim re-checkable.
//   metadata         manifests, findings, provenance, toolchain identities.
//   model-trace      records of model calls (prompts, responses, routing decisions). Short: they hold the most sensitive content.
//   secret           anything credential-like captured in the course of a run. Default 0 days (delete at the next sweep) and a hard
//                    ceiling of 7 days. A secret is never exported.
//
// `RETENTION_DEFAULTS` are engineering defaults, not a regulatory claim; an operator sets their own per class, and a configured value
// above the class's `maxDays` is clamped down and the clamp is disclosed (a TTL that can be configured to "never" is not a TTL), the
// same rule retention-policy.js applies.
//
// THE ORDER OF PROTECTION, each tested in both directions:
//   1. a REQUIRED CURRENT receipt is never deleted, whatever its age and whether or not a hold exists. A record is required when it
//      is named in `currentReceiptIds`, or when a unit listed in its `requiredBy` is `verified` in the store right now. When it is also
//      past its retention the plan says so (`expiredButRequired`): the deletion is blocked loudly, never skipped silently. Once the unit
//      goes stale, is cancelled or is re-planned, the record is no longer required and ages out normally.
//   2. a LEGAL HOLD (identity-bound, reasoned, optionally expiring: the shape and the check of posture/legal-hold.js, which this reuses)
//      on the record, its class or its repository keeps it. A hold on a `secret` is honoured and flagged, because a hold is a legal act.
//   3. otherwise a record past its class's retention is deleted; a record in a class the policy does not know is KEPT and reported.
//
// DELETION IS LOGGED, AND LOGGED FIRST. Each deletion appends an intent entry to a hash-chained log (record id, class, path, size, content
// digest, reason, age, policy version, actor) and only then removes the file; an outcome entry follows. If the log cannot be written
// nothing is deleted. The log records that a deletion happened and what it was, never the content. Paths are confined to the root,
// symlinks are refused, and a directory record is refused (not recursed into).
//
// `planRetention` is pure. `applyRetention` re-plans at the moment of deletion with the live store, so a plan made earlier cannot delete
// a record that has become required since.







const RETENTION_CLASSES = Object.freeze(['replay-evidence', 'metadata', 'model-trace', 'secret']);
const RETENTION_DEFAULTS = Object.freeze({
  'replay-evidence': Object.freeze({ defaultDays: 365, maxDays: 1095 }),
  metadata: Object.freeze({ defaultDays: 730, maxDays: 1825 }),
  'model-trace': Object.freeze({ defaultDays: 30, maxDays: 90 }),
  secret: Object.freeze({ defaultDays: 0, maxDays: 7 }),
});
const RETENTION_LOG_SCHEMA = 'agentic-security/retention-log';
const DAY = 86_400_000;
const BUNDLE_ROLE_CLASS = Object.freeze({ 'replay-manifest': 'replay-evidence', receipt: 'replay-evidence', manifest: 'metadata', findings: 'metadata', provenance: 'metadata', toolchain: 'metadata' });

/** The retention class of a portfolio bundle role (bundle.js ROLES). An unknown role has no class and is never deleted by this module. */
const classOfBundleRole = (role) => BUNDLE_ROLE_CLASS[role] ?? null;

/** Validate a policy `{ version, classes: { <class>: { retainDays } } }` and return the effective days per class, with any clamp disclosed. */
function resolveRetentionPolicy(policy) {
  const errors = [];
  if (policy !== undefined && policy !== null && (typeof policy !== 'object' || Array.isArray(policy))) return { ok: false, errors: [{ code: 'BAD_POLICY', message: 'a policy is an object' }] };
  const version = policy?.version ?? 'defaults';
  if (typeof version !== 'string' || !version) errors.push({ code: 'BAD_POLICY', message: 'version must be a non-empty string' });
  const effective = {};
  for (const cls of Object.keys(policy?.classes ?? {})) if (!RETENTION_CLASSES.includes(cls)) errors.push({ code: 'UNKNOWN_CLASS', message: `'${cls}' is not a retention class` });
  for (const cls of RETENTION_CLASSES) {
    const b = RETENTION_DEFAULTS[cls];
    const set = policy?.classes?.[cls]?.retainDays;
    if (set !== undefined && !(typeof set === 'number' && Number.isFinite(set) && set >= 0)) { errors.push({ code: 'BAD_DAYS', message: `${cls}.retainDays must be a non-negative number` }); continue; }
    const days = set === undefined ? b.defaultDays : Math.min(set, b.maxDays);
    effective[cls] = { days, source: set === undefined ? 'default' : 'policy', clamped: set !== undefined && set > b.maxDays, maxDays: b.maxDays };
  }
  return errors.length ? { ok: false, errors } : { ok: true, version, effective };
}

/**
 * Validate legal holds. A hold is `{ target, owner, reason, expires_at? }` with `target` one of `{ id }`, `{ class }`, `{ repository }`.
 * Identity-bound (owner), reasoned (reason), and an expiry, when present, must parse. Returns the holds in the shape legal-hold.js reads.
 */
function normalizeHolds(holds) {
  const errors = []; const out = [];
  for (const [i, h] of (Array.isArray(holds) ? holds : []).entries()) {
    const t = h?.target;
    const key = t && typeof t === 'object' ? (t.id ? `id:${t.id}` : t.class ? `class:${t.class}` : t.repository ? `repository:${t.repository}` : null) : null;
    if (!key) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold targets an id, a class or a repository' }); continue; }
    if (t.class && !RETENTION_CLASSES.includes(t.class)) { errors.push({ code: 'BAD_HOLD', index: i, message: `'${t.class}' is not a retention class` }); continue; }
    if (typeof h.owner !== 'string' || !h.owner) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold needs an owner (identity-bound)' }); continue; }
    if (typeof h.reason !== 'string' || !h.reason) { errors.push({ code: 'BAD_HOLD', index: i, message: 'a hold needs a reason' }); continue; }
    if (h.expires_at && !Number.isFinite(Date.parse(h.expires_at))) { errors.push({ code: 'BAD_HOLD', index: i, message: 'expires_at must be a parseable date' }); continue; }
    out.push({ artifact: key, owner: h.owner, reason: h.reason, expires_at: h.expires_at ?? null });
  }
  return { ok: errors.length === 0, errors, holds: out };
}

const createdMs = (r) => (typeof r.createdAt === 'number' ? r.createdAt : Date.parse(r.createdAt));

/**
 * @param {object} p
 * @param {Array<{id:string, class:string, path:string, createdAt:number|string, repository?:string, requiredBy?:string[]}>} p.records
 * @param {object} [p.policy]
 * @param {Array} [p.holds]
 * @param {number} p.now  milliseconds
 * @param {object} [p.store]  a portfolio store: a record whose `requiredBy` names a verified unit is a required current receipt
 * @param {Iterable<string>} [p.currentReceiptIds]
 */
function planRetention({ records, policy, holds = [], now, store = null, currentReceiptIds = [] } = {}) {
  const pol = resolveRetentionPolicy(policy);
  if (!pol.ok) return { ok: false, errors: pol.errors };
  const h = normalizeHolds(holds);
  if (!h.ok) return { ok: false, errors: h.errors };
  if (!Number.isFinite(now)) return { ok: false, errors: [{ code: 'NO_NOW', message: 'now (milliseconds) is required' }] };
  const required = new Set(currentReceiptIds);
  const decisions = [];
  for (const r of Array.isArray(records) ? records : []) {
    const base = { id: r?.id ?? null, class: r?.class ?? null, path: r?.path ?? null };
    if (!r || typeof r.id !== 'string' || !r.id || typeof r.path !== 'string' || !Number.isFinite(createdMs(r))) { decisions.push({ ...base, action: 'keep', reason: 'malformed-record', detail: 'a record needs an id, a path and a creation time; it is not deleted' }); continue; }
    if (!RETENTION_CLASSES.includes(r.class)) { decisions.push({ ...base, action: 'keep', reason: 'unclassified', detail: `'${r.class}' is not a retention class; unclassified records are never deleted` }); continue; }
    const ageDays = (now - createdMs(r)) / DAY;
    const ttl = pol.effective[r.class].days;
    const expired = ageDays > ttl;
    const requiredNow = required.has(r.id) || (Array.isArray(r.requiredBy) && r.requiredBy.some((uid) => store?.units?.[uid]?.state === 'verified'));
    const d = { ...base, ageDays: Math.round(ageDays * 100) / 100, ttlDays: ttl, expired };
    if (requiredNow) { decisions.push({ ...d, action: 'protect', reason: 'required-current-receipt', expiredButRequired: expired, detail: expired ? 'past its retention, but a current verified result depends on it: deletion is blocked' : 'a current verified result depends on it' }); continue; }
    const names = [`id:${r.id}`, `class:${r.class}`, ...(r.repository ? [`repository:${r.repository}`] : [])];
    const hold = names.map((n) => (0,legal_hold.isUnderHold)(n, h.holds, now)).find(Boolean);
    if (hold) { decisions.push({ ...d, action: 'keep', reason: 'legal-hold', hold: { target: hold.artifact, owner: hold.owner, reason: hold.reason, expires_at: hold.expires_at }, ...(r.class === 'secret' ? { warning: 'a secret is being retained under a legal hold' } : {}) }); continue; }
    decisions.push(expired ? { ...d, action: 'delete', reason: r.class === 'secret' ? 'secret-expired' : 'expired' } : { ...d, action: 'keep', reason: 'within-retention' });
  }
  const count = (a) => decisions.filter((x) => x.action === a).length;
  return {
    ok: true, policyVersion: pol.version, effective: pol.effective, now, decisions,
    summary: { records: decisions.length, delete: count('delete'), keep: count('keep'), protect: count('protect'), expiredButRequired: decisions.filter((x) => x.expiredButRequired).length, heldByLegalHold: decisions.filter((x) => x.reason === 'legal-hold').length },
  };
}

// ---------------------------------------------------------------- the deletion log

const entryDigest = (e) => (0,identity/* digestOf */.ol)(e);

function readLog(file) {
  let raw;
  try { raw = external_node_fs_.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/** Verify the hash chain of a deletion log. Returns `{ ok, entries, errors }`. */
function verifyRetentionLog(file) {
  let entries;
  try { entries = readLog(file); } catch { return { ok: false, entries: [], errors: [{ code: 'LOG_UNREADABLE', message: 'the deletion log is unreadable' }] }; }
  const errors = []; let prev = null;
  entries.forEach((e, i) => {
    const { digest, ...body } = e;
    if (e.seq !== i + 1 || e.prev !== prev || entryDigest(body) !== digest) errors.push({ code: 'LOG_BROKEN', seq: i + 1, message: `entry ${i + 1} was altered, removed or reordered` });
    prev = digest;
  });
  return { ok: errors.length === 0, entries, errors };
}

function appendLog(file, entry) {
  const v = verifyRetentionLog(file);
  if (!v.ok) throw Object.assign(new Error('the deletion log fails verification; nothing will be deleted'), { code: 'LOG_BROKEN' });
  const last = v.entries.at(-1);
  const body = { schema: RETENTION_LOG_SCHEMA, seq: v.entries.length + 1, prev: last ? last.digest : null, ...entry };
  external_node_fs_.mkdirSync(external_node_path_.dirname(external_node_path_.resolve(file)), { recursive: true });
  const fd = external_node_fs_.openSync(file, 'a', 0o600);
  try { external_node_fs_.writeSync(fd, `${JSON.stringify({ ...body, digest: entryDigest(body) })}\n`); external_node_fs_.fsyncSync(fd); } finally { external_node_fs_.closeSync(fd); }
}

function confined(root, rel) {
  if (external_node_path_.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) return null;
  const abs = external_node_path_.resolve(root, rel);
  const rootReal = external_node_fs_.realpathSync(root);
  if (abs !== rootReal && !abs.startsWith(rootReal + external_node_path_.sep) && !abs.startsWith(external_node_path_.resolve(root) + external_node_path_.sep)) return null;
  // a directory inside the root that is a link out of it must not carry a deletion out of the root either
  const parentReal = external_node_fs_.realpathSync(external_node_path_.dirname(abs));
  if (parentReal !== rootReal && !parentReal.startsWith(rootReal + external_node_path_.sep)) return null;
  return abs;
}

/**
 * Plan and apply, logging every deletion first. `dryRun` plans only. Returns the plan plus what happened.
 * @returns {{ ok: boolean, plan?: object, deleted: object[], failed: object[], blocked: object[], errors?: object[] }}
 */
function applyRetention({ root, logFile, actor, dryRun = false, ...planInput } = {}) {
  const plan = planRetention(planInput);
  if (!plan.ok) return { ok: false, errors: plan.errors, deleted: [], failed: [], blocked: [] };
  const blocked = plan.decisions.filter((d) => d.expiredButRequired).map((d) => ({ id: d.id, reason: d.reason, detail: d.detail }));
  if (dryRun) return { ok: true, plan, dryRun: true, deleted: [], failed: [], blocked };
  if (typeof actor !== 'string' || !actor) return { ok: false, errors: [{ code: 'NO_ACTOR', message: 'a deletion is attributed to an actor' }], plan, deleted: [], failed: [], blocked };
  const deleted = []; const failed = [];
  for (const d of plan.decisions.filter((x) => x.action === 'delete')) {
    const fail = (code, message) => failed.push({ id: d.id, code, message });
    let abs;
    try { abs = confined(root, d.path); } catch { abs = null; }
    if (!abs) { fail('PATH_ESCAPES_ROOT', 'the record path is not inside the retention root'); continue; }
    let st;
    try { st = external_node_fs_.lstatSync(abs); } catch (e) { fail(e.code === 'ENOENT' ? 'ALREADY_GONE' : 'STAT_FAILED', 'the file is not there to delete'); continue; }
    if (st.isSymbolicLink()) { fail('SYMLINK_REFUSED', 'a symbolic link is not followed or removed'); continue; }
    if (!st.isFile()) { fail('NOT_A_FILE', 'only files are deleted, never directories'); continue; }
    const digest = `sha256:${external_node_crypto_.createHash('sha256').update(external_node_fs_.readFileSync(abs)).digest('hex')}`;
    const entry = { recordId: d.id, class: d.class, path: d.path, bytes: st.size, contentDigest: digest, reason: d.reason, ageDays: d.ageDays, ttlDays: d.ttlDays, policyVersion: plan.policyVersion, actor, at: new Date(plan.now).toISOString() };
    try { appendLog(logFile, { type: 'delete-intent', ...entry }); } catch (e) { fail(e.code ?? 'LOG_FAILED', 'the deletion could not be logged, so the file was not deleted'); continue; }
    try { external_node_fs_.unlinkSync(abs); } catch (e) {
      try { appendLog(logFile, { type: 'delete-failed', recordId: d.id, code: e.code ?? 'UNLINK_FAILED', at: entry.at }); } catch { /* the intent entry stands */ }
      fail(e.code ?? 'UNLINK_FAILED', 'the file could not be removed'); continue;
    }
    try { appendLog(logFile, { type: 'deleted', recordId: d.id, contentDigest: digest, at: entry.at }); } catch { /* the intent entry already recorded it */ }
    deleted.push({ id: d.id, class: d.class, path: d.path, contentDigest: digest });
  }
  return { ok: true, plan, deleted, failed, blocked };
}

// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: ./src/posture/portfolio/bundle.js + 1 modules
var bundle = __webpack_require__(33889);
;// CONCATENATED MODULE: ./src/posture/portfolio/backend.js
// Pluggable storage backends and offline operation for portfolios (X-708.AC02, X-708.AC03).
//
// Everything in the portfolio works with no hosted service: state is plain files, written atomically, readable with the standard
// library. This module adds the one thing a single store file cannot give, a defined way to run it from SEVERAL workers or hosts that
// share a directory, and a defined answer when that directory is not there.
//
// THE BACKEND INTERFACE (what a replacement implements)
//   kind                       'local-fs' | 'shared-dir' (a label that appears in every report)
//   describe()                 { kind, root, consistency } and what the backend does NOT claim
//   probe()                    { ok: true } or { ok: false, state: 'blocked', code, reason }; never throws, never creates anything
//   storeFile(name)            the path of a named document, for the portfolio store and ledger
//   withExclusive(name, fn)    run `fn` while holding a cross-process lock; throws BACKEND_UNAVAILABLE if the backend went away
//   acquireLease / renewLease / releaseLease / readLease
//                              a named, expiring, FENCED lease (below)
//
// REFERENCE IMPLEMENTATION. `FileLockBackend` uses exclusive file creation (`open(..., 'wx')`) in a directory. `createLocalBackend`
// makes the directory if needed (single user, durable restart). `createSharedBackend` will NOT: it requires a marker file written by
// an explicit `initSharedBackend`, so an unmounted path, a mistyped path or an empty mount point is a typed `blocked`, never a quietly
// fresh store.
//
// LEASE SEMANTICS (each tested, including two real processes contending):
//   - mutual exclusion: at most one holder has an unexpired lease on a resource at a time;
//   - fencing: every grant increments a `fence` number that never goes down (a release keeps it). A holder presents its fence on
//     renew and release, so a holder that was replaced after its lease expired is refused and learns it lost the lease (`lost`);
//   - expiry takeover: an expired lease can be taken by anyone; the previous holder's renew then fails;
//   - release by anyone but the holder, or with a stale fence, is refused.
//
// WHAT IS NOT CLAIMED. These semantics were verified on one machine's local filesystem, with several processes. Exclusive file
// creation is atomic on a local POSIX filesystem; whether it is atomic on a particular network filesystem depends on that filesystem
// and its mount options, and this build has not tested any. A shared directory used from several HOSTS therefore needs the operator to
// verify exclusive-create atomicity on that mount, and lease expiry compares wall clocks, so hosts' clocks must agree to well within a
// lease. Stale-lock recovery (a holder that died inside a critical section) has a narrow window in which two recoverers can both
// believe they broke the lock; critical sections here last milliseconds, and `lockStaleMs` is far above that. `networkFilesystem` is
// reported `unverified` in `describe()`.
//
// UNAVAILABLE BACKEND. Selecting a shared backend that cannot be used returns `{ ok: false, state: 'blocked', code, reason }` from
// `openBackend`, and there is no fallback argument: nothing here ever "degrades" to a local write. Callers must stop, not substitute.










const BACKEND_MARKER = '.agentic-security-backend.json';
const BACKEND_MARKER_SCHEMA = 'agentic-security/portfolio-backend-marker';
const STATE_EXPORT_SCHEMA = 'agentic-security/portfolio-state-export';
const BLOCK_CODES = Object.freeze(['backend-missing', 'backend-not-initialized', 'backend-not-a-directory', 'backend-symlink', 'backend-not-writable', 'backend-marker-invalid']);
const BACKEND_LIMITS = Object.freeze({ lockStaleMs: 30_000, lockWaitMs: 5000, maxLeaseMs: 6 * 60 * 60_000, maxExportBytes: 64 * 1024 * 1024 });
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
const unavailable = (probe) => (0,work_units/* typedError */.Zz)('BACKEND_UNAVAILABLE', `the portfolio backend is unavailable (${probe.code}): ${probe.reason}`, { state: 'blocked', probe });

/** The reference backend: exclusive-create file locks in a directory. */
class FileLockBackend {
  constructor({ kind, root, requireMarker, lockStaleMs = BACKEND_LIMITS.lockStaleMs, lockWaitMs = BACKEND_LIMITS.lockWaitMs, nodeId = null }) {
    this.kind = kind; this.root = external_node_path_.resolve(root); this.requireMarker = requireMarker;
    this.lockStaleMs = lockStaleMs; this.lockWaitMs = lockWaitMs;
    this.nodeId = nodeId ?? `${external_node_os_.hostname()}:${process.pid}`;
  }

  describe() {
    return {
      kind: this.kind, root: this.root, requiresMarker: this.requireMarker,
      consistency: {
        mutualExclusion: 'verified for processes sharing one local filesystem (two-process contention test)',
        fencing: 'monotonic per resource; a stale holder is refused on renew and release',
        networkFilesystem: 'unverified',
        clocks: 'lease expiry compares wall clocks; hosts sharing a directory must agree to well within a lease',
        staleLockRecovery: `a lock file older than ${this.lockStaleMs} ms is treated as abandoned; the recovery has a narrow race and is not a substitute for short critical sections`,
      },
    };
  }

  probe() {
    let st;
    try { st = external_node_fs_.lstatSync(this.root); } catch { return { ok: false, state: 'blocked', code: 'backend-missing', reason: `${this.kind} backend directory does not exist or cannot be read` }; }
    if (st.isSymbolicLink()) return { ok: false, state: 'blocked', code: 'backend-symlink', reason: 'the backend directory is a symbolic link; it is not followed' };
    if (!st.isDirectory()) return { ok: false, state: 'blocked', code: 'backend-not-a-directory', reason: 'the backend path is not a directory' };
    if (this.requireMarker) {
      let m;
      try { m = JSON.parse(external_node_fs_.readFileSync(external_node_path_.join(this.root, BACKEND_MARKER), 'utf8')); } catch (e) {
        return { ok: false, state: 'blocked', code: e.code === 'ENOENT' ? 'backend-not-initialized' : 'backend-marker-invalid', reason: e.code === 'ENOENT' ? 'the shared directory has no backend marker: it is not initialized (an unmounted or empty directory is not a store)' : 'the backend marker is unreadable' };
      }
      if (m?.schema !== BACKEND_MARKER_SCHEMA || m.kind !== this.kind) return { ok: false, state: 'blocked', code: 'backend-marker-invalid', reason: 'the backend marker does not describe this kind of backend' };
    }
    try {
      const probeFile = external_node_path_.join(this.root, `.probe-${process.pid}-${external_node_crypto_.randomBytes(4).toString('hex')}`);
      external_node_fs_.writeFileSync(probeFile, '', { flag: 'wx' }); external_node_fs_.unlinkSync(probeFile);
    } catch { return { ok: false, state: 'blocked', code: 'backend-not-writable', reason: 'the backend directory is not writable' }; }
    return { ok: true };
  }

  storeFile(name = 'portfolio-store.json') {
    if (!NAME_RE.test(name)) throw (0,work_units/* typedError */.Zz)('BAD_NAME', `'${name}' is not an allowed document name`);
    return external_node_path_.join(this.root, name);
  }

  _lockPath(name) {
    if (!NAME_RE.test(name)) throw (0,work_units/* typedError */.Zz)('BAD_NAME', `'${name}' is not an allowed lock name`);
    return external_node_path_.join(this.root, '.locks', `${name}.lock`);
  }

  /** Run `fn` under the named cross-process lock. The backend is re-probed first: a backend that went away is an error, not an empty store. */
  withExclusive(name, fn, { waitMs = this.lockWaitMs } = {}) {
    const p = this.probe();
    if (!p.ok) throw unavailable(p);
    const lock = this._lockPath(name);
    external_node_fs_.mkdirSync(external_node_path_.dirname(lock), { recursive: true });
    const token = external_node_crypto_.randomBytes(12).toString('hex');
    const body = JSON.stringify({ token, node: this.nodeId, pid: process.pid });
    const start = Date.now();
    for (;;) {
      try { external_node_fs_.writeFileSync(lock, body, { flag: 'wx' }); break; } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        this._breakIfStale(lock);
        if (Date.now() - start > waitMs) throw (0,work_units/* typedError */.Zz)('LOCK_TIMEOUT', `could not take lock '${name}' within ${waitMs} ms`);
        sleepSync(3);
      }
    }
    try { return fn(); } finally {
      // release only OUR lock: if it was recovered as stale and re-taken, the file belongs to someone else now
      try { if (JSON.parse(external_node_fs_.readFileSync(lock, 'utf8')).token === token) external_node_fs_.unlinkSync(lock); } catch { /* already gone */ }
    }
  }

  _breakIfStale(lock) {
    let st; let seen;
    try { st = external_node_fs_.statSync(lock); seen = JSON.parse(external_node_fs_.readFileSync(lock, 'utf8')).token; } catch { return; }
    if (Date.now() - st.mtimeMs <= this.lockStaleMs) return;
    const grave = `${lock}.broken-${process.pid}-${external_node_crypto_.randomBytes(3).toString('hex')}`;
    try { external_node_fs_.renameSync(lock, grave); } catch { return; }
    let got = null;
    try { got = JSON.parse(external_node_fs_.readFileSync(grave, 'utf8')).token; } catch { /* unreadable: treated as the stale one */ }
    if (got !== null && got !== seen) { try { external_node_fs_.linkSync(grave, lock); } catch { /* the lock was re-taken meanwhile: the documented narrow race */ } }
    try { external_node_fs_.unlinkSync(grave); } catch { /* ignore */ }
  }

  _leaseFile(resource) {
    if (!NAME_RE.test(resource)) throw (0,work_units/* typedError */.Zz)('BAD_NAME', `'${resource}' is not an allowed lease name`);
    return external_node_path_.join(this.root, 'leases', `${resource}.json`);
  }

  _readLease(resource) {
    try { return JSON.parse(external_node_fs_.readFileSync(this._leaseFile(resource), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw (0,work_units/* typedError */.Zz)('LEASE_CORRUPT', `lease '${resource}' is unreadable`); }
  }

  _writeLease(resource, doc) {
    const file = this._leaseFile(resource);
    external_node_fs_.mkdirSync(external_node_path_.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}`;
    external_node_fs_.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
    external_node_fs_.renameSync(tmp, file);
  }

  readLease(resource) { return this.withExclusive(`lease-${resource}`, () => this._readLease(resource)); }

  acquireLease(resource, { holder, ttlMs, now }) {
    if (typeof holder !== 'string' || !holder) throw (0,work_units/* typedError */.Zz)('BAD_HOLDER', 'a lease needs a holder');
    if (!(Number.isFinite(ttlMs) && ttlMs >= 1) || !Number.isFinite(now)) throw (0,work_units/* typedError */.Zz)('BAD_LEASE', 'a lease needs a positive ttlMs and a now');
    const ttl = Math.min(ttlMs, BACKEND_LIMITS.maxLeaseMs);
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (cur && cur.holder && cur.expiresAt > now) return { ok: false, code: 'held', heldBy: cur.holder, expiresAt: cur.expiresAt, fence: cur.fence };
      const fence = (cur?.fence ?? 0) + 1;
      const doc = { resource, holder, fence, expiresAt: now + ttl, acquiredAt: now, node: this.nodeId };
      this._writeLease(resource, doc);
      return { ok: true, fence, expiresAt: doc.expiresAt, takenOver: !!(cur && cur.holder) };
    });
  }

  renewLease(resource, { holder, fence, ttlMs, now }) {
    const ttl = Math.min(ttlMs, BACKEND_LIMITS.maxLeaseMs);
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (!cur || cur.holder !== holder || cur.fence !== fence) return { ok: false, code: 'lost', reason: 'the lease is held by another holder or generation' };
      if (cur.expiresAt <= now) return { ok: false, code: 'expired', reason: 'the lease expired; it must be acquired again' };
      cur.expiresAt = now + ttl;
      this._writeLease(resource, cur);
      return { ok: true, fence, expiresAt: cur.expiresAt };
    });
  }

  releaseLease(resource, { holder, fence }) {
    return this.withExclusive(`lease-${resource}`, () => {
      const cur = this._readLease(resource);
      if (!cur || cur.holder !== holder || cur.fence !== fence) return { ok: false, code: 'not-holder', reason: 'only the current holder, with its fence, can release' };
      this._writeLease(resource, { resource, holder: null, fence: cur.fence, expiresAt: 0, node: this.nodeId });
      return { ok: true };
    });
  }
}

/** Create the marker that makes a directory a shared backend. An explicit operator act; `openBackend` never does it. */
function initSharedBackend(dir, { id = crypto.randomBytes(8).toString('hex') } = {}) {
  const root = path.resolve(dir);
  fs.mkdirSync(root, { recursive: true });
  const marker = path.join(root, BACKEND_MARKER);
  if (fs.existsSync(marker)) return { ok: true, created: false };
  fs.writeFileSync(marker, JSON.stringify({ schema: BACKEND_MARKER_SCHEMA, kind: 'shared-dir', id }), { flag: 'wx' });
  return { ok: true, created: true };
}

const createLocalBackend = (dir, o = {}) => { external_node_fs_.mkdirSync(external_node_path_.resolve(dir), { recursive: true }); return new FileLockBackend({ kind: 'local-fs', root: dir, requireMarker: false, ...o }); };
const createSharedBackend = (dir, o = {}) => new FileLockBackend({ kind: 'shared-dir', root: dir, requireMarker: true, ...o });

/**
 * Select a backend. `mode` is 'local' or 'shared'. A shared backend that is not usable returns `{ ok: false, state: 'blocked', ... }`;
 * there is no fallback to the local backend, by design.
 */
function openBackend({ mode, dir }) {
  if (mode !== 'local' && mode !== 'shared') return { ok: false, state: 'blocked', code: 'invalid-mode', reason: "mode must be 'local' or 'shared'" };
  if (typeof dir !== 'string' || !dir) return { ok: false, state: 'blocked', code: 'backend-missing', reason: 'a backend directory is required' };
  const backend = mode === 'local' ? createLocalBackend(dir) : createSharedBackend(dir);
  const p = backend.probe();
  return p.ok ? { ok: true, backend } : p;
}

// ---------------------------------------------------------------- offline export and import

/**
 * A single self-checking file holding the portfolio store and ledger (and optionally the deletion log), for moving state to an
 * air-gapped machine or archiving it. Reads nothing from the network. Refused if the store fails verification or any text in it has a
 * secret shape.
 */
function exportState({ storeFile, outFile, retentionLog = null, now }) {
  const storeText = external_node_fs_.readFileSync(storeFile, 'utf8');
  if (storeText.length > BACKEND_LIMITS.maxExportBytes) throw (0,work_units/* typedError */.Zz)('EXPORT_TOO_LARGE', 'the store is larger than the export limit');
  const store = JSON.parse(storeText);
  const v = (0,work_units/* verifyStore */.H9)(store);
  if (!v.ok) throw (0,work_units/* typedError */.Zz)('STORE_CORRUPT', `refusing to export a store that fails verification: ${v.errors[0].code}`);
  const ledger = (0,scheduler/* readLedger */.SC)(storeFile);
  const log = retentionLog && external_node_fs_.existsSync(retentionLog) ? external_node_fs_.readFileSync(retentionLog, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  const body = { schema: STATE_EXPORT_SCHEMA, version: 1, ...(store.synthetic ? { synthetic: true } : {}), exportedAtMs: now, store, ledger, retentionLog: log };
  const secret = (0,bundle/* findSecret */.mt)(JSON.stringify(body));
  if (secret) throw (0,work_units/* typedError */.Zz)('SECRET_IN_EXPORT', `the state contains a secret-shaped string (${secret}); it was not exported`);
  const doc = { ...body, digest: (0,identity/* digestOf */.ol)(body) };
  external_node_fs_.mkdirSync(external_node_path_.dirname(external_node_path_.resolve(outFile)), { recursive: true });
  const tmp = `${outFile}.tmp-${process.pid}`;
  external_node_fs_.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
  external_node_fs_.renameSync(tmp, outFile);
  return { ok: true, digest: doc.digest, units: Object.keys(store.units).length };
}

/** Offline verification of an export: re-derives its digest and verifies the store inside. Executes nothing. */
function verifyStateExport(file) {
  let doc;
  try {
    const st = external_node_fs_.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile() || st.size > BACKEND_LIMITS.maxExportBytes) return { ok: false, code: 'BAD_FILE', reason: 'not a regular file within the size limit' };
    doc = JSON.parse(external_node_fs_.readFileSync(file, 'utf8'));
  } catch { return { ok: false, code: 'BAD_FILE', reason: 'unreadable or not JSON' }; }
  if (doc?.schema !== STATE_EXPORT_SCHEMA || doc.version !== 1) return { ok: false, code: 'BAD_SCHEMA', reason: 'not a portfolio state export of a supported version' };
  const { digest, ...body } = doc;
  if ((0,identity/* digestOf */.ol)(body) !== digest) return { ok: false, code: 'DIGEST_MISMATCH', reason: 'the export was modified after it was written' };
  const v = (0,work_units/* verifyStore */.H9)(doc.store);
  if (!v.ok) return { ok: false, code: 'STORE_INVALID', reason: `the store inside fails verification: ${v.errors[0].code}` };
  return { ok: true, doc };
}

/** Import into a backend that holds no portfolio store yet. Verifies first; never overwrites. */
function importState({ from, backend, name = 'portfolio-store.json' }) {
  const p = backend.probe();
  if (!p.ok) return p;
  const v = verifyStateExport(from);
  if (!v.ok) return { ok: false, state: 'rejected', code: v.code, reason: v.reason };
  const file = backend.storeFile(name);
  return backend.withExclusive('import', () => {
    if (external_node_fs_.existsSync(file)) return { ok: false, state: 'rejected', code: 'WOULD_OVERWRITE', reason: 'the backend already holds a portfolio store; import never overwrites' };
    external_node_fs_.writeFileSync(file, JSON.stringify(v.doc.store), { flag: 'wx', mode: 0o600 });
    external_node_fs_.writeFileSync((0,scheduler/* ledgerPathFor */.GN)(file), JSON.stringify(v.doc.ledger), { flag: 'wx', mode: 0o600 });
    return { ok: true, file, units: Object.keys(v.doc.store.units).length };
  });
}


;// CONCATENATED MODULE: ./src/posture/portfolio/cli.js
// `agentic-security portfolio <progress|retention|backend|export|import>` (X-707, X-708 CLI surface).
//
//   portfolio progress  --store <file> [--budgets <file>] [--findings <file>] [--blocking-severity <s>] [--now <ms>] [--json]
//       The coverage-aware progress view (see portfolio/progress.js). Exit 0, 1 refused (feature off, store failed verification), 2 usage.
//   portfolio retention plan|apply --records <file> --root <dir> [--policy <file>] [--holds <file>] [--store <file>]
//                                  [--log <file> --actor <name>] [--now <ms>] [--json]
//       Retention by class with legal holds (see portfolio/retention.js). `plan` deletes nothing. `apply` needs --log and --actor, logs
//       each deletion first, and exits 1 if anything it should have deleted could not be deleted. Exit 0 ok, 1 refused or incomplete, 2 usage.
//   portfolio retention verify-log --log <file>     checks the hash chain of the deletion log. Exit 0 intact, 1 broken.
//   portfolio backend probe --mode local|shared --dir <dir>
//       Reports whether a backend is usable. An unusable shared backend is the typed `blocked` state, exit 1; nothing is created.
//   portfolio export --store <file> --out <file> [--retention-log <file>]    one self-checking, secret-free file for an air-gapped machine
//   portfolio import --from <file> --mode local|shared --dir <dir>            verifies first; never overwrites a store
//
// Every subcommand is off unless the `portfolio-assurance` feature is on (assurance/config.js), so a default install behaves exactly as
// before. Nothing here makes a network call: the whole command works air-gapped. The logic lives here, not in bin/, so tests run it
// without spawning the CLI; bin/ only dispatches. Paths are the operator's own and resolve against the working directory (the MCP
// tool, which takes paths from an agent, confines them to its session root instead).










const USAGE = [
  'Usage: agentic-security portfolio progress  --store <file> [--budgets <file>] [--findings <file>] [--blocking-severity <s>] [--now <ms>] [--json]',
  '       agentic-security portfolio retention plan|apply --records <file> --root <dir> [--policy <file>] [--holds <file>] [--store <file>] [--log <file> --actor <name>] [--now <ms>] [--json]',
  '       agentic-security portfolio retention verify-log --log <file>',
  '       agentic-security portfolio backend probe --mode local|shared --dir <dir>',
  '       agentic-security portfolio export --store <file> --out <file> [--retention-log <file>]',
  '       agentic-security portfolio import --from <file> --mode local|shared --dir <dir>',
].join('\n');

const abs = (cwd, p) => external_node_path_.resolve(cwd, String(p));
const readJsonFile = (file) => {
  const st = external_node_fs_.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile() || st.size > 32 * 1024 * 1024) throw new Error('not a regular JSON file within the size limit');
  return JSON.parse(external_node_fs_.readFileSync(file, 'utf8'));
};

/**
 * @param {{ _: string[], flags: object }} args
 * @param {{ cwd?: string, out?: (s: string) => void, err?: (s: string) => void, env?: object, now?: () => number }} [io]
 * @returns {Promise<number>} the exit code
 */
async function runPortfolioCommand(args, io = {}) {
  const cwd = io.cwd || process.cwd();
  const out = io.out || ((s) => process.stdout.write(s));
  const err = io.err || ((s) => process.stderr.write(s));
  const sub = args._[1];
  const flags = args.flags || {};
  const clock = io.now || (() => Date.now());
  const emit = (value, lines) => out(flags.json ? `${JSON.stringify(value, null, 2)}\n` : `${lines.join('\n')}\n`);
  if (!['progress', 'retention', 'backend', 'export', 'import'].includes(sub)) { err(`${USAGE}\n`); return 2; }

  const config = (0,assurance_config.resolveAssuranceConfig)({ scanRoot: cwd, env: io.env || process.env });
  const gate = (0,assurance_config/* featureStatus */.FX)(config, wording/* FEATURE_ID */.DU);
  if (gate.status !== 'ok') { err(`agentic-security portfolio ${sub}: ${gate.status}: ${gate.reason ?? gate.code}\n`); return 1; }
  const nowMs = flags.now !== undefined ? Number(flags.now) : clock();

  try {
    if (sub === 'progress') {
      if (typeof flags.store !== 'string') { err(`${USAGE}\n`); return 2; }
      const storePath = abs(cwd, flags.store);
      const store = (0,work_units/* readStore */.uz)(storePath);
      if (!store) { err('agentic-security portfolio progress: no portfolio store at that path\n'); return 1; }
      const r = (0,progress/* buildProgressView */.TJ)({
        store, ledger: (0,scheduler/* readLedger */.SC)(storePath), now: nowMs,
        budgets: typeof flags.budgets === 'string' ? readJsonFile(abs(cwd, flags.budgets)) : null,
        findings: typeof flags.findings === 'string' ? readJsonFile(abs(cwd, flags.findings)) : null,
        blockingSeverity: typeof flags['blocking-severity'] === 'string' ? flags['blocking-severity'] : undefined,
      });
      if (!r.ok) { err(`agentic-security portfolio progress: ${r.errors[0].message}\n`); return 1; }
      emit(r.view, r.view.lines);
      return 0;
    }

    if (sub === 'retention') {
      const mode = args._[2];
      if (mode === 'verify-log') {
        if (typeof flags.log !== 'string') { err(`${USAGE}\n`); return 2; }
        const v = verifyRetentionLog(abs(cwd, flags.log));
        emit(v, [v.ok ? `Deletion log verified: ${v.entries.length} entr${v.entries.length === 1 ? 'y' : 'ies'}, chain intact.` : `Deletion log FAILED verification: ${v.errors[0].message}`]);
        return v.ok ? 0 : 1;
      }
      if (!['plan', 'apply'].includes(mode) || typeof flags.records !== 'string' || typeof flags.root !== 'string') { err(`${USAGE}\n`); return 2; }
      const input = {
        records: readJsonFile(abs(cwd, flags.records)), now: nowMs,
        policy: typeof flags.policy === 'string' ? readJsonFile(abs(cwd, flags.policy)) : undefined,
        holds: typeof flags.holds === 'string' ? readJsonFile(abs(cwd, flags.holds)) : [],
        store: typeof flags.store === 'string' ? (0,work_units/* readStore */.uz)(abs(cwd, flags.store)) : null,
      };
      if (mode === 'plan') {
        const plan = planRetention(input);
        if (!plan.ok) { err(`agentic-security portfolio retention: ${plan.errors[0].message}\n`); return 1; }
        emit(plan, [`Retention plan (policy ${plan.policyVersion}): ${plan.summary.delete} to delete, ${plan.summary.keep} kept (${plan.summary.heldByLegalHold} under legal hold), ${plan.summary.protect} protected as required current receipts${plan.summary.expiredButRequired ? ` (${plan.summary.expiredButRequired} past retention but required: deletion blocked)` : ''}.`, 'Nothing was deleted.']);
        return 0;
      }
      if (typeof flags.log !== 'string' || typeof flags.actor !== 'string') { err(`${USAGE}\n`); return 2; }
      const r = applyRetention({ ...input, root: abs(cwd, flags.root), logFile: abs(cwd, flags.log), actor: flags.actor });
      if (!r.ok) { err(`agentic-security portfolio retention: ${r.errors[0].message}\n`); return 1; }
      emit(r, [`Retention applied: ${r.deleted.length} deleted and logged, ${r.blocked.length} blocked as required current receipts, ${r.failed.length} could not be deleted.`, ...r.failed.map((f) => `  ${f.id}: ${f.code}: ${f.message}`)]);
      return r.failed.length ? 1 : 0;
    }

    if (sub === 'backend') {
      if (args._[2] !== 'probe' || typeof flags.dir !== 'string') { err(`${USAGE}\n`); return 2; }
      const b = openBackend({ mode: flags.mode, dir: abs(cwd, flags.dir) });
      if (!b.ok) { emit(b, [`Backend ${flags.mode ?? '?'}: ${b.state} (${b.code}): ${b.reason}`, 'Nothing was created and no other location is used instead.']); return 1; }
      const d = b.backend.describe();
      emit({ ok: true, ...d }, [`Backend ${d.kind} at ${d.root}: usable.`, `  Network filesystems: ${d.consistency.networkFilesystem}.`]);
      return 0;
    }

    if (sub === 'export') {
      if (typeof flags.store !== 'string' || typeof flags.out !== 'string') { err(`${USAGE}\n`); return 2; }
      const r = exportState({ storeFile: abs(cwd, flags.store), outFile: abs(cwd, flags.out), retentionLog: typeof flags['retention-log'] === 'string' ? abs(cwd, flags['retention-log']) : null, now: nowMs });
      emit(r, [`Exported ${r.units} unit(s) to ${flags.out} (${r.digest}).`]);
      return 0;
    }

    if (sub === 'import') {
      if (typeof flags.from !== 'string' || typeof flags.dir !== 'string') { err(`${USAGE}\n`); return 2; }
      const b = openBackend({ mode: flags.mode, dir: abs(cwd, flags.dir) });
      if (!b.ok) { err(`agentic-security portfolio import: ${b.state} (${b.code}): ${b.reason}\n`); return 1; }
      const v = verifyStateExport(abs(cwd, flags.from));
      if (!v.ok) { err(`agentic-security portfolio import: ${v.code}: ${v.reason}\n`); return 1; }
      const r = importState({ from: abs(cwd, flags.from), backend: b.backend });
      if (!r.ok) { err(`agentic-security portfolio import: ${r.code}: ${r.reason}\n`); return 1; }
      emit(r, [`Imported ${r.units} unit(s) into ${r.file}.`]);
      return 0;
    }
  } catch (e) {
    err(`agentic-security portfolio ${sub}: ${e.code ?? 'error'}: ${String(e.message).slice(0, 300)}\n`);
    return 1;
  }
  return 2;
}


/***/ })

};
