export const id = 730;
export const ids = [730,144];
export const modules = {

/***/ 5144:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   addLegalHold: () => (/* binding */ addLegalHold),
/* harmony export */   isUnderHold: () => (/* binding */ isUnderHold),
/* harmony export */   listLegalHolds: () => (/* binding */ listLegalHolds),
/* harmony export */   loadLegalHolds: () => (/* binding */ loadLegalHolds),
/* harmony export */   removeLegalHold: () => (/* binding */ removeLegalHold)
/* harmony export */ });
/* unused harmony export LEGAL_HOLD_FILE */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1174);
/* harmony import */ var _artifact_registry_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(471);
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
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .statePath */ .BQ)(scanRoot, LEGAL_HOLD_FILE); } catch { return []; }
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
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .statePath */ .BQ)(scanRoot, LEGAL_HOLD_FILE);
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
    const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .statePath */ .BQ)(scanRoot, LEGAL_HOLD_FILE);
    (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .safeWriteState */ .Ep)(fp, JSON.stringify(remaining, null, 2) + '\n');
  }
  return removedCount;
}


/***/ }),

/***/ 6730:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findExpiredArtifacts: () => (/* binding */ findExpiredArtifacts)
/* harmony export */ });
/* unused harmony exports RETENTION_DEFAULTS, loadRetentionPolicy, effectiveTtlDays */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var _util_yaml_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(2340);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1174);
/* harmony import */ var _artifact_registry_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(471);
/* harmony import */ var _legal_hold_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(5144);
// Retention policy: default and maximum TTL by artifact class (assurance-
// hardening PRD FR-702).
//
// "Enforce default and maximum TTL by artifact class | Expired caches,
// scans, evidence, tickets, and backups are purged or archived according
// to policy."
//
// TWO NUMBERS PER CLASS, ON PURPOSE
// --------------------------------------------------------------------------
// `defaultDays` is what applies when nobody configures anything — a
// reasonable, disclosed starting point, not a regulatory citation (an
// operator with a real compliance regime should configure their own via
// the policy file below). `maxDays` is a CEILING an operator's own
// configuration cannot exceed: the literal "default AND maximum" wording
// asks for both a floor-free default and a hard cap, not just a knob. An
// operator who wants indefinite retention for `evidence` for their own
// audit reasons should say so in their own retention program — this
// module will not silently allow a TTL past its built-in ceiling for a
// class, because "TTL" than can be configured to "never" is not a TTL.
//
// PURGE, NOT ARCHIVE
// --------------------------------------------------------------------------
// The acceptance criterion allows either. This implements PURGE (delete)
// only — the simpler, safer, and more directly verifiable of the two.
// "Archive" implies a defined export format and destination, which is
// FR-706's own separate scope (manifest-based export); an operator who
// wants to archive before purging already has the tool for it once FR-706
// exists, or can back up `.agentic-security/` by their own means before
// running the enforcement command.
//
// WHICH ARTIFACTS THIS APPLIES TO
// --------------------------------------------------------------------------
// Only 'generated' artifacts carrying a `retentionClass` in
// artifact-registry.js — deliberately a SUBSET of all generated artifacts
// (see that module's own header for which ones were left classless and
// why). An 'operator-config' artifact is NEVER touched by this module,
// regardless of age, matching FR-703's own "reset preserves operator-
// authored configuration" precedent.







const POLICY_FILE = 'retention-policy.yml';
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Engineering defaults, not a regulatory claim — see the header above.
const RETENTION_DEFAULTS = {
  cache: { defaultDays: 7, maxDays: 30 },
  scan: { defaultDays: 90, maxDays: 365 },
  evidence: { defaultDays: 365, maxDays: 1095 },
  ticket: { defaultDays: 180, maxDays: 730 },
  backup: { defaultDays: 30, maxDays: 180 },
};

/**
 * Load an operator's `.agentic-security/retention-policy.yml`. Never
 * throws — a missing or malformed file degrades to "no overrides," the
 * same no-op-until-configured convention this repo uses for every other
 * policy surface. Shape:
 *   cache: { defaultDays: 3 }
 *   evidence: { defaultDays: 730 }
 * A class not mentioned, or a file not present at all, uses
 * RETENTION_DEFAULTS unmodified.
 */
function loadRetentionPolicy(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, POLICY_FILE); } catch { return null; }
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return null; }
  try {
    const doc = _util_yaml_js__WEBPACK_IMPORTED_MODULE_1__/* .load */ .Hh(raw);
    if (!doc || typeof doc !== 'object') return null;
    return doc;
  } catch { return null; }
}

/**
 * The TTL (in days) actually in effect for a class, after applying any
 * operator override and clamping it to the class's own maxDays — an
 * override CANNOT raise retention past the ceiling, only lower it (or
 * leave it at the default). An unrecognised class (should not happen —
 * only artifact-registry.js's own 5 named classes are ever passed in)
 * degrades to null, meaning "not subject to a TTL."
 */
function effectiveTtlDays(retentionClass, policy) {
  const bounds = RETENTION_DEFAULTS[retentionClass];
  if (!bounds) return null;
  const override = policy?.[retentionClass]?.defaultDays;
  if (typeof override === 'number' && Number.isFinite(override) && override >= 0) {
    return Math.min(override, bounds.maxDays);
  }
  return bounds.defaultDays;
}

/**
 * Which registered, retention-classed artifacts under `scanRoot`'s state
 * dir are currently past their effective TTL. Never throws — a missing
 * state dir or an artifact that does not exist on disk is simply absent
 * from the result, not an error.
 *
 * @returns {Array<{name: string, isDir: boolean, retentionClass: string,
 *   ageDays: number, ttlDays: number}>}
 */
function findExpiredArtifacts(scanRoot, { now = Date.now() } = {}) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .stateDir */ .Pn)(scanRoot);
  let dirExists = true;
  try { node_fs__WEBPACK_IMPORTED_MODULE_0__.accessSync(dir); } catch { dirExists = false; }
  if (!dirExists) return [];
  const policy = loadRetentionPolicy(scanRoot);
  // FR-707: an artifact under an active legal hold is NEVER reported as
  // expired, regardless of TTL — checked here (not just in cmdReset) so
  // any future caller of this function inherits the same guarantee.
  const holds = (0,_legal_hold_js__WEBPACK_IMPORTED_MODULE_4__.loadLegalHolds)(scanRoot);
  const expired = [];
  for (const artifact of (0,_artifact_registry_js__WEBPACK_IMPORTED_MODULE_3__/* .listArtifactsWithRetentionClass */ .U_)()) {
    const ttlDays = effectiveTtlDays(artifact.retentionClass, policy);
    if (ttlDays === null) continue;
    if ((0,_legal_hold_js__WEBPACK_IMPORTED_MODULE_4__.isUnderHold)(artifact.name, holds, now)) continue;
    const p = `${dir}/${artifact.name}`;
    let st;
    try { st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p); } catch { continue; } // not present — nothing to expire
    const ageDays = (now - st.mtimeMs) / MS_PER_DAY;
    if (ageDays > ttlDays) {
      expired.push({ name: artifact.name, isDir: st.isDirectory(), retentionClass: artifact.retentionClass, ageDays, ttlDays });
    }
  }
  return expired;
}


/***/ })

};
