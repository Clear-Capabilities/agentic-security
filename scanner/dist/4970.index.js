export const id = 4970;
export const ids = [4970];
export const modules = {

/***/ 4970:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ASSURANCE_MODES: () => (/* binding */ ASSURANCE_MODES),
/* harmony export */   DEFAULT_ASSURANCE_MODE: () => (/* binding */ DEFAULT_ASSURANCE_MODE),
/* harmony export */   evaluateAssuranceMode: () => (/* binding */ evaluateAssuranceMode)
/* harmony export */ });
/* unused harmony export _internals */
/* harmony import */ var _posture_provenance_schema_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(4594);
// Assurance modes (assurance-hardening PRD FR-204).
//
// "Add assurance modes: advisory, standard, and strict | Strict mode fails
// when a required analyzer fails, times out, is unavailable, or is
// silently skipped." Section 12.1 names the CLI surface:
// `--assurance advisory|standard|strict`.
//
// Built directly on FR-203's coverage ledger (pipeline/coverage-ledger.js)
// and FR-206's scan-health.js -- this module adds no new signal collection
// of its own, only a POLICY over signals that already exist. That is
// deliberate: assurance modes decide how strict to be about incomplete
// analysis; they must never be the thing that DEFINES what "incomplete"
// means, or the two concepts would drift out of sync.
//
// THREE MODES:
//   advisory — never fails the gate over scan health, regardless of what
//     scanHealth reports. Purely informational (surfaced in scanHealth /
//     toShipVerdict / `ci`'s stderr, per FR-206's fix -- this mode does not
//     suppress that, it just does not ADD a build-failing consequence).
//   standard (the DEFAULT, matching this codebase's behavior before and
//     after FR-204) — same as advisory for gate purposes: an incomplete
//     scan is surfaced, never silently hidden, but does not itself fail a
//     build independent of the ordinary --fail-on severity threshold. The
//     distinction from advisory is one of INTENT/reporting emphasis, not
//     mechanism -- see the module-level note below on why this codebase
//     does not invent a mechanical difference the PRD text does not ask
//     for.
//   strict — an incomplete scan (any analyzer failed, timed out, or was
//     skipped by policy -- the ledger's own three non-"completed" outcomes)
//     is a HARD FAILURE, independent of and IN ADDITION TO --fail-on,
//     mirroring cmdCi's own existing precedent for its --policy gate
//     ("Policy runs ALONGSIDE the --fail-on threshold; either gate can
//     fail the build").
//
// WHY ADVISORY AND STANDARD ARE MECHANICALLY IDENTICAL HERE: the PRD's own
// one-line acceptance criterion only specifies STRICT mode's behavior in
// full ("fails when..."); it does not name a distinct mechanical
// consequence for standard beyond "the default, not strict." Inventing an
// intermediate failure condition neither named in the PRD nor requested
// would be exactly the kind of unrequested scope-widening this codebase's
// own conventions warn against. If a future requirement needs standard
// mode to behave differently from advisory, that is a deliberate, separate
// decision -- not something to guess at here.



const ASSURANCE_MODES = Object.freeze(['advisory', 'standard', 'strict']);
const DEFAULT_ASSURANCE_MODE = 'standard';

function _isValidMode(mode) {
  return ASSURANCE_MODES.includes(mode);
}

/**
 * @param {string} mode - one of ASSURANCE_MODES; invalid/missing degrades to the default.
 * @param {object|null} scanHealth - the engine's computed scan.scanHealth (FR-206).
 * @returns {{ok: boolean, mode: string, reason: string|null, conditions: string[]}}
 *   ok:false only ever happens in strict mode; advisory/standard always ok:true
 *   (they report, they do not gate).
 */
function evaluateAssuranceMode(mode, scanHealth, findings = []) {
  const effectiveMode = _isValidMode(mode) ? mode : DEFAULT_ASSURANCE_MODE;
  const conditions = Array.isArray(scanHealth?.conditions) ? scanHealth.conditions : [];

  if (effectiveMode !== 'strict') {
    return { ok: true, mode: effectiveMode, reason: null, conditions };
  }

  // Strict: any of the ledger's three non-"completed" analyzer outcomes,
  // OR an annotator error / deep-mode failure (scanHealth's OTHER,
  // non-analyzer conditions) -- "a required analyzer... is unavailable, or
  // is silently skipped" covers more than just coverage-ledger.js's own
  // per-detector accounting; a scan whose ANY known-good signal degraded
  // is not "complete" under strict's own definition.
  const status = scanHealth?.status;
  if (!scanHealth || status !== 'complete') {
    const a = scanHealth?.analyzers;
    const parts = [];
    if (a?.failed > 0) parts.push(`${a.failed} analyzer(s) failed`);
    if (a?.timedOut > 0) parts.push(`${a.timedOut} analyzer(s) timed out`);
    if (a?.skippedByPolicy > 0) parts.push(`${a.skippedByPolicy} analyzer(s) silently skipped by policy`);
    const analyzerSummary = parts.length ? ` (${parts.join(', ')})` : '';
    return {
      ok: false,
      mode: 'strict',
      reason: `strict mode requires a fully complete scan; scanHealth.status is '${status ?? 'unknown'}'${analyzerSummary}`,
      conditions,
    };
  }

  // M2 §2.5: strict cares about overall scan completeness, which now
  // explicitly includes PROVENANCE completeness, not just detector/analyzer
  // completeness. A finding whose findingProvenance status is outside
  // ['complete','uncommitted'] — including a finding with NO
  // findingProvenance at all, e.g. --no-provenance was used — means strict
  // cannot vouch for this scan's provenance the same way it already refuses
  // to vouch for a scan with a failed analyzer.
  //
  // KNOWN INTERACTION: scan.secrets/scan.logicVulns are unconditionally
  // stamped not_available today (M0+M1 deliberately deferred real origin
  // resolution for those two channels — see the M2/M3/M4 design spec's
  // §2.6). Any real secret or logic finding therefore fails strict mode
  // until that resolution work lands. This is the literal, intended
  // consequence of "never false certainty" applied to strict's own
  // definition, not an oversight — a strict-mode operator with secrets
  // findings should expect this until M3+ closes that gap.
  //
  // This list is INCOMPLETE without scan.supplyChain, and the omission
  // matters more than the secrets/logic one above because it hits nearly
  // every real project. engine.js stamps every supplyChain entry
  // not_available too (see the loop over `supplyChain` right after the
  // `annotateGitProvenance` calls), and that bucket covers three distinct
  // populations, not one:
  //
  //  - transitive `vulnerable_dep` findings: a genuine, if currently
  //    unresolved, DEFERRAL — same shape as secrets/logicVulns above. The
  //    vulnerable version was never declared in this repo's own manifests,
  //    so there is no local commit to walk yet, but one could exist to
  //    resolve in a later phase.
  //  - `unpinned_dep` / `no_lockfile` findings: a CATEGORY ERROR, not a
  //    deferral. These describe an ABSENT state (a version range with no
  //    pin, a manifest with no lockfile) — there is no "commit that
  //    introduced a missing lockfile" for any future resolver to find,
  //    because the finding is about the absence of an event, not an event
  //    itself. No amount of future engineering work makes these resolvable.
  //
  // Direct `vulnerable_dep` findings DO go through real origin resolution
  // (`resolveDirectSCAOrigin`, gated on `isDirect`) and are not part of this
  // limitation.
  //
  // Net effect: because `unpinned_dep`/`no_lockfile` findings are a category
  // error rather than a deferral, `--assurance strict` will fail on nearly
  // any real project that has a `package.json` (or equivalent manifest)
  // today — an unpinned or unlocked dependency is common, and this check has
  // no way to ever resolve one. This is a known, disclosed limitation of the
  // current implementation, not a bug, and it is not something this check
  // should route around: exempting these finding types from the strict-mode
  // gate was considered and deliberately deferred to a future milestone
  // rather than done here, so strict mode keeps refusing to vouch for
  // provenance it cannot actually speak to.
  const badProvenance = (Array.isArray(findings) ? findings : []).filter((f) => !(0,_posture_provenance_schema_js__WEBPACK_IMPORTED_MODULE_0__/* .isProvenanceHealthy */ .lL)(f?.findingProvenance));
  if (badProvenance.length > 0) {
    return {
      ok: false,
      mode: 'strict',
      reason: `strict mode requires complete finding provenance; ${badProvenance.length} finding(s) have status outside [complete, uncommitted]`,
      conditions,
    };
  }

  return { ok: true, mode: 'strict', reason: null, conditions };
}

const _internals = { _isValidMode };


/***/ })

};
