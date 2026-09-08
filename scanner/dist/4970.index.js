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

// A real user hit this: `agentic-security ci <a directory downloaded as a
// GitHub zip, no .git present> --assurance strict` failed with the bare
// count this function used to produce alone — "1210 finding(s) have status
// outside [complete, uncommitted]" — with no indication that all 1210
// findings failed for the exact same, simple, fixable reason
// (`coordinator.js`'s `annotateGitProvenance` already knows and records it,
// in `finding.findingProvenance.limitations[0]`, but that reason never
// reached this message). A user reading "1210 problems" reasonably assumes
// their CODE has 1210 problems, not that their DIRECTORY isn't a git
// repository. This surfaces the dominant recorded reason instead of a bare
// count, and gives the two most common, fully-fixable reasons ("not a Git
// repository" from a zip download instead of `git clone`; a shallow CI
// checkout) a one-line, specific remedy — the same specificity the
// scanHealth branch above already gives for a stale-EPSS-cache failure.
function _provenanceFailureReason(badProvenance, totalFindings) {
  const counts = new Map();
  for (const f of badProvenance) {
    const reason = f?.findingProvenance?.limitations?.[0] || f?.findingProvenance?.status || 'unknown';
    counts.set(reason, (counts.get(reason) || 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const base = `strict mode requires complete finding provenance; ${badProvenance.length}/${totalFindings} finding(s) have status outside [complete, uncommitted]`;

  const gitReasons = ranked.filter(([r]) => r === 'not a Git repository' || r === 'repository state unavailable');
  const gitCount = gitReasons.reduce((s, [, n]) => s + n, 0);
  // engine.js's own comment on this branch: "unpinned_dep / no_lockfile...
  // describe the ABSENCE of a declaration, so 'which commit introduced this
  // version' is not a question that has an answer to defer ... this is a
  // known, disclosed limitation, not a bug... strict mode WILL fail on
  // nearly any real project that has a package.json." That disclosure lived
  // only in a source comment nobody hits this error reads — the README's
  // own quickstart explicitly invites pointing --assurance strict at "your
  // own project," where this is the single most likely outcome. Named here
  // so the person who hits it learns it is expected and permanent, not
  // something to keep investigating. This prefix is deliberately narrower
  // than "every non-vulnerable_dep supply-chain entry" — engine.js's
  // provenance-stamping loop only uses it for unpinned_dep/no_lockfile,
  // which genuinely have no origin commit; cdn_no_integrity/dynamic_require
  // carry a real file:line and get a DIFFERENT string precisely so they
  // never land in this "permanent, give up" bucket (adversarial premortem
  // R2, 2026-09-07 — conflating the two told a user a resolvable coverage
  // gap was an unfixable, by-design limitation).
  const supplyChainReasons = ranked.filter(([r]) => r.startsWith('origin resolution does not apply to a'));
  const supplyChainCount = supplyChainReasons.reduce((s, [, n]) => s + n, 0);
  // Third known bucket (S1, adversarial premortem third pass, 2026-09-07):
  // cdn_no_integrity/dynamic_require's "not yet wired" string (see the
  // engine.js comment this file's `supplyChainReasons` block already
  // references) was previously falling through to the generic `otherReasons`
  // path below — honest, but verbose, and with no recommended next step,
  // unlike every other named bucket here. Giving it its own bucket closes
  // that inconsistency without touching the two already-fixed buckets.
  const notYetWiredReasons = ranked.filter(([r]) => r.startsWith('origin resolution is not yet wired for a'));
  const notYetWiredCount = notYetWiredReasons.reduce((s, [, n]) => s + n, 0);
  const knownReasonSet = new Set([...gitReasons, ...supplyChainReasons, ...notYetWiredReasons].map(([r]) => r));
  const otherReasons = ranked.filter(([r]) => !knownReasonSet.has(r));
  const otherCount = badProvenance.length - gitCount - supplyChainCount - notYetWiredCount;
  const knownCategoryCount = (gitCount > 0 ? 1 : 0) + (supplyChainCount > 0 ? 1 : 0) + (notYetWiredCount > 0 ? 1 : 0);

  // Exactly one KNOWN category, and nothing outside it — the shape every
  // caller before this fix assumed was the only shape, and the one every
  // existing test was written against. Kept as tight, single-topic prose
  // rather than the multi-segment form below.
  if (knownCategoryCount === 0) {
    if (otherReasons.length === 1) {
      return `${base} — all ${badProvenance.length} share the same reason: "${otherReasons[0][0]}".`;
    }
    const breakdown = otherReasons.slice(0, 5).map(([reason, n]) => `${n}× "${reason}"`).join(', ');
    return `${base} — breakdown: ${breakdown}${otherReasons.length > 5 ? ', …' : ''}.`;
  }
  if (knownCategoryCount === 1 && otherCount === 0) {
    if (gitCount > 0) {
      const gitReasonNames = gitReasons.map(([r]) => `"${r}"`).join(' and ');
      return `${base} — reason: ${gitCount === badProvenance.length ? 'all of them are' : `${gitCount} of them are`} ${gitReasonNames}. ` +
        `strict mode resolves finding provenance from git history, so it requires a real git repository ` +
        `(a GitHub "Download ZIP" extracts without one). Run \`git init && git add -A && git commit -m init\` in ` +
        `the scanned directory, point the scan at a real \`git clone\`, or drop --assurance strict for standard/advisory.`;
    }
    if (supplyChainCount > 0) {
      return `${base} — ${supplyChainCount} of them describe an ABSENT dependency declaration ` +
        `(an unpinned version, a missing lockfile) that has no origin commit to resolve, by design. This is a ` +
        `known, permanent limitation: strict mode cannot pass while any are present, on any real project with ` +
        `such a dependency. Fix the underlying SCA finding(s) (pin the version / add a lockfile) if you want ` +
        `strict to pass, or use --assurance standard/advisory for a project you don't control the dependencies of.`;
    }
    return `${base} — ${notYetWiredCount} of them point at a real source location (a CDN script tag, a dynamic ` +
      `require) this engine can't yet trace back to the commit that introduced it — unlike the ABSENT-declaration ` +
      `case above, this is an ordinary coverage gap, not a permanent limitation, but it isn't fixable from your ` +
      `side either. Use --assurance standard/advisory if you need this scan to pass today.`;
  }

  // Two or more independently-blocking categories on the SAME scan — the
  // defect this closes (adversarial premortem R1, 2026-09-07): the old
  // code picked whichever category had the most findings and silently
  // dropped every other one, so a user could "fix" the reported problem,
  // rerun, and hit a second wall the first run already had full information
  // about but never mentioned — the same "the tool knew and didn't tell me"
  // complaint this whole function exists to fix, recurring in a milder form.
  //
  // Rendered as a bulleted, newline-separated list rather than one
  // semicolon-joined paragraph (S2, adversarial premortem third pass,
  // 2026-09-07) — each bullet is independently actionable, and a wall of
  // clauses buried the fact that they are SEPARATE problems, each with its
  // own fix, rather than one problem described three ways.
  const segments = [];
  if (gitCount > 0) {
    const gitReasonNames = gitReasons.map(([r]) => `"${r}"`).join(' and ');
    segments.push(`${gitCount} of them are ${gitReasonNames} — strict mode requires a real git repository; ` +
      `run \`git init && git add -A && git commit\`, or scan a real \`git clone\`.`);
  }
  if (supplyChainCount > 0) {
    segments.push(`${supplyChainCount} of them describe an ABSENT dependency declaration (unpinned version / ` +
      `missing lockfile) with no origin commit to resolve — a known, permanent limitation, not something a ` +
      `rerun will fix.`);
  }
  if (notYetWiredCount > 0) {
    segments.push(`${notYetWiredCount} of them point at a real source location this engine can't yet trace ` +
      `back to a commit — an ordinary coverage gap, not a permanent limitation, but not fixable from your side.`);
  }
  if (otherCount > 0) {
    if (otherReasons.length === 1) {
      segments.push(`${otherCount} share the reason "${otherReasons[0][0]}".`);
    } else {
      const breakdown = otherReasons.slice(0, 5).map(([reason, n]) => `${n}× "${reason}"`).join(', ');
      segments.push(`${otherCount} break down as: ${breakdown}${otherReasons.length > 5 ? ', …' : ''}.`);
    }
  }
  const bullets = segments.map((s) => `  - ${s}`).join('\n');
  return `${base} — MULTIPLE distinct reasons, not just one:\n${bullets}\nEvery category above must be ` +
    `resolved for strict to pass (or drop to --assurance standard/advisory) — fixing only one will surface the ` +
    `next on your following run.`;
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
      reason: _provenanceFailureReason(badProvenance, findings.length),
      conditions,
    };
  }

  return { ok: true, mode: 'strict', reason: null, conditions };
}

const _internals = { _isValidMode, _provenanceFailureReason };


/***/ })

};
