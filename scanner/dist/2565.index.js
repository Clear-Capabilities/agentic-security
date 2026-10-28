export const id = 2565;
export const ids = [2565];
export const modules = {

/***/ 32565:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   assessFrameworkTruth: () => (/* binding */ assessFrameworkTruth)
/* harmony export */ });
/* unused harmony exports TRUTH_STATES, classifyControl */
// The compliance truth model (E7-04): what can honestly be said about each control of a framework, in six states, with the denominators beside them.
//
// The framework evaluators (`auditor-walkthrough.js#evaluateFramework` and the privacy one) already refuse to call an unexamined bucket evidence, and the OSCAL
// export already refuses to invent a verdict for a control nobody decided. This module states the rules once, for any evaluator's rows, so that a report cannot
// say more than the evidence allows and a reader can see how much of the framework was actually looked at.
//
//   assessed_satisfied      every automated signal the control needs ran, cleared, on a complete scan, and the control is one the scanner can decide alone
//   assessed_not_satisfied  at least one signal found an open problem the finding list attributes to this control. A failure is conclusive even when the rest of
//                           the scan was incomplete
//   not_assessed            nothing looked: the control is rated checkable by its publisher but this tool has no check for it, or the evaluator reported a status
//                           this module does not recognise
//   not_applicable          someone with the authority declared it so, with a reason; the tool never infers this
//   requires_human_review   the control needs a person: no automated mapping and not code-testable, or the automated signals cleared but the control also needs
//                           organisational evidence, or a single scanner signal stands for an obligation wider than one check
//   insufficient_evidence   signals exist but cannot carry a verdict: the scan was incomplete or examined nothing, a mapping is unverifiable, or the evidence is weak
//
// NEVER claimed: that the system complies with the framework. `frameworkClaim.established` is false unless every applicable control is assessed_satisfied, and
// even then the statement is about the automated signals, not about compliance. One SAST family clearing never satisfies a control the publisher rates only
// partly or not at all checkable by code.
const TRUTH_STATES = Object.freeze(['assessed_satisfied', 'assessed_not_satisfied', 'not_assessed', 'not_applicable', 'requires_human_review', 'insufficient_evidence']);

/**
 * @param {{control:object, status:string, observations?:string[], controlRefs?:any[], evidence?:{tier?:string}, partiallyEvidenced?:boolean}} row one row of an evaluator
 * @param {{scanStatus?:string, scanExaminedFiles?:boolean, notApplicable?:Object<string,{reason:string, declaredBy:string}>}} ctx
 * @returns {{state:string, reasons:string[]}}
 */
function classifyControl(row, ctx = {}) {
  const c = (row && row.control) || {};
  const id = c.id;
  const reasons = [];
  const na = ctx.notApplicable && id !== undefined ? ctx.notApplicable[id] : null;
  if (na) {
    if (!na.reason || !na.declaredBy) return { state: 'insufficient_evidence', reasons: ['a not-applicable declaration needs a reason and a person who declared it; this one has neither, so it is not honoured'] };
    return { state: 'not_applicable', reasons: [`declared not applicable by ${na.declaredBy}: ${na.reason}`] };
  }
  const testable = c.codeTestable;                 // 'yes' | 'partial' | 'no' | undefined
  const status = row && row.status;
  const maps = Array.isArray(c.mapsTo) ? c.mapsTo : [];
  const scanComplete = ctx.scanStatus === 'complete';

  if (status === 'manual') {
    if (testable === 'yes' || testable === 'partial') return { state: 'not_assessed', reasons: ['the publisher rates this control as checkable by code (at least in part) but this tool implements no check for it: a gap in the tool, not a finding about the system'] };
    return { state: 'requires_human_review', reasons: ['no automated mapping, and the control is not code-testable: it needs a person'] };
  }
  if (!['present', 'partial', 'absent'].includes(status)) return { state: 'not_assessed', reasons: [`the evaluator reported status ${JSON.stringify(status)}, which this model does not recognise, so no verdict is made`] };

  const attributable = Array.isArray(row.controlRefs) && row.controlRefs.length > 0;
  if (status === 'absent' || (status === 'partial' && attributable)) {
    return { state: 'assessed_not_satisfied', reasons: [attributable ? `${row.controlRefs.length} open finding(s) are attributed to this control` : 'signals exist for this control and none cleared'] };
  }
  if (status === 'partial') return { state: 'insufficient_evidence', reasons: ['no open finding is attributed to this control, but a mapped signal could not be verified, so a clean result is not evidence'] };

  // status === 'present': every mapped signal cleared. What else has to be true before that is a verdict?
  if (ctx.scanExaminedFiles === false) return { state: 'insufficient_evidence', reasons: ['the scan examined no files, so an empty finding list is not evidence'] };
  if (!scanComplete) return { state: 'insufficient_evidence', reasons: [`the scan was ${JSON.stringify(ctx.scanStatus ?? 'unknown')}, not complete: a signal that cleared may not have looked everywhere`] };
  if (row.partiallyEvidenced || (row.evidence && ['weak', 'unmeasured'].includes(row.evidence.tier))) return { state: 'insufficient_evidence', reasons: [`the evidence behind the signals is rated ${JSON.stringify(row.evidence && row.evidence.tier)}`] };
  if (testable === 'no') return { state: 'requires_human_review', reasons: ['the automated signals cleared, but the publisher rates this control as not code-testable: they cannot decide it'] };
  if (testable === 'partial') return { state: 'requires_human_review', reasons: ['the automated signals cleared, but the publisher rates this control as only partly code-testable: the rest needs organisational evidence'] };
  if (maps.length === 1 && testable !== 'yes') return { state: 'requires_human_review', reasons: ['a single scanner signal stands for this obligation and the control is not rated fully code-testable'] };
  reasons.push(`${Math.max(maps.length, 1)} automated signal(s) cleared on a complete scan, and the control is rated code-testable`);
  return { state: 'assessed_satisfied', reasons };
}

/**
 * Classify every control of a framework and state the denominators.
 * @returns {{frameworkId:string|null, controls:object[], denominators:object, frameworkClaim:object}}
 */
function assessFrameworkTruth(framework, rows, ctx = {}) {
  const controls = (rows || []).map((r) => {
    const t = classifyControl(r, ctx);
    return { id: r && r.control ? r.control.id : null, title: r && r.control ? (r.control.summary || r.control.title || '') : '', state: t.state, reasons: t.reasons, codeTestable: r && r.control ? r.control.codeTestable ?? null : null, evaluatorStatus: r ? r.status : null, observations: (r && r.observations) || [] };
  });
  const by = Object.fromEntries(TRUTH_STATES.map((s) => [s, controls.filter((c) => c.state === s).length]));
  const total = controls.length;
  const applicable = total - by.not_applicable;
  const assessed = by.assessed_satisfied + by.assessed_not_satisfied;
  const declared = framework && Number.isInteger(framework.controlCount) ? framework.controlCount : null;
  const denominators = {
    declaredControls: declared, evaluatedControls: total, unevaluatedControls: declared === null ? null : Math.max(0, declared - total),
    applicable, byState: by,
    assessed, assessedOfApplicable: applicable === 0 ? null : Number((assessed / applicable).toFixed(4)),
    satisfied: by.assessed_satisfied, satisfiedOfApplicable: applicable === 0 ? null : Number((by.assessed_satisfied / applicable).toFixed(4)),
    needAPersonOrMoreEvidence: by.requires_human_review + by.insufficient_evidence + by.not_assessed,
  };
  const everyApplicableSatisfied = applicable > 0 && by.assessed_satisfied === applicable;
  const frameworkClaim = {
    established: false,
    statement: everyApplicableSatisfied
      ? 'Every applicable control this tool can decide was satisfied by its automated signals. That is a statement about those signals; it is not a statement that the system complies with the framework.'
      : `This tool assessed ${assessed} of ${applicable} applicable controls from automated signals (${by.assessed_satisfied} satisfied, ${by.assessed_not_satisfied} not satisfied); ${denominators.needAPersonOrMoreEvidence} need a person or more evidence. It does not establish compliance with the framework.`,
    reasons: [
      ...(by.assessed_not_satisfied ? [`${by.assessed_not_satisfied} control(s) are not satisfied`] : []),
      ...(by.requires_human_review ? [`${by.requires_human_review} control(s) require human review`] : []),
      ...(by.insufficient_evidence ? [`${by.insufficient_evidence} control(s) have insufficient evidence`] : []),
      ...(by.not_assessed ? [`${by.not_assessed} control(s) were not assessed`] : []),
      ...(denominators.unevaluatedControls ? [`${denominators.unevaluatedControls} control(s) of the framework were not evaluated at all`] : []),
    ],
  };
  return { frameworkId: framework && framework.id ? framework.id : null, controls, denominators, frameworkClaim };
}


/***/ })

};
