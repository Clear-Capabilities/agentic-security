// Strategic metrics: three numbers a scan, its findings and its fix attempts already carry the inputs for, each reported with its numerator
// and denominator and the basis it was counted on. Pure: no fs, no clock.
//
//   Assurance Coverage       of the analysis the scan was asked to do, how much finished (scanHealth files and analyzers)
//   Evidence Conversion      of the findings, how many reached an evidence state stronger than one analyzer's say-so
//   Verified Remediation     of the fix attempts, how many reached the strongest verification tier
//
// A fourth, the Security Learning Rate, is reported as not measured: nothing measures it independently of the rule compiler's own corpus.
//
// The rules that keep these honest:
//   - a figure never appears without its numerator and denominator, and an empty denominator is `null`, not 0% or 100%;
//   - a quantity the scan did not report (`expected: null`) makes that component `unmeasured`, never zero;
//   - the headline of Assurance Coverage is the LOWER of its two components, so a complete analyzer set cannot hide unread files;
//   - Evidence Conversion counts a state only when its evidence is present on the finding, and names the state each finding reached;
//   - Verified Remediation is a lower bound where the strongest tier does not apply to a class, and says so.

export const STRATEGIC_METRICS_SCHEMA = 'agentic-security/strategic-metrics';
export const STRATEGIC_METRICS_VERSION = 1;

/** Evidence states, weakest first. A finding is counted at the strongest state it has evidence for. */
export const EVIDENCE_STATES = Object.freeze(['single-signal', 'corroborated', 'taint-confirmed', 'execution-proven']);

const rate = (n, d) => ({ numerator: n, denominator: d, percent: d > 0 ? Math.round((n / d) * 1000) / 10 : null });
const isNum = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

/** Of the analysis requested, how much finished. `scanHealth` is the scan's own record. */
export function assuranceCoverage(scanHealth) {
  if (!scanHealth || typeof scanHealth !== 'object') {
    return { status: 'unmeasured', reason: 'the scan carries no scan health record', files: null, analyzers: null, percent: null, scanStatus: null };
  }
  const f = scanHealth.files || {};
  const a = scanHealth.analyzers || {};
  const files = isNum(f.expected) && isNum(f.scanned)
    ? { ...rate(Math.max(0, Math.min(f.scanned, f.expected) - (isNum(f.timedOut) ? f.timedOut : 0)), f.expected), skipped: isNum(f.skipped) ? f.skipped : 0, unanalysed: isNum(f.unanalysed) ? f.unanalysed : 0, timedOut: isNum(f.timedOut) ? f.timedOut : 0 }
    : null;
  const analyzers = isNum(a.expected) && isNum(a.completed)
    ? { ...rate(Math.min(a.completed, a.expected), a.expected), failed: isNum(a.failed) ? a.failed : 0, timedOut: isNum(a.timedOut) ? a.timedOut : 0, skippedByPolicy: isNum(a.skippedByPolicy) ? a.skippedByPolicy : 0 }
    : null;
  const parts = [files, analyzers].filter((p) => p && p.percent !== null);
  const percent = parts.length ? Math.min(...parts.map((p) => p.percent)) : null;
  const missing = [!files && 'files', !analyzers && 'analyzers'].filter(Boolean);
  return {
    status: parts.length === 2 ? 'measured' : parts.length === 1 ? 'partial' : 'unmeasured',
    ...(missing.length ? { reason: `the scan did not report the expected count for: ${missing.join(', ')}` } : {}),
    files, analyzers, percent, scanStatus: typeof scanHealth.status === 'string' ? scanHealth.status : null,
  };
}

/** The strongest evidence state a finding has evidence for. */
export function evidenceStateOf(f) {
  if (!f || typeof f !== 'object') return 'single-signal';
  const proof = f.proof && typeof f.proof.verdict === 'string' ? f.proof.verdict : null;
  if (f.proofTier === 'execution-proven' || (proof && /^(proven|confirmed|exploit-confirmed|still-exploitable)$/i.test(proof))) return 'execution-proven';
  if (f.parser === 'IR-TAINT' || f.proofTier === 'taint-proven' || f.proofTier === 'taint-confirmed') return 'taint-confirmed';
  const by = f.corroboration && Array.isArray(f.corroboration.by) ? new Set(f.corroboration.by).size : (Number(f.corroborationCount) || 0);
  if (by >= 2) return 'corroborated';
  return 'single-signal';
}

/** Of the findings, how many reached a state stronger than one analyzer's say-so. */
export function evidenceConversion(findings) {
  const list = Array.isArray(findings) ? findings.filter((f) => f && typeof f === 'object') : [];
  const byState = Object.fromEntries(EVIDENCE_STATES.map((s) => [s, 0]));
  for (const f of list) byState[evidenceStateOf(f)]++;
  const converted = list.length - byState['single-signal'];
  return { ...rate(converted, list.length), byState, basis: 'findings that reached corroborated or stronger, over all findings' };
}

const strongest = (a) => {
  if (typeof a.verifiedFull === 'boolean') return a.verifiedFull;
  const disappeared = a.rescanOk === true || (a.ok === true && a.rescanOk !== false);
  return disappeared && a.testsRan === true && a.testsOk !== false && a.pocOk === true;
};

/** Of the fix attempts, how many reached the strongest verification tier. A lower bound: some classes have no independent proof to run. */
export function verifiedRemediationRate(attempts) {
  const list = Array.isArray(attempts) ? attempts.filter((a) => a && typeof a === 'object') : [];
  const full = list.filter(strongest).length;
  const disappearedOnly = list.filter((a) => typeof a.verifiedFull !== 'boolean' && (a.rescanOk === true || (a.ok === true && a.rescanOk !== false)) && !(a.testsRan === true && a.testsOk !== false) && a.pocOk !== true).length;
  return {
    ...rate(full, list.length),
    disappearedOnly,
    basis: 'attempts that passed the re-scan, the project tests and the independent attack replay, over all attempts. A lower bound where a class has no replay',
  };
}

/** Nothing measures it independently of the rule compiler's own corpus, so it is reported as not measured. */
export function securityLearningRate() {
  return { status: 'not-measured', reason: 'the rule compiler grades its rules against a corpus built from the same finding; no independent measurement of novel weaknesses converted into reusable knowledge exists' };
}

/**
 * @param {object} o
 * @param {object} [o.scan] a scan result (`scanHealth`, `findings`)
 * @param {object[]} [o.fixAttempts] fix verification attempts
 */
export function computeStrategicMetrics({ scan = null, fixAttempts = [] } = {}) {
  return {
    schema: STRATEGIC_METRICS_SCHEMA, version: STRATEGIC_METRICS_VERSION,
    assuranceCoverage: assuranceCoverage(scan && scan.scanHealth),
    evidenceConversion: evidenceConversion(scan && scan.findings),
    verifiedRemediationRate: verifiedRemediationRate(fixAttempts),
    securityLearningRate: securityLearningRate(),
  };
}

const pc = (r) => (r && r.percent !== null && r.percent !== undefined ? `${r.percent}%` : 'not measurable');

export function renderStrategicMetrics(m) {
  const ac = m.assuranceCoverage; const ec = m.evidenceConversion; const vr = m.verifiedRemediationRate;
  const L = [];
  L.push(`Assurance Coverage: ${ac.percent === null ? 'not measurable' : `${ac.percent}% (the lower of the two components)`}${ac.scanStatus ? `; scan ${ac.scanStatus}` : ''}`);
  if (ac.files) L.push(`  files: ${ac.files.numerator} of ${ac.files.denominator} completed (${pc(ac.files)}); ${ac.files.skipped} skipped, ${ac.files.unanalysed} not analysed, ${ac.files.timedOut} timed out`);
  if (ac.analyzers) L.push(`  analyzers: ${ac.analyzers.numerator} of ${ac.analyzers.denominator} completed (${pc(ac.analyzers)}); ${ac.analyzers.failed} failed, ${ac.analyzers.timedOut} timed out`);
  if (ac.reason) L.push(`  ${ac.reason}`);
  L.push(`Evidence Conversion: ${ec.numerator} of ${ec.denominator} findings reached corroborated or stronger (${pc(ec)})`);
  L.push(`  ${EVIDENCE_STATES.map((s) => `${s} ${ec.byState[s]}`).join(', ')}`);
  L.push(`Verified Remediation Rate: ${vr.numerator} of ${vr.denominator} fix attempts reached the strongest verification tier (${pc(vr)})${vr.denominator ? '; a lower bound where a class has no attack replay' : ''}`);
  if (vr.disappearedOnly) L.push(`  ${vr.disappearedOnly} satisfied only the re-scan, which is also what deleting the code produces`);
  L.push(`Security Learning Rate: not measured. ${m.securityLearningRate.reason}`);
  return L.join('\n');
}
