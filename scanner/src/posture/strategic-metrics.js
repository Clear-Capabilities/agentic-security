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
  return { status: list.length ? 'measured' : 'unmeasured', ...rate(converted, list.length), byState, basis: 'findings that reached corroborated or stronger, over all findings of the last scan' };
}

const strongest = (a) => {
  if (typeof a.verifiedFull === 'boolean') return a.verifiedFull;
  const disappeared = a.rescanOk === true || (a.ok === true && a.rescanOk !== false);
  return disappeared && a.testsRan === true && a.testsOk !== false && a.pocOk === true;
};

const isoOrNull = (v) => (typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? v : null);

/**
 * One attempt per finding (GA-11): a fix tried five times is one remediation, not five, so the LATEST recorded attempt for each
 * finding id is the one counted and the earlier ones are reported as `repeated`. An attempt with no finding id cannot be matched to
 * another and counts on its own. Order is by `at` where every record has one, else by position in the log.
 */
function dedupeAttempts(attempts) {
  const list = Array.isArray(attempts) ? attempts.filter((a) => a && typeof a === 'object') : [];
  const latest = new Map();
  const loose = [];
  list.forEach((a, i) => {
    const key = typeof a.stableId === 'string' && a.stableId ? a.stableId : (typeof a.findingId === 'string' && a.findingId ? a.findingId : null);
    if (!key) { loose.push(a); return; }
    const prev = latest.get(key);
    const newer = !prev || (isoOrNull(a.at) && isoOrNull(prev.at) ? Date.parse(a.at) >= Date.parse(prev.at) : i > prev._i);
    if (newer) latest.set(key, Object.assign(Object.create(null), a, { _i: i }));
  });
  const kept = [...latest.values()].map((a) => { const { _i, ...rest } = a; return rest; }).concat(loose);
  return { attempts: kept, recorded: list.length, repeated: list.length - kept.length };
}

/** The time span the recorded attempts cover: `from` and `to` are the earliest and latest `at`, or `null` when none carries one. */
function attemptsWindow(attempts) {
  const times = (Array.isArray(attempts) ? attempts : []).map((a) => a && isoOrNull(a.at)).filter(Boolean).sort();
  return { from: times[0] ?? null, to: times[times.length - 1] ?? null };
}

/** Of the fix attempts, how many reached the strongest verification tier. A lower bound: some classes have no independent proof to run. */
export function verifiedRemediationRate(attempts) {
  const { attempts: list, recorded, repeated } = dedupeAttempts(attempts);
  const full = list.filter(strongest).length;
  const disappearedOnly = list.filter((a) => typeof a.verifiedFull !== 'boolean' && (a.rescanOk === true || (a.ok === true && a.rescanOk !== false)) && !(a.testsRan === true && a.testsOk !== false) && a.pocOk !== true).length;
  const failed = list.filter((a) => a.ok === false || a.verifiedFull === false).length;
  return {
    status: list.length ? 'measured' : 'unmeasured',
    ...rate(full, list.length),
    recorded, repeated, failed, disappearedOnly,
    window: attemptsWindow(attempts),
    basis: 'the latest attempt per finding that passed the re-scan, the project tests and the independent attack replay, over the latest attempt per finding. A lower bound where a class has no replay',
  };
}

/** Nothing measures it independently of the rule compiler's own corpus, so it is reported as unmeasured, with the reason. */
export function securityLearningRate() {
  return { status: 'unmeasured', reason: 'the rule compiler grades its rules against a corpus built from the same finding and the reviewer-supplied independent examples; no independent longitudinal measurement of novel weaknesses converted into reusable knowledge exists' };
}

/**
 * @param {object} o
 * @param {object} [o.scan] a scan result (`scanHealth`, `findings`)
 * @param {object[]} [o.fixAttempts] fix verification attempts
 */
export function computeStrategicMetrics({ scan = null, fixAttempts = [] } = {}) {
  const attempts = Array.isArray(fixAttempts) ? fixAttempts : [];
  return {
    schema: STRATEGIC_METRICS_SCHEMA, version: STRATEGIC_METRICS_VERSION,
    // The scope and time basis (GA-11): these are per-scan figures for ONE scan plus the attempts recorded on this machine, never an
    // organisation trend. The scan is named by its id and start time; the attempts by the span their timestamps cover.
    scope: {
      kind: 'per-scan',
      scanId: scan && typeof scan.scanId === 'string' ? scan.scanId : null,
      scanStartedAt: scan ? isoOrNull(scan.startedAt) : null,
      attempts: { ...attemptsWindow(attempts), recorded: attempts.filter((a) => a && typeof a === 'object').length },
      trend: 'not a trend: one scan and this machine\'s recorded attempts; compare scans by scanId to see movement',
    },
    assuranceCoverage: assuranceCoverage(scan && scan.scanHealth),
    evidenceConversion: evidenceConversion(scan && scan.findings),
    verifiedRemediationRate: verifiedRemediationRate(attempts),
    securityLearningRate: securityLearningRate(),
  };
}

const pc = (r) => (r && r.percent !== null && r.percent !== undefined ? `${r.percent}%` : 'not measurable');

export function renderStrategicMetrics(m) {
  const ac = m.assuranceCoverage; const ec = m.evidenceConversion; const vr = m.verifiedRemediationRate;
  const L = [];
  if (m.scope) L.push(`Scope: one scan${m.scope.scanId ? ` (${m.scope.scanId}${m.scope.scanStartedAt ? `, started ${m.scope.scanStartedAt}` : ''})` : ''} and ${m.scope.attempts.recorded} fix attempt(s) recorded on this machine${m.scope.attempts.from ? ` between ${m.scope.attempts.from} and ${m.scope.attempts.to}` : ''}; not a trend`);
  L.push(`Assurance Coverage: ${ac.percent === null ? 'not measurable' : `${ac.percent}% (the lower of the two components)`}${ac.scanStatus ? `; scan ${ac.scanStatus}` : ''}`);
  if (ac.files) L.push(`  files: ${ac.files.numerator} of ${ac.files.denominator} completed (${pc(ac.files)}); ${ac.files.skipped} skipped, ${ac.files.unanalysed} not analysed, ${ac.files.timedOut} timed out`);
  if (ac.analyzers) L.push(`  analyzers: ${ac.analyzers.numerator} of ${ac.analyzers.denominator} completed (${pc(ac.analyzers)}); ${ac.analyzers.failed} failed, ${ac.analyzers.timedOut} timed out`);
  if (ac.reason) L.push(`  ${ac.reason}`);
  L.push(`Evidence Conversion: ${ec.numerator} of ${ec.denominator} findings reached corroborated or stronger (${pc(ec)})`);
  L.push(`  ${EVIDENCE_STATES.map((s) => `${s} ${ec.byState[s]}`).join(', ')}`);
  L.push(`Verified Remediation Rate: ${vr.numerator} of ${vr.denominator} fix attempts reached the strongest verification tier (${pc(vr)})${vr.denominator ? '; a lower bound where a class has no attack replay' : ''}`);
  if (vr.disappearedOnly) L.push(`  ${vr.disappearedOnly} satisfied only the re-scan, which is also what deleting the code produces`);
  if (vr.repeated) L.push(`  ${vr.recorded} attempt(s) recorded; ${vr.repeated} earlier attempt(s) on the same finding counted once, by the latest`);
  L.push(`Security Learning Rate: not measured. ${m.securityLearningRate.reason}`);
  return L.join('\n');
}
