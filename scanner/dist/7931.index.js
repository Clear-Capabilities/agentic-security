export const id = 7931;
export const ids = [7931];
export const modules = {

/***/ 86067:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   D: () => (/* binding */ releaseVerdict),
/* harmony export */   s: () => (/* binding */ verifyStatedVerdict)
/* harmony export */ });
// The release verdict (E7-08): a deterministic function from a release package to one of three answers, with every reason in plain words.
//
//   not_deployable   a condition the policy treats as blocking is present: an unfinished scan, files that were not scanned, an analyzer that timed out or failed,
//                    a fix that was claimed and not verified, an open finding that is proven exploitable, an open high or critical finding
//   needs_review     nothing blocks, but something is unknown and a person has to decide: a signal the context analysis could not settle, runtime evidence that
//                    came from a different build, a finding of unproven exploitability that is high or critical
//   deployable       none of the above. This is NOT a statement that the release is safe; it says no blocking or unknown condition was found in the evidence the package holds
//
// The word "safe" is never produced. The verdict is a function of the package alone (no clock, no environment), so the same package gives the same verdict and the same
// reasons in the same order, and a stated verdict that differs from the one recomputed here is refused (`verifyStatedVerdict`).
//
// WHAT COUNTS AS A BLOCKER is the policy below, not a judgement made per release. Waived findings (a waiver the package lists as honoured) do not block but are listed.
const SEV_BLOCK = new Set(['critical', 'high']);

const asArray = (v) => (Array.isArray(v) ? v : []);
const by = (pkg, kind) => asArray(pkg && pkg.evidence).filter((e) => e && e.ref && e.ref.kind === kind);

/**
 * @param {object} pkg a release package
 * @param {{waivedIds?:string[]}} [opts] finding ids covered by an honoured waiver
 * @returns {{verdict:'not_deployable'|'needs_review'|'deployable', blockers:{code:string, message:string, evidence:string[]}[], unknowns:{code:string, message:string, evidence:string[]}[], waived:string[], statement:string}}
 */
function releaseVerdict(pkg, { waivedIds = [] } = {}) {
  const blockers = []; const unknowns = [];
  const block = (code, message, evidence = []) => blockers.push({ code, message, evidence });
  const unk = (code, message, evidence = []) => unknowns.push({ code, message, evidence });
  const waived = new Set(waivedIds);

  // ---- the scan itself
  const health = by(pkg, 'scan-health')[0];
  if (!health) block('NO_SCAN_HEALTH', 'the package holds no scan health, so nothing says the scan finished');
  else {
    const h = health.payload || {}; const ev = [health.ref.digest];
    if (h.status !== 'complete') block('SCAN_INCOMPLETE', `the scan did not finish cleanly (status ${JSON.stringify(h.status ?? 'unknown')}): ${asArray(h.conditions).join('; ') || 'no reason was recorded'}`, ev);
    const f = h.files || {};
    if (Number.isFinite(f.expected) && Number.isFinite(f.scanned) && f.scanned < f.expected) block('FILES_NOT_SCANNED', `${f.expected - f.scanned} of ${f.expected} files were not scanned`, ev);
    else if (Number.isFinite(f.unanalysed) ? f.unanalysed > 0 : (Number.isFinite(f.skipped) && f.skipped > 0)) block('FILES_SKIPPED', `${Number.isFinite(f.unanalysed) ? f.unanalysed : f.skipped} file(s) were skipped (too large or too dense to analyse)`, ev);
    if (Number.isFinite(f.timedOut) && f.timedOut > 0) block('FILES_TIMED_OUT', `${f.timedOut} file(s) exceeded the per-file analysis time`, ev);
    const a = h.analyzers || {};
    if (Number.isFinite(a.timedOut) && a.timedOut > 0) block('ANALYZER_TIMED_OUT', `${a.timedOut} analyzer(s) timed out, so what they would have found is not in this result`, ev);
    if (Number.isFinite(a.failed) && a.failed > 0 && !(Number.isFinite(a.timedOut) && a.failed === a.timedOut)) block('ANALYZER_FAILED', `${a.failed} analyzer(s) failed, so what they would have found is not in this result`, ev);
    if (h.deepAnalysis && Array.isArray(h.deepAnalysis.incomplete) && h.deepAnalysis.incomplete.length) unk('DEEP_ANALYSIS_INCOMPLETE', `deep analysis stopped short: ${h.deepAnalysis.incomplete.map((x) => `${x.reason} x${x.count}`).join(', ')}`, ev);
  }

  // ---- findings and fixes
  const fixes = by(pkg, 'fix-verification');
  const fixFor = (id) => fixes.filter((x) => x.payload && (x.payload.findingStableId === id || x.payload.findingId === id));
  for (const e of by(pkg, 'finding')) {
    const f = e.payload || {}; const id = e.ref.payloadId || f.stableId || f.id; const ev = [e.ref.digest];
    const triage = f.triage && f.triage.state;
    const falsePositive = triage === 'false_positive' || f.falsePositive === true;
    const myFixes = fixFor(id); const fixed = myFixes.find((x) => x.payload.verifiedFull === true);
    if (waived.has(id)) continue;
    if (falsePositive) {
      if (!(f.triage && f.triage.by && f.triage.reason)) unk('FALSE_POSITIVE_UNJUSTIFIED', `finding ${id} is marked a false positive without a named person and a reason`, ev);
      continue;
    }
    for (const x of myFixes) if (x.payload.verifiedFull !== true) block('FIX_NOT_VERIFIED', `a fix for ${id} is claimed but was not fully verified (${asArray(x.payload.degradedLegs).map((d) => (typeof d === 'string' ? d : d && d.leg)).filter(Boolean).join(', ') || 'checks did not all pass'})`, [...ev, x.ref.digest]);
    if (fixed) continue;
    const sev = String(f.severity || 'info'); const tier = typeof f.proofTier === 'string' ? f.proofTier : 'unproven';
    const ci = f.contextIntelligence && (f.contextIntelligence.counterexample && f.contextIntelligence.counterexample.state || f.contextIntelligence.state);
    if (tier === 'execution-proven') block('PROVEN_OPEN_FINDING', `finding ${id} (${sev}) is proven exploitable and is open`, ev);
    else if (SEV_BLOCK.has(sev)) {
      if (ci === 'unresolved' || ci === 'plausible') unk('CONTEXT_SIGNAL_UNSETTLED', `finding ${id} (${sev}) rests on a context signal the analysis could not settle (${ci}); a person has to decide whether it is real`, ev);
      else block('OPEN_HIGH_FINDING', `finding ${id} is open at severity ${sev}`, ev);
    } else if (ci === 'unresolved' || ci === 'plausible') unk('CONTEXT_SIGNAL_UNSETTLED', `finding ${id} rests on a context signal the analysis could not settle (${ci})`, ev);
  }

  // ---- runtime evidence from another build
  for (const e of by(pkg, 'runtime-explanation')) {
    const edges = asArray(e.payload && e.payload.runtime && e.payload.runtime.edges); const bad = edges.filter((x) => Number(x.mismatchedRecords) > 0);
    if (bad.length) unk('RUNTIME_BUILD_MISMATCH', `runtime records for ${bad.length} edge(s) of ${e.ref.payloadId || 'a finding'} came from a different build than the one released, so they say nothing about this release and are not counted as corroboration`, [e.ref.digest]);
    const miss = asArray(e.payload && e.payload.runtime && e.payload.runtime.missingObservations);
    if (!bad.length && miss.length && e.payload.compare && e.payload.compare.state !== 'corroborated') unk('RUNTIME_NOT_CORROBORATED', `runtime evidence for ${e.ref.payloadId || 'a finding'} does not corroborate the path: ${miss[0]}`, [e.ref.digest]);
  }

  blockers.sort((a, b) => (a.code + a.message < b.code + b.message ? -1 : 1)); unknowns.sort((a, b) => (a.code + a.message < b.code + b.message ? -1 : 1));
  const verdict = blockers.length ? 'not_deployable' : unknowns.length ? 'needs_review' : 'deployable';
  const statement = verdict === 'deployable'
    ? 'No blocking or unknown condition was found in the evidence this package holds. That is not a statement that the release is safe.'
    : verdict === 'needs_review' ? `Nothing blocks the release, but ${unknowns.length} thing(s) are unknown and a person has to decide.` : `${blockers.length} condition(s) block the release.`;
  return { verdict, blockers, unknowns, waived: [...waived].sort(), statement };
}

/** Is the verdict a package states the one its own contents give? @returns {{ok:boolean, stated:string|null, computed:string, message:string|null}} */
function verifyStatedVerdict(pkg, opts) {
  const computed = releaseVerdict(pkg, opts).verdict;
  const decisions = asArray(pkg && pkg.policy && pkg.policy.decisions);
  const d = decisions.find((x) => x && x.id === 'release-verdict');
  const stated = d ? d.outcome : null;
  if (stated === null) return { ok: false, stated, computed, message: 'the package states no release verdict' };
  if (stated !== computed) return { ok: false, stated, computed, message: `the package states "${stated}" but its own contents give "${computed}"` };
  return { ok: true, stated, computed, message: null };
}


/***/ }),

/***/ 37931:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildViews: () => (/* binding */ buildViews),
/* harmony export */   renderHtml: () => (/* binding */ renderHtml),
/* harmony export */   renderText: () => (/* binding */ renderText)
/* harmony export */ });
/* unused harmony export buildCanonicalFindings */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var _posture_assurance_release_verdict_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(86067);
// Three views of one release (E7-07): what a developer needs, what a CISO needs, what an auditor needs, all built from the SAME canonical list of findings so they
// cannot disagree.
//
//   developer  where the problem is, why it is one, how to fix it, and whether a fix was verified
//   CISO       what is proven and what is not, what changed since the previous release, how risky and how complete
//   auditor    for each assertion and each unknown, the evidence it rests on (by digest) and why anything is unknown; the issuer and what the signature does not prove
//
// One list, three projections. `canonicalFindings` is computed once from the release package; every view only selects and arranges its fields, and each entry
// carries the same finding id, status, evidence hash and confidence wherever it appears. Nothing is recomputed per view.
//
// The package is DATA from a repository we do not control: every string is escaped before it reaches HTML, the page loads nothing from anywhere and runs no script, and a
// content security policy says so.



const esc = (v) => String(v ?? '').replace(/[&<>"'`]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function confidenceOf(f) {
  if (typeof f.confidence === 'number') return f.confidence >= 0.8 ? 'high' : f.confidence >= 0.5 ? 'medium' : 'low';
  return typeof f.confidenceTier === 'string' ? f.confidenceTier : 'unknown';
}

/**
 * @param {object} pkg a release package (E7-03). It is assumed to have been verified by the caller; the views carry `verification` as the caller states it.
 * @param {{previous?:object, ranking?:object, verification?:{ok:boolean, errors?:object[]}}} opts `previous` is the previous release's package; `ranking` is a result of rankFleetExposure
 */
function buildCanonicalFindings(pkg) {
  const entries = Array.isArray(pkg && pkg.evidence) ? pkg.evidence : [];
  const byKind = (k) => entries.filter((e) => e.ref && e.ref.kind === k);
  const fixes = byKind('fix-verification');
  const out = [];
  for (const e of byKind('finding')) {
    const f = e.payload || {};
    const id = e.ref.payloadId || f.stableId || f.id;
    const fixesFor = fixes.filter((x) => x.payload && (x.payload.findingStableId === id || x.payload.findingId === id || x.payload.findingId === f.id) );
    const fix = fixesFor.find((x) => x.payload.verifiedFull === true) || fixesFor[0] || null;
    const status = !fix ? 'open' : fix.payload.verifiedFull === true ? 'fix-verified' : 'fix-unverified';
    out.push({
      id, evidenceHash: e.ref.digest, status, confidence: confidenceOf(f), severity: f.severity || 'info', proofTier: typeof f.proofTier === 'string' ? f.proofTier : 'unproven',
      where: { file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null }, title: f.vuln || f.title || 'finding', cwe: f.cwe || null,
      why: f.description || f.reason || null, how: f.remediation || null,
      fix: fix ? { evidenceHash: fix.ref.digest, verifiedFull: fix.payload.verifiedFull === true, completeness: fix.payload.fixCompleteness || null, degradedLegs: Array.isArray(fix.payload.degradedLegs) ? fix.payload.degradedLegs.map((d) => (typeof d === 'string' ? d : d && d.leg) ).filter(Boolean) : [] } : null,
    });
  }
  return out.sort((a, b) => (sevRank[b.severity] - sevRank[a.severity]) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function buildViews(pkg, { previous = null, ranking = null, verification = null } = {}) {
  const findings = buildCanonicalFindings(pkg);
  const packageDigest = `sha256:${(0,node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash)('sha256').update(JSON.stringify(pkg && pkg.lineageOrder || [])).digest('hex')}`;
  const prev = previous ? buildCanonicalFindings(previous) : null;
  const prevById = prev ? new Map(prev.map((f) => [f.id, f])) : null;
  const ids = new Set(findings.map((f) => f.id));
  const change = prev ? {
    new: findings.filter((f) => !prevById.has(f.id)).map((f) => f.id),
    resolved: prev.filter((f) => !ids.has(f.id)).map((f) => f.id),
    statusChanged: findings.filter((f) => prevById.has(f.id) && prevById.get(f.id).status !== f.status).map((f) => ({ id: f.id, from: prevById.get(f.id).status, to: f.status })),
    unchanged: findings.filter((f) => prevById.has(f.id) && prevById.get(f.id).status === f.status).length,
  } : null;
  const rankById = ranking ? new Map(ranking.ranked.map((r) => [r.id, r])) : null;
  const tier = (t) => findings.filter((f) => f.proofTier === t).length;
  const completeness = pkg && pkg.completeness ? { verdict: pkg.completeness.verdict, scanStatus: pkg.completeness.scanStatus, conditions: pkg.completeness.conditions || [] } : { verdict: 'unknown', scanStatus: 'unknown', conditions: [] };
  const unknowns = [];
  if (completeness.verdict !== 'complete') for (const c of completeness.conditions.length ? completeness.conditions : ['the scan did not report that it finished']) unknowns.push({ about: 'scan completeness', reason: c, evidence: pkg.completeness && pkg.completeness.source ? [pkg.completeness.source] : [] });
  for (const a of (pkg && pkg.assertions) || []) if (a.status !== 'supported') unknowns.push({ about: a.text, reason: a.reason || `the assertion is ${a.status}`, evidence: a.evidence || [] });
  for (const f of findings) if (f.proofTier !== 'execution-proven') unknowns.push({ about: `exploitability of ${f.id}`, reason: `proof tier is ${f.proofTier}: it has not been shown to be exploitable`, evidence: [f.evidenceHash] });

  const developer = findings.map((f) => ({ id: f.id, evidenceHash: f.evidenceHash, status: f.status, confidence: f.confidence, severity: f.severity, where: f.where, why: f.why, how: f.how, title: f.title, cwe: f.cwe, fix: f.fix }));
  const verdict = (0,_posture_assurance_release_verdict_js__WEBPACK_IMPORTED_MODULE_1__/* .releaseVerdict */ .D)(pkg);
  const ciso = {
    verdict: { verdict: verdict.verdict, statement: verdict.statement, blockers: verdict.blockers.map((b) => b.message), unknowns: verdict.unknowns.map((u) => u.message) },
    verified: verification ? verification.ok === true : null,
    scan: completeness,
    proven: { executionProven: tier('execution-proven'), taintProven: tier('taint-proven'), unproven: findings.length - tier('execution-proven') - tier('taint-proven'), total: findings.length },
    bySeverity: Object.fromEntries(['critical', 'high', 'medium', 'low', 'info'].map((s) => [s, findings.filter((f) => f.severity === s).length])),
    fixes: { verified: findings.filter((f) => f.status === 'fix-verified').length, unverified: findings.filter((f) => f.status === 'fix-unverified').length, open: findings.filter((f) => f.status === 'open').length },
    changeSinceLast: change,
    risk: ranking ? { byPriority: ranking.summary.byPriority, incompleteCoverage: ranking.summary.incompleteCoverage, top: ranking.ranked.slice(0, 5).map((r) => ({ id: r.id, priority: r.priority, rule: r.rule })) } : null,
    findings: findings.map((f) => ({ id: f.id, evidenceHash: f.evidenceHash, status: f.status, confidence: f.confidence, severity: f.severity, proofTier: f.proofTier, priority: rankById && rankById.get(f.id) ? rankById.get(f.id).priority : null })),
  };
  const auditor = {
    package: { lineageDigest: packageDigest, snapshot: pkg && pkg.snapshot ? { commit: pkg.snapshot.commit, immutable: pkg.snapshot.immutable, digest: pkg.snapshot.digest } : null },
    issuer: pkg && pkg.issuance ? { trustBasis: pkg.issuance.trustBasis, independentlyCertified: pkg.issuance.independentlyCertified, keyFingerprint: pkg.issuance.issuer && pkg.issuance.issuer.keyFingerprint } : null,
    verification: verification ? { ok: verification.ok === true, errors: (verification.errors || []).map((e) => `${e.code}: ${e.message}`) } : { ok: null, errors: ['no verification was performed by this view'] },
    proves: pkg && pkg.proves || null, doesNotProve: pkg && pkg.doesNotProve || null,
    assertions: ((pkg && pkg.assertions) || []).map((a) => ({ id: a.id, text: a.text, status: a.status, evidence: a.evidence || [], reason: a.reason || null })),
    unknowns,
    findings: findings.map((f) => ({ id: f.id, evidenceHash: f.evidenceHash, status: f.status, confidence: f.confidence, proofTier: f.proofTier, fixEvidence: f.fix ? f.fix.evidenceHash : null })),
    policyDecisions: (pkg && pkg.policy && pkg.policy.decisions) || [],
  };
  return { canonical: findings, developer, ciso, auditor };
}

// ---- text ------------------------------------------------------------------------------------------------------------------------

function renderText(views, view = 'all') {
  const L = [];
  const dev = () => { L.push('DEVELOPER VIEW'); for (const f of views.developer) { L.push(`  [${f.severity}] ${f.title}  ${f.where.file ?? '?'}:${f.where.line ?? '?'}  id=${f.id}  status=${f.status}  confidence=${f.confidence}  evidence=${f.evidenceHash.slice(0, 19)}`); if (f.why) L.push(`      why: ${String(f.why).slice(0, 300)}`); if (f.how) L.push(`      fix: ${String(f.how).slice(0, 300)}`); if (f.fix) L.push(`      fix check: ${f.fix.verifiedFull ? 'verified' : 'not fully verified'}${f.fix.degradedLegs.length ? ` (not passed: ${f.fix.degradedLegs.join(', ')})` : ''}`); } if (!views.developer.length) L.push('  no findings'); };
  const ciso = () => { const c = views.ciso; L.push('CISO VIEW'); L.push(`  release verdict: ${c.verdict.verdict}. ${c.verdict.statement}`); for (const b of c.verdict.blockers) L.push(`    blocks: ${b}`); for (const u of c.verdict.unknowns) L.push(`    unknown: ${u}`); L.push(`  scan: ${c.scan.verdict} (${c.scan.scanStatus})${c.scan.conditions.length ? ' - ' + c.scan.conditions.join('; ') : ''}`); L.push(`  proven: ${c.proven.executionProven} executed, ${c.proven.taintProven} taint path, ${c.proven.unproven} unproven, of ${c.proven.total}`); L.push(`  fixes: ${c.fixes.verified} verified, ${c.fixes.unverified} unverified, ${c.fixes.open} open`); if (c.changeSinceLast) L.push(`  since last release: ${c.changeSinceLast.new.length} new, ${c.changeSinceLast.resolved.length} resolved, ${c.changeSinceLast.statusChanged.length} changed status`); else L.push('  since last release: no previous release was supplied'); if (c.risk) L.push(`  risk: ${JSON.stringify(c.risk.byPriority)}; ${c.risk.incompleteCoverage} with incomplete coverage`); L.push(`  verification: ${c.verified === null ? 'not performed here' : c.verified ? 'signature and contents verified' : 'FAILED'}`); };
  const aud = () => { const a = views.auditor; L.push('AUDITOR VIEW'); L.push(`  snapshot: ${a.package.snapshot ? `${a.package.snapshot.commit ?? 'no commit'} (${a.package.snapshot.immutable ? 'immutable' : 'NOT immutable'})` : 'none'}`); L.push(`  issuer: ${a.issuer ? `${a.issuer.trustBasis}, independently certified: ${a.issuer.independentlyCertified}` : 'none'}`); L.push(`  verification: ${a.verification.ok === null ? 'not performed here' : a.verification.ok ? 'ok' : 'FAILED: ' + a.verification.errors.join('; ')}`); for (const x of a.assertions) L.push(`  assertion ${x.id} [${x.status}]: ${x.text}  evidence=${x.evidence.map((d) => d.slice(0, 19)).join(',') || 'none'}`); for (const u of a.unknowns) L.push(`  unknown: ${u.about} - ${u.reason}`); L.push(`  does not prove: ${a.doesNotProve}`); };
  if (view === 'developer' || view === 'all') dev();
  if (view === 'ciso' || view === 'all') ciso();
  if (view === 'auditor' || view === 'all') aud();
  return L.join('\n') + '\n';
}

// ---- html ------------------------------------------------------------------------------------------------------------------------

/** One self-contained page, no script, nothing loaded from elsewhere. Every value is escaped. */
function renderHtml(views, { title = 'Release assurance report' } = {}) {
  const c = views.ciso; const a = views.auditor;
  const row = (f, cols) => `<tr data-finding="${esc(f.id)}" data-evidence="${esc(f.evidenceHash)}" data-status="${esc(f.status)}" data-confidence="${esc(f.confidence)}">${cols.map((x) => `<td>${x}</td>`).join('')}</tr>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>${esc(title)}</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#555;--line:#d0d0d0;--bad:#a40000;--ok:#0a6b2b}
@media (prefers-color-scheme: dark){:root{--bg:#14161a;--fg:#e8e8e8;--muted:#a0a0a0;--line:#3a3d44;--bad:#ff8080;--ok:#6fd48e}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:72rem;padding:1rem 16px}
h1,h2{line-height:1.2}table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace;font-size:.9em}.muted{color:var(--muted)}.bad{color:var(--bad)}.ok{color:var(--ok)}details{margin:1rem 0}summary{cursor:pointer;font-weight:600}
</style></head><body>
<h1>${esc(title)}</h1>
<p class="muted">Snapshot ${esc(a.package.snapshot ? a.package.snapshot.commit : 'none')} (${a.package.snapshot && a.package.snapshot.immutable ? 'immutable' : 'not immutable'}). Verification: <span class="${a.verification.ok === true ? 'ok' : 'bad'}">${esc(a.verification.ok === null ? 'not performed by this page' : a.verification.ok ? 'passed' : 'FAILED')}</span>.</p>
<details open><summary>Developer: where, why, how to fix</summary>
<table><thead><tr><th>Finding</th><th>Where</th><th>Why</th><th>How to fix</th><th>Status</th><th>Confidence</th></tr></thead><tbody>
${views.developer.map((f) => row(f, [`<code>${esc(f.id)}</code> ${esc(f.title)}<br><span class="muted">${esc(f.severity)}${f.cwe ? ' ' + esc(f.cwe) : ''}</span>`, `<code>${esc(f.where.file ?? '?')}:${esc(f.where.line ?? '?')}</code>`, esc(f.why ?? ''), esc(f.how ?? ''), esc(f.status), esc(f.confidence)])).join('\n') || '<tr><td colspan="6">No findings.</td></tr>'}
</tbody></table></details>
<details open><summary>CISO: what is proven, what changed, risk and coverage</summary>
<p><strong>Release verdict: ${esc(c.verdict.verdict)}.</strong> ${esc(c.verdict.statement)}</p>
<ul>${c.verdict.blockers.map((b) => `<li class="bad">Blocks: ${esc(b)}</li>`).join('')}${c.verdict.unknowns.map((u) => `<li>Unknown: ${esc(u)}</li>`).join('')}</ul>
<p>Scan: <strong>${esc(c.scan.verdict)}</strong> (${esc(c.scan.scanStatus)}). ${c.scan.conditions.map((x) => esc(x)).join('; ')}</p>
<p>Proven: ${esc(c.proven.executionProven)} by execution, ${esc(c.proven.taintProven)} by a taint path, ${esc(c.proven.unproven)} unproven, of ${esc(c.proven.total)}. Fixes: ${esc(c.fixes.verified)} verified, ${esc(c.fixes.unverified)} unverified, ${esc(c.fixes.open)} open.</p>
<p>${c.changeSinceLast ? `Since the previous release: ${esc(c.changeSinceLast.new.length)} new, ${esc(c.changeSinceLast.resolved.length)} resolved, ${esc(c.changeSinceLast.statusChanged.length)} changed status.` : 'No previous release was supplied, so no change is reported.'}</p>
<table><thead><tr><th>Finding</th><th>Severity</th><th>Proof</th><th>Priority</th><th>Status</th><th>Confidence</th></tr></thead><tbody>
${c.findings.map((f) => row(f, [`<code>${esc(f.id)}</code>`, esc(f.severity), esc(f.proofTier), esc(f.priority ?? 'not ranked'), esc(f.status), esc(f.confidence)])).join('\n') || '<tr><td colspan="6">No findings.</td></tr>'}
</tbody></table></details>
<details open><summary>Auditor: evidence behind each statement, and what is unknown</summary>
<p>Issuer: ${esc(a.issuer ? a.issuer.trustBasis : 'none')}; independently certified: ${esc(a.issuer ? a.issuer.independentlyCertified : 'n/a')}.</p>
<p class="muted">Proves: ${esc(a.proves)}<br>Does not prove: ${esc(a.doesNotProve)}</p>
<table><thead><tr><th>Finding</th><th>Evidence hash</th><th>Fix evidence</th><th>Status</th><th>Confidence</th></tr></thead><tbody>
${a.findings.map((f) => row(f, [`<code>${esc(f.id)}</code>`, `<code>${esc(f.evidenceHash)}</code>`, `<code>${esc(f.fixEvidence ?? 'none')}</code>`, esc(f.status), esc(f.confidence)])).join('\n') || '<tr><td colspan="5">No findings.</td></tr>'}
</tbody></table>
<h2>Assertions</h2><ul>${a.assertions.map((x) => `<li><strong>${esc(x.status)}</strong>: ${esc(x.text)} <span class="muted">(${x.evidence.length ? x.evidence.map((d) => `<code>${esc(d)}</code>`).join(', ') : 'no evidence cited'}${x.reason ? '; ' + esc(x.reason) : ''})</span></li>`).join('') || '<li>None.</li>'}</ul>
<h2>Unknowns</h2><ul>${a.unknowns.map((u) => `<li>${esc(u.about)}: ${esc(u.reason)}</li>`).join('') || '<li>None.</li>'}</ul>
</details></body></html>
`;
}


/***/ })

};
