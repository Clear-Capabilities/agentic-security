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
export function releaseVerdict(pkg, { waivedIds = [] } = {}) {
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
export function verifyStatedVerdict(pkg, opts) {
  const computed = releaseVerdict(pkg, opts).verdict;
  const decisions = asArray(pkg && pkg.policy && pkg.policy.decisions);
  const d = decisions.find((x) => x && x.id === 'release-verdict');
  const stated = d ? d.outcome : null;
  if (stated === null) return { ok: false, stated, computed, message: 'the package states no release verdict' };
  if (stated !== computed) return { ok: false, stated, computed, message: `the package states "${stated}" but its own contents give "${computed}"` };
  return { ok: true, stated, computed, message: null };
}
