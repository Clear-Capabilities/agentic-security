export const id = 5620;
export const ids = [5620,3736];
export const modules = {

/***/ 53948:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = __webpack_require__.p + "b4289e728659450b5e19.js";

/***/ }),

/***/ 80313:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   JQ: () => (/* binding */ rollupFleet),
/* harmony export */   LL: () => (/* binding */ renderFleetSummary),
/* harmony export */   gI: () => (/* binding */ runFleet)
/* harmony export */ });
/* unused harmony exports loadFleetState, ownersFor, renderFleetHtml, _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _policy_bundle_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(23736);
// PRD Epic 5 — fleet orchestration.
//
// Many repositories, one invocation, one rolled-up result set. The existing
// `org-scan` could iterate repos; what it could not do is survive an
// interruption, bound its own concurrency, tell you what is NEW since the last
// run, or route a finding to the person who owns the file. Those four are the
// difference between a loop and something an organisation can put on a
// schedule.
//
// THE HARD LINE (PRD §2.2, §10): everything here runs from the CLI on the
// customer's infrastructure. There is no server, no account, no multi-tenancy,
// and the "UI" is a static artifact generated from local files. A fleet feature
// is exactly where a local-first tool drifts into a platform, so the constraint
// is stated here rather than left to judgement.
//
// FOUR PROPERTIES, EACH OF WHICH IS A FAILURE MODE IF ABSENT:
//
//   1. ISOLATION — one repo that explodes must not take the run with it. A
//      fleet scan that dies on repo 3 of 50 is worse than useless: it looks
//      like a completed scan of 3 repos.
//   2. RESUMABILITY — the checkpoint records COMPLETED repos, and is written
//      after each one. A resumed run skips them rather than re-scanning, which
//      is what makes a 50-repo run survivable on a laptop or a flaky runner.
//   3. BOUNDED CONCURRENCY — an unbounded fan-out over 50 repos will exhaust
//      memory or file handles on the machine it was supposed to help.
//   4. HONEST ROLL-UP — a repo that FAILED is counted as failed, never folded
//      into "0 findings". Silent zeros are how a fleet report says everything
//      is fine because nothing ran.
//
// DELTA IS COMPUTED FROM STABLE IDS, not counts. "3 more criticals than last
// week" tells you nothing about which; a set difference over stableId tells you
// exactly what appeared, and is what a scheduled run should notify on.





const SCHEMA = 'agentic-security/fleet-state@1';

/** Read a checkpoint, or an empty one. Never throws. */
function loadFleetState(stateFile) {
  try {
    const j = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(stateFile, 'utf8'));
    if (j && j.schema === SCHEMA) return j;
  } catch { /* absent or unreadable -> start clean */ }
  return { schema: SCHEMA, completed: {}, startedAt: null };
}

function _saveFleetState(stateFile, state) {
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(stateFile), { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(stateFile, JSON.stringify(state, null, 2));
    return true;
  } catch { return false; }
}

/**
 * Owners for a path, from a CODEOWNERS file.
 *
 * Last matching rule wins, which is the documented CODEOWNERS precedence — a
 * first-match implementation silently routes to the most general owner, which
 * is the one least able to act on the finding.
 */
function ownersFor(codeownersText, filePath) {
  if (typeof codeownersText !== 'string' || !filePath) return [];
  let owners = [];
  for (const raw of codeownersText.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    const pattern = parts.shift();
    const these = parts.filter(p => p.startsWith('@') || p.includes('@'));
    if (!these.length) continue;
    if (_matchesGlob(pattern, filePath)) owners = these;
  }
  return owners;
}

function _matchesGlob(pattern, file) {
  const f = file.replace(/^\.?\//, '');
  let p = pattern.replace(/^\.?\//, '');
  if (p === '*') return true;
  if (p.endsWith('/')) return f.startsWith(p);
  const PLACEHOLDER = '\uE000'; // escape SEQUENCE in source -- 6 ASCII chars, not a raw embedded byte
  const rx = new RegExp('^' + p
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, PLACEHOLDER)
    .replace(/\*/g, '[^/]*')
    .replace(new RegExp(PLACEHOLDER, 'g'), '.*') + '(/.*)?$');
  return rx.test(f);
}

function _readCodeowners(repoRoot) {
  for (const rel of ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS']) {
    try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(repoRoot, rel), 'utf8'); } catch { /* next */ }
  }
  return null;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function _summarise(scan) {
  const all = [
    ...(scan.findings || []), ...(scan.secrets || []),
    ...(scan.logicVulns || []), ...(scan.supplyChain || []),
  ];
  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  const ids = [];
  let proven = 0;
  for (const f of all) {
    const sev = String(f.severity || 'info').toLowerCase();
    if (sev in bySeverity) bySeverity[sev]++;
    if (f.stableId) ids.push(f.stableId);
    if (f.proofTier === 'execution-proven') proven++;
  }
  return { total: all.length, bySeverity, proven, ids, findings: all };
}

/**
 * M4 §4.4 — provenance-aware debt for ONE repo, computed here (inside the
 * worker, from the untrimmed findings array) rather than inside `rollupFleet`,
 * because FR-1005 forbids raw finding data from surviving onto the per-repo
 * result entry (`test('FR-1005: ... the entry must not carry the raw findings
 * array at all')` in fleet.test.js) — a finding can carry a raw source
 * snippet, so only this derived summary (a finding id, a commit date, a day
 * count; never a file path or snippet) is threaded onto `entry.provenanceDebt`.
 *
 * A finding contributes only when its `findingProvenance.status` is
 * `'complete'` — the honest end of the confidence spectrum (see
 * `provenance/schema.js`'s `PROVENANCE_STATUS`). `partial`/`uncommitted`/etc.
 * are not proof of origin and must never win "oldest".
 */
function _provenanceDebtForRepo(findings, now = Date.now()) {
  let oldest = null;
  let completeCount = 0;
  for (const f of (findings || [])) {
    if (f.findingProvenance?.status !== 'complete') continue;
    const authorDate = f.findingProvenance?.findingOrigin?.authorDate;
    if (!authorDate) continue;
    completeCount++;
    const ageDays = Math.max(0, Math.floor((now - Date.parse(authorDate)) / 86400000));
    if (!oldest || ageDays > oldest.ageDays) {
      // FR-PROV-019: "Reports never show an age without its basis and
      // confidence." The basis is structurally implied here (only
      // status:'complete' findings reach this line, so the age is always
      // git-derived, and the rendered text says "proven-origin") — but the
      // confidence half has to be carried explicitly, same as
      // mttr.js's renderSlaSummary. Captured at selection time so the
      // renderers below cannot show the age without it.
      oldest = {
        findingId: f.id || f.stableId || null,
        authorDate,
        ageDays,
        confidence: f.findingProvenance?.confidence?.level || null,
      };
    }
  }
  return { oldest, completeCount };
}

/**
 * Scan many repositories with bounded concurrency, resumably.
 *
 * `runScan` is injected so this module has no engine import cycle and so the
 * orchestration can be tested without running real scans.
 */
async function runFleet({
  repos = [], concurrency = 4, stateFile, runScan,
  resume = true, previous = null, onProgress = () => {},
  // X-704: repositories whose every durable portfolio work unit is verified and current
  // (portfolio/work-units.js `fullyVerifiedRepositories`). They are skipped like a resumed completed repo,
  // and, as with a resumed repo, the skip is reported in `skipped` rather than counted as scanned.
  portfolioVerified = [],
} = {}) {
  if (typeof runScan !== 'function') {
    return { ok: false, reason: 'no runScan supplied' };
  }
  const state = (resume && stateFile) ? loadFleetState(stateFile) : { schema: SCHEMA, completed: {}, startedAt: null };
  const results = [];
  const skipped = [];

  const queue = repos.filter((r) => {
    if ((resume && state.completed[r]) || portfolioVerified.includes(r)) { skipped.push(r); return false; }
    return true;
  });

  const limit = Math.max(1, Math.min(concurrency, 32));
  let cursor = 0;

  async function worker() {
    while (cursor < queue.length) {
      const repo = queue[cursor++];
      let entry;
      try {
        const { scan } = await runScan(repo);
        const s = _summarise(scan);
        const codeowners = _readCodeowners(repo);
        // Route each finding to the owner of its file. Done here rather than at
        // report time because the CODEOWNERS file lives in the repo, and by
        // report time the fleet has moved on.
        const owners = {};
        if (codeowners) {
          for (const f of s.findings) {
            if (!f.file) continue;
            const o = ownersFor(codeowners, f.file);
            for (const own of o) (owners[own] ||= []).push(f.stableId || `${f.file}:${f.line}`);
          }
        }
        // FR-1006: "assurance-health views" and "policy drift" — a repo can
        // be RISK-clean (zero/low findings) while still having a governance
        // gap (a partial scan, a rejected/expired policy bundle nobody
        // noticed). scanHealth comes straight from the engine's own
        // computeScanHealth (FR-206) — nothing new is inferred here, this is
        // the first time the fleet rollup SURFACES a signal that already
        // existed per-scan. computePolicyDrift is null (not an empty object)
        // when the repo has no policy bundles configured at all — matching
        // this session's "no baseline configured -> no-op" convention.
        let policyDrift = null;
        try { policyDrift = (0,_policy_bundle_js__WEBPACK_IMPORTED_MODULE_2__/* .computePolicyDrift */ .rE)(repo); } catch { /* best-effort — never fail a repo's scan over drift reporting */ }
        // M4 §4.4: provenance-aware debt, computed HERE (from `s.findings`,
        // the untrimmed array) rather than in `rollupFleet` — by the time
        // `rollupFleet` sees `results`, the raw findings are gone (FR-1005).
        // Only the derived summary (id/date/age, never a file or snippet)
        // survives onto the entry. `mttr` threads through the SAME aggregate
        // `mttr.js`'s `computeMTTR` already produces (`scan.mttr`, stamped by
        // the CLI's persistence step — see posture/mttr.js) rather than
        // inventing a second notion of remediation time; there is no
        // `scan.remediatedFindings` field anywhere in this codebase.
        const provenanceDebt = _provenanceDebtForRepo(s.findings);
        entry = {
          repo, ok: true, total: s.total, bySeverity: s.bySeverity,
          proven: s.proven, ids: s.ids, owners, scannedAt: new Date().toISOString(),
          scanHealth: scan.scanHealth || null, policyDrift,
          provenanceDebt, mttr: scan.mttr || null,
        };
      } catch (e) {
        // A failed repo is FAILED, never zero findings.
        entry = { repo, ok: false, error: String(e?.message || e), total: null, bySeverity: null, ids: [], scannedAt: new Date().toISOString(), scanHealth: null, policyDrift: null, provenanceDebt: null, mttr: null };
      }
      results.push(entry);
      if (stateFile) {
        // FR-1006 (assurance-hardening PRD): "scan freshness" — this field
        // existed as an always-null stub before (never read anywhere, never
        // populated), which is the same as not existing for anyone trying to
        // answer "when was this repo last scanned". Stamped from the SAME
        // entry.scannedAt the results array already carries, not a second,
        // possibly-diverging timestamp.
        state.completed[repo] = { at: entry.scannedAt, ok: entry.ok, total: entry.total };
        _saveFleetState(stateFile, state);
      }
      onProgress(entry);
    }
  }

  await Promise.all(Array.from({ length: limit }, () => worker()));
  return { ok: true, results, skipped, rollup: rollupFleet(results, previous) };
}

/**
 * Roll many per-repo results into one view, with a delta when a previous run
 * is supplied.
 */
function rollupFleet(results, previous = null) {
  const scanned = results.filter(r => r.ok);
  const failed = results.filter(r => !r.ok);
  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  let total = 0, proven = 0;
  for (const r of scanned) {
    total += r.total || 0;
    proven += r.proven || 0;
    for (const s of SEVERITIES) bySeverity[s] += r.bySeverity?.[s] || 0;
  }

  // Delta by stable id, not by count.
  let newFindings = null;
  if (previous && Array.isArray(previous.results)) {
    const before = new Set(previous.results.flatMap(r => r.ids || []));
    newFindings = {};
    for (const r of scanned) {
      const fresh = (r.ids || []).filter(id => !before.has(id));
      if (fresh.length) newFindings[r.repo] = fresh;
    }
  }

  // FR-1006: governance/coverage gaps, counted and surfaced SEPARATELY from
  // the risk rollup above (total/bySeverity/proven) — a repo can contribute
  // zero to those and still need attention here. `null` scanHealth (a
  // failed repo, or a runScan that predates FR-206) is not counted as
  // partial — absence of a signal is not evidence of a problem.
  const partialScanHealth = scanned.filter(r => r.scanHealth && r.scanHealth.status !== 'complete');
  const withPolicyDrift = scanned.filter(r => r.policyDrift && (r.policyDrift.overrides.length || r.policyDrift.rejected.length));

  // M4 §4.4: provenance-aware debt + MTTR, surfaced as its own section
  // alongside the FR-1006 governance section above — same additive pattern,
  // same reason: a repo can be risk-clean and still carry old, PROVEN debt,
  // and that must not be folded into (or hidden by) the risk rollup above.
  //
  // `oldestProvenDebt` only ever comes from a repo's own `provenanceDebt`,
  // which `runFleet`'s worker computed from `findingProvenance.status ===
  // 'complete'` findings only — never a wall-clock guess dressed as proof.
  // A repo with no complete-status findings is disclosed BY NAME in
  // `reposWithNoProvenDebt`, never silently absent from a "no debt" story a
  // reader could misread as "this repo has no old findings" when the truth
  // is "we couldn't PROVE any origin here". A `results` entry that predates
  // this field (no `provenanceDebt` key at all — e.g. an older checkpoint,
  // or a hand-built test fixture) is treated the same as "none found",
  // consistent with every other optional signal in this rollup (scanHealth,
  // policyDrift).
  let oldestProvenDebt = null;
  const reposWithNoProvenDebt = [];
  const perRepoOldestProvenDebt = [];
  for (const r of scanned) {
    const oldest = r.provenanceDebt?.oldest || null;
    if (!oldest) { reposWithNoProvenDebt.push(r.repo); continue; }
    const withRepo = { repo: r.repo, ...oldest };
    perRepoOldestProvenDebt.push(withRepo);
    if (!oldestProvenDebt || oldest.ageDays > oldestProvenDebt.ageDays) oldestProvenDebt = withRepo;
  }

  // Fleet-wide MTTR reuses each repo's own `scan.mttr` (mttr.js's
  // `computeMTTR` output — `{count, meanDays, medianDays, perSeverity}`),
  // combined as a count-weighted mean, rather than recomputing wall-clock
  // remediation time here from a second source of truth. `byAgeBasis` is
  // deliberately always `{}`: `computeMTTR` does not track ageBasis per
  // remediated finding (only per-severity), and there is no
  // `scan.remediatedFindings` array anywhere in this codebase to derive one
  // from — see `runFleet`'s worker comment. Reporting a fabricated breakdown
  // would be worse than reporting none.
  //
  // FINAL-REVIEW FIX (M4, item 4): `mttr` used to default to `{n:0, ...}`
  // whenever no scanned repo's `.mttr` counted a remediation — which is
  // exactly what happens on EVERY real production fleet run, since
  // `scripts/fleet.mjs` drives `runFleet` with `runScan` straight from
  // `src/runScan.js`, and that function never sets `.mttr` at all (the only
  // real setter is the CLI's OWN single-repo persistence step in
  // `bin/agentic-security.js`, which fleet mode does not go through — see
  // that file's comment for the full investigation). `{n:0,...}` and "no
  // repo ever attempted to compute this" are materially different facts:
  // the first is a real, honest zero; the second is a missing capability.
  // Collapsing them made every real fleet run silently render a fabricated-
  // looking "no remediated findings recorded yet" line that reads as a
  // measurement rather than an absence.
  //
  // `anyMttrSupplied` distinguishes them: it is true only when at least one
  // SCANNED repo's entry carried a non-null `.mttr` object at all — which
  // only happens when something upstream (the CLI's own persistence path,
  // or a caller-supplied `runScan` that wires the same pipeline itself)
  // actually ran `computeMTTR`. `mttr` stays `null` — not a zeroed object —
  // when nothing did, so a consumer can tell "tracked, zero fixes so far"
  // from "not tracked at all" without inspecting `n`.
  let mttrCount = 0, mttrWeightedDays = 0, anyMttrSupplied = false;
  for (const r of scanned) {
    const m = r.mttr;
    if (m == null) continue;
    anyMttrSupplied = true;
    if (typeof m.count === 'number' && m.count > 0 && typeof m.meanDays === 'number') {
      mttrCount += m.count;
      mttrWeightedDays += m.meanDays * m.count;
    }
  }
  const mttr = anyMttrSupplied
    ? { n: mttrCount, meanDays: mttrCount ? mttrWeightedDays / mttrCount : null, byAgeBasis: {} }
    : null;

  return {
    repos: results.length,
    scanned: scanned.length,
    // Surfaced at the top level, not buried: a fleet report whose failures are
    // a footnote reads as a clean fleet.
    failed: failed.length,
    failures: failed.map(f => ({ repo: f.repo, error: f.error })),
    total, proven, bySeverity,
    reposWithPartialScanHealth: partialScanHealth.length,
    reposWithPolicyDrift: withPolicyDrift.length,
    ...(newFindings ? { newFindings } : {}),
    provenance: { oldestProvenDebt, reposWithNoProvenDebt, perRepoOldestProvenDebt, mttr },
  };
}

/** One-line summary. Leads with failures when there are any. */
function renderFleetSummary(rollup) {
  if (!rollup) return null;
  const head = rollup.failed
    ? `${rollup.failed} of ${rollup.repos} repo(s) FAILED to scan — their findings are unknown, not zero; `
    : '';
  const sev = SEVERITIES.filter(s => rollup.bySeverity[s]).map(s => `${rollup.bySeverity[s]} ${s}`).join(', ');
  const nf = rollup.newFindings
    ? ` ${Object.values(rollup.newFindings).reduce((a, b) => a + b.length, 0)} new since last run.`
    : '';
  // FR-1006: governance/coverage gaps reported as their own clause, never
  // folded into the risk sentence — a fleet with zero findings but 12 repos
  // on a partial scan is not "clean."
  const gov = [];
  if (rollup.reposWithPartialScanHealth) gov.push(`${rollup.reposWithPartialScanHealth} repo(s) with a partial (not complete) scan`);
  if (rollup.reposWithPolicyDrift) gov.push(`${rollup.reposWithPolicyDrift} repo(s) with policy drift or a rejected policy bundle`);
  const govClause = gov.length ? ` GOVERNANCE: ${gov.join('; ')}.` : '';
  // M4 §4.4: proven-origin debt as its own clause, matching the governance
  // clause's honesty rule — a null `oldestProvenDebt` gets an explicit "none"
  // line rather than silently vanishing from the sentence, which would read
  // as "no debt" instead of "nothing PROVEN yet."
  const prov = rollup.provenance;
  let provClause = '';
  if (prov) {
    // FR-PROV-019: the age never ships without its basis ("proven-origin",
    // structurally guaranteed by the status:'complete' filter upstream) AND
    // its confidence. A finding whose provenance carried no confidence level
    // says so rather than implying certainty by omission.
    const bits = prov.oldestProvenDebt
      ? [`oldest proven-origin finding: ${prov.oldestProvenDebt.repo} (${prov.oldestProvenDebt.ageDays}d, `
         + `${prov.oldestProvenDebt.confidence ? `${String(prov.oldestProvenDebt.confidence).toUpperCase()} confidence` : 'confidence unknown'})`]
      : ['no proven-origin findings across the fleet'];
    if (prov.reposWithNoProvenDebt.length) bits.push(`${prov.reposWithNoProvenDebt.length} repo(s) with no complete-status provenance`);
    provClause = ` PROVENANCE: ${bits.join('; ')}.`;
  }
  // X-707: portfolio progress is its own clause, present only when the `portfolio-assurance` feature attached it
  // (portfolio/progress.js `attachPortfolioProgress`), so flag-off output is byte-identical. It states verified units and
  // repositories separately from the scan counts above: a finished controller is not a passing portfolio.
  const pp = rollup.portfolioProgress;
  const portfolioClause = pp ? ` PORTFOLIO: ${pp.units.verified}/${pp.units.total} unit(s) verified, ${pp.coverage.fullyVerified}/${pp.coverage.total} repo(s) fully verified, ${pp.review.pending} pending human review; ${pp.completion.statement}` : '';
  return `${head}${rollup.scanned} repo(s) scanned, ${rollup.total} finding(s)`
    + `${sev ? ` (${sev})` : ''}, ${rollup.proven} execution-proven.${nf}${govClause}${provClause}${portfolioClause}`;
}

/**
 * A self-contained rollup page. No network, no scripts, no fonts — it must
 * render from local artifacts on an air-gapped machine (PRD AC3).
 */
function renderFleetHtml(rollup, results) {
  const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  // FR-1006: "scan freshness" — WHEN each repo was last scanned, not just
  // whether it was. A failed repo still carries a real scannedAt (the
  // attempt happened; it just didn't succeed) so a reader can tell "failed
  // just now" from "failed, and nobody has retried in weeks" apart.
  const rows = results.map(r => r.ok
    ? `<tr><td>${esc(r.repo)}</td><td>${r.total}</td>`
      + SEVERITIES.map(s => `<td>${r.bySeverity?.[s] ?? 0}</td>`).join('')
      + `<td>${r.proven ?? 0}</td><td>${esc(r.scannedAt || 'unknown')}</td></tr>`
    : `<tr class="fail"><td>${esc(r.repo)}</td><td colspan="7">SCAN FAILED — ${esc(r.error)}</td><td>${esc(r.scannedAt || 'unknown')}</td></tr>`).join('\n');
  // FR-1006: a SEPARATE table, not a column bolted onto the risk table above
  // — "distinguishes risk findings from scan and governance coverage gaps"
  // is most honestly satisfied by keeping the two visually and structurally
  // apart, not by merging them into one row a reader has to parse. Only
  // repos with something to report appear here; a fleet with nothing to flag
  // gets a one-line "nothing to report" rather than an empty table.
  const govRows = results
    .filter(r => (r.scanHealth && r.scanHealth.status !== 'complete') || (r.policyDrift && (r.policyDrift.overrides.length || r.policyDrift.rejected.length)))
    .map(r => {
      const healthCell = r.scanHealth && r.scanHealth.status !== 'complete'
        ? esc(`${r.scanHealth.status}: ${(r.scanHealth.conditions || []).join('; ') || 'see scanHealth'}`)
        : '—';
      const driftParts = [];
      if (r.policyDrift?.overrides?.length) {
        driftParts.push(...r.policyDrift.overrides.map(o => `${esc(o.key)} overridden by ${esc(o.overriddenBy)}`));
      }
      if (r.policyDrift?.rejected?.length) {
        driftParts.push(...r.policyDrift.rejected.map(x => `${esc(x.scope)} policy REJECTED: ${esc(x.reason)}`));
      }
      const driftCell = driftParts.length ? driftParts.join('; ') : '—';
      return `<tr><td>${esc(r.repo)}</td><td>${healthCell}</td><td>${driftCell}</td></tr>`;
    }).join('\n');
  const govSection = govRows
    ? `<h2>Governance / coverage gaps</h2>
<table border="1" cellpadding="4">
<tr><th>repo</th><th>scan health</th><th>policy drift</th></tr>
${govRows}
</table>`
    : `<h2>Governance / coverage gaps</h2>
<p>Nothing to report — every scanned repo has a complete scan and no policy drift.</p>`;
  // M4 §4.4: a SEPARATE section, same precedent as the governance section
  // above — proven-origin debt is neither a risk-severity fact nor a
  // governance-coverage fact, so it gets its own visual and structural space
  // rather than being bolted onto either existing table. Lists the oldest
  // finding PER REPO (not just the single fleet-wide oldest), so a reader can
  // see which repos are carrying old proven debt, not only the single worst
  // one.
  const prov = rollup.provenance;
  let provSection = '';
  if (prov) {
    // FR-PROV-019: the confidence column is not decoration — an age column
    // with no confidence beside it is exactly the "age without its basis and
    // confidence" the PRD forbids. The basis is the table's own framing
    // (every row is proven-origin by construction); the confidence has to be
    // shown per row, and an absent level reads "unknown" rather than blank,
    // so a missing value can never be mistaken for a confident one.
    const provRows = (prov.perRepoOldestProvenDebt || [])
      .map(p => `<tr><td>${esc(p.repo)}</td><td>${esc(p.findingId ?? 'unknown')}</td><td>${esc(p.authorDate)}</td><td>${p.ageDays}</td><td>${esc(p.confidence ? String(p.confidence).toUpperCase() : 'unknown')}</td></tr>`)
      .join('\n');
    const provTable = provRows
      ? `<table border="1" cellpadding="4">
<tr><th>repo</th><th>finding</th><th>author date</th><th>age (days)</th><th>origin confidence</th></tr>
${provRows}
</table>`
      : `<p>No complete-status (proven-origin) findings across the fleet.</p>`;
    const noProvenNote = prov.reposWithNoProvenDebt.length
      ? `<p>${prov.reposWithNoProvenDebt.length} repo(s) with no complete-status provenance: ${prov.reposWithNoProvenDebt.map(esc).join(', ')}</p>`
      : '';
    const mttrByBasisRows = Object.entries(prov.mttr?.byAgeBasis || {})
      .map(([basis, n]) => `<tr><td>${esc(basis)}</td><td>${n}</td></tr>`).join('\n');
    const mttrByBasisTable = mttrByBasisRows
      ? `<table border="1" cellpadding="4">
<tr><th>age basis</th><th>count</th></tr>
${mttrByBasisRows}
</table>`
      : '';
    // Three distinct states, not two (final-review fix, item 4): `prov.mttr
    // === null` means no scanned repo ever supplied a real mttr.js aggregate
    // at all — the honest disclosure is "not available", never "no
    // remediated findings recorded yet", which reads as a real zero
    // measurement rather than an absent capability. A non-null `mttr` with
    // `n === 0` is the legitimate zero: something DID track remediation and
    // genuinely found none yet.
    const mttrLine = !prov.mttr
      ? `<p>Fleet MTTR: not available — fleet mode does not yet track finding remediation history across runs.</p>`
      : prov.mttr.n > 0
      ? `<p>Fleet MTTR: ${prov.mttr.n} remediated finding(s)${prov.mttr.meanDays != null ? `, mean ${Math.round(prov.mttr.meanDays)}d to remediate` : ''}.</p>${mttrByBasisTable}`
      : `<p>Fleet MTTR: no remediated findings recorded yet.</p>`;
    provSection = `<h2>Provenance-Proven Debt</h2>
${provTable}
${noProvenNote}
${mttrLine}`;
  }
  return `<!-- generated offline; no external resources -->
<h1>Fleet scan</h1>
<p>${esc(renderFleetSummary(rollup) || '')}</p>
<h2>Risk findings</h2>
<table border="1" cellpadding="4">
<tr><th>repo</th><th>total</th>${SEVERITIES.map(s => `<th>${s}</th>`).join('')}<th>proven</th><th>scanned at</th></tr>
${rows}
</table>
${govSection}
${provSection}`;
}

const _internals = { SCHEMA, SEVERITIES, _matchesGlob, _summarise, _provenanceDebtForRepo };


/***/ }),

/***/ 25620:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   cmdFleet: () => (/* binding */ cmdFleet),
/* harmony export */   parseFleetQuestion: () => (/* binding */ parseFleetQuestion)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(77598);
/* harmony import */ var _fleet_manifest_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(62790);
/* harmony import */ var _fleet_graph_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(94355);
/* harmony import */ var _fleet_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(80313);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(31174);
/* harmony import */ var _job_store_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(20121);
/* harmony import */ var _job_runner_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(89072);
/* harmony import */ var _org_health_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(75435);
/* harmony import */ var _discover_edges_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(89632);
/* harmony import */ var _enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(81630);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_job_runner_js__WEBPACK_IMPORTED_MODULE_8__]);
_job_runner_js__WEBPACK_IMPORTED_MODULE_8__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// `agentic-security fleet init|scan|status|resume|query|explore`.
//
// The scanning half is the job fabric: a manifest becomes one idempotent job per repository in a local SQLite store, workers lease
// them, every scan runs in a supervised child under a hard timeout, and `resume` continues a run after anything stops it. The
// per-repository entry and the roll-up are the existing `posture/fleet.js` ones (counts, owners, scan health, delta), so a fleet
// report reads as it always has, with the organization's health and the enterprise graph added on top.
//
// Exit codes: 0 the organization is GREEN, 1 it is not (a required repository has no result, or a result is partial), 4 usage.













const GRAPH_FILE = 'fleet-graph.json';
const ENTERPRISE_FILE = node_path__WEBPACK_IMPORTED_MODULE_1__.join('fleet', 'enterprise-graph.json');
const DB_FILE = node_path__WEBPACK_IMPORTED_MODULE_1__.join('fleet', 'fleet.db');
const ROLLUP_FILE = 'fleet-rollup.json';
const sha = (s) => (0,node_crypto__WEBPACK_IMPORTED_MODULE_2__.createHash)('sha256').update(s).digest('hex');

const usage = () => { console.error('usage: fleet init | edges [--undeclared] | scan <manifest.yaml> [--workers N] [--retries N] [--timeout-seconds N | --timeout-ms N] [--no-cache] [--no-discover] [--lineage] | status [run-id] | resume <run-id|manifest.yaml> [--retry-failed] | query (--depends-on <id> | --blast-radius <component> [--version v] | --internet-to <data-class> [--involving-vulnerable auth|<repo>] | "<question>") | explore [--out file.html]'); return 4; };
const isManifestArg = (s) => /\.ya?ml$/i.test(String(s ?? ''));
const manifestArg = (args) => { const m = args._[2]; return m && !String(m).startsWith('--') ? m : 'fleet.yaml'; };
const dbPath = (root) => (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, DB_FILE);

async function cmdFleet(args, root) {
  const sub = args._[1];
  if (sub === 'init') return cmdInit(args, root);
  if (sub === 'scan') return cmdScan(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'resume') return cmdResume(args, root);
  if (sub === 'query') return cmdQuery(args, root);
  if (sub === 'explore') return cmdExplore(args, root);
  if (sub === 'edges') return cmdEdges(args, root);
  return usage();
}

/** `fleet edges [--undeclared] [--json]`: every edge of the last enterprise graph with the evidence it rests on; --undeclared keeps the ones found only in code. */
async function cmdEdges(args, root) {
  const f = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ENTERPRISE_FILE);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(f)) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const g = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8'));
  const edges = g.edges.filter((e) => e.type !== 'exposes' && (!args.flags.undeclared || e.discovered));
  if (args.flags.json) { console.log(JSON.stringify({ discovery: g.discovery ?? null, edges }, null, 2)); return 0; }
  if (!edges.length) { console.log(args.flags.undeclared ? 'No edge was found in code that the manifest does not declare.' : 'The graph has no edges.'); }
  for (const e of edges) {
    const where = e.evidence.filter((x) => x.source === 'discovered-code-literal' || x.source === 'code-boundaries').map((x) => (x.file ? `${x.file}:${x.line}` : `code boundaries: ${x.host ?? x.topic ?? x.name}`));
    console.log(`${e.from} -[${e.type}]-> ${e.to}  ${e.discovered ? 'FOUND ONLY IN CODE' : where.length ? 'declared, and seen in code' : 'declared'}${where.length ? `  (${where.join(', ')})` : ''}`);
  }
  if (g.discovery?.limitations) console.log(`\nLimits: ${g.discovery.limitations.join(' ')}`);
  else if (g.discovery?.note) console.log(`\nEdge discovery: ${g.discovery.note}.`);
  return 0;
}

async function cmdInit(args, root) {
  const target = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, manifestArg(args) === 'fleet.yaml' ? 'fleet.yaml' : manifestArg(args));
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(target) && !args.flags.force) { console.error(`${target} already exists. Pass --force to overwrite.`); return 4; }
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(target, (0,_fleet_manifest_js__WEBPACK_IMPORTED_MODULE_3__/* .starterManifestYaml */ .yr)(args.flags.organization || 'example'));
  console.log(`Wrote ${target}. Edit it to list your repositories, then run: agentic-security fleet scan ${node_path__WEBPACK_IMPORTED_MODULE_1__.basename(target)}`);
  return 0;
}

function overrides(manifest, args) {
  const m = { ...manifest };
  const num = (v, lo, hi) => { const n = Number(v); return Number.isInteger(n) && n >= lo && n <= hi ? n : null; };
  if (args.flags.workers !== undefined) { const n = num(args.flags.workers, 1, 32); if (n == null) return { error: '--workers must be an integer from 1 to 32' }; m.workers = n; }
  if (args.flags.retries !== undefined) { const n = num(args.flags.retries, 0, 5); if (n == null) return { error: '--retries must be an integer from 0 to 5' }; m.retries = n; }
  if (args.flags['timeout-ms'] !== undefined) { const n = num(args.flags['timeout-ms'], 50, 86400000); if (n == null) return { error: '--timeout-ms must be an integer from 50 to 86400000' }; m.perRepoTimeoutMs = n; }
  if (args.flags['timeout-seconds'] !== undefined) { const n = num(args.flags['timeout-seconds'], 1, 86400); if (n == null) return { error: '--timeout-seconds must be an integer from 1 to 86400' }; m.perRepoTimeoutMs = n * 1000; }
  return { manifest: m };
}

function entriesOf(artifacts, manifest) {
  return manifest.repositories.filter((r) => artifacts.has(r.id)).map((r) => ({ ...artifacts.get(r.id).entry, repo: r.id }));
}

/** The PRD names its commands `fleet status JOB-ID` and `fleet resume JOB-ID`; a run is a set of jobs, so a job id names the run it belongs to. */
function runOfJob(store, id) {
  const job = store.getJob(String(id));
  return job ? store.getRun(job.runId) : null;
}

async function finishRun({ args, root, store, runId, manifest, manifestFile, interrupted }) {
  const { artifacts, problems } = (0,_job_runner_js__WEBPACK_IMPORTED_MODULE_8__/* .loadArtifacts */ .kZ)({ store, runId, root });
  const jobs = store.listJobs(runId);
  const health = (0,_org_health_js__WEBPACK_IMPORTED_MODULE_9__/* .computeOrgHealth */ .WB)({ manifest, jobs });
  for (const p of problems) { const r = health.repositories.find((x) => x.id === p.repoId); if (r) { r.state = 'failed'; r.error = p.problem; } }
  if (problems.length) { health.counts.complete -= problems.filter((p) => health.repositories.find((x) => x.id === p.repoId)).length; health.counts.failed += problems.length; if (health.assurance !== 'red' && manifest.repositories.some((r) => r.required && problems.some((p) => p.repoId === r.id))) health.assurance = 'red'; health.reasons.push(`${problems.length} result(s) could not be verified: ${problems.map((p) => `${p.repoId} (${p.problem})`).join(', ')}`); }

  let previous = null;
  const rollupFile = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ROLLUP_FILE);
  try { previous = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(rollupFile, 'utf8')); } catch { /* first run */ }
  const rollup = (0,_fleet_js__WEBPACK_IMPORTED_MODULE_5__/* .rollupFleet */ .JQ)(entriesOf(artifacts, manifest).concat(health.repositories.filter((r) => !artifacts.has(r.id) && r.state !== 'complete' && r.state !== 'partial').map((r) => ({ repo: r.id, ok: false, error: r.error || r.state, total: null, bySeverity: null, ids: [], scannedAt: new Date().toISOString(), scanHealth: null, policyDrift: null, provenanceDebt: null, mttr: null }))), previous);
  (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.safeWriteState)(rollupFile, JSON.stringify(rollup, null, 2));

  const dep = (0,_fleet_graph_js__WEBPACK_IMPORTED_MODULE_4__/* .buildFleetDependencyGraph */ .u_)(manifest.repositories);
  (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.safeWriteState)((0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, GRAPH_FILE), JSON.stringify({ organization: manifest.organization, builtAt: new Date().toISOString(), ...dep }, null, 2));
  // edges the code implies; skipped with --no-discover. A failure here never fails the run: the graph is then declared-only and says so.
  let discovered = null; let discoveryNote = args.flags['no-discover'] ? 'skipped (--no-discover)' : null;
  if (!args.flags['no-discover']) { try { discovered = (0,_discover_edges_js__WEBPACK_IMPORTED_MODULE_10__/* .discoverEdges */ .U)({ manifest }); } catch (e) { discoveryNote = `failed (${String(e.message).slice(0, 80)}); the graph holds declared edges only`; } }
  const split = discovered ? (0,_discover_edges_js__WEBPACK_IMPORTED_MODULE_10__/* .splitDeclared */ .Z)(discovered, manifest) : null;
  const lineageByRepo = new Map([...artifacts].filter(([, a]) => a.lineage).map(([id, a]) => [id, a.lineage]));
  const graph = (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .finalizeGraph */ .Th)((0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .buildEnterpriseGraph */ .Ws)({ manifest, dependencyGraph: dep, discovered, lineage: lineageByRepo.size ? lineageByRepo : null }));
  const findingsByRepo = Object.fromEntries([...artifacts].map(([id, a]) => [id, a.findings ?? []]));
  (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.safeWriteState)((0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ENTERPRISE_FILE), JSON.stringify({ ...graph, runId, manifestFile, findingsByRepo, codeBoundaries: lineageByRepo.size ? { repositories: lineageByRepo.size, undeclaredDataClasses: Object.fromEntries(graph.nodes.filter((n) => n.discoveredDataClasses?.length).map((n) => [n.id, n.discoveredDataClasses])) } : { note: args.flags.lineage ? 'no repository returned a Code Boundaries graph' : 'not requested (--lineage)' }, discovery: discovered ? { scanned: discovered.scanned, limitations: discovered.limitations, undeclared: split.undeclared.length, confirmed: split.confirmed.length } : { note: discoveryNote }, builtAt: new Date().toISOString() }));

  if (args.flags.json) console.log(JSON.stringify({ runId, health, rollup }, null, 2));
  else {
    console.log((0,_fleet_js__WEBPACK_IMPORTED_MODULE_5__/* .renderFleetSummary */ .LL)(rollup));
    console.log(`\nRun: ${runId}\n${(0,_org_health_js__WEBPACK_IMPORTED_MODULE_9__/* .renderOrgHealth */ .Vp)(health)}`);
    if (lineageByRepo.size) { const und = graph.nodes.filter((n) => n.discoveredDataClasses?.length); console.log(`\nCode Boundaries: ${lineageByRepo.size} repositor${lineageByRepo.size === 1 ? 'y' : 'ies'} contributed a data flow graph.${und.length ? ` Data classes found in code but not declared: ${und.map((n) => `${n.id} (${n.discoveredDataClasses.join(', ')})`).join('; ')}.` : ' No undeclared data class was found.'}`); }
    if (split) console.log(`\nEdges found in code: ${split.undeclared.length} not in the manifest, ${split.confirmed.length} matching a declared edge. ${split.undeclared.length ? 'List them with: agentic-security fleet edges --undeclared' : ''}`.trimEnd());
    else if (discoveryNote) console.log(`\nEdge discovery ${discoveryNote}.`);
    if (interrupted) console.log(`\nInterrupted. Continue with: agentic-security fleet resume ${runId}`);
    else if (health.counts.failed || health.counts.timedOut || health.counts.notRun) console.log(`\nRetry the failed and timed-out repositories with: agentic-security fleet resume ${runId} --retry-failed`);
  }
  return health.assurance === 'green' && !interrupted ? 0 : 1;
}

async function runAll({ args, root, store, runId, manifest, manifestFile }) {
  const ac = new AbortController(); const onSig = () => ac.abort(); process.once('SIGINT', onSig); process.once('SIGTERM', onSig);
  try {
    // Code Boundaries are requested at scan time and remembered on the run, so a resume does the same thing the scan would have
    const lineage = !!args.flags.lineage || !!store.getRun(runId)?.meta?.lineage;
    await (0,_job_runner_js__WEBPACK_IMPORTED_MODULE_8__/* .runJobs */ .Ag)({ manifest, store, runId, root, scan: _job_runner_js__WEBPACK_IMPORTED_MODULE_8__/* .childScan */ .IT, scanOptions: { lineage }, signal: ac.signal, useCache: !args.flags['no-cache'], onEvent: (e) => {
      if (args.flags.json) return;
      if (e.type === 'done') console.error(`[fleet] done: ${e.repo}${e.cached ? ' (cached)' : ''}${e.status === 'partial' ? ' (partial)' : ''}`);
      else if (e.type === 'failed') console.error(`[fleet] ${e.timedOut ? 'TIMED OUT' : 'FAILED'}: ${e.repo} (${e.error})${e.next === 'queued' ? ', will retry' : ''}`);
      else if (e.type === 'fenced') console.error(`[fleet] ${e.repo}: result discarded, another worker holds the job`);
    } });
    return await finishRun({ args, root, store, runId, manifest, manifestFile, interrupted: ac.signal.aborted });
  } finally { process.off('SIGINT', onSig); process.off('SIGTERM', onSig); }
}

async function cmdScan(args, root) {
  const manifestFile = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, manifestArg(args));
  const loaded = (0,_fleet_manifest_js__WEBPACK_IMPORTED_MODULE_3__/* .loadFleetManifest */ .Cb)(manifestFile);
  if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
  const o = overrides(loaded.manifest, args);
  if (o.error) { console.error(o.error); return 4; }
  const { manifest } = o;
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.ensureStateDir)(root)) { console.error('No safe state directory for this project.'); return 4; }
  const store = await (0,_job_store_js__WEBPACK_IMPORTED_MODULE_7__/* .createSqliteJobStore */ .J6)({ file: dbPath(root) });
  try {
    const manifestHash = sha(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(manifestFile));
    console.error(`[fleet] planning ${manifest.repositories.length} repository(ies) for ${manifest.organization} (${manifest.workers} worker(s), ${manifest.retries} retr${manifest.retries === 1 ? 'y' : 'ies'}, ${Math.round(manifest.perRepoTimeoutMs / 1000)}s per repository)...`);
    const plan = (0,_job_runner_js__WEBPACK_IMPORTED_MODULE_8__/* .planRun */ .nY)({ manifest, manifestHash, store, config: args.flags.lineage ? { lineage: true } : {}, meta: { manifestFile, lineage: !!args.flags.lineage } });
    return await runAll({ args, root, store, runId: plan.runId, manifest, manifestFile });
  } finally { store.close(); }
}

async function cmdResume(args, root) {
  const target = String(args._[2] ?? '');
  if (!target) return usage();
  const dbFile = dbPath(root);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(dbFile)) { console.error('No fleet run exists in this project. Start one with: agentic-security fleet scan <manifest.yaml>'); return 4; }
  const store = await (0,_job_store_js__WEBPACK_IMPORTED_MODULE_7__/* .createSqliteJobStore */ .J6)({ file: dbFile });
  try {
    let run;
    if (isManifestArg(target)) {
      const hash = sha(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, target)));
      run = store.listRuns().find((r) => r.manifestHash === hash && store.listJobs(r.runId).some((j) => ['queued', 'leased'].includes(j.status)));
      if (!run) { console.error('Nothing to resume for that manifest: no run of it has unfinished work. Use `fleet resume <run-id> --retry-failed` to retry failed repositories.'); return 4; }
    } else run = store.getRun(target) ?? runOfJob(store, target);
    if (!run) { console.error(`No run ${target}. Runs: ${store.listRuns().slice(0, 5).map((r) => r.runId).join(', ') || 'none'}`); return 4; }
    const full = store.getRun(run.runId);
    const manifestFile = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, args.flags.manifest ?? full.meta?.manifestFile ?? (isManifestArg(target) ? target : 'fleet.yaml'));
    const loaded = (0,_fleet_manifest_js__WEBPACK_IMPORTED_MODULE_3__/* .loadFleetManifest */ .Cb)(manifestFile);
    if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
    const hash = sha(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(manifestFile));
    if (hash !== full.manifestHash) { console.error(`The manifest ${node_path__WEBPACK_IMPORTED_MODULE_1__.basename(manifestFile)} has changed since run ${full.runId} was planned. A resumed run must scan what it planned; start a new scan instead.`); return 4; }
    const o = overrides(loaded.manifest, args);
    if (o.error) { console.error(o.error); return 4; }
    const freed = (0,_job_runner_js__WEBPACK_IMPORTED_MODULE_8__/* .reclaimDeadWorkers */ .zD)(store, full.runId) + store.reclaimExpired(full.runId, { now: Date.now() });
    const requeued = args.flags['retry-failed'] ? store.requeueTerminal(full.runId, ['failed', 'timed_out']) : 0;
    // a limit given on the command line applies to the work still to do, including the work just re-queued
    if (args.flags['timeout-ms'] !== undefined || args.flags['timeout-seconds'] !== undefined) store.retime(full.runId, o.manifest.perRepoTimeoutMs);
    const open = store.listJobs(full.runId).filter((j) => ['queued', 'leased'].includes(j.status)).length;
    console.error(`[fleet] resuming ${full.runId}: ${open} unfinished, ${freed} lease(s) recovered${requeued ? `, ${requeued} failed repository(ies) re-queued` : ''}; finished results are reused.`);
    return await runAll({ args, root, store, runId: full.runId, manifest: o.manifest, manifestFile });
  } finally { store.close(); }
}

async function cmdStatus(args, root) {
  const dbFile = dbPath(root);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(dbFile)) {
    const f = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ROLLUP_FILE);
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(f)) { console.error('No fleet scan has been run yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
    const rollup = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8'));
    console.log(args.flags.json ? JSON.stringify(rollup, null, 2) : (0,_fleet_js__WEBPACK_IMPORTED_MODULE_5__/* .renderFleetSummary */ .LL)(rollup));
    return 0;
  }
  const store = await (0,_job_store_js__WEBPACK_IMPORTED_MODULE_7__/* .createSqliteJobStore */ .J6)({ file: dbFile });
  try {
    const arg = args._[2];
    const run = arg && !isManifestArg(arg) ? (store.getRun(String(arg)) ?? runOfJob(store, String(arg))) : store.listRuns()[0] && store.getRun(store.listRuns()[0].runId);
    if (!run) { console.error(arg && !isManifestArg(arg) ? `No run or job ${arg}.` : 'No fleet run exists yet.'); return 4; }
    if (arg && !isManifestArg(arg) && String(arg) !== run.runId) console.error(`Job ${arg} belongs to run ${run.runId}.`);
    const meta = run.meta ?? {};
    const manifest = (0,_fleet_manifest_js__WEBPACK_IMPORTED_MODULE_3__/* .loadFleetManifest */ .Cb)(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, meta.manifestFile ?? 'fleet.yaml'));
    const jobs = store.listJobs(run.runId);
    const m = manifest.ok ? manifest.manifest : { repositories: jobs.map((j) => ({ id: j.repoId, required: j.required })) };
    const health = (0,_org_health_js__WEBPACK_IMPORTED_MODULE_9__/* .computeOrgHealth */ .WB)({ manifest: m, jobs });
    if (args.flags.json) { console.log(JSON.stringify({ runId: run.runId, health, jobs: jobs.map((j) => ({ jobId: j.jobId, repo: j.repoId, status: j.status, attempts: j.attempts, worker: j.worker, leaseExpiresAt: j.leaseExpiresAt, error: j.error })) }, null, 2)); return 0; }
    console.log(`Run: ${run.runId} (${run.organization})\n${(0,_org_health_js__WEBPACK_IMPORTED_MODULE_9__/* .renderOrgHealth */ .Vp)(health)}`);
    const live = jobs.filter((j) => j.status === 'leased');
    if (live.length) console.log(`\nIn progress: ${live.map((j) => `${j.repoId} (attempt ${j.attempts}, lease until ${new Date(j.leaseExpiresAt).toISOString()})`).join(', ')}`);
    const f = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ROLLUP_FILE);
    if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(f)) console.log(`\n${(0,_fleet_js__WEBPACK_IMPORTED_MODULE_5__/* .renderFleetSummary */ .LL)(JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8')))}`);
    return 0;
  } finally { store.close(); }
}

// "Show every Internet-facing path to PCI data involving vulnerable authentication code" is recognised as a fixed shape and mapped
// to the structured query below. Anything else is refused with the flags to use; this is not a natural-language engine.
function parseFleetQuestion(text) {
  const m = /^\s*show\s+every\s+internet-facing\s+path\s+to\s+([a-z][a-z0-9-]*)\s+data(?:\s+involving\s+vulnerable\s+([a-z][a-z0-9-]*)\s+(?:code|components?|librar(?:y|ies)))?\s*\.?\s*$/i.exec(String(text ?? ''));
  if (!m) return null;
  const word = m[2]?.toLowerCase() ?? null;
  return { toDataClass: m[1].toLowerCase(), involving: word ? { family: word === 'authentication' || word === 'authorization' ? 'auth' : word } : null };
}

function readEnterprise(root) {
  const f = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, ENTERPRISE_FILE);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(f)) return null;
  try { return JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8')); } catch { return null; }
}

async function cmdQuery(args, root) {
  const flags = args.flags;
  const question = args._[2] && !isManifestArg(args._[2]) ? String(args._[2]) : null;
  const parsed = question ? parseFleetQuestion(question) : null;
  if (question && !parsed) { console.error(`Not a recognised question. This command answers one shape: "Show every Internet-facing path to <data class> data [involving vulnerable <authentication|family> code]". For anything else use --depends-on, --blast-radius, or --internet-to with --involving-vulnerable.`); return 4; }

  if (flags['depends-on']) {
    const f = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, GRAPH_FILE);
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(f)) { console.error('No fleet dependency graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
    const graph = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(f, 'utf8'));
    const target = String(flags['depends-on']);
    if (!graph.nodes.some((n) => n.id === target)) { console.error(`${target} is not a repository in the last fleet scan.`); return 4; }
    const radius = (0,_fleet_graph_js__WEBPACK_IMPORTED_MODULE_4__/* .blastRadius */ .X2)(graph, target);
    if (flags.json) { console.log(JSON.stringify({ target, blastRadius: radius }, null, 2)); return 0; }
    if (!radius.length) { console.log(`No fleet repository depends on ${target} (by declared package name).`); return 0; }
    console.log(`Repositories depending on ${target} (directly or transitively):`);
    for (const r of radius) console.log(`  ${r.id}  (depth ${r.depth}, via ${r.path.slice(1).join(' -> ')})`);
    return 0;
  }

  const ent = readEnterprise(root);
  if (!ent) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const bad = (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .validateEnterpriseGraph */ .cl)(ent);
  if (bad.length) { console.error(`The stored enterprise graph is inconsistent (${bad[0]}). Re-run the scan.`); return 1; }
  const findings = new Map(Object.entries(ent.findingsByRepo ?? {}));

  if (flags['blast-radius']) {
    const r = (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .componentBlastRadius */ ._o)({ graph: ent, component: String(flags['blast-radius']), version: flags.version ? String(flags.version) : null });
    if (!r) { console.error(`${flags['blast-radius']} is not in the last fleet scan.`); return 4; }
    console.log(flags.json ? JSON.stringify(r, null, 2) : (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .renderBlastRadius */ .lB)(r));
    return 0;
  }

  const toClass = parsed?.toDataClass ?? flags['internet-to'];
  if (toClass) {
    const sel = parsed?.involving ?? (flags['involving-vulnerable'] ? (/^[a-z][a-z0-9-]*$/.test(String(flags['involving-vulnerable'])) && ent.nodes.some((n) => n.id === flags['involving-vulnerable']) ? { repo: String(flags['involving-vulnerable']) } : { family: String(flags['involving-vulnerable']) }) : null);
    const involving = sel ? (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .vulnerableSet */ .r8)({ graph: ent, findingsByRepo: findings, selector: sel }) : null;
    const res = (0,_enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .attackPaths */ .Nn)({ graph: ent, toDataClass: String(toClass).toLowerCase(), involving });
    if (flags.json) { console.log(JSON.stringify({ ...res, involving: involving ? { direct: [...involving.direct], all: [...involving.all], why: Object.fromEntries(involving.why) } : null }, null, 2)); return 0; }
    if (!res.targets.length) { console.log(`No node in the fleet manifest is marked as holding ${toClass} data, so there is nothing to reach.`); return 0; }
    if (!res.paths.length) console.log(`No Internet-facing path to ${toClass} data${involving ? ' involving that vulnerable code' : ''} was found in the declared graph.${res.truncated ? ' (search bound reached)' : ''}`);
    for (const p of res.paths) {
      console.log(p.nodes.map((n) => (n === _enterprise_graph_js__WEBPACK_IMPORTED_MODULE_11__/* .INTERNET */ .aw ? 'Internet' : n)).join(' -> '));
      if (p.discoveredEdges?.length) console.log(`    rests on edge(s) found only in code, not declared: ${p.discoveredEdges.join(', ')}`);
      if (p.discoveredDataClassNodes?.length) console.log(`    reaches ${toClass} data only because the code shows it, not the manifest: ${p.discoveredDataClassNodes.join(', ')}`);
      if (p.involving.length) console.log(`    involves vulnerable code: ${p.involving.map((n) => `${n} (${involving.why.get(n)})`).join(', ')}`);
    }
    if (res.paths.length) console.log(`\n${res.paths.length} path(s). Reach edges are as declared in the fleet manifest, plus any marked above as found only in code.${res.truncated ? ' The search bound was reached; more may exist.' : ''}`);
    return 0;
  }
  return usage();
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function cmdExplore(args, root) {
  const ent = readEnterprise(root);
  if (!ent) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const rows = ent.edges.map((e) => `<tr><td>${esc(e.from)}</td><td>${esc(e.type)}${e.reach ? '' : ' (dependency)'}</td><td>${esc(e.to)}</td><td>${e.evidence.map((x) => esc(`${x.source}: ${x.repo ?? ''} ${x.field ?? x.declared ?? ''} ${x.value ?? x.spec ?? ''}`.trim())).join('<br>')}</td></tr>`).join('\n');
  const nodes = ent.nodes.map((n) => `<tr><td>${esc(n.id)}</td><td>${esc(n.type)}</td><td>${n.internetFacing ? 'yes' : ''}</td><td>${esc(n.environment ?? '')}</td><td>${esc(n.dataClasses.join(', '))}</td><td>${esc(n.trustZone ?? '')}</td></tr>`).join('\n');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fleet graph</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;margin:.5rem 0 2rem;width:100%}td,th{border:1px solid #8884;padding:.25rem .6rem;text-align:left;vertical-align:top}</style></head><body><h1>${esc(ent.organization)} fleet graph</h1><p>Run ${esc(ent.runId)}. Reach edges are as declared in the fleet manifest; dependency edges come from package manifests. Every edge lists its evidence.</p><h2>Nodes</h2><table><tr><th>id</th><th>type</th><th>internet-facing</th><th>environment</th><th>data</th><th>trust zone</th></tr>${nodes}</table><h2>Edges</h2><table><tr><th>from</th><th>type</th><th>to</th><th>evidence</th></tr>${rows}</table></body></html>\n`;
  const out = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, String(args.flags.out ?? 'fleet-graph.html'));
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(out, html);
  console.log(`Wrote ${out} (${ent.nodes.length} nodes, ${ent.edges.length} edges). A static page, no server.`);
  return 0;
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 89632:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   U: () => (/* binding */ discoverEdges),
/* harmony export */   Z: () => (/* binding */ splitDeclared)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
// Edges the code implies but the manifest does not declare (PRD 4: the enterprise graph should not be only what someone wrote down).
//
// What this does: reads the text of each repository's source and configuration files and looks for a few exact, checkable
// patterns that name ANOTHER node of the manifest:
//   * a URL literal whose host IS a node's id or alias, or whose first label is (payments-api matches payments-api.svc.cluster.local);
//   * a queue/topic resource's name or alias as a string literal on a line that publishes to it, or on one that consumes from it;
//   * a database resource's name or alias on a line that opens a connection.
// Each hit becomes an edge of type `calls`, `produces`, `consumes` or `connects-to` with the file and line that produced it, tagged
// `source: discovered-code-literal`, and is reported separately from declared edges: a discovered edge never replaces or hides a
// declared one, and a query result says which of its edges were only discovered.
//
// What it cannot do, and says so: it matches whole tokens, not substrings (so `orders` never matches `reorders`); it sees literals, not
// values built at run time, environment-supplied URLs or service-mesh routing; it cannot tell the direction of a database use; it
// skips comment lines but does not parse code, so a literal in a string that is never executed still counts. A discovered edge is a
// lead with evidence, not a fact. It is bounded in files, bytes and time.




const DISCOVERY_LIMITS = Object.freeze({ maxFilesPerRepo: 2000, maxFileBytes: 512 * 1024, maxTotalBytes: 64 * 1024 * 1024, maxEvidencePerEdge: 3 });
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', '.venv', 'venv', '__pycache__', 'target', _state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .STATE_DIR_NAME */ .Ky, 'coverage', '.next', 'dist-newstyle', '.stack-work']);
const TEXT_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|py|java|kt|go|rb|php|cs|rs|scala|ya?ml|json|toml|properties|env|tf|conf|ini|hs|nix)$/i;
const COMMENT = /^\s*(?:\/\/|#|\*|\/\*|--|;)/;
const URL_RE = /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^\s'"`<>)\]}]{1,300}/gi;
const PUBLISH = /\b(?:send_?message|publish|produce|send_?to_?queue|enqueue|put_?record|xadd|lpush|rpush|sendmessage|sendtoqueue|emit_?to)\b/i;
const CONSUME = /\b(?:consume|subscribe|receive_?message|poll|on_?message|get_?messages?|basic_?consume|xread|brpop|blpop|receivemessage)\b/i;
const CONNECT = /(?:\b(?:connect|create_?connection|createpool|new\s+pool|mongoclient|drivermanager|sqlalchemy|create_engine|database_url|dbname)\b|jdbc:|postgres(?:ql)?:\/\/|mysql:\/\/|mongodb(?:\+srv)?:\/\/|redis:\/\/)/i;

/** The names a node answers to: its id plus declared aliases, lower-case. */
function namesOf(node) { return [node.id, ...(node.aliases ?? [])].map((x) => String(x).toLowerCase()); }

function* sourceFiles(root, limits) {
  let count = 0; let bytes = 0;
  const stack = ['']; const rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root);
  while (stack.length) {
    const rel = stack.pop();
    let ents; try { ents = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(r); continue; }
      if (!e.isFile() || !TEXT_EXT.test(e.name)) continue;
      let st; try { st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(root, r)); } catch { continue; }
      if (st.size > limits.maxFileBytes) continue;
      if (++count > limits.maxFilesPerRepo || (bytes += st.size) > limits.maxTotalBytes) return;
      let real; try { real = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(root, r)); } catch { continue; }
      if (!real.startsWith(rootReal + node_path__WEBPACK_IMPORTED_MODULE_1__.sep)) continue;
      yield { rel: r, abs: real };
    }
  }
}

const stringLiterals = (line) => [...line.matchAll(/(['"`])((?:\\.|(?!\1).){1,200})\1/g)].map((m) => m[2]);
const tokenIn = (haystackLiteral, name) => new RegExp(`(?:^|[^a-z0-9_-])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z0-9_-])`, 'i').test(haystackLiteral);

/**
 * @param {{manifest: object, limits?: object}} o
 * @returns {{edges: Array<{type: string, from: string, to: string, evidence: object[]}>, scanned: Record<string, {files: number, truncated: boolean}>, limitations: string[]}}
 */
function discoverEdges({ manifest, limits = DISCOVERY_LIMITS }) {
  const L = { ...DISCOVERY_LIMITS, ...limits };
  const repoNodes = manifest.repositories.map((r) => ({ id: r.id, aliases: r.aliases ?? [], kind: 'repo' }));
  const resNodes = (manifest.resources ?? []).map((r) => ({ id: r.id, aliases: r.aliases ?? [], kind: r.kind }));
  const found = new Map(); const scanned = {};
  const add = (type, from, to, ev) => {
    const key = `${type}\u0000${from}\u0000${to}`;
    const e = found.get(key) ?? { type, from, to, evidence: [] };
    if (e.evidence.length < L.maxEvidencePerEdge) e.evidence.push({ source: 'discovered-code-literal', repo: from, declared: false, ...ev });
    found.set(key, e);
  };
  for (const repo of manifest.repositories) {
    let files = 0; let truncated = false;
    const targets = [...repoNodes.filter((n) => n.id !== repo.id), ...resNodes];
    const it = sourceFiles(repo.path, L);
    for (;;) {
      const nx = it.next();
      if (nx.done) break;
      files++;
      let text; try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(nx.value.abs, 'utf8'); } catch { continue; }
      if (text.includes('\0')) continue;
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000 || COMMENT.test(line)) continue;
        // 1. URL literals naming a repository or gateway
        for (const m of line.matchAll(URL_RE)) {
          let host; try { host = new URL(m[0].replace(/[.,;]+$/, '')).hostname.toLowerCase(); } catch { continue; }
          const first = host.split('.')[0];
          for (const n of targets) {
            if (n.kind !== 'repo' && n.kind !== 'gateway' && n.kind !== 'external-provider') continue;
            if (namesOf(n).some((nm) => nm === host || nm === first)) add(n.kind === 'external-provider' ? 'uses-provider' : 'calls', repo.id, n.id, { file: nx.value.rel, line: i + 1, host });
          }
          for (const n of targets) if (n.kind === 'database' && namesOf(n).some((nm) => nm === host || nm === host.split('.')[0]) && CONNECT.test(m[0])) add('connects-to', repo.id, n.id, { file: nx.value.rel, line: i + 1, host });
        }
        // 2. queue and database names as literals on a publishing / consuming / connecting line
        const lits = stringLiterals(line);
        if (!lits.length) continue;
        for (const n of targets) {
          if (n.kind === 'queue') {
            if (!lits.some((l) => namesOf(n).some((nm) => tokenIn(l, nm)))) continue;
            if (PUBLISH.test(line)) add('produces', repo.id, n.id, { file: nx.value.rel, line: i + 1, name: n.id });
            else if (CONSUME.test(line)) add('consumes', n.id, repo.id, { file: nx.value.rel, line: i + 1, name: n.id });
          } else if (n.kind === 'database' && CONNECT.test(line) && lits.some((l) => namesOf(n).some((nm) => tokenIn(l, nm)))) add('connects-to', repo.id, n.id, { file: nx.value.rel, line: i + 1, name: n.id });
        }
      }
    }
    if (files >= L.maxFilesPerRepo) truncated = true;
    scanned[repo.id] = { files, truncated };
  }
  return {
    edges: [...found.values()].sort((a, b) => (a.type + a.from + a.to < b.type + b.from + b.to ? -1 : 1)),
    scanned,
    limitations: [
      'Only string and URL literals are seen: a URL built at run time, read from the environment or routed by a mesh is not found.',
      'Names match as whole tokens; an alias must be declared in the manifest for a node whose code name differs from its id.',
      'The direction of a database use is not known, so those edges are `connects-to`.',
      'A discovered edge is a lead with file and line evidence, not a confirmed call.',
    ],
  };
}

/** Discovered edges whose (type, from, to) the manifest already declares, and those it does not. */
function splitDeclared(discovered, manifest) {
  const declared = new Set();
  for (const r of manifest.repositories) {
    for (const t of r.calls) declared.add(`calls\u0000${r.id}\u0000${t}`);
    for (const t of r.produces) declared.add(`produces\u0000${r.id}\u0000${t}`);
    for (const t of r.consumes) declared.add(`consumes\u0000${t}\u0000${r.id}`);
    for (const t of r.providers) declared.add(`uses-provider\u0000${r.id}\u0000${t}`);
    for (const t of [...r.reads, ...r.writes]) declared.add(`connects-to\u0000${r.id}\u0000${t}`);
  }
  const undeclared = []; const confirmed = [];
  for (const e of discovered.edges) (declared.has(`${e.type}\u0000${e.from}\u0000${e.to}`) ? confirmed : undeclared).push(e);
  return { undeclared, confirmed };
}


/***/ }),

/***/ 81630:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Nn: () => (/* binding */ attackPaths),
/* harmony export */   Th: () => (/* binding */ finalizeGraph),
/* harmony export */   Ws: () => (/* binding */ buildEnterpriseGraph),
/* harmony export */   _o: () => (/* binding */ componentBlastRadius),
/* harmony export */   aw: () => (/* binding */ INTERNET),
/* harmony export */   cl: () => (/* binding */ validateEnterpriseGraph),
/* harmony export */   lB: () => (/* binding */ renderBlastRadius),
/* harmony export */   r8: () => (/* binding */ vulnerableSet)
/* harmony export */ });
/* unused harmony export MAX_DEPTH */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
// The enterprise graph (PRD 4, requirements 6 to 8): the repositories, APIs, queues, databases, external providers and trust zones
// of an organization, with every edge carrying the evidence it came from.
//
// Two kinds of edge, never confused:
//   * `depends-on` edges come from each repository's own package manifest (the declared name and the spec it pins). A flaw in the
//     dependency can affect the dependent. They are NOT movement an attacker makes.
//   * REACH edges are what an attacker can move along: a call from one service to another, a producer to a queue, a queue to its
//     consumer, a service to a database or an external provider, and the Internet to anything declared Internet-facing. Those come
//     from the fleet manifest, which is operator-declared. They are labelled `source: fleet-manifest` and are exactly as good as the
//     operator's declaration; nothing here pretends to have discovered them. (Code-derived call and queue edges are what the Data
//     Flow Explorer's per-repository graph provides; joining that in is not built.)
//
// A graph edge without evidence is a bug, and `validateEnterpriseGraph` says so: "every graph edge traceable to source evidence".


const ENTERPRISE_GRAPH_SCHEMA = 'agentic-security/enterprise-graph';
const INTERNET = 'internet';
const MAX_PATHS = 200;
const MAX_DEPTH = 8;
const AUTH_CWES = new Set(['CWE-287', 'CWE-306', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-384', 'CWE-613', 'CWE-639', 'CWE-290', 'CWE-294', 'CWE-308', 'CWE-1390']);

const edgeId = (type, from, to) => `edge:${type}:${from}:${to}`;
const hash = (v) => (0,node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash)('sha256').update(JSON.stringify(v)).digest('hex');

function buildEnterpriseGraph({ manifest, dependencyGraph, discovered = null, lineage = null }) {
  const nodes = new Map();
  const edges = new Map();
  const addNode = (n) => nodes.set(n.id, n);
  const addEdge = (type, from, to, evidence, reach) => {
    const id = edgeId(type, from, to);
    const e = edges.get(id) ?? { id, type, from, to, reach, evidence: [] };
    e.evidence.push(evidence);
    edges.set(id, e);
  };
  addNode({ id: INTERNET, type: 'internet', kind: 'internet', internetFacing: false, environment: null, dataClasses: [], trustZone: 'internet', required: false });
  for (const r of manifest.repositories) addNode({ id: r.id, type: 'repository', kind: r.kind, internetFacing: r.internetFacing, environment: r.environment, dataClasses: r.dataClasses, trustZone: r.trustZone, required: r.required });
  for (const r of manifest.resources ?? []) addNode({ id: r.id, type: r.kind, kind: r.kind, internetFacing: r.internetFacing, environment: r.environment, dataClasses: r.dataClasses, trustZone: r.trustZone, required: false });

  const ev = (repo, field, value) => ({ source: 'fleet-manifest', repo, field, value });
  for (const n of [...nodes.values()]) if (n.internetFacing) addEdge('exposes', INTERNET, n.id, ev(n.id, 'internetFacing', true), true);
  for (const r of manifest.repositories) {
    for (const t of r.calls) addEdge('calls', r.id, t, ev(r.id, 'calls', t), true);
    for (const t of r.produces) addEdge('produces', r.id, t, ev(r.id, 'produces', t), true);
    for (const t of r.consumes) addEdge('consumes', t, r.id, ev(r.id, 'consumes', t), true);
    for (const t of r.reads) addEdge('reads', r.id, t, ev(r.id, 'reads', t), true);
    for (const t of r.writes) addEdge('writes', r.id, t, ev(r.id, 'writes', t), true);
    for (const t of r.providers) addEdge('uses-provider', r.id, t, ev(r.id, 'providers', t), true);
  }
  for (const d of dependencyGraph?.edges ?? []) addEdge('depends-on', d.from, d.to, d.evidence?.[0] ?? { source: 'package-manifest', repo: d.from, file: null, declared: d.via, spec: null }, false);
  // Edges found in the code. They share an id with a declared edge of the same type and endpoints, so the evidence list shows both; an
  // edge with ONLY discovered evidence is marked `discovered: true` so a query can say it rests on a code literal, not on a declaration.
  for (const d of discovered?.edges ?? []) for (const evidence of d.evidence) addEdge(d.type, d.from, d.to, evidence, true);
  // Code Boundaries (each repository's own data flow graph, summarized): data classes the code handles, and destinations it sends to.
  // These add to what the manifest declared and never replace it; a class the manifest did not declare is listed on the node so a path
  // that exists only because of it can say so.
  const aliasesOf = new Map([...manifest.repositories, ...(manifest.resources ?? [])].map((n) => [n.id, [n.id, ...(n.aliases ?? [])].map((a) => String(a).toLowerCase())]));
  for (const [repoId, sum] of lineage ?? []) {
    const node = nodes.get(repoId);
    if (!node || !sum) continue;
    const declared = new Set(node.dataClasses);
    const found = (sum.dataClasses ?? []).filter((c) => !declared.has(c));
    node.dataClasses = [...declared, ...found];
    node.discoveredDataClasses = found;
    const cb = (extra) => ({ source: 'code-boundaries', repo: repoId, declared: false, file: null, ...extra });
    for (const d of sum.externalDestinations ?? []) {
      if (!d.host) continue;
      const first = d.host.split('.')[0];
      for (const [target, names] of aliasesOf) {
        if (target === repoId || !(names.includes(d.host) || names.includes(first))) continue;
        const tn = nodes.get(target);
        addEdge(tn?.type === 'external-provider' ? 'uses-provider' : 'calls', repoId, target, cb({ host: d.host, nodeKind: 'external' }), true);
      }
    }
    for (const q of sum.queues ?? []) {
      for (const [target, names] of aliasesOf) {
        const tn = nodes.get(target);
        if (tn?.type !== 'queue' || !names.includes(String(q.topic).toLowerCase())) continue;
        if (q.operation === 'consume') addEdge('consumes', target, repoId, cb({ topic: q.topic }), true); else addEdge('produces', repoId, target, cb({ topic: q.topic }), true);
      }
    }
    for (const st of sum.stores ?? []) {
      for (const key of [st.host, st.database]) {
        if (!key) continue;
        const k = String(key).toLowerCase();
        for (const [target, names] of aliasesOf) {
          const tn = nodes.get(target);
          if (tn?.type !== 'database' || !(names.includes(k) || names.includes(k.split('.')[0]))) continue;
          addEdge('connects-to', repoId, target, cb({ store: st.subtype, name: key }), true);
        }
      }
    }
  }
  const FOUND_IN_CODE = new Set(['discovered-code-literal', 'code-boundaries']);
  for (const e of edges.values()) e.discovered = e.evidence.every((x) => FOUND_IN_CODE.has(x.source));
  return { schema: ENTERPRISE_GRAPH_SCHEMA, version: 1, organization: manifest.organization, nodes: [...nodes.values()], edges: [...edges.values()], digest: null };
}

function finalizeGraph(graph) { return { ...graph, digest: hash({ n: graph.nodes, e: graph.edges }) }; }

/** Every edge has evidence, every endpoint exists. Returns a list of problems. */
function validateEnterpriseGraph(g) {
  const errs = [];
  const ids = new Set((g?.nodes ?? []).map((n) => n.id));
  for (const e of g?.edges ?? []) {
    if (!Array.isArray(e.evidence) || !e.evidence.length || !e.evidence.every((x) => x && typeof x.source === 'string')) errs.push(`edge ${e.id} has no source evidence`);
    if (!ids.has(e.from) || !ids.has(e.to)) errs.push(`edge ${e.id} points at a node that is not in the graph`);
  }
  return errs;
}

const nodeOf = (g, id) => g.nodes.find((n) => n.id === id);

/** Repositories that match a "vulnerable code" selector, and everything that depends on them. */
function vulnerableSet({ graph, findingsByRepo = new Map(), selector }) {
  const direct = new Set(); const why = new Map();
  if (selector.repo) { direct.add(selector.repo); why.set(selector.repo, 'named'); }
  for (const [repo, findings] of findingsByRepo) {
    const hit = (findings ?? []).find((f) => (selector.family === 'auth' ? (AUTH_CWES.has(String(f.cwe)) || /auth/i.test(String(f.family ?? ''))) : selector.family ? new RegExp(selector.family, 'i').test(String(f.family ?? f.vuln ?? '')) : false) || (selector.cwe && selector.cwe.includes(String(f.cwe))));
    if (hit) { direct.add(repo); why.set(repo, `finding ${hit.id ?? hit.stableId ?? ''} ${hit.cwe ?? ''}`.trim()); }
  }
  const incoming = new Map();
  for (const e of graph.edges) if (e.type === 'depends-on') { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e.from); }
  const all = new Set(direct); const stack = [...direct];
  while (stack.length) { const c = stack.pop(); for (const f of incoming.get(c) ?? []) if (!all.has(f)) { all.add(f); why.set(f, `depends on ${c}`); stack.push(f); } }
  return { direct, all, why };
}

/**
 * Attack paths: simple paths from the Internet to any node holding `toDataClass`, along reach edges only. A path is "involving"
 * when it passes through a repository in `involving`. Bounded in depth and count; `truncated` says when a bound was hit.
 */
function attackPaths({ graph, toDataClass, from = INTERNET, involving = null, maxDepth = MAX_DEPTH, maxPaths = MAX_PATHS }) {
  const out = new Map();
  for (const e of graph.edges) if (e.reach) { if (!out.has(e.from)) out.set(e.from, []); out.get(e.from).push(e); }
  const results = []; let truncated = false;
  const targets = new Set(graph.nodes.filter((n) => n.dataClasses.includes(toDataClass)).map((n) => n.id));
  const walk = (id, nodePath, edgePath) => {
    if (results.length >= maxPaths) { truncated = true; return; }
    if (targets.has(id) && nodePath.length > 1) {
      const inv = involving ? nodePath.filter((n) => involving.all.has(n)) : [];
      if (!involving || inv.length) results.push({ nodes: [...nodePath], edges: edgePath.map((e) => e.id), involving: inv, discoveredEdges: edgePath.filter((e) => e.discovered).map((e) => e.id), discoveredDataClassNodes: nodePath.filter((n) => (nodeOf(graph, n)?.discoveredDataClasses ?? []).includes(toDataClass)), evidence: edgePath.flatMap((e) => e.evidence.map((x) => ({ edge: e.id, ...x }))) });
    }
    if (nodePath.length > maxDepth) { truncated = true; return; }
    for (const e of out.get(id) ?? []) if (!nodePath.includes(e.to)) walk(e.to, [...nodePath, e.to], [...edgePath, e]);
  };
  if (nodeOf(graph, from)) walk(from, [from], []);
  return { dataClass: toDataClass, targets: [...targets], paths: results, truncated, bounds: { maxDepth, maxPaths } };
}

/** The shared-component report: who depends on `component` (transitively), and how many of them are exposed, in production, or hold regulated data. */
function componentBlastRadius({ graph, component, version = null }) {
  if (!nodeOf(graph, component)) return null;
  const incoming = new Map();
  for (const e of graph.edges) if (e.type === 'depends-on') { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e); }
  const found = new Map(); const queue = [{ id: component, path: [component], vm: 'not-asked' }];
  while (queue.length) {
    const { id, path, vm: parentVm } = queue.shift();
    for (const e of incoming.get(id) ?? []) {
      if (found.has(e.from)) continue;
      const spec = e.evidence.map((x) => x.spec).find((x) => x != null) ?? null;
      // only the dependents that pin the component itself can be judged against a version; one reached THROUGH another repository
      // inherits that repository's status, and is not reached at all when the repository in between was ruled out
      const direct = id === component;
      const vm = direct ? (version == null ? 'not-asked' : spec == null ? 'unknown' : String(spec).includes(version) ? 'matched' : 'mismatch') : parentVm;
      found.set(e.from, { id: e.from, depth: path.length, path: [...path, e.from], spec, versionMatch: vm, inherited: !direct, evidence: e.evidence });
      if (vm !== 'mismatch') queue.push({ id: e.from, path: [...path, e.from], vm });
    }
  }
  const all = [...found.values()].sort((a, b) => a.depth - b.depth || a.id.localeCompare(b.id));
  const counted = all.filter((d) => d.versionMatch !== 'mismatch');
  const attrs = (d) => nodeOf(graph, d.id);
  const classes = {};
  for (const d of counted) for (const c of attrs(d).dataClasses) classes[c] = (classes[c] ?? 0) + 1;
  return {
    component, version, dependents: all,
    counts: { repositories: counted.length, internetFacing: counted.filter((d) => attrs(d).internetFacing).length, production: counted.filter((d) => attrs(d).environment === 'production').length, byDataClass: classes },
    excludedByVersion: all.filter((d) => d.versionMatch === 'mismatch').map((d) => d.id),
    unknownVersion: counted.filter((d) => d.versionMatch === 'unknown').map((d) => d.id),
  };
}

function renderBlastRadius(r) {
  const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
  const L = [`${r.component}${r.version ? `@${r.version}` : ''}`, '', 'Used by:', n(r.counts.repositories, 'repository', 'repositories'), n(r.counts.internetFacing, 'Internet-facing service', 'Internet-facing services'), n(r.counts.production, 'production app', 'production apps')];
  for (const [c, k] of Object.entries(r.counts.byDataClass).sort()) L.push(n(k, `${c.toUpperCase()}-scoped service`, `${c.toUpperCase()}-scoped services`));
  if (r.excludedByVersion.length) L.push('', `Excluded, their pinned version does not match: ${r.excludedByVersion.join(', ')}`);
  if (r.unknownVersion.length) L.push('', `Counted, but their pinned version could not be read: ${r.unknownVersion.join(', ')}`);
  return L.join('\n');
}


/***/ }),

/***/ 94355:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   X2: () => (/* binding */ blastRadius),
/* harmony export */   u_: () => (/* binding */ buildFleetDependencyGraph)
/* harmony export */ });
/* unused harmony export readRepoManifest */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
// The cross-repository dependency graph for the fleet feature (PRD 4).
//
// Reads each repo's own manifest to learn (a) the package name it publishes under, if any, and (b) the package
// names it depends on. An edge A -> B means "A declares a dependency that resolves to B's own published name" —
// i.e. B is upstream of A, and a defect in B can affect A. This is a real, lightweight cross-repo dependency graph
// built purely from manifests already on disk; it does not need deployment config (Kubernetes/compose/Terraform)
// the way the existing deployment-boundary graph does, so a fleet of plain application repos works out of the box.



const MANIFESTS = Object.freeze([
  { file: 'package.json', ecosystem: 'npm' },
  { file: 'go.mod', ecosystem: 'go' },
  { file: 'Cargo.toml', ecosystem: 'cargo' },
  { file: 'requirements.txt', ecosystem: 'pypi' },
  { file: 'pyproject.toml', ecosystem: 'pypi' },
]);

function readBounded(p, maxBytes = 1024 * 1024) {
  try {
    const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p);
    if (!st.isFile() || st.size > maxBytes) return null;
    return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(p, 'utf8');
  } catch { return null; }
}

function parsePackageJson(text) {
  let j;
  try { j = JSON.parse(text); } catch { return { name: null, deps: new Set() }; }
  const specs = new Map();
  for (const block of [j.peerDependencies, j.devDependencies, j.dependencies]) for (const [k, v] of Object.entries(block || {})) if (typeof v === 'string') specs.set(k, v.slice(0, 200));
  const deps = new Set([...Object.keys(j.dependencies || {}), ...Object.keys(j.devDependencies || {}), ...Object.keys(j.peerDependencies || {})]);
  return { name: typeof j.name === 'string' ? j.name : null, deps, specs, version: typeof j.version === 'string' ? j.version : null };
}

function parseGoMod(text) {
  const m = /^module\s+(\S+)/m.exec(text);
  const deps = new Set();
  const block = /require\s*\(([\s\S]*?)\)/.exec(text);
  const lines = block ? block[1].split('\n') : text.split('\n').filter((l) => /^require\s/.test(l.trim()));
  for (const raw of lines) {
    const l = raw.replace(/^require\s+/, '').trim();
    const dm = /^(\S+)\s+v?\S+/.exec(l);
    if (dm) deps.add(dm[1]);
  }
  return { name: m ? m[1] : null, deps };
}

function parseCargoToml(text) {
  const nm = /\[package\][\s\S]*?\bname\s*=\s*"([^"]+)"/.exec(text);
  const deps = new Set();
  const section = /\[dependencies\]([\s\S]*?)(\n\[|$)/.exec(text);
  if (section) {
    for (const line of section[1].split('\n')) {
      const dm = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
      if (dm) deps.add(dm[1]);
    }
  }
  return { name: nm ? nm[1] : null, deps };
}

function parseRequirementsTxt(text) {
  const deps = new Set();
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith('-')) continue;
    const dm = /^([A-Za-z0-9._-]+)/.exec(l);
    if (dm) deps.add(dm[1].toLowerCase());
  }
  return { name: null, deps };
}

function parsePyprojectToml(text) {
  const nm = /\[project\][\s\S]*?\bname\s*=\s*"([^"]+)"/.exec(text);
  const deps = new Set();
  const section = /dependencies\s*=\s*\[([\s\S]*?)\]/.exec(text);
  if (section) {
    for (const m of section[1].matchAll(/"([A-Za-z0-9._-]+)/g)) deps.add(m[1].toLowerCase());
  }
  return { name: nm ? nm[1] : null, deps };
}

const PARSERS = { 'package.json': parsePackageJson, 'go.mod': parseGoMod, 'Cargo.toml': parseCargoToml, 'requirements.txt': parseRequirementsTxt, 'pyproject.toml': parsePyprojectToml };

/** One repo's declared identity and dependency names, merged across every manifest file it has. */
function readRepoManifest(repoPath) {
  let name = null;
  const deps = new Set();
  const ecosystems = new Set();
  const specs = new Map();
  const files = new Map();
  for (const { file, ecosystem } of MANIFESTS) {
    const text = readBounded(node_path__WEBPACK_IMPORTED_MODULE_1__.join(repoPath, file));
    if (text == null) continue;
    const parsed = PARSERS[file](text);
    if (parsed.name && !name) name = parsed.name;
    for (const d of parsed.deps) { deps.add(d); if (!files.has(d)) files.set(d, file); }
    for (const [d, spec] of parsed.specs ?? []) specs.set(d, spec);
    ecosystems.add(ecosystem);
  }
  return { name, deps, ecosystems: [...ecosystems], specs, files };
}

/**
 * Build the fleet dependency graph. `repos`: [{id, path}]. An edge {from, to} means `from` depends on `to` (so a
 * defect in `to` can affect `from`). Matching is by declared package NAME only — two repos that happen to share a
 * name under different ecosystems are not disambiguated, a disclosed limit, not a guess.
 */
function buildFleetDependencyGraph(repos) {
  const manifests = new Map();
  for (const r of repos) manifests.set(r.id, { ...r, manifest: readRepoManifest(r.path) });

  const byName = new Map();
  for (const [id, r] of manifests) if (r.manifest.name) {
    if (!byName.has(r.manifest.name)) byName.set(r.manifest.name, []);
    byName.get(r.manifest.name).push(id);
  }

  const edges = [];
  for (const [id, r] of manifests) {
    for (const dep of r.manifest.deps) {
      const targets = byName.get(dep);
      if (!targets) continue;
      for (const to of targets) if (to !== id) edges.push({ from: id, to, via: dep, evidence: [{ source: 'package-manifest', repo: id, file: r.manifest.files.get(dep) ?? null, declared: dep, spec: r.manifest.specs.get(dep) ?? null }] });
    }
  }
  const nodes = [...manifests.values()].map((r) => ({ id: r.id, path: r.path, declaredName: r.manifest.name, ecosystems: r.manifest.ecosystems }));
  return { nodes, edges };
}

/** Transitive downstream closure: which fleet repos depend on `repoId`, directly or transitively, with the shortest path to each. */
function blastRadius(graph, repoId) {
  const incoming = new Map();
  for (const e of graph.edges) { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e.from); }
  const best = new Map();
  const queue = [{ id: repoId, path: [repoId] }];
  while (queue.length) {
    const { id, path: p } = queue.shift();
    for (const from of incoming.get(id) || []) {
      if (best.has(from)) continue;
      const newPath = [...p, from];
      best.set(from, { depth: newPath.length - 1, path: newPath });
      queue.push({ id: from, path: newPath });
    }
  }
  return [...best.entries()].map(([id, v]) => ({ id, ...v })).sort((a, b) => a.depth - b.depth || (a.id < b.id ? -1 : 1));
}


/***/ }),

/***/ 62790:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Cb: () => (/* binding */ loadFleetManifest),
/* harmony export */   yr: () => (/* binding */ starterManifestYaml)
/* harmony export */ });
/* unused harmony exports ENVIRONMENTS, parseDuration, validateFleetManifest */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _util_yaml_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(82340);
// The fleet manifest (PRD 4 "Fleet Manifest"). `fleet.yaml`:
//
//   organization: example
//   repositories:
//     - id: frontend
//       path: ../frontend
//   workers: 4
//   perRepoTimeout: 20m
//
// Parsing reuses util/yaml.js (the one YAML entry point in this codebase). Validation is closed-world: an unknown
// top-level key, a duplicate repository id, or a path that does not resolve to a real directory all refuse the
// whole manifest rather than silently skipping one repo.




const FLEET_MANIFEST_SCHEMA_KEYS = Object.freeze(['organization', 'repositories', 'workers', 'perRepoTimeout', 'retries', 'resources']);
const REPO_KEYS = Object.freeze(['id', 'path', 'required', 'kind', 'internetFacing', 'environment', 'dataClasses', 'trustZone', 'calls', 'produces', 'consumes', 'reads', 'writes', 'providers', 'aliases']);
const RESOURCE_KEYS = Object.freeze(['id', 'kind', 'dataClasses', 'trustZone', 'internetFacing', 'environment', 'aliases']);
const REPO_KINDS = Object.freeze(['service', 'library', 'frontend', 'worker', 'gateway']);
const RESOURCE_KINDS = Object.freeze(['queue', 'database', 'external-provider', 'gateway']);
const ENVIRONMENTS = Object.freeze(['production', 'staging', 'development']);
const NAME_RE = /^[a-z][a-z0-9-]{0,63}$/;
const DURATION_RE = /^(\d+)(s|m|h)$/;

function parseDuration(s, fallbackMs) {
  if (typeof s === 'number' && s > 0) return s * 1000;
  const m = DURATION_RE.exec(String(s ?? ''));
  if (!m) return fallbackMs;
  const n = Number(m[1]);
  return m[2] === 's' ? n * 1000 : m[2] === 'm' ? n * 60000 : n * 3600000;
}

/** Validate a parsed manifest object against the manifest's own base directory (for path resolution). */
function validateFleetManifest(doc, { baseDir = '.' } = {}) {
  const errors = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, errors: ['manifest must be a YAML mapping'] };
  for (const k of Object.keys(doc)) if (!FLEET_MANIFEST_SCHEMA_KEYS.includes(k)) errors.push(`unknown top-level key: ${k}`);
  if (typeof doc.organization !== 'string' || !doc.organization) errors.push('organization is required and must be a string');
  if (!Array.isArray(doc.repositories) || doc.repositories.length === 0) errors.push('repositories must be a non-empty array');
  const seen = new Set();
  const repos = [];
  const idList = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || !v.every((x) => typeof x === 'string' && NAME_RE.test(x))) { errors.push(`${where} must be a list of ids`); return []; } return v; };
  const aliasList = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || v.length > 16 || !v.every((x) => typeof x === 'string' && /^[a-z0-9][a-z0-9._-]{0,99}$/.test(x))) { errors.push(`${where} must be a list of up to 16 lower-case names or hostnames`); return []; } return v; };
  const classes = (v, where) => { if (v === undefined) return []; if (!Array.isArray(v) || !v.every((x) => typeof x === 'string' && /^[a-z][a-z0-9-]{0,30}$/.test(x))) { errors.push(`${where} must be a list of data class names such as pci or pii`); return []; } return v; };
  for (const [i, r] of (Array.isArray(doc.repositories) ? doc.repositories : []).entries()) {
    if (!r || typeof r !== 'object') { errors.push(`repositories[${i}] must be a mapping`); continue; }
    for (const k of Object.keys(r)) if (!REPO_KEYS.includes(k)) errors.push(`repositories[${i}]: unknown key ${k}`);
    if (typeof r.id !== 'string' || !NAME_RE.test(r.id)) { errors.push(`repositories[${i}].id must be a lowercase kebab-case string`); continue; }
    if (seen.has(r.id)) { errors.push(`duplicate repository id: ${r.id}`); continue; }
    seen.add(r.id);
    if (typeof r.path !== 'string' || !r.path) { errors.push(`repositories[${i}].path is required`); continue; }
    const abs = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(baseDir, r.path);
    let isDir = false;
    try { isDir = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(abs).isDirectory(); } catch { /* reported below */ }
    if (!isDir) errors.push(`repositories[${i}].path does not resolve to a directory: ${r.path}`);
    if (r.kind !== undefined && !REPO_KINDS.includes(r.kind)) errors.push(`repositories[${i}].kind must be one of ${REPO_KINDS.join(', ')}`);
    if (r.environment !== undefined && !ENVIRONMENTS.includes(r.environment)) errors.push(`repositories[${i}].environment must be one of ${ENVIRONMENTS.join(', ')}`);
    for (const k of ['required', 'internetFacing']) if (r[k] !== undefined && typeof r[k] !== 'boolean') errors.push(`repositories[${i}].${k} must be true or false`);
    if (r.trustZone !== undefined && !(typeof r.trustZone === 'string' && NAME_RE.test(r.trustZone))) errors.push(`repositories[${i}].trustZone must be a name`);
    repos.push({
      id: r.id, path: abs, required: r.required !== false, kind: r.kind ?? null, internetFacing: r.internetFacing === true, environment: r.environment ?? null,
      dataClasses: classes(r.dataClasses, `repositories[${i}].dataClasses`), trustZone: r.trustZone ?? null,
      aliases: aliasList(r.aliases, `repositories[${i}].aliases`), calls: idList(r.calls, `repositories[${i}].calls`), produces: idList(r.produces, `repositories[${i}].produces`), consumes: idList(r.consumes, `repositories[${i}].consumes`),
      reads: idList(r.reads, `repositories[${i}].reads`), writes: idList(r.writes, `repositories[${i}].writes`), providers: idList(r.providers, `repositories[${i}].providers`),
    });
  }
  const resources = [];
  const resIds = new Set();
  if (doc.resources !== undefined && !Array.isArray(doc.resources)) errors.push('resources must be a list');
  for (const [i, r] of (Array.isArray(doc.resources) ? doc.resources : []).entries()) {
    if (!r || typeof r !== 'object') { errors.push(`resources[${i}] must be a mapping`); continue; }
    for (const k of Object.keys(r)) if (!RESOURCE_KEYS.includes(k)) errors.push(`resources[${i}]: unknown key ${k}`);
    if (typeof r.id !== 'string' || !NAME_RE.test(r.id)) { errors.push(`resources[${i}].id must be a lowercase kebab-case string`); continue; }
    if (seen.has(r.id) || resIds.has(r.id)) { errors.push(`resource id ${r.id} collides with another repository or resource`); continue; }
    resIds.add(r.id);
    if (!RESOURCE_KINDS.includes(r.kind)) errors.push(`resources[${i}].kind must be one of ${RESOURCE_KINDS.join(', ')}`);
    if (r.environment !== undefined && !ENVIRONMENTS.includes(r.environment)) errors.push(`resources[${i}].environment must be one of ${ENVIRONMENTS.join(', ')}`);
    if (r.internetFacing !== undefined && typeof r.internetFacing !== 'boolean') errors.push(`resources[${i}].internetFacing must be true or false`);
    resources.push({ id: r.id, kind: r.kind, aliases: aliasList(r.aliases, `resources[${i}].aliases`), dataClasses: classes(r.dataClasses, `resources[${i}].dataClasses`), trustZone: r.trustZone ?? null, internetFacing: r.internetFacing === true, environment: r.environment ?? null });
  }
  const known = new Set([...seen, ...resIds]);
  for (const r of repos) {
    for (const [field, kinds] of [['calls', ['repo', 'gateway']], ['produces', ['queue']], ['consumes', ['queue']], ['reads', ['database']], ['writes', ['database']], ['providers', ['external-provider']]]) {
      for (const target of r[field]) {
        if (!known.has(target)) { errors.push(`repository ${r.id}: ${field} names ${target}, which is neither a repository nor a resource`); continue; }
        const res = resources.find((x) => x.id === target);
        const ok = res ? kinds.includes(res.kind) : kinds.includes('repo');
        if (!ok) errors.push(`repository ${r.id}: ${field} cannot point at ${target}${res ? ` (a ${res.kind})` : ' (a repository)'}`);
      }
    }
  }
  if (doc.workers != null && !(Number.isInteger(doc.workers) && doc.workers >= 1 && doc.workers <= 32)) errors.push('workers must be an integer in 1..32');
  if (doc.retries != null && !(Number.isInteger(doc.retries) && doc.retries >= 0 && doc.retries <= 5)) errors.push('retries must be an integer in 0..5');
  if (doc.perRepoTimeout != null && parseDuration(doc.perRepoTimeout, null) == null) errors.push(`perRepoTimeout is not a valid duration: ${doc.perRepoTimeout}`);
  if (errors.length) return { ok: false, errors };
  return {
    ok: true, errors: [],
    manifest: {
      organization: doc.organization, repositories: repos, resources,
      workers: doc.workers ?? 4, retries: doc.retries ?? 1, perRepoTimeoutMs: parseDuration(doc.perRepoTimeout, 20 * 60000),
    },
  };
}

function loadFleetManifest(filePath) {
  let text;
  try { text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(filePath, 'utf8'); } catch (e) { return { ok: false, errors: [`cannot read ${filePath}: ${e.message}`] }; }
  let doc;
  try { doc = (0,_util_yaml_js__WEBPACK_IMPORTED_MODULE_2__/* .load */ .Hh)(text); } catch (e) { return { ok: false, errors: [`invalid YAML: ${e.message}`] }; }
  return validateFleetManifest(doc, { baseDir: node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(filePath)) });
}

function starterManifestYaml(organization = 'example') {
  return `organization: ${organization}
repositories:
  - id: example-repo
    path: .
workers: 4
perRepoTimeout: 20m
`;
}


/***/ }),

/***/ 89072:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Ag: () => (/* binding */ runJobs),
/* harmony export */   IT: () => (/* binding */ childScan),
/* harmony export */   kZ: () => (/* binding */ loadArtifacts),
/* harmony export */   nY: () => (/* binding */ planRun),
/* harmony export */   zD: () => (/* binding */ reclaimDeadWorkers)
/* harmony export */ });
/* unused harmony export DEFAULTS */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
/* harmony import */ var node_url__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(73136);
/* harmony import */ var _sandbox_supervise_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(74676);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(31174);
/* harmony import */ var _scan_cache_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(75846);
/* harmony import */ var _scan_child_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(3398);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_scan_child_js__WEBPACK_IMPORTED_MODULE_8__]);
_scan_child_js__WEBPACK_IMPORTED_MODULE_8__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// The fleet scan controller (PRD 4, requirements 2 to 5). It turns a manifest into jobs in the job store and runs them with bounded
// workers, each scan in its own child process under a hard timeout, so one hung repository costs one worker for one timeout and
// nothing else. Every state change is in the store, which is what makes `fleet resume` an ordinary continuation.
//
//   plan      fingerprint each repository, derive its cache key, enqueue one idempotent job per repository
//   run       claim -> (cache hit | scan in a supervised child, heartbeating) -> complete | fail-with-retry
//   recover   an expired lease, or a lease held by a dead process on this host, goes back in the queue
//
// A worker that loses its lease (it stopped heartbeating long enough for another worker to take the job) is fenced out: its late
// result is refused by the store and its scan is aborted. Results are written per attempt (`<repo>.<epoch>.json`) and the job row
// points at the winning one, so a retry can never produce two sets of findings for one repository.










const SCAN_CHILD = (0,node_url__WEBPACK_IMPORTED_MODULE_4__.fileURLToPath)(new URL(/* asset import */ __webpack_require__(53948), __webpack_require__.b));
const sha = (s) => (0,node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash)('sha256').update(s).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const DEFAULTS = Object.freeze({ leaseMs: 30_000, heartbeatMs: 10_000, retryDelayMs: 2_000, pollMs: 100 });

/** The default scan: one supervised child process per repository. Throws `{code: 'TIMEOUT'|'ERROR', message}`. */
async function childScan(repoPath, { timeoutMs, signal, lineage = false }) {
  const r = await (0,_sandbox_supervise_js__WEBPACK_IMPORTED_MODULE_5__/* .superviseSpawn */ .u)(process.execPath, [SCAN_CHILD, repoPath], { cwd: repoPath, env: { ...process.env, AGENTIC_SECURITY_NO_STATE: '1', ...(lineage ? { AGENTIC_SECURITY_LINEAGE_DEEP: '1' } : {}) }, timeoutMs, signal, maxOutputBytes: 96 * 1024 * 1024 });
  const fail = (code, message) => Object.assign(new Error(message), { code });
  if (r.timedOut) throw fail('TIMEOUT', `no result within ${Math.round(timeoutMs / 1000)}s`);
  if (r.cancelled) throw fail('CANCELLED', 'cancelled');
  if (r.spawnError) throw fail('ERROR', `could not start the scan: ${r.spawnError}`);
  if (r.outputCapped) throw fail('ERROR', 'the scan produced more output than allowed');
  if (r.exitCode !== 0) throw fail('ERROR', `scan exited ${r.exitCode}: ${String(r.stderr).trim().split('\n').pop()?.slice(0, 200) ?? ''}`);
  const a = r.stdout.indexOf(_scan_child_js__WEBPACK_IMPORTED_MODULE_8__/* .BEGIN */ .Q); const b = r.stdout.indexOf(_scan_child_js__WEBPACK_IMPORTED_MODULE_8__/* .END */ .K);
  if (a < 0 || b < a) throw fail('ERROR', 'the scan produced no result block');
  try { return JSON.parse(r.stdout.slice(a + _scan_child_js__WEBPACK_IMPORTED_MODULE_8__/* .BEGIN */ .Q.length, b)); } catch (e) { throw fail('ERROR', `unreadable scan result: ${e.message}`); }
}

const hostId = () => node_os__WEBPACK_IMPORTED_MODULE_1__.hostname();
const pidAlive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };

/** Free jobs held by workers on THIS host whose process no longer exists. Other hosts are handled by lease expiry alone. */
function reclaimDeadWorkers(store, runId, { host = hostId(), alive = pidAlive, self = null } = {}) {
  let freed = 0;
  const seen = new Set();
  for (const j of store.listJobs(runId)) {
    if (j.status !== 'leased' || !j.worker || seen.has(j.worker) || j.worker === self) continue;
    const m = /^(.*):(\d+):\d+$/.exec(j.worker);
    if (!m || m[1] !== host) continue;
    seen.add(j.worker);
    if (!alive(Number(m[2]))) freed += store.reclaimWorker(runId, j.worker);
  }
  return freed;
}

function planRun({ manifest, manifestHash, store, runId = null, config = {}, now = Date.now(), identity = (0,_scan_cache_js__WEBPACK_IMPORTED_MODULE_7__/* .scannerIdentity */ .fs)(), fingerprint = _scan_cache_js__WEBPACK_IMPORTED_MODULE_7__/* .repoFingerprint */ .NJ, retries = manifest.retries, meta = {} }) {
  const scanConfig = { provenance: false, ...config };
  const prints = manifest.repositories.map((r) => ({ r, fp: fingerprint(r.path) }));
  const configHash = sha(JSON.stringify(scanConfig));
  const id = runId ?? `frun-${sha(JSON.stringify({ manifestHash, configHash, identity, t: now, prints: prints.map((p) => [p.r.id, p.fp.content]) })).slice(0, 16)}`;
  store.begin({ runId: id, organization: manifest.organization, manifestHash, configHash, scannerIdentity: identity, createdAt: now, meta: { workers: manifest.workers, perRepoTimeoutMs: manifest.perRepoTimeoutMs, retries, ...meta } });
  const created = store.enqueue(id, prints.map(({ r, fp }) => ({ jobId: `${id}:${r.id}`, repoId: r.id, commit: fp.commit, cacheKey: (0,_scan_cache_js__WEBPACK_IMPORTED_MODULE_7__/* .cacheKey */ .k$)({ fingerprint: fp, config: scanConfig, identity }), timeoutMs: manifest.perRepoTimeoutMs, maxAttempts: retries + 1, required: r.required })), { now });
  return { runId: id, created, identity };
}

/**
 * Run (or continue) a planned run until no job is queued or leased by a live worker. Returns when the work is done, the signal
 * aborts, or `maxWaitMs` passes with only other workers' leases outstanding.
 */
async function runJobs({ manifest, store, runId, root, scan = childScan, scanOptions = {}, workers = manifest.workers, leaseMs = DEFAULTS.leaseMs, heartbeatMs = DEFAULTS.heartbeatMs, retryDelayMs = DEFAULTS.retryDelayMs, pollMs = DEFAULTS.pollMs, maxWaitMs = null, signal, now = () => Date.now(), onEvent = () => {}, cacheDir = null, artifactDir = null, useCache = true }) {
  const repoById = new Map(manifest.repositories.map((r) => [r.id, r]));
  const cacheD = cacheDir ?? (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, 'fleet', 'cache');
  const artD = artifactDir ?? (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, 'fleet', 'artifacts', runId);
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(artD, { recursive: true, mode: 0o700 });
  const deadline = maxWaitMs ?? (manifest.perRepoTimeoutMs * 3 + leaseMs);
  const writeArtifact = (job, payload) => {
    const text = JSON.stringify({ schema: 'agentic-security/fleet-scan-artifact', version: 1, runId, repoId: job.repoId, epoch: job.epoch, commit: job.commit, ...payload });
    const file = node_path__WEBPACK_IMPORTED_MODULE_2__.join(artD, `${job.repoId}.${job.epoch}.json`);
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(file, text, { mode: 0o600 });
    return { file, sha256: sha(text) };
  };

  async function worker(slot) {
    const id = `${hostId()}:${process.pid}:${slot}`;
    let idleSince = null;
    for (;;) {
      if (signal?.aborted) return;
      store.reclaimExpired(runId, { now: now() });
      const job = store.claim(runId, { worker: id, leaseMs, now: now() });
      if (!job) {
        const open = store.listJobs(runId).filter((j) => j.status === 'queued' || j.status === 'leased');
        if (!open.length) return;
        idleSince ??= now();
        if (now() - idleSince > deadline) return;
        await sleep(pollMs);
        continue;
      }
      idleSince = null;
      const repo = repoById.get(job.repoId);
      onEvent({ type: 'start', repo: job.repoId, attempt: job.attempts });
      const cached = useCache ? (0,_scan_cache_js__WEBPACK_IMPORTED_MODULE_7__/* .readCache */ .xe)(cacheD, job.cacheKey) : null;
      if (cached) {
        const a = writeArtifact(job, { entry: cached.entry, findings: cached.findings, findingsTruncated: !!cached.findingsTruncated, lineage: cached.lineage ?? null, cached: true });
        const status = cached.entry?.scanHealth && cached.entry.scanHealth.status !== 'complete' ? 'partial' : 'succeeded';
        if (store.complete(job.jobId, job.epoch, { status, artifactSha256: a.sha256, summary: { total: cached.entry?.total ?? null, cached: true, artifact: node_path__WEBPACK_IMPORTED_MODULE_2__.basename(a.file) }, now: now() })) onEvent({ type: 'done', repo: job.repoId, cached: true, status });
        continue;
      }
      const ac = new AbortController();
      const onAbort = () => ac.abort();
      signal?.addEventListener('abort', onAbort, { once: true });
      let lost = false;
      const hb = setInterval(() => { if (!store.heartbeat(job.jobId, job.epoch, { now: now(), leaseMs })) { lost = true; ac.abort(); } }, heartbeatMs);
      try {
        const out = await scan(repo.path, { timeoutMs: job.timeoutMs, signal: ac.signal, ...scanOptions });
        clearInterval(hb);
        if (lost) { onEvent({ type: 'fenced', repo: job.repoId }); continue; }
        if (!out?.entry) throw Object.assign(new Error('the scan returned no entry'), { code: 'ERROR' });
        if (out.entry.ok === false) throw Object.assign(new Error(out.entry.error || 'the scan failed'), { code: 'ERROR' });
        const a = writeArtifact(job, { entry: out.entry, findings: out.findings ?? [], findingsTruncated: !!out.findingsTruncated, lineage: out.lineage ?? null });
        const status = out.entry.scanHealth && out.entry.scanHealth.status !== 'complete' ? 'partial' : 'succeeded';
        if (store.complete(job.jobId, job.epoch, { status, artifactSha256: a.sha256, summary: { total: out.entry.total ?? null, cached: false, artifact: node_path__WEBPACK_IMPORTED_MODULE_2__.basename(a.file) }, now: now() })) {
          if (useCache && status === 'succeeded') (0,_scan_cache_js__WEBPACK_IMPORTED_MODULE_7__/* .writeCache */ .aR)(cacheD, job.cacheKey, { entry: out.entry, findings: out.findings ?? [], findingsTruncated: !!out.findingsTruncated, lineage: out.lineage ?? null });
          onEvent({ type: 'done', repo: job.repoId, cached: false, status });
        } else onEvent({ type: 'fenced', repo: job.repoId });
      } catch (e) {
        clearInterval(hb);
        if (lost || e?.code === 'CANCELLED') { if (e?.code === 'CANCELLED' && !lost) store.fail(job.jobId, job.epoch, { error: 'cancelled', now: now(), retryDelayMs: 0 }); continue; }
        const r = store.fail(job.jobId, job.epoch, { error: e?.message ?? String(e), timedOut: e?.code === 'TIMEOUT', now: now(), retryDelayMs });
        onEvent({ type: 'failed', repo: job.repoId, error: e?.message ?? String(e), timedOut: e?.code === 'TIMEOUT', next: r?.state ?? null });
      } finally { clearInterval(hb); signal?.removeEventListener('abort', onAbort); }
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(workers, 32)) }, (_, i) => worker(i)));
  return { aborted: !!signal?.aborted };
}

/** Load the artifacts the jobs point at, verifying each against the hash the store recorded. A missing or altered artifact is reported, not used. */
function loadArtifacts({ store, runId, root, artifactDir = null }) {
  const dir = artifactDir ?? (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(root, 'fleet', 'artifacts', runId);
  const out = new Map(); const problems = [];
  for (const j of store.listJobs(runId)) {
    if (!['succeeded', 'partial'].includes(j.status)) continue;
    const file = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, j.summary?.artifact ?? `${j.repoId}.${j.epoch}.json`);
    try {
      const text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8');
      if (sha(text) !== j.artifactSha256) { problems.push({ repoId: j.repoId, problem: 'artifact does not match the recorded hash' }); continue; }
      out.set(j.repoId, JSON.parse(text));
    } catch { problems.push({ repoId: j.repoId, problem: 'artifact is missing or unreadable' }); }
  }
  return { artifacts: out, problems };
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 20121:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Hd: () => (/* binding */ isTerminal),
/* harmony export */   J6: () => (/* binding */ createSqliteJobStore)
/* harmony export */ });
/* unused harmony exports JOB_STATUSES, createMemoryJobStore */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
// The fleet job store (PRD 4, requirements 2 and 3): jobs with a lease, a heartbeat, a retry count, a timeout and a result hash,
// behind one small interface so the storage can change without the scheduler noticing.
//
//   createSqliteJobStore({ file })   local deployment, one file, no server (node:sqlite)
//   createMemoryJobStore()           the reference implementation; the conformance tests run the SAME assertions against both,
//                                    which is what shows the interface does not secretly depend on SQLite. A PostgreSQL or a
//                                    queue-backed store would be a third implementation of the same methods.
//
// Semantics that matter (and are tested on both stores):
//   * IDEMPOTENT: a job's id is derived from its run, repository, commit and configuration, and `enqueue` of an existing id does
//     nothing. Enqueueing a run twice does not make two jobs.
//   * LEASED: `claim` hands one queued job to one worker, increments a fencing `epoch`, and starts a lease. A worker that stops
//     heartbeating loses the job when the lease expires; `reclaimExpired` puts it back in the queue.
//   * FENCED: `heartbeat`, `complete` and `fail` must present the epoch they were given. A worker that lost its lease (and whose
//     job another worker now holds) is refused, so a slow zombie can neither extend a lease it no longer has nor overwrite the
//     result of the worker that replaced it. That is what keeps a retry from duplicating findings.
//   * BOUNDED RETRIES: a failure puts the job back in the queue until `maxAttempts`, then it is `failed` (or `timed_out`),
//     terminal, and visible in the organization's health. A job is never silently dropped.



const JOB_STATUSES = Object.freeze(['queued', 'leased', 'succeeded', 'partial', 'failed', 'timed_out', 'cancelled']);
const TERMINAL = new Set(['succeeded', 'partial', 'failed', 'timed_out', 'cancelled']);
const isTerminal = (s) => TERMINAL.has(s);

const jobOf = (r) => (r ? {
  jobId: r.job_id, runId: r.run_id, repoId: r.repo_id, commit: r.commit_sha ?? null, cacheKey: r.cache_key ?? null, status: r.status, worker: r.worker ?? null,
  epoch: r.epoch, leaseExpiresAt: r.lease_expires_at ?? null, heartbeatAt: r.heartbeat_at ?? null, attempts: r.attempts, maxAttempts: r.max_attempts,
  timeoutMs: r.timeout_ms, nextAttemptAt: r.next_attempt_at ?? 0, artifactSha256: r.artifact_sha256 ?? null, summary: r.summary ? JSON.parse(r.summary) : null,
  error: r.error ?? null, createdAt: r.created_at, startedAt: r.started_at ?? null, finishedAt: r.finished_at ?? null, required: !!r.required,
} : null);

// ------------------------------------------------------------------------------------------------------- memory
function createMemoryJobStore() {
  const runs = new Map(); const jobs = new Map();
  const all = (runId) => [...jobs.values()].filter((j) => j.runId === runId);
  const store = {
    kind: 'memory',
    begin(run) { if (!runs.has(run.runId)) runs.set(run.runId, { ...run }); return runs.get(run.runId); },
    getRun: (runId) => runs.get(runId) ?? null,
    listRuns: () => [...runs.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))),
    enqueue(runId, list, { now = Date.now() } = {}) {
      let created = 0;
      for (const j of list) { if (jobs.has(j.jobId)) continue; jobs.set(j.jobId, { runId, repoId: j.repoId, jobId: j.jobId, commit: j.commit ?? null, cacheKey: j.cacheKey ?? null, status: 'queued', worker: null, epoch: 0, leaseExpiresAt: null, heartbeatAt: null, attempts: 0, maxAttempts: j.maxAttempts ?? 2, timeoutMs: j.timeoutMs, nextAttemptAt: 0, artifactSha256: null, summary: null, error: null, createdAt: now, startedAt: null, finishedAt: null, required: j.required !== false }); created++; }
      return created;
    },
    claim(runId, { worker, leaseMs, now = Date.now() }) {
      const j = all(runId).filter((x) => x.status === 'queued' && x.nextAttemptAt <= now).sort((a, b) => a.createdAt - b.createdAt || a.repoId.localeCompare(b.repoId))[0];
      if (!j) return null;
      Object.assign(j, { status: 'leased', worker, epoch: j.epoch + 1, attempts: j.attempts + 1, leaseExpiresAt: now + leaseMs, heartbeatAt: now, startedAt: now, error: null });
      return { ...j };
    },
    heartbeat(jobId, epoch, { now = Date.now(), leaseMs }) { const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return false; j.heartbeatAt = now; j.leaseExpiresAt = now + leaseMs; return true; },
    complete(jobId, epoch, { status = 'succeeded', artifactSha256 = null, summary = null, now = Date.now() }) {
      const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return false;
      Object.assign(j, { status, artifactSha256, summary, finishedAt: now, leaseExpiresAt: null, error: null }); return true;
    },
    fail(jobId, epoch, { error, timedOut = false, now = Date.now(), retryDelayMs = 0 }) {
      const j = jobs.get(jobId); if (!j || j.status !== 'leased' || j.epoch !== epoch) return null;
      j.error = String(error ?? '').slice(0, 500); j.leaseExpiresAt = null; j.worker = null;
      if (j.attempts < j.maxAttempts) { j.status = 'queued'; j.nextAttemptAt = now + retryDelayMs; return { state: 'queued', attempts: j.attempts }; }
      j.status = timedOut ? 'timed_out' : 'failed'; j.finishedAt = now; return { state: j.status, attempts: j.attempts };
    },
    reclaimExpired(runId, { now = Date.now() }) { let n = 0; for (const j of all(runId)) if (j.status === 'leased' && j.leaseExpiresAt != null && j.leaseExpiresAt <= now) { j.status = 'queued'; j.worker = null; j.leaseExpiresAt = null; j.nextAttemptAt = 0; j.error = 'lease expired'; n++; } return n; },
    reclaimWorker(runId, worker) { let n = 0; for (const j of all(runId)) if (j.status === 'leased' && j.worker === worker) { j.status = 'queued'; j.worker = null; j.leaseExpiresAt = null; j.nextAttemptAt = 0; j.error = 'worker is gone'; n++; } return n; },
    cancel(runId, { now = Date.now() }) { let n = 0; for (const j of all(runId)) if (!TERMINAL.has(j.status)) { j.status = 'cancelled'; j.finishedAt = now; j.leaseExpiresAt = null; n++; } return n; },
    retime(runId, timeoutMs) { let n = 0; for (const j of all(runId)) if (j.status === 'queued') { j.timeoutMs = timeoutMs; n++; } return n; },
    requeueTerminal(runId, statuses) { let n = 0; for (const j of all(runId)) if (statuses.includes(j.status)) { Object.assign(j, { status: 'queued', worker: null, attempts: 0, nextAttemptAt: 0, leaseExpiresAt: null, finishedAt: null, error: null }); n++; } return n; },
    listJobs: (runId) => all(runId).map((j) => ({ ...j })).sort((a, b) => a.repoId.localeCompare(b.repoId)),
    getJob: (jobId) => (jobs.get(jobId) ? { ...jobs.get(jobId) } : null),
    close() {},
  };
  return store;
}

// ------------------------------------------------------------------------------------------------------- sqlite
const SCHEMA = `
CREATE TABLE IF NOT EXISTS fleet_runs (run_id TEXT PRIMARY KEY, organization TEXT NOT NULL, manifest_hash TEXT NOT NULL, config_hash TEXT NOT NULL, scanner_identity TEXT, created_at INTEGER NOT NULL, meta TEXT);
CREATE TABLE IF NOT EXISTS fleet_jobs (
  job_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES fleet_runs(run_id), repo_id TEXT NOT NULL, commit_sha TEXT, cache_key TEXT,
  status TEXT NOT NULL, worker TEXT, epoch INTEGER NOT NULL DEFAULT 0, lease_expires_at INTEGER, heartbeat_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, timeout_ms INTEGER NOT NULL, next_attempt_at INTEGER NOT NULL DEFAULT 0,
  artifact_sha256 TEXT, summary TEXT, error TEXT, created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, required INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS fleet_jobs_run_status ON fleet_jobs (run_id, status);
`;

async function createSqliteJobStore({ file }) {
  const { DatabaseSync } = await Promise.resolve(/* import() */).then(__webpack_require__.t.bind(__webpack_require__, 80099, 19));
  if (file !== ':memory:') node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(file), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  const tx = (fn) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; } };
  const q = (sql, ...p) => db.prepare(sql).all(...p);
  const one = (sql, ...p) => db.prepare(sql).get(...p);
  const run = (sql, ...p) => db.prepare(sql).run(...p);
  return {
    kind: 'sqlite', file,
    begin(r) { run('INSERT OR IGNORE INTO fleet_runs (run_id, organization, manifest_hash, config_hash, scanner_identity, created_at, meta) VALUES (?,?,?,?,?,?,?)', r.runId, r.organization, r.manifestHash, r.configHash, r.scannerIdentity ?? null, r.createdAt, JSON.stringify(r.meta ?? {})); return this.getRun(r.runId); },
    getRun(runId) { const r = one('SELECT * FROM fleet_runs WHERE run_id = ?', runId); return r ? { runId: r.run_id, organization: r.organization, manifestHash: r.manifest_hash, configHash: r.config_hash, scannerIdentity: r.scanner_identity, createdAt: r.created_at, meta: JSON.parse(r.meta ?? '{}') } : null; },
    listRuns() { return q('SELECT * FROM fleet_runs ORDER BY created_at DESC').map((r) => ({ runId: r.run_id, organization: r.organization, manifestHash: r.manifest_hash, createdAt: r.created_at })); },
    enqueue(runId, list, { now = Date.now() } = {}) {
      return tx(() => { let created = 0; for (const j of list) { const r = run('INSERT OR IGNORE INTO fleet_jobs (job_id, run_id, repo_id, commit_sha, cache_key, status, max_attempts, timeout_ms, created_at, required) VALUES (?,?,?,?,?,?,?,?,?,?)', j.jobId, runId, j.repoId, j.commit ?? null, j.cacheKey ?? null, 'queued', j.maxAttempts ?? 2, j.timeoutMs, now, j.required === false ? 0 : 1); created += Number(r.changes); } return created; });
    },
    claim(runId, { worker, leaseMs, now = Date.now() }) {
      return tx(() => {
        const j = one("SELECT job_id FROM fleet_jobs WHERE run_id = ? AND status = 'queued' AND next_attempt_at <= ? ORDER BY created_at, repo_id LIMIT 1", runId, now);
        if (!j) return null;
        run("UPDATE fleet_jobs SET status = 'leased', worker = ?, epoch = epoch + 1, attempts = attempts + 1, lease_expires_at = ?, heartbeat_at = ?, started_at = ?, error = NULL WHERE job_id = ?", worker, now + leaseMs, now, now, j.job_id);
        return jobOf(one('SELECT * FROM fleet_jobs WHERE job_id = ?', j.job_id));
      });
    },
    heartbeat(jobId, epoch, { now = Date.now(), leaseMs }) { return Number(run("UPDATE fleet_jobs SET heartbeat_at = ?, lease_expires_at = ? WHERE job_id = ? AND status = 'leased' AND epoch = ?", now, now + leaseMs, jobId, epoch).changes) === 1; },
    complete(jobId, epoch, { status = 'succeeded', artifactSha256 = null, summary = null, now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = ?, artifact_sha256 = ?, summary = ?, finished_at = ?, lease_expires_at = NULL, error = NULL WHERE job_id = ? AND status = 'leased' AND epoch = ?", status, artifactSha256, summary ? JSON.stringify(summary) : null, now, jobId, epoch).changes) === 1; },
    fail(jobId, epoch, { error, timedOut = false, now = Date.now(), retryDelayMs = 0 }) {
      return tx(() => {
        const j = one("SELECT attempts, max_attempts FROM fleet_jobs WHERE job_id = ? AND status = 'leased' AND epoch = ?", jobId, epoch);
        if (!j) return null;
        const msg = String(error ?? '').slice(0, 500);
        if (j.attempts < j.max_attempts) { run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = ?, error = ? WHERE job_id = ?", now + retryDelayMs, msg, jobId); return { state: 'queued', attempts: j.attempts }; }
        const st = timedOut ? 'timed_out' : 'failed';
        run('UPDATE fleet_jobs SET status = ?, worker = NULL, lease_expires_at = NULL, finished_at = ?, error = ? WHERE job_id = ?', st, now, msg, jobId);
        return { state: st, attempts: j.attempts };
      });
    },
    reclaimExpired(runId, { now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = 0, error = 'lease expired' WHERE run_id = ? AND status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?", runId, now).changes); },
    reclaimWorker(runId, worker) { return Number(run("UPDATE fleet_jobs SET status = 'queued', worker = NULL, lease_expires_at = NULL, next_attempt_at = 0, error = 'worker is gone' WHERE run_id = ? AND status = 'leased' AND worker = ?", runId, worker).changes); },
    cancel(runId, { now = Date.now() }) { return Number(run("UPDATE fleet_jobs SET status = 'cancelled', finished_at = ?, lease_expires_at = NULL WHERE run_id = ? AND status IN ('queued','leased')", now, runId).changes); },
    retime(runId, timeoutMs) { return Number(run("UPDATE fleet_jobs SET timeout_ms = ? WHERE run_id = ? AND status = 'queued'", timeoutMs, runId).changes); },
    requeueTerminal(runId, statuses) { return Number(run(`UPDATE fleet_jobs SET status = 'queued', worker = NULL, attempts = 0, next_attempt_at = 0, lease_expires_at = NULL, finished_at = NULL, error = NULL WHERE run_id = ? AND status IN (${statuses.map(() => '?').join(',')})`, runId, ...statuses).changes); },
    listJobs: (runId) => q('SELECT * FROM fleet_jobs WHERE run_id = ? ORDER BY repo_id', runId).map(jobOf),
    getJob: (jobId) => jobOf(one('SELECT * FROM fleet_jobs WHERE job_id = ?', jobId)),
    close() { try { db.close(); } catch { /* already closed */ } },
  };
}


/***/ }),

/***/ 81010:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   h: () => (/* binding */ summarizeLineage)
/* harmony export */ });
// A bounded summary of one repository's Code Boundaries graph (the Data Flow Explorer's `DataFlowGraph v1`), for the enterprise graph
// (PRD 4: "federate Code Boundaries across repositories"). The whole graph is not copied: a fleet of hundreds of repositories does not
// need each node, only what crosses a repository boundary or changes what the organization knows about it:
//   * the data classes that appear in the code (so a repository holding payment data is known to, even if the manifest forgot to say);
//   * the external destinations the code sends data to, by host;
//   * the queue topics it publishes to or consumes from;
//   * the stores it touches, by host/database/table name;
//   * counts, including flows that carry sensitive classes across a trust boundary.
// Pure; hostile input (the graph came out of a scan of someone's code), so every string is bounded and shape-checked.
const MAX_ITEMS = 64;
const SENSITIVE = new Set(['pii', 'phi', 'pci', 'fin', 'credentials']);
const arr = (v) => (Array.isArray(v) ? v : []);
const clean = (v, max = 120) => (typeof v === 'string' && v.length > 0 && v.length <= max && !/[\s\u0000-\u001f]/.test(v) ? v : null);

function hostOf(literal) {
  if (typeof literal !== 'string') return null;
  try { const h = new URL(literal).hostname.toLowerCase(); return clean(h, 253); } catch { /* not a URL */ }
  const bare = literal.toLowerCase().replace(/:\d+$/, '');
  return /^[a-z0-9][a-z0-9.-]{0,252}$/.test(bare) ? bare : null;
}

function summarizeLineage(graph) {
  if (!graph || typeof graph !== 'object') return null;
  const classes = new Set();
  for (const d of arr(graph.dataElements)) for (const c of arr(d?.dataClasses)) { if (typeof c !== 'string') continue; const l = clean(c.toLowerCase(), 31); if (l && /^[a-z][a-z0-9-]*$/.test(l)) classes.add(l); }
  const ext = new Map(); const queues = new Map(); const stores = new Map();
  for (const n of arr(graph.nodes)) {
    if (!n || typeof n !== 'object') continue;
    if (n.kind === 'external') {
      const host = hostOf(n.destination?.literalValue);
      const key = `${n.subtype ?? 'external'}|${host ?? ''}`;
      if (!ext.has(key) && ext.size < MAX_ITEMS) ext.set(key, { subtype: clean(n.subtype, 60) ?? 'external', host });
    } else if (n.kind === 'queue') {
      const topic = clean(n.queueDetail?.topic, 120); const op = n.queueDetail?.operation === 'consume' || n.queueDetail?.operation === 'receive' ? 'consume' : 'publish';
      if (topic && queues.size < MAX_ITEMS) queues.set(`${topic}|${op}`, { topic, operation: op });
    } else if (n.kind === 'store') {
      const d = n.storeDetail ?? {};
      const item = { subtype: clean(n.subtype, 60) ?? 'store', host: hostOf(d.host), database: clean(d.database, 120), table: clean(d.table, 120) };
      const key = JSON.stringify(item);
      if (stores.size < MAX_ITEMS) stores.set(key, item);
    }
  }
  const edges = arr(graph.edges);
  const crossing = new Set(edges.filter((e) => arr(e?.boundaryCrossings).length).map((e) => e.id));
  const dataById = new Map(arr(graph.dataElements).map((d) => [d?.id, d]));
  const sensitiveCrossing = arr(graph.flows).filter((f) => arr(f?.edgeIds).some((id) => crossing.has(id)) && arr(f?.dataElementIds).some((id) => arr(dataById.get(id)?.dataClasses).some((c) => SENSITIVE.has(String(c).toLowerCase())))).length;
  return {
    schema: 'agentic-security/fleet-lineage-summary', version: 1,
    dataClasses: [...classes].sort().slice(0, MAX_ITEMS),
    externalDestinations: [...ext.values()],
    queues: [...queues.values()],
    stores: [...stores.values()],
    counts: { nodes: arr(graph.nodes).length, edges: edges.length, flows: arr(graph.flows).length, boundaryCrossingEdges: crossing.size, sensitiveFlowsCrossingBoundary: sensitiveCrossing },
  };
}


/***/ }),

/***/ 75435:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Vp: () => (/* binding */ renderOrgHealth),
/* harmony export */   WB: () => (/* binding */ computeOrgHealth)
/* harmony export */ });
/* unused harmony export ASSURANCE */
/* harmony import */ var _job_store_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(20121);
// Organization-level scan health (PRD 4, requirement 9). Pure.
//
//   Repositories requested: 1,250
//   Complete: 1,228   Partial: 11   Failed: 6   Timed out: 5   Not run: ...
//
// The one rule: an organization is not GREEN while a required repository has no usable result. A repository that was requested but
// has no job, was cancelled, is still queued or leased, failed or timed out is counted under its own heading and can never disappear
// from the total. `partial` (the scan finished but the engine itself reported a degraded scan) keeps the organization out of GREEN
// as well, because a partial scan is not evidence of a clean repository.
//
//   green      every required repository has a complete result and no optional repository has a problem
//   degraded   every required repository has a result, but some result is partial, or an optional repository has a problem
//   red        at least one required repository has no result


const ASSURANCE = Object.freeze(['green', 'degraded', 'red']);

function computeOrgHealth({ manifest, jobs }) {
  const byRepo = new Map(jobs.map((j) => [j.repoId, j]));
  const counts = { requested: manifest.repositories.length, complete: 0, partial: 0, failed: 0, timedOut: 0, cancelled: 0, notRun: 0 };
  const repos = [];
  for (const r of manifest.repositories) {
    const j = byRepo.get(r.id);
    let state;
    if (!j) state = 'not-run';
    else if (j.status === 'succeeded') state = 'complete';
    else if (j.status === 'partial') state = 'partial';
    else if (j.status === 'failed') state = 'failed';
    else if (j.status === 'timed_out') state = 'timed-out';
    else if (j.status === 'cancelled') state = 'cancelled';
    else state = 'not-run'; // queued or leased: no result yet
    counts[{ complete: 'complete', partial: 'partial', failed: 'failed', 'timed-out': 'timedOut', cancelled: 'cancelled', 'not-run': 'notRun' }[state]]++;
    repos.push({ id: r.id, required: r.required, state, attempts: j?.attempts ?? 0, error: j?.error ?? null, cached: !!j?.summary?.cached, findings: j?.summary?.total ?? null, jobStatus: j?.status ?? null, finished: j ? (0,_job_store_js__WEBPACK_IMPORTED_MODULE_0__/* .isTerminal */ .Hd)(j.status) : false });
  }
  const noResult = (x) => !['complete', 'partial'].includes(x.state);
  const requiredMissing = repos.filter((x) => x.required && noResult(x));
  const requiredPartial = repos.filter((x) => x.required && x.state === 'partial');
  const optionalProblems = repos.filter((x) => !x.required && x.state !== 'complete');
  const assurance = requiredMissing.length ? 'red' : (requiredPartial.length || optionalProblems.length) ? 'degraded' : 'green';
  const reasons = [
    ...(requiredMissing.length ? [`${requiredMissing.length} required ${requiredMissing.length === 1 ? 'repository has' : 'repositories have'} no result: ${requiredMissing.slice(0, 8).map((x) => `${x.id} (${x.state})`).join(', ')}${requiredMissing.length > 8 ? ', ...' : ''}`] : []),
    ...(requiredPartial.length ? [`${requiredPartial.length} required ${requiredPartial.length === 1 ? 'repository was' : 'repositories were'} only partially scanned: ${requiredPartial.map((x) => x.id).join(', ')}`] : []),
    ...(optionalProblems.length ? [`${optionalProblems.length} optional ${optionalProblems.length === 1 ? 'repository has' : 'repositories have'} a problem: ${optionalProblems.map((x) => `${x.id} (${x.state})`).join(', ')}`] : []),
  ];
  return { counts, assurance, reasons, repositories: repos };
}

const n = (x) => x.toLocaleString('en-US');
function renderOrgHealth(h) {
  const c = h.counts;
  const L = [`Repositories requested: ${n(c.requested)}`, `Complete: ${n(c.complete)}`, `Partial: ${n(c.partial)}`, `Failed: ${n(c.failed)}`, `Timed out: ${n(c.timedOut)}`];
  if (c.cancelled) L.push(`Cancelled: ${n(c.cancelled)}`);
  if (c.notRun) L.push(`Not run: ${n(c.notRun)}`);
  L.push('', `Assurance: ${h.assurance.toUpperCase()}`, ...h.reasons.map((r) => `  ${r}`));
  return L.join('\n');
}


/***/ }),

/***/ 75846:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   NJ: () => (/* binding */ repoFingerprint),
/* harmony export */   aR: () => (/* binding */ writeCache),
/* harmony export */   fs: () => (/* binding */ scannerIdentity),
/* harmony export */   k$: () => (/* binding */ cacheKey),
/* harmony export */   xe: () => (/* binding */ readCache)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(77598);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31421);
/* harmony import */ var node_url__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(73136);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(31174);
// The content-addressed scan cache (PRD 4, requirement 5). A repository's scan result is reused only when EVERYTHING that could
// change it is unchanged: the commit (and any uncommitted change), the lockfiles, the scan configuration and the scanner itself.
//
//   key = sha256( repository fingerprint, lockfile digests, configuration, scanner identity )
//
// Anything that cannot be determined makes the key `null`, and a null key means "do not cache": an unknown input must never be
// treated as an unchanged one. The scanner identity is the package version plus the SHA-256 recorded for the shipped bundle, so a
// change to scanner logic changes the key. A source checkout with no built bundle has no such identity and therefore never reuses
// a cached result.
//
// A cached record carries its own digest; one that was edited, truncated or does not match its key is a miss, never a hit.







const LOCKFILES = Object.freeze(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'go.sum', 'Cargo.lock', 'Pipfile.lock', 'poetry.lock', 'requirements.txt', 'Gemfile.lock', 'composer.lock', 'flake.lock', 'cabal.project.freeze', 'stack.yaml.lock']);
const SKIP = new Set(['.git', 'node_modules', _state_dir_js__WEBPACK_IMPORTED_MODULE_5__/* .STATE_DIR_NAME */ .Ky]);
const sha = (s) => (0,node_crypto__WEBPACK_IMPORTED_MODULE_2__.createHash)('sha256').update(s).digest('hex');
const MAX_FILES = 5000; const MAX_FILE_BYTES = 2 * 1024 * 1024; const MAX_TOTAL_BYTES = 128 * 1024 * 1024;

function git(repo, args, timeout = 10000) {
  const r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_3__.spawnSync)('git', ['-C', repo, ...args], { encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  return r.error || r.status !== 0 ? null : r.stdout;
}

function treeDigest(root) {
  const h = (0,node_crypto__WEBPACK_IMPORTED_MODULE_2__.createHash)('sha256'); let files = 0; let total = 0; let complete = true;
  const walk = (d, rel) => {
    let ents = [];
    try { ents = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); } catch { complete = false; return; }
    for (const e of ents) {
      if (!complete) return;
      if (SKIP.has(e.name)) continue;
      const p = node_path__WEBPACK_IMPORTED_MODULE_1__.join(d, e.name); const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { h.update(`L ${r}\0`); continue; }
      if (e.isDirectory()) { walk(p, r); continue; }
      if (!e.isFile()) continue;
      if (++files > MAX_FILES) { complete = false; return; }
      let st; try { st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p); } catch { complete = false; return; }
      total += st.size;
      if (total > MAX_TOTAL_BYTES) { complete = false; return; }
      if (st.size > MAX_FILE_BYTES) { h.update(`B ${r} ${st.size}\0`); continue; }
      try { h.update(`F ${r}\0${sha(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(p))}\0`); } catch { complete = false; return; }
    }
  };
  walk(root, '');
  return complete ? h.digest('hex') : null;
}

/** What identifies this repository's content right now, or null parts where it cannot be determined. */
function repoFingerprint(repoPath) {
  const head = git(repoPath, ['rev-parse', 'HEAD']);
  const commit = head ? head.trim() : null;
  let content = null; let dirty = null;
  if (commit) {
    const status = git(repoPath, ['status', '--porcelain=v1', '-uall']);
    dirty = status == null ? null : status.trim().length > 0;
    if (dirty === false) content = `git:${commit}`;
    else if (dirty === true) { const t = treeDigest(repoPath); content = t ? `git+worktree:${commit}:${t}` : null; }
  } else { const t = treeDigest(repoPath); content = t ? `tree:${t}` : null; }
  const lock = {};
  for (const f of LOCKFILES) { try { const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(repoPath, f)); if (st.isFile() && st.size <= 32 * 1024 * 1024) lock[f] = sha(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(repoPath, f))); } catch { /* absent */ } }
  return { commit, dirty, content, lockfiles: lock };
}

/** Package version + the bundle's recorded hash. Null when the scanner cannot be identified (a source checkout), which disables the cache. */
function scannerIdentity() {
  try {
    const here = node_path__WEBPACK_IMPORTED_MODULE_1__.dirname((0,node_url__WEBPACK_IMPORTED_MODULE_4__.fileURLToPath)(import.meta.url));
    for (const base of [node_path__WEBPACK_IMPORTED_MODULE_1__.join(here, '..', '..', '..'), node_path__WEBPACK_IMPORTED_MODULE_1__.join(here, '..', '..', '..', '..')]) {
      const pkg = node_path__WEBPACK_IMPORTED_MODULE_1__.join(base, 'package.json');
      const sidecar = node_path__WEBPACK_IMPORTED_MODULE_1__.join(base, 'dist', 'agentic-security.mjs.sha256');
      if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(pkg) && node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(sidecar)) {
        const version = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(pkg, 'utf8')).version;
        const digest = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(sidecar, 'utf8').trim().split(/\s+/)[0];
        if (version && /^[0-9a-f]{64}$/i.test(digest)) return `${version}+${digest}`;
      }
    }
  } catch { /* unknown */ }
  return null;
}

function cacheKey({ fingerprint, config, identity }) {
  if (!fingerprint?.content || !identity) return null;
  return sha(JSON.stringify({ c: fingerprint.content, l: fingerprint.lockfiles, cfg: config, id: identity }));
}

function readCache(dir, key) {
  if (!key || !/^[0-9a-f]{64}$/.test(key)) return null;
  try {
    const doc = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, `${key}.json`), 'utf8'));
    if (doc.key !== key) return null;
    const { digest, ...rest } = doc;
    return digest === sha(JSON.stringify(rest)) ? doc : null;
  } catch { return null; }
}

function writeCache(dir, key, payload) {
  if (!key || !/^[0-9a-f]{64}$/.test(key)) return false;
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const body = { schema: 'agentic-security/fleet-scan-cache', version: 1, key, ...payload };
    const doc = { ...body, digest: sha(JSON.stringify(body)) };
    const tmp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, `.${key}.${process.pid}.tmp`);
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(tmp, JSON.stringify(doc), { mode: 0o600 });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.renameSync(tmp, node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, `${key}.json`));
    return true;
  } catch { return false; }
}


/***/ }),

/***/ 3398:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   K: () => (/* binding */ END),
/* harmony export */   Q: () => (/* binding */ BEGIN)
/* harmony export */ });
/* harmony import */ var _fleet_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(80313);
/* harmony import */ var _runScan_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(45950);
/* harmony import */ var _lineage_summary_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(81010);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_runScan_js__WEBPACK_IMPORTED_MODULE_1__]);
_runScan_js__WEBPACK_IMPORTED_MODULE_1__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// Child-process entry for ONE repository's scan inside a fleet run (PRD 4, requirement 4: one hung repository must not stop the
// fleet). `node scan-child.js <repoPath>`. It exists as its own process so the controller can kill a scan that does not finish,
// together with everything the scan started; an in-process scan cannot be interrupted.
//
// It runs the scan through the existing `runFleet` for a single repository, so the per-repository entry (finding counts, owners
// from CODEOWNERS, scan health, policy drift, provenance debt) is exactly what a fleet entry has always been, and prints that entry
// plus a slim copy of the findings between markers. Scan state writes are disabled (`AGENTIC_SECURITY_NO_STATE=1`, set by the
// controller): scanning a repository for the fleet must not change that repository.




const BEGIN = '@@FLEET-SCAN-BEGIN@@';
const END = '@@FLEET-SCAN-END@@';
const MAX_FINDINGS = 5000;

const slim = (f) => ({ id: f.id ?? null, stableId: f.stableId ?? null, severity: f.severity ?? null, cwe: f.cwe ?? null, family: f.family ?? null, vuln: f.vuln ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, parser: f.parser ?? null });

async function main(repoPath) {
  let captured = null;
  const res = await (0,_fleet_js__WEBPACK_IMPORTED_MODULE_0__/* .runFleet */ .gI)({ repos: [repoPath], concurrency: 1, resume: false, runScan: async (p) => { const r = await (0,_runScan_js__WEBPACK_IMPORTED_MODULE_1__.runScan)(p, { provenance: false }); captured = r.scan; return r; } });
  const entry = res.results?.[0];
  if (!entry) throw new Error('the scan produced no entry');
  const findings = (captured?.findings ?? []).slice(0, MAX_FINDINGS).map(slim);
  // the Code Boundaries graph exists only when the controller asked for it (AGENTIC_SECURITY_LINEAGE_DEEP=1); it is summarized, never copied whole
  const lineage = process.env.AGENTIC_SECURITY_LINEAGE_DEEP === '1' ? (0,_lineage_summary_js__WEBPACK_IMPORTED_MODULE_2__/* .summarizeLineage */ .h)(captured?.lineageGraph) : null;
  process.stdout.write(`${BEGIN}${JSON.stringify({ entry, findings, findingsTruncated: (captured?.findings?.length ?? 0) > MAX_FINDINGS, lineage })}${END}`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main(process.argv[2]).then(() => process.exit(0), (e) => { process.stderr.write(String(e?.stack || e).slice(0, 4000)); process.exit(1); });
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 23736:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildPolicyBundle: () => (/* binding */ buildPolicyBundle),
/* harmony export */   ensurePolicyKeyPair: () => (/* binding */ ensurePolicyKeyPair),
/* harmony export */   loadPolicyBundles: () => (/* binding */ loadPolicyBundles),
/* harmony export */   loadPolicyPublicKey: () => (/* binding */ loadPolicyPublicKey),
/* harmony export */   rE: () => (/* binding */ computePolicyDrift),
/* harmony export */   resolveEffectivePolicy: () => (/* binding */ resolveEffectivePolicy),
/* harmony export */   signPolicyBundle: () => (/* binding */ signPolicyBundle)
/* harmony export */ });
/* unused harmony exports POLICY_BUNDLE_SCHEMA, SCOPES, canonicalPolicyBytes, verifyPolicyBundle */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
/* harmony import */ var _evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(98317);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(31174);
// Signed, portable policy bundles (assurance-hardening PRD FR-1001).
//
// "Support signed portable policy bundles with organization, repository, and
// environment inheritance" | "Tampered or expired policy is rejected;
// effective policy is explainable."
//
// WHY REUSE evidence-bundle.js's Ed25519 SCHEME, NOT integrity.js's HMAC
// -------------------------------------------------------------------------
// A policy bundle is authored by one party (typically a central security
// team, "the organization") and distributed to many repositories that never
// had the signing key. integrity.js's per-install symmetric HMAC is
// tamper-evidence for the SAME install that wrote it — a different install
// verifying a bundle it didn't sign is exactly the case that scheme cannot
// serve. evidence-bundle.js already solved this for findings: Ed25519,
// verify with only the public key. This module reuses that primitive
// directly (canonicalisation shape, allowlist-signed-fields discipline,
// exclusive-create key generation) rather than inventing a third signing
// mechanism, per this session's own established "survey before building a
// parallel primitive" practice (see D-0023/D-0025 for the same discipline
// applied to identity and exception mechanisms respectively).
//
// EA-03 LESSON, APPLIED HERE FROM THE START
// -------------------------------------------------------------------------
// evidence-bundle.js's own history (see its EA-03 comment) is the reason
// `canonicalPolicyBytes` signs an explicit ALLOWLIST and `verifyPolicyBundle`
// REJECTS any top-level key outside it: a bundle with a field stapled on
// after signing must fail verification, not silently pass with the addition
// unverified. Getting this right on the first pass — rather than discovering
// the gap the way evidence-bundle.js did — is the entire point of writing it
// down here.
//
// SCOPE — WHAT THIS MODULE DOES NOT DO
// -------------------------------------------------------------------------
// It does not invent a policy SCHEMA — `policy` is an opaque object; whatever
// keys a bundle carries (egress rules, severity floors, approved providers,
// anything else this repo already treats as policy) are merged the same way.
// It does not implement deep/recursive merging — inheritance is shallow,
// top-level-key override (organization -> repository -> environment, most
// specific wins per key), matching how every other flat policy config file
// in this repo (egress-policy.yml, compliance-severity-policy.json, …) is
// already shaped. A future consumer needing nested-key inheritance is new,
// separate scope, not assumed here.








const POLICY_BUNDLE_SCHEMA = 'agentic-security/policy-bundle@1';

const SCOPES = ['organization', 'repository', 'environment'];
// Inheritance order — later entries override earlier ones, per top-level key.
const INHERITANCE_ORDER = ['organization', 'repository', 'environment'];

function keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME || node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.config');
  return node_path__WEBPACK_IMPORTED_MODULE_2__.join(xdg, 'agentic-security', 'policy-bundles');
}

/** A SEPARATE Ed25519 keypair from evidence-bundle.js's finding-attestation
 * key — signing "this policy is authentic" and "this finding really came
 * from a scan run by me" are different trust domains and must not share a
 * key. Reuses evidence-bundle.js's hardened, race-safe generation logic
 * directly (its exclusive-create collision handling is the kind of code
 * worth NOT re-implementing) rather than duplicating it — the separation
 * that matters is the DIRECTORY (`policy-bundles/`, isolated from
 * evidence-bundle.js's own key dir), not the leaf filenames, which are
 * `attest-key.pem`/`attest-key.pub.pem` regardless of caller (a
 * evidence-bundle.js internal, not overridable here) — a readability wart,
 * not a security one, since the directory is what prevents key reuse. */
function ensurePolicyKeyPair(dir = keyDir()) {
  return (0,_evidence_bundle_js__WEBPACK_IMPORTED_MODULE_4__.ensureKeyPair)(dir);
}

/**
 * Deterministic JSON, keys sorted at every level — identical algorithm to
 * evidence-bundle.js's canonicalJson (duplicated rather than imported: it is
 * a pure, three-line function, and importing it would couple this module's
 * signature format to evidence-bundle.js's internals for no real benefit).
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

// The complete set of fields a legitimately-built bundle carries, BEFORE
// signing. This is the signed allowlist AND (in verifyPolicyBundle) the
// complete set of keys a signed bundle is permitted to have alongside
// `signature` — see the EA-03 note above for why both matter.
const BUNDLE_FIELDS = ['schema', 'scope', 'policy', 'issuedAt', 'expiresAt'];
const BUNDLE_TOP_LEVEL_KEYS = new Set([...BUNDLE_FIELDS, 'signature']);

function canonicalPolicyBytes(bundle) {
  const signed = {};
  for (const k of BUNDLE_FIELDS) signed[k] = bundle[k] ?? null;
  return Buffer.from(canonicalJson(signed), 'utf8');
}

/**
 * Build an unsigned bundle. `policy` is caller-supplied and opaque — this
 * module does not validate its shape, only its provenance and freshness.
 */
function buildPolicyBundle(scope, policy, { issuedAt, expiresAt } = {}) {
  if (!SCOPES.includes(scope)) return null;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return null;
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    scope,
    policy,
    issuedAt: issuedAt ?? new Date().toISOString(),
    expiresAt: expiresAt ?? null,
  };
}

/** Sign a bundle. Returns a new object; the input is not mutated. */
function signPolicyBundle(bundle, privateKeyPem) {
  const sig = node_crypto__WEBPACK_IMPORTED_MODULE_3__.sign(null, canonicalPolicyBytes(bundle), privateKeyPem);
  return {
    ...bundle,
    signature: { algorithm: 'ed25519', canonicalisation: POLICY_BUNDLE_SCHEMA, value: sig.toString('base64') },
  };
}

/**
 * Verify a bundle: signature authenticity AND freshness. Never throws — a
 * malformed or tampered bundle from an untrusted source (a repo checking out
 * whatever an org distributed) is an expected input, not exceptional.
 *
 * @returns {{ok: boolean, reason: string|null}}
 */
function verifyPolicyBundle(bundle, publicKeyPem, { now = Date.now() } = {}) {
  if (!bundle || typeof bundle !== 'object') return { ok: false, reason: 'bundle is not an object' };
  if (bundle.schema !== POLICY_BUNDLE_SCHEMA) return { ok: false, reason: `unrecognised schema: ${bundle.schema}` };
  if (!SCOPES.includes(bundle.scope)) return { ok: false, reason: `unrecognised scope: ${bundle.scope}` };
  const unknownKeys = Object.keys(bundle).filter(k => !BUNDLE_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = bundle.signature;
  if (!sig?.value) return { ok: false, reason: 'bundle is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  let sigOk = false;
  try {
    sigOk = node_crypto__WEBPACK_IMPORTED_MODULE_3__.verify(null, canonicalPolicyBytes(bundle), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  if (!sigOk) return { ok: false, reason: 'signature does not match the bundle contents — it was modified after signing' };
  if (bundle.expiresAt) {
    const exp = Date.parse(bundle.expiresAt);
    if (!Number.isFinite(exp)) return { ok: false, reason: `expiresAt is not a valid date: ${bundle.expiresAt}` };
    if (exp < now) return { ok: false, reason: `policy expired on ${bundle.expiresAt}` };
  }
  return { ok: true, reason: null };
}

/**
 * Merge verified bundles into one effective policy, in inheritance order
 * (organization -> repository -> environment; most specific wins per key).
 * A tampered or expired bundle is EXCLUDED from the merge (rejected, not
 * silently dropped — its scope and reason are reported so a rejection is
 * visible, not just absent). `provenance[key]` names which scope's bundle
 * last set that key — the "effective policy is explainable" half of the
 * acceptance criterion.
 *
 * @param {Array<{scope: string, bundle: object}>} entries
 * @param {string} publicKeyPem
 * @returns {{effective: object, provenance: Record<string,string>,
 *   accepted: string[], rejected: Array<{scope:string, reason:string}>}}
 */
function resolveEffectivePolicy(entries, publicKeyPem, { now = Date.now() } = {}) {
  const byScope = new Map();
  for (const e of entries || []) {
    if (e && SCOPES.includes(e.scope)) byScope.set(e.scope, e.bundle);
  }
  const effective = {};
  const provenance = {};
  const accepted = [];
  const rejected = [];
  for (const scope of INHERITANCE_ORDER) {
    const bundle = byScope.get(scope);
    if (!bundle) continue;
    const v = verifyPolicyBundle(bundle, publicKeyPem, { now });
    if (!v.ok) { rejected.push({ scope, reason: v.reason }); continue; }
    accepted.push(scope);
    for (const [k, val] of Object.entries(bundle.policy)) {
      effective[k] = val;
      provenance[k] = scope;
    }
  }
  return { effective, provenance, accepted, rejected };
}

/**
 * Load whichever policy bundle files exist under
 * `.agentic-security/policy-bundles/{organization,repository,environment}.json`.
 * Degrades gracefully — a missing directory or missing/malformed individual
 * file is simply absent from the result, never thrown. Read-first-in-try/
 * catch throughout (no existsSync-then-readFileSync — D-0012/D-0022).
 */
function loadPolicyBundles(scanRoot) {
  if (!scanRoot) return [];
  const entries = [];
  for (const scope of SCOPES) {
    let fp;
    try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.statePath)(scanRoot, 'policy-bundles', `${scope}.json`); } catch { continue; }
    let raw;
    try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { continue; }
    try {
      const bundle = JSON.parse(raw);
      if (bundle && typeof bundle === 'object') entries.push({ scope, bundle });
    } catch { /* malformed — skip, do not throw */ }
  }
  return entries;
}

/**
 * Read the operator-supplied public key an org distributes alongside its
 * bundles, from `.agentic-security/policy-bundle-public-key.pem`. Returns
 * null (not a throw) if absent or unreadable — resolution then rejects
 * every bundle for lack of a key, same as any other "no public key
 * supplied" case in verifyPolicyBundle.
 */
function loadPolicyPublicKey(scanRoot) {
  if (!scanRoot) return null;
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_5__.statePath)(scanRoot, 'policy-bundle-public-key.pem'); } catch { return null; }
  try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return null; }
}

/**
 * FR-1006 ("policy drift"): does this repository's LOCALLY resolved effective
 * policy diverge from what the organization-scope bundle alone specifies —
 * and is anything the repo is relying on actually being rejected (tampered
 * or expired) rather than enforced? Both are GOVERNANCE gaps, distinct from
 * risk findings, which is the exact distinction FR-1006's acceptance
 * criterion asks fleet output to make.
 *
 * No bundles configured at all is a no-op (`null`), matching this session's
 * established convention: drift can only be reported relative to a
 * baseline, and a repo with no organization bundle has no baseline to drift
 * from.
 *
 * @returns {{accepted: string[], rejected: Array<{scope,reason}>,
 *   overrides: Array<{key, organizationValue, effectiveValue, overriddenBy}>}
 *   | null}
 */
function computePolicyDrift(scanRoot) {
  const entries = loadPolicyBundles(scanRoot);
  if (!entries.length) return null;
  const publicKeyPem = loadPolicyPublicKey(scanRoot);
  const { effective, provenance, accepted, rejected } = resolveEffectivePolicy(entries, publicKeyPem);

  const overrides = [];
  const orgEntry = entries.find(e => e.scope === 'organization');
  if (orgEntry && accepted.includes('organization')) {
    for (const [key, organizationValue] of Object.entries(orgEntry.bundle.policy || {})) {
      const overriddenBy = provenance[key];
      if (overriddenBy && overriddenBy !== 'organization' && !_deepEqual(effective[key], organizationValue)) {
        overrides.push({ key, organizationValue, effectiveValue: effective[key], overriddenBy });
      }
    }
  }
  return { accepted, rejected, overrides };
}

function _deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}


/***/ })

};
