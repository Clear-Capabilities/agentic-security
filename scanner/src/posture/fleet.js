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

import fs from 'node:fs';
import path from 'node:path';
import { computePolicyDrift } from './policy-bundle.js';

const SCHEMA = 'agentic-security/fleet-state@1';

/** Read a checkpoint, or an empty one. Never throws. */
export function loadFleetState(stateFile) {
  try {
    const j = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    if (j && j.schema === SCHEMA) return j;
  } catch { /* absent or unreadable -> start clean */ }
  return { schema: SCHEMA, completed: {}, startedAt: null };
}

function _saveFleetState(stateFile, state) {
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
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
export function ownersFor(codeownersText, filePath) {
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
    try { return fs.readFileSync(path.join(repoRoot, rel), 'utf8'); } catch { /* next */ }
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
export async function runFleet({
  repos = [], concurrency = 4, stateFile, runScan,
  resume = true, previous = null, onProgress = () => {},
} = {}) {
  if (typeof runScan !== 'function') {
    return { ok: false, reason: 'no runScan supplied' };
  }
  const state = (resume && stateFile) ? loadFleetState(stateFile) : { schema: SCHEMA, completed: {}, startedAt: null };
  const results = [];
  const skipped = [];

  const queue = repos.filter((r) => {
    if (resume && state.completed[r]) { skipped.push(r); return false; }
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
        try { policyDrift = computePolicyDrift(repo); } catch { /* best-effort — never fail a repo's scan over drift reporting */ }
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
export function rollupFleet(results, previous = null) {
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
export function renderFleetSummary(rollup) {
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
  return `${head}${rollup.scanned} repo(s) scanned, ${rollup.total} finding(s)`
    + `${sev ? ` (${sev})` : ''}, ${rollup.proven} execution-proven.${nf}${govClause}${provClause}`;
}

/**
 * A self-contained rollup page. No network, no scripts, no fonts — it must
 * render from local artifacts on an air-gapped machine (PRD AC3).
 */
export function renderFleetHtml(rollup, results) {
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

export const _internals = { SCHEMA, SEVERITIES, _matchesGlob, _summarise, _provenanceDebtForRepo };
