// Vulnerability exposure window (PRD 7, requirement 5): combine WHEN the flaw entered the code, WHEN a build containing it
// first ran, WHEN the fix was committed and deployed, and WHAT telemetry exists, into the span that can actually be hunted.
//
// Every date is sourced (provenance, a deployment record, a git commit, a hunt's own telemetry window). A date that has no
// source is reported as unknown and listed under `unknowns`; the window that depends on it is then `partial`, or
// `unavailable`, and the output never fills a gap with an assumption. Part of the exposure that predates the telemetry is
// reported as `unobservableBefore`: it happened, and nothing here can say whether it was exploited.
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

export const MAX_DEPLOYMENTS = 1000;
const SHA_RE = /^[0-9a-f]{7,64}$/i;
const ts = (v) => { if (v == null) return null; const t = Date.parse(v); return Number.isNaN(t) ? null : t; };
const iso = (t) => (t == null ? null : new Date(t).toISOString());

/** Parse a deployment-history file. Returns {deployments, problems}. Unusable entries are listed, never silently dropped. */
export function loadDeployments(file, { environment = null } = {}) {
  const problems = [];
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return { deployments: [], problems: [`could not read deployment history: ${e.code || e.message}`] }; }
  const list = Array.isArray(raw) ? raw : Array.isArray(raw?.deployments) ? raw.deployments : null;
  if (!list) return { deployments: [], problems: ['deployment history must be a list, or an object with a "deployments" list'] };
  if (list.length > MAX_DEPLOYMENTS) problems.push(`only the first ${MAX_DEPLOYMENTS} of ${list.length} deployments were read`);
  const deployments = [];
  list.slice(0, MAX_DEPLOYMENTS).forEach((d, i) => {
    if (!d || typeof d !== 'object') { problems.push(`deployment ${i}: not an object`); return; }
    if (typeof d.commit !== 'string' || !SHA_RE.test(d.commit)) { problems.push(`deployment ${i}: commit must be a hex sha`); return; }
    if (ts(d.deployedAt) == null) { problems.push(`deployment ${i}: deployedAt is not a date`); return; }
    if (environment && d.environment !== environment) return;
    deployments.push({ commit: d.commit.toLowerCase(), deployedAt: iso(ts(d.deployedAt)), environment: typeof d.environment === 'string' ? d.environment.slice(0, 40) : null, artifactDigest: typeof d.artifactDigest === 'string' ? d.artifactDigest.slice(0, 80) : null });
  });
  return { deployments, problems };
}

function git(repo, args, timeoutMs = 15000) {
  const r = spawnSync('git', args, { cwd: repo, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 20 });
  return r.error || r.status === null ? { ok: false, status: null, out: '' } : { ok: true, status: r.status, out: r.stdout.trim() };
}
/** true / false / null (null: git could not answer, e.g. an unknown commit or a shallow clone). */
export function isAncestor(repo, ancestor, descendant) {
  const r = git(repo, ['merge-base', '--is-ancestor', ancestor, descendant]);
  if (!r.ok) return null;
  return r.status === 0 ? true : r.status === 1 ? false : null;
}
export function commitDate(repo, sha) {
  const r = git(repo, ['show', '-s', '--format=%cI', sha]);
  return r.ok && r.status === 0 && r.out ? iso(ts(r.out)) : null;
}

/** True only when the NEWEST recorded deployment is one that contains the flaw: a statement about the record, not about today. */
function stillExposed(deployments, vulnerable) {
  if (!deployments.length || !vulnerable.length) return false;
  const newest = [...deployments].sort((a, b) => Date.parse(b.deployedAt) - Date.parse(a.deployedAt))[0];
  return vulnerable.some((d) => d.commit === newest.commit && d.deployedAt === newest.deployedAt);
}

export function computeExposureWindow({ finding, repo, deployments: rawDeployments = [], deploymentProblems = [], fixCommit = null, telemetry = null, deps = {} } = {}) {
  // callers may pass records that did not come through loadDeployments; normalise dates so every output is comparable
  const deployments = rawDeployments.filter((d) => d && ts(d.deployedAt) != null).map((d) => ({ ...d, deployedAt: iso(ts(d.deployedAt)) }));
  const anc = deps.isAncestor ?? ((a, d) => isAncestor(repo, a, d));
  const cdate = deps.commitDate ?? ((sha) => commitDate(repo, sha));
  const unknowns = [];
  const origin = finding?.findingProvenance?.findingOrigin ?? null;
  const introCommit = origin?.commit ?? null;
  const introducedAt = iso(ts(origin?.authorDate ?? origin?.committerDate));
  if (!introCommit) unknowns.push('introduction commit (the finding has no resolved origin)');
  else if (!introducedAt) unknowns.push('introduction date');

  const fixAt = fixCommit ? cdate(fixCommit) : null;
  if (!fixCommit) unknowns.push('fix commit (not supplied)');
  else if (!fixAt) unknowns.push('fix commit date (the commit could not be read)');

  const unresolved = [];
  const vulnerable = []; const fixed = [];
  if (!deployments.length) unknowns.push('deployment history (none supplied)');
  for (const d of deployments) {
    if (!introCommit) break;
    const hasBug = anc(introCommit, d.commit);
    if (hasBug === null) { unresolved.push({ commit: d.commit, deployedAt: d.deployedAt, reason: 'ancestry could not be determined' }); continue; }
    const hasFix = fixCommit ? anc(fixCommit, d.commit) : false;
    if (fixCommit && hasFix === null) { unresolved.push({ commit: d.commit, deployedAt: d.deployedAt, reason: 'fix ancestry could not be determined' }); continue; }
    if (hasBug && !hasFix) vulnerable.push(d);
    if (hasFix) fixed.push(d);
  }
  if (unresolved.length) unknowns.push(`${unresolved.length} deployment(s) whose contents could not be resolved against the introduction/fix commits`);
  const byTime = (a, b) => Date.parse(a.deployedAt) - Date.parse(b.deployedAt);
  const firstVulnerable = [...vulnerable].sort(byTime)[0] ?? null;
  const fixDeployedAt = [...fixed].sort(byTime)[0] ?? null;
  if (introCommit && deployments.length && !firstVulnerable && !unresolved.length) unknowns.push('no recorded deployment contains the vulnerable code');
  if (fixCommit && deployments.length && !fixDeployedAt && !unresolved.length) unknowns.push('the fix has not been deployed according to the deployment history');

  const exposureStart = ts(firstVulnerable?.deployedAt);
  const exposureEnd = ts(fixDeployedAt?.deployedAt);
  const telStart = ts(telemetry?.start); const telEnd = ts(telemetry?.end);
  if (telStart == null || telEnd == null) unknowns.push('telemetry window (no dated telemetry)');

  let observable = null; let unobservableBefore = null;
  if (exposureStart != null) {
    const end = exposureEnd ?? telEnd;
    if (telStart != null && telEnd != null && end != null) {
      const s = Math.max(exposureStart, telStart); const e = Math.min(end, telEnd);
      if (s <= e) observable = { start: iso(s), end: iso(e), openEnded: exposureEnd == null };
      if (exposureStart < telStart) unobservableBefore = { start: iso(exposureStart), end: iso(Math.min(telStart, end ?? telStart)) };
    }
  }
  const status = exposureStart == null ? 'unavailable' : (unknowns.length || !observable) ? 'partial' : 'complete';
  return {
    schema: 'agentic-security/exposure-window', version: 1, findingId: finding?.stableId ?? finding?.id ?? null, status,
    vulnerabilityIntroduced: introducedAt ? { at: introducedAt, commit: introCommit, source: 'finding-provenance' } : null,
    firstVulnerableDeployment: firstVulnerable ? { at: firstVulnerable.deployedAt, commit: firstVulnerable.commit, environment: firstVulnerable.environment, artifactDigest: firstVulnerable.artifactDigest } : null,
    fixCommitted: fixAt ? { at: fixAt, commit: fixCommit } : null,
    fixDeployed: fixDeployedAt ? { at: fixDeployedAt.deployedAt, commit: fixDeployedAt.commit, environment: fixDeployedAt.environment, artifactDigest: fixDeployedAt.artifactDigest } : null,
    stillExposed: stillExposed(deployments, vulnerable),
    telemetryWindow: telStart != null && telEnd != null ? { start: iso(telStart), end: iso(telEnd) } : null,
    observableWindow: observable, unobservableBefore, unresolvedDeployments: unresolved, deploymentProblems, unknowns,
    statement: 'The observable window is the part of the exposure that telemetry covers. Exposure outside it is unobserved, which is not the same as unexploited.',
  };
}

export function formatExposureWindow(w) {
  const day = (x) => (x ? x.at.slice(0, 10) : 'unknown');
  const lines = [
    `Vulnerability introduced: ${day(w.vulnerabilityIntroduced)}`,
    `First vulnerable deployment: ${day(w.firstVulnerableDeployment)}`,
    `Fix committed: ${day(w.fixCommitted)}`,
    `Fix deployed: ${w.fixDeployed ? day(w.fixDeployed) : w.stillExposed ? 'not deployed (still exposed)' : 'unknown'}`,
    `Telemetry available: ${w.telemetryWindow ? `${w.telemetryWindow.start.slice(0, 10)} to ${w.telemetryWindow.end.slice(0, 10)}` : 'unknown'}`,
    '',
    `Observable exposure window: ${w.observableWindow ? `${w.observableWindow.start.slice(0, 10)} to ${w.observableWindow.openEnded ? 'present (fix not deployed)' : w.observableWindow.end.slice(0, 10)}` : 'cannot be determined'}`,
  ];
  if (w.unobservableBefore) lines.push(`Exposed but not observable: ${w.unobservableBefore.start.slice(0, 10)} to ${w.unobservableBefore.end.slice(0, 10)} (before telemetry began)`);
  if (w.unknowns.length) lines.push('', `Status: ${w.status}. Unknown: ${w.unknowns.join('; ')}`);
  return lines.join('\n');
}
