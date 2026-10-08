// Release orchestration: the decisions, with every external effect injected so they can be tested without a network or a repository.
//
// WHY THIS EXISTS. A release used to be a sequence of manual steps with idle gaps between them: a gate would pass and the tag wait for hours,
// a watch would expire and nobody notice, a merge commit (a new SHA over an identical tree) would trigger a second CI wait and a second full
// verification of content already verified. Measured on the last releases: the hosted gate is ~25 minutes of which publishing is seconds, and
// the rest was waiting. This module holds the logic that removes the waiting; scripts/ship.mjs drives it.
//
// WHAT IT NEVER DOES. It never skips a gate, never passes --no-verify, never passes --allow-unverified-ci, never force-pushes, and never tags
// a commit that was not verified. The only shortcut is TREE EQUIVALENCE: when the merge commit's tree is byte-identical to the verified PR
// head's tree, the PR head's verdicts (the pre-push gate, the PR's CI) are verdicts about the same content, so the PR head is what gets tagged
// and the second CI wait is not needed. Any difference in tree falls back to waiting for CI on the merge commit.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const PHASES = Object.freeze(['preflight', 'push', 'pr', 'checks', 'merge', 'verify', 'tag', 'release', 'npm', 'done']);

// ── tree equivalence ───────────────────────────────────────────────────────────────────────────────────────

/**
 * Which commit to release. The PR head when the merge commit has the identical tree (its verdicts apply as they are); otherwise the merge
 * commit, which then needs its own CI and verification.
 * @param {{prHead: string, mergeSha: string, git: (args: string[]) => string}} p
 */
export function chooseReleaseSha({ prHead, mergeSha, git }) {
  if (!prHead || !mergeSha) throw new Error('chooseReleaseSha needs both the PR head and the merge commit');
  if (prHead === mergeSha) return { sha: mergeSha, treeEquivalent: true, why: 'the merge was a fast-forward: the PR head is the merge commit' };
  const a = git(['rev-parse', `${prHead}^{tree}`]).trim();
  const b = git(['rev-parse', `${mergeSha}^{tree}`]).trim();
  if (!/^[0-9a-f]{40}$/.test(a) || !/^[0-9a-f]{40}$/.test(b)) throw new Error('could not read the commit trees');
  if (a === b) return { sha: prHead, treeEquivalent: true, why: `the merge commit's tree equals the verified PR head's (${a.slice(0, 10)}): its CI and gate verdicts apply unchanged` };
  return { sha: mergeSha, treeEquivalent: false, why: 'the merge commit differs from the PR head (the base moved), so it needs its own CI and verification' };
}

// ── CI checks ──────────────────────────────────────────────────────────────────────────────────────────────

/** Parse `gh pr checks` output: tab-separated `name state duration url`. */
export function parseChecks(text) {
  return String(text || '').split('\n').filter((l) => l.includes('\t')).map((l) => { const [name, state] = l.split('\t'); return { name: name.trim(), state: (state || '').trim() }; });
}

/**
 * Judge the blocking checks. A blocking check that has not appeared is `missing`: a workflow that did not run on this change is not a pass, and
 * the caller decides (a path-filtered workflow legitimately may not run) by passing `allowMissing`.
 */
export function classifyChecks(rows, blocking, { allowMissing = [] } = {}) {
  const by = new Map(rows.map((r) => [r.name, r.state]));
  const failing = [], pending = [], missing = [];
  for (const name of blocking) {
    const s = by.get(name);
    if (s === undefined) { if (!allowMissing.includes(name)) missing.push(name); continue; }
    if (s === 'fail' || s === 'cancel') failing.push(name);
    else if (s === 'pending' || s === 'queued' || s === 'in_progress') pending.push(name);
    else if (s !== 'pass' && s !== 'skipping') failing.push(name);   // an unknown state is never read as green
  }
  return { green: !failing.length && !pending.length && !missing.length, failing, pending, missing };
}

/**
 * Jobs that have been running far longer than any healthy run: a hung download (a 55-minute Neovim fetch once held a PR for an hour) looks
 * like "pending" forever. A stuck job is cancelled and re-run, bounded by the caller.
 */
export function findStuckJobs(jobs, now, { maxMinutes = 40 } = {}) {
  return (jobs || []).filter((j) => j && j.status === 'in_progress' && j.startedAt && (now - Date.parse(j.startedAt)) / 60000 > maxMinutes)
    .map((j) => ({ name: j.name, minutes: Math.round((now - Date.parse(j.startedAt)) / 60000) }));
}

// ── release workflow ───────────────────────────────────────────────────────────────────────────────────────

/**
 * Was a failed release run the infrastructure's fault (worth an automatic re-run) or the gate's (a real failure to stop on)? Only an
 * unambiguous infrastructure signature is retried: a cancelled or timed-out job, or a failure before any gate step ran.
 */
export function classifyReleaseFailure(jobs) {
  const failed = (jobs || []).filter((j) => j.conclusion && !['success', 'skipped'].includes(j.conclusion));
  if (!failed.length) return { kind: 'none', reason: 'no failed job' };
  const INFRA_STEPS = /^(Set up job|Run actions\/(checkout|setup-node|download-artifact|upload-artifact)|Post |Complete job|Ensure npm supports|Install scanner dependencies)/;
  const stepsFailed = (j) => (j.steps || []).filter((s) => s.conclusion && !['success', 'skipped'].includes(s.conclusion));
  // A real gate failure wins over everything else. With a fail-fast matrix, one leg failing a gate makes its siblings `cancelled`; reading
  // those cancellations as "infrastructure" would re-run a release over a genuine failure.
  const gate = failed.filter((j) => j.conclusion === 'failure' && !(stepsFailed(j).length && stepsFailed(j).every((s) => INFRA_STEPS.test(s.name))));
  if (gate.length) return { kind: 'gate', reason: gate.map((j) => `${j.name}: ${stepsFailed(j).filter((s) => s.conclusion === 'failure').map((s) => s.name).join(', ') || j.conclusion}`).join('; ') };
  const j = failed[0];
  if (j.conclusion === 'cancelled' || j.conclusion === 'timed_out') return { kind: 'infra', reason: `${j.name} was ${j.conclusion}` };
  return { kind: 'infra', reason: `${j.name} failed in ${(stepsFailed(j)[0] || {}).name || 'setup'}, before any gate ran` };
}

// ── npm ────────────────────────────────────────────────────────────────────────────────────────────────────

/** What the registry says about one version, from its packument. Never claims more than the document shows. */
export function npmFacts(packument, version) {
  const v = packument && packument.versions && packument.versions[version];
  if (!v) return { published: false, latest: packument && packument['dist-tags'] ? packument['dist-tags'].latest : null };
  return {
    published: true, latest: packument['dist-tags'] ? packument['dist-tags'].latest : null, isLatest: packument['dist-tags'] && packument['dist-tags'].latest === version,
    attested: Boolean(v.dist && v.dist.attestations), publishedAt: (packument.time && packument.time[version]) || null,
    descriptionLength: (v.description || '').length, readmeLength: (packument.readme || '').length,
  };
}

// ── preflight ──────────────────────────────────────────────────────────────────────────────────────────────

/** Problems that would fail a release late, found before anything is pushed. Pure: the caller supplies the file texts. */
export function preflightProblems({ version, files, changelog, npmLatest, branch, dirty }) {
  const problems = [];
  if (!/^\d+\.\d+\.\d+$/.test(version || '')) problems.push(`the package version "${version}" is not X.Y.Z`);
  if (branch === 'main') problems.push('run this from a feature branch, not main: a release goes through a pull request');
  if (dirty) problems.push(`the working tree has ${dirty} uncommitted change(s)`);
  if (npmLatest && version && cmpVersions(version, npmLatest) <= 0) problems.push(`version ${version} is not greater than the published ${npmLatest}`);
  for (const [path, text] of Object.entries(files || {})) if (version && !String(text).includes(version)) problems.push(`${path} does not mention version ${version}`);
  if (version && !new RegExp(`^## ${version.replace(/\./g, '\\.')}\\b`, 'm').test(changelog || '')) problems.push(`CHANGELOG.md has no "## ${version}" entry`);
  return problems;
}

export function cmpVersions(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
  return 0;
}

// ── state: what the dashboard and a resumed run read ─────────────────────────────────────────────────────────

export class ShipState {
  constructor(path, now = () => Date.now()) { this.path = path; this.now = now; this.data = { phases: {}, started: this.now(), events: [] }; }
  static load(path, now) { const s = new ShipState(path, now); try { s.data = JSON.parse(readFileSync(path, 'utf8')); } catch { /* a fresh run */ } return s; }
  save() { mkdirSync(dirname(this.path), { recursive: true }); const tmp = `${this.path}.${process.pid}.tmp`; writeFileSync(tmp, JSON.stringify(this.data, null, 1)); renameSync(tmp, this.path); }
  // Only the facts the flow records, so a stray or hostile key (a `__proto__`, say) can never be merged into the state.
  static KEYS = ['branch', 'version', 'tag', 'pr', 'prUrl', 'releaseSha', 'mergeSha', 'prHead', 'treeEquivalent', 'releaseRun', 'current', 'finished', 'failed'];
  set(patch) {
    for (const k of Object.keys(patch || {})) if (ShipState.KEYS.includes(k)) this.data[k] = patch[k];
    this.data.updated = this.now(); this.save();
  }
  begin(phase, detail = null) { this.data.current = phase; this.data.phases[phase] = { ...(this.data.phases[phase] || {}), state: 'running', startedAt: this.now(), detail }; this.data.updated = this.now(); this.save(); }
  note(phase, detail) { this.data.phases[phase] = { ...(this.data.phases[phase] || {}), detail }; this.data.updated = this.now(); this.save(); }
  finish(phase, ok, detail = null) {
    const p = this.data.phases[phase] || {};
    this.data.phases[phase] = { ...p, state: ok ? 'done' : 'failed', endedAt: this.now(), seconds: p.startedAt ? Math.round((this.now() - p.startedAt) / 1000) : null, detail: detail ?? p.detail ?? null };
    this.data.updated = this.now(); this.save();
  }
  event(text) { this.data.events.push({ at: this.now(), text }); this.data.events = this.data.events.slice(-60); this.data.updated = this.now(); this.save(); }
  summary() {
    return PHASES.map((p) => { const x = this.data.phases[p]; return `${p.padEnd(10)} ${x ? `${x.state}${x.seconds != null ? ` ${x.seconds}s` : ''}` : '-'}`; }).join('\n');
  }
}

/** Poll until `probe()` returns a truthy value, with a deadline and a backoff that never exceeds `maxIntervalMs`. The clock and sleep are injected. */
export async function waitFor(probe, { timeoutMs, intervalMs = 10000, maxIntervalMs = 30000, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)), onTick = null }) {
  const end = now() + timeoutMs;
  let wait = intervalMs;
  for (;;) {
    const v = await probe();
    if (v) return { ok: true, value: v };
    if (now() >= end) return { ok: false, value: null };
    if (onTick) onTick();
    await sleep(Math.min(wait, Math.max(0, end - now())));
    wait = Math.min(Math.round(wait * 1.25), maxIntervalMs);
  }
}
