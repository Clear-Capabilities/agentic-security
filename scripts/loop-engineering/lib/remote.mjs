// Hosted-CI executor (verification of a suite on a machine that has the tool this one lacks).
//
// WHAT IT IS. Some acceptance suites need a tool or an environment this host cannot offer: `nix`, and for NIX-012 a booted NixOS guest.
// Rather than reporting those criteria "blocked" forever, the controller can run the suite on a GitHub-hosted runner and record the
// outcome as evidence. The evidence says so (`remote`, `invoker`, a limitation line); it is never presented as a local run.
//
// WHAT KEEPS IT HONEST. Nothing here trusts a conclusion alone. The controller:
//   * refuses unless the working tree is clean and HEAD is the tip of a pushed branch (what runs is exactly what is on disk here);
//   * dispatches the committed workflow with HEAD's sha, the requirement and the watch globs it will be judged on, plus a nonce, and finds
//     ITS run by that nonce, not "the latest";
//   * requires the run to have executed that workflow at that sha (`workflow_sha`), and requires the digest of the watched files computed
//     on the runner to equal the digest computed here (so the runner tested the same bytes);
//   * reads per-test results from the TAP the runner produced, with the same parser and the same tag-to-criterion mapping as a local
//     run, and requires EVERY declared leg (for NIX-012: an x86_64 NixOS guest and an emulated aarch64 one) to pass each criterion;
//   * records the run id, URL, artifact digest and the hashes of every log it read, so the evidence can be checked later.
// A criterion with no passing test, a missing leg, a wrong digest, a failed run or an unreadable artifact fails closed.
//
// WHAT IT CANNOT DO. It trusts GitHub's account of what ran, and the committed workflow. It does not make hosted CI a substitute for a
// local run where a local run is possible: it is only reached when a required tool is missing here.

import { execFile } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { mkdirSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { sha256 } from './util.mjs';
import { parseTap } from './tap.mjs';

export const REMOTE_VERSION = '1';

// ASYNC, never execFileSync: a synchronous call freezes the controller's event loop (and its heartbeat) for as long as GitHub takes to answer.
const defaultRun = (cmd, args, opts = {}) => new Promise((resolve, reject) => {
  execFile(cmd, args, { encoding: 'utf8', timeout: opts.timeoutMs || 120_000, maxBuffer: 64 * 1024 * 1024, cwd: opts.cwd }, (err, stdout, stderr) => {
    if (err) { err.stderr = err.stderr || stderr; reject(err); } else resolve(stdout);
  });
});
// A MONOTONIC clock for every deadline in this file. Date.now() jumps when the machine sleeps, so a 10-minute wait can expire before the
// process has polled once; performance.now() does not advance while the machine is asleep, so a deadline measures time the controller was running.
const monotonic = () => performance.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A reset connection is not a verdict. Single-shot calls (dispatch, download) are retried a few times with a short backoff; a call that
// still fails is reported as what it is. Polling calls already tolerate a failed poll.
const TRANSIENT = /connection reset|ECONNRESET|ETIMEDOUT|EOF|timed? ?out|temporarily unavailable|502|503|504|TLS handshake|i\/o timeout/i;
function retrying(run, tries = 4, backoffMs = 5000) {
  return async (cmd, args, opts) => {
    let last;
    for (let i = 0; i < tries; i++) {
      try { return await run(cmd, args, opts); } catch (e) {
        last = e;
        if (!TRANSIENT.test(String(e.stderr || e.message))) throw e;
        if (i < tries - 1) await sleep(backoffMs * (i + 1));
      }
    }
    throw last;
  };
}

/** Can a remote run be started from this checkout? Returns {ok, reason?, sha?, branch?, repo?}. */
export async function remotePreflight({ repoRoot, workflow, run: rawRun = defaultRun }) {
  const run = retrying(rawRun, 3, 3000);
  const git = async (...a) => String(await run('git', a, { cwd: repoRoot })).trim();
  let dirty;
  try { dirty = await git('status', '--porcelain', '--untracked-files=all'); } catch (e) { return { ok: false, reason: `git status failed: ${String(e.message).slice(0, 120)}` }; }
  if (dirty) return { ok: false, reason: 'the working tree has uncommitted or untracked files: a remote run tests a commit, so commit (or discard) them first' };
  const sha = await git('rev-parse', 'HEAD');
  let branches = '';
  try { branches = String(await run('git', ['ls-remote', '--heads', 'origin'], { cwd: repoRoot, timeoutMs: 60_000 })); } catch (e) { return { ok: false, reason: `could not read the remote's branches: ${String(e.message).slice(0, 120)}` }; }
  const tip = branches.split('\n').map((l) => l.trim().split(/\s+/)).filter((p) => p[0] === sha).map((p) => p[1].replace(/^refs\/heads\//, ''));
  if (!tip.length) return { ok: false, reason: `HEAD ${sha.slice(0, 12)} is not the tip of any pushed branch: push it first (the workflow is dispatched on a branch whose tip is exactly this commit)` };
  let tracked = '';
  try { tracked = await git('ls-files', '--error-unmatch', `.github/workflows/${workflow}`); } catch { /* handled below */ }
  if (!tracked) return { ok: false, reason: `.github/workflows/${workflow} is not committed` };
  let repo = null;
  try { repo = String(await run('gh', ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner'], { cwd: repoRoot, timeoutMs: 60_000 })).trim(); } catch (e) { return { ok: false, reason: `gh is not usable (is it installed and logged in?): ${String(e.message).slice(0, 120)}` }; }
  return { ok: true, sha, branch: tip.includes('main') ? 'main' : tip[0], repo };
}

/**
 * Runs `req` remotely and returns what verifyRequirement needs to build an evidence envelope:
 *   { status: 'ok'|'failed'|'unavailable', reason, criteria, counts, remote, files: [{path, sha256, bytes}], limitations }
 * `watchDigest` is the digest of the requirement's watched files computed LOCALLY; the runner must reproduce it.
 */
export async function runRemote({ repoRoot, evidenceDir, req, watch, watchDigest, remoteCfg, evaluateCriteria, run: rawRun = defaultRun, now = monotonic, pollMs = 20_000, logger = () => {}, retryBackoffMs = 5000 }) {
  const run = retrying(rawRun, 4, retryBackoffMs);
  const pre = await remotePreflight({ repoRoot, workflow: remoteCfg.workflow, run });
  if (!pre.ok) return { status: 'unavailable', reason: `hosted-CI verification is not possible: ${pre.reason}`, criteria: failAll(req, `hosted-CI verification is not possible: ${pre.reason}`), counts: zero(), files: [], limitations: [] };

  const nonce = randomBytes(6).toString('hex');
  const watchJson = JSON.stringify(watch);
  const dispatchedAt = now();
  try {
    await run('gh', ['workflow', 'run', remoteCfg.workflow, '--ref', pre.branch, '-f', `requirement=${req.id}`, '-f', `sha=${pre.sha}`, '-f', `watch=${watchJson}`, '-f', `nonce=${nonce}`, '-f', `target=${remoteCfg.target}`], { cwd: repoRoot, timeoutMs: 60_000 });
  } catch (e) { return fail(req, `could not dispatch ${remoteCfg.workflow}: ${String(e.stderr || e.message).slice(0, 200)}`); }
  logger(`dispatched ${remoteCfg.workflow} for ${req.id} at ${pre.sha.slice(0, 12)} (nonce ${nonce})`);

  // find OUR run by its nonce (run-name carries it)
  let runInfo = null;
  const appearBy = dispatchedAt + 10 * 60_000;
  while (now() < appearBy && !runInfo) {
    await sleep(Math.min(pollMs, 5000));
    let list = [];
    try { list = JSON.parse(await run('gh', ['run', 'list', '--workflow', remoteCfg.workflow, '--branch', pre.branch, '--event', 'workflow_dispatch', '--limit', '30', '--json', 'databaseId,displayTitle,headSha,createdAt,url'], { cwd: repoRoot, timeoutMs: 60_000 })); } catch { /* retry */ }
    runInfo = list.find((r) => String(r.displayTitle || '').includes(nonce)) || null;
  }
  if (!runInfo) return fail(req, `no run carrying nonce ${nonce} appeared within 10 minutes`);

  // wait for completion within the declared deadline
  const deadline = dispatchedAt + (remoteCfg.timeoutSeconds || 3600) * 1000;
  let state = null;
  for (;;) {
    try { state = JSON.parse(await run('gh', ['run', 'view', String(runInfo.databaseId), '--json', 'status,conclusion,headSha,url'], { cwd: repoRoot, timeoutMs: 60_000 })); } catch { state = null; }
    if (state && state.status === 'completed') break;
    if (now() > deadline) return fail(req, `run ${runInfo.databaseId} did not finish within ${remoteCfg.timeoutSeconds || 3600} s (the run was left to finish; it is not cancelled)`);
    await sleep(pollMs);
  }
  if (state.headSha !== pre.sha) return fail(req, `run ${runInfo.databaseId} executed ${String(state.headSha).slice(0, 12)}, not ${pre.sha.slice(0, 12)}`);

  // download and read what the runner produced
  const dest = join(evidenceDir, `${Date.now()}-remote`);
  mkdirSync(dest, { recursive: true, mode: 0o700 });
  try { await run('gh', ['run', 'download', String(runInfo.databaseId), '-n', `verify-${req.id}`, '-D', dest], { cwd: repoRoot, timeoutMs: 300_000 }); } catch (e) { return fail(req, `could not download the verification artifact of run ${runInfo.databaseId}: ${String(e.stderr || e.message).slice(0, 160)}`); }
  let artifactDigest = null;
  try {
    const repoSlug = pre.repo;
    const arts = JSON.parse(await run('gh', ['api', `repos/${repoSlug}/actions/runs/${runInfo.databaseId}/artifacts`], { cwd: repoRoot, timeoutMs: 60_000 }));
    const a = (arts.artifacts || []).find((x) => x.name === `verify-${req.id}`);
    artifactDigest = a && a.digest ? a.digest : null;
  } catch { /* the digest is extra evidence; its absence is recorded as null */ }

  const meta = readJsonSafe(join(dest, 'meta.json'));
  const checked = validateMeta({ meta, req, sha: pre.sha, watchJson, watchDigest, remoteCfg, dest, run: runInfo, state });
  if (checked.problems.length) return { status: 'failed', reason: `the runner's result is not acceptable: ${checked.problems[0]}`, criteria: failAll(req, checked.problems[0]), counts: zero(), files: filesIn(dest), remote: remoteRecord({ pre, runInfo, state, artifactDigest, meta, nonce, legs: [] }), limitations: checked.problems.slice(1) };

  // per-leg criteria, then the conjunction over legs
  const perLeg = checked.legs.map((leg) => {
    const tap = parseTap(readFileSync(join(dest, leg.tap), 'utf8'));
    return { leg, tap, criteria: evaluateCriteria(req, tap, leg.exitCode === 0) };
  });
  const criteria = req.criteria.map((c) => {
    const rows = perLeg.map((p) => ({ leg: p.leg.name, c: p.criteria.find((x) => x.id === c.id) }));
    const bad = rows.find((r) => !r.c || r.c.state !== 'pass');
    if (bad) return { id: c.id, state: 'fail', reason: `leg ${bad.leg}: ${bad.c ? bad.c.reason || 'not passing' : 'no result'}`, assertions: rows.flatMap((r) => (r.c ? r.c.assertions.map((a) => ({ ...a, name: `[${r.leg}] ${a.name}` })) : [])) };
    return { id: c.id, state: 'pass', assertions: rows.flatMap((r) => r.c.assertions.map((a) => ({ ...a, name: `[${r.leg}] ${a.name}` }))) };
  });
  const counts = perLeg.reduce((acc, p) => ({ tests: acc.tests + (p.tap.summary.tests ?? p.tap.tests.length), pass: acc.pass + (p.tap.summary.pass ?? p.tap.tests.filter((t) => t.ok).length), fail: acc.fail + (p.tap.summary.fail ?? p.tap.tests.filter((t) => !t.ok).length), skipped: acc.skipped + (p.tap.summary.skipped ?? 0) + (p.tap.summary.todo ?? 0) }), zero());
  const legBad = perLeg.find((p) => p.leg.exitCode !== 0 || (p.tap.summary.fail ?? 0) > 0 || (p.tap.summary.skipped ?? 0) + (p.tap.summary.todo ?? 0) > 0 || !p.tap.tests.length);
  const reason = legBad ? `leg ${legBad.leg.name}: exit ${legBad.leg.exitCode}, ${legBad.tap.summary.fail ?? 0} failed, ${(legBad.tap.summary.skipped ?? 0) + (legBad.tap.summary.todo ?? 0)} skipped, ${legBad.tap.tests.length} tests read` : null;
  return {
    status: reason || !criteria.every((c) => c.state === 'pass') ? 'failed' : 'ok',
    reason: reason || (criteria.every((c) => c.state === 'pass') ? null : `criteria not passing: ${criteria.filter((c) => c.state !== 'pass').map((c) => c.id).join(', ')}`),
    criteria, counts, files: filesIn(dest),
    remote: remoteRecord({ pre, runInfo, state, artifactDigest, meta, nonce, legs: checked.legs }),
    limitations: [`verified on a GitHub-hosted runner (run ${runInfo.databaseId}), not on this host: ${remoteCfg.legs.join(', ')}`],
  };
}

function validateMeta({ meta, req, sha, watchJson, watchDigest, remoteCfg, dest, run: runInfo, state }) {
  const problems = [];
  if (!meta) return { problems: ['meta.json is missing or unreadable in the artifact'], legs: [] };
  if (state.conclusion !== 'success') problems.push(`the run concluded ${state.conclusion}, not success`);
  if (meta.requirement !== req.id) problems.push(`meta names requirement ${meta.requirement}, not ${req.id}`);
  if (meta.sha !== sha) problems.push(`the runner tested ${String(meta.sha).slice(0, 12)}, not ${sha.slice(0, 12)}`);
  if (meta.workflowSha !== sha) problems.push(`the workflow that ran was ${String(meta.workflowSha).slice(0, 12)}, not the committed ${sha.slice(0, 12)}`);
  if (meta.watchSha256 !== sha256(watchJson)) problems.push('the runner digested a different set of watched files than the controller asked for');
  if (meta.treeDigest !== watchDigest) problems.push(`the runner's digest of the watched files (${String(meta.treeDigest).slice(0, 12)}) differs from this checkout's (${String(watchDigest).slice(0, 12)}): different bytes were tested`);
  const have = new Map((meta.legs || []).map((l) => [l.name, l]));
  const legs = [];
  for (const name of remoteCfg.legs) {
    const l = have.get(name);
    if (!l) { problems.push(`leg ${name} is missing from the runner's result`); continue; }
    const f = join(dest, l.tap || '');
    if (!l.tap || !existsSync(f)) { problems.push(`leg ${name}: its TAP file ${l.tap || '(none)'} is missing`); continue; }
    if (sha256(readFileSync(f)) !== l.tapSha256) { problems.push(`leg ${name}: the TAP file does not match the hash the runner recorded`); continue; }
    legs.push(l);
  }
  void runInfo;
  return { problems, legs };
}

const zero = () => ({ tests: 0, pass: 0, fail: 0, skipped: 0 });
const failAll = (req, reason) => req.criteria.map((c) => ({ id: c.id, state: 'fail', reason, assertions: [] }));
const fail = (req, reason) => ({ status: 'failed', reason, criteria: failAll(req, reason), counts: zero(), files: [], limitations: [] });
const readJsonSafe = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
function filesIn(dir) {
  const out = [];
  for (const n of readdirSync(dir)) { const p = join(dir, n); try { const b = readFileSync(p); out.push({ path: p, sha256: sha256(b), bytes: b.length }); } catch { /* a directory */ } }
  return out;
}
function remoteRecord({ pre, runInfo, state, artifactDigest, meta, nonce, legs }) {
  return {
    version: REMOTE_VERSION, provider: 'github-actions', repository: pre.repo, ref: pre.branch, sha: pre.sha, nonce,
    runId: runInfo.databaseId, runUrl: state.url || runInfo.url || null, conclusion: state.conclusion, artifactDigest,
    workflowSha: meta ? meta.workflowSha : null, runnerDigest: meta ? meta.treeDigest : null,
    legs: legs.map((l) => ({ name: l.name, system: l.system || null, exitCode: l.exitCode, tapSha256: l.tapSha256, toolVersions: l.toolVersions || null })),
  };
}
