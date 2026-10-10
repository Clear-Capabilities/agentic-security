// Remote prerequisite attestation (REL-001.AC03, REL-003.AC03). A release-closure step that only hosted CI can run
// (a GHC toolchain, a NixOS host) is satisfied by evidence from the hosted CI jobs that ran it, read from GitHub through
// the `gh` CLI (read-only; no token is handled here), for ONE exact commit.
//
// The rule is deliberately one-sided: this module can only ever produce an attestation from a job that
//   1. exists as a check run on exactly the commit asked about,
//   2. is completed with conclusion `success` (the JOB's own conclusion, never the workflow run's, so a job marked
//      continue-on-error whose failure the workflow ignored is not read as a pass),
//   3. belongs to the `ci` workflow,
//   4. has no failed step other than a step the plan declares tolerated, and
//   5. shows every required step as `success`.
// Anything else (missing job, wrong sha, in progress, cancelled, skipped, neutral, failure, a partial matrix, `gh` missing,
// unauthenticated or offline) yields NO attestation and a typed refusal. It never fabricates, never reuses another commit's
// result, and never turns uncertainty into a pass.

/** The workflow whose jobs may attest: `name:` in .github/workflows/ci.yml. */
export const ATTESTING_WORKFLOW = 'ci';
export const ATTESTATION_SOURCE_KIND = 'github-actions-jobs';

const SHA = /^[0-9a-f]{40}$/;
const FAILED = new Set(['failure', 'cancelled', 'timed_out', 'startup_failure', 'action_required']);

/** A runner is `(args: string[]) => { code: number|null, out: string, err: string }`. This is the real one. */
export async function realGh(args) {
  const { spawnSync } = await import('node:child_process');
  const r = spawnSync('gh', args, { encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024, env: { ...process.env, GH_PROMPT_DISABLED: '1' } });
  if (r.error) return { code: null, out: '', err: `${r.error.code || 'ERROR'}: ${r.error.message}` };
  return { code: r.status, out: r.stdout || '', err: r.stderr || '' };
}

/** Why a failed `gh` call produced nothing: a typed code, never a pass. */
export function classifyGhFailure(r) {
  const err = String(r?.err || '');
  if (r == null || r.code === null || /ENOENT|command not found|not found in PATH/i.test(err)) return 'gh-unavailable';
  if (/gh auth login|not logged|authentication|HTTP 401|bad credentials|requires authentication/i.test(err)) return 'gh-unauthenticated';
  if (/HTTP 404|not found/i.test(err)) return 'gh-not-found';
  if (/could not resolve|connection|timed? ?out|dial tcp|network|offline|ETIMEDOUT|ENOTFOUND/i.test(err)) return 'gh-offline';
  return 'gh-error';
}

function parseLines(text) {
  const rows = [];
  for (const line of String(text).split('\n')) { const t = line.trim(); if (!t) continue; rows.push(JSON.parse(t)); }
  return rows;
}

/** Why an attestation does not cover a remote step for a commit, or null when it does. */
export function explainAttestation(step, att, commit) {
  const legs = step?.remote?.legs || [];
  if (!att || typeof att !== 'object') return 'no attestation object';
  if (att.stepId !== step.id) return 'it is for another step';
  if (!SHA.test(commit || '') || att.commit !== commit) return `it is bound to commit ${String(att.commit).slice(0, 12)}, not ${String(commit).slice(0, 12)}`;
  if (att.conclusion !== 'success') return `its conclusion is ${att.conclusion}`;
  const src = att.source;
  if (!src || typeof src !== 'object' || src.kind !== ATTESTATION_SOURCE_KIND) return 'it does not name hosted CI jobs as its source';
  if (!legs.length) return 'the step declares no CI jobs to attest from';
  for (const leg of legs) {
    const got = (src.legs || []).find((l) => l && l.name === leg);
    if (!got || !got.jobId) return `it does not cover job '${leg}'`;
    if (got.conclusion !== 'success') return `job '${leg}' did not conclude success`;
    if (got.commit !== commit) return `job '${leg}' ran for another commit`;
  }
  return null;
}

function checkSteps(leg, job, remote) {
  const steps = Array.isArray(job.steps) ? job.steps : [];
  const tolerated = new Set(remote.toleratedFailedSteps || []);
  const bad = steps.find((s) => FAILED.has(s.conclusion) && !tolerated.has(s.name));
  if (bad) return { code: 'step-failed', detail: `job '${leg}': step '${bad.name}' ${bad.conclusion}` };
  const required = remote.requiredSteps?.[leg] || [];
  for (const need of required) {
    const anyOf = Array.isArray(need) ? need : [need];
    if (!anyOf.some((n) => steps.some((s) => s.name === n && s.conclusion === 'success'))) return { code: 'required-step-not-successful', detail: `job '${leg}': none of [${anyOf.join(' | ')}] concluded success` };
  }
  return null;
}

/**
 * Read hosted CI for `commit` and attest every remote step whose every leg is green for exactly that commit.
 *   steps: the closure plan; gh: injected runner (see realGh).
 * -> { commit, attestations: [...], refusals: [{ stepId, job, code, detail }] }
 */
export async function attestFromCi({ steps, commit, gh = realGh, workflow = ATTESTING_WORKFLOW }) {
  const remote = steps.filter((s) => s.remote);
  const attestations = [];
  const refusals = [];
  const refuseAll = (code, detail) => { for (const s of remote) refusals.push({ stepId: s.id, job: s.remote.job, code, detail }); return { commit, attestations, refusals }; };
  if (!SHA.test(commit || '')) return refuseAll('bad-commit', 'a full 40 character commit sha is required; an abbreviation or a ref is never guessed');

  let runs;
  try {
    const r = await gh(['api', '--paginate', `repos/{owner}/{repo}/commits/${commit}/check-runs?per_page=100`, '--jq', '.check_runs[] | {id, name, head_sha, status, conclusion, completed_at, html_url}']);
    if (r.code !== 0) return refuseAll(classifyGhFailure(r), String(r.err || '').trim().slice(0, 200) || 'gh failed');
    runs = parseLines(r.out);
  } catch (e) { return refuseAll('bad-response', `check runs could not be read: ${e.message}`); }

  for (const step of remote) {
    const legs = step.remote.legs || [];
    const got = [];
    let refusal = null;
    if (!legs.length) refusal = { code: 'no-legs-declared', detail: 'the step declares no CI jobs' };
    for (const leg of legs) {
      if (refusal) break;
      const mine = runs.filter((r) => r && r.name === leg);
      if (!mine.length) { refusal = { code: 'job-missing', detail: `no check run named '${leg}' for this commit` }; break; }
      const run = mine.reduce((a, b) => (Number(b.id) > Number(a.id) ? b : a));
      if (run.head_sha !== commit) { refusal = { code: 'sha-mismatch', detail: `job '${leg}' ran for ${String(run.head_sha).slice(0, 12)}, not ${commit.slice(0, 12)}` }; break; }
      if (run.status !== 'completed') { refusal = { code: 'job-not-completed', detail: `job '${leg}' is ${run.status}` }; break; }
      if (run.conclusion !== 'success') { refusal = { code: `job-${run.conclusion || 'no-conclusion'}`, detail: `job '${leg}' concluded ${run.conclusion}` }; break; }
      let job;
      try {
        const jr = await gh(['api', `repos/{owner}/{repo}/actions/jobs/${run.id}`]);
        if (jr.code !== 0) { refusal = { code: classifyGhFailure(jr), detail: String(jr.err || '').trim().slice(0, 200) || 'gh failed' }; break; }
        job = JSON.parse(jr.out);
      } catch (e) { refusal = { code: 'bad-response', detail: `job '${leg}' could not be read: ${e.message}` }; break; }
      if (job.head_sha !== commit) { refusal = { code: 'sha-mismatch', detail: `job '${leg}' detail names ${String(job.head_sha).slice(0, 12)}` }; break; }
      if (job.status !== 'completed' || job.conclusion !== 'success') { refusal = { code: 'job-detail-not-success', detail: `job '${leg}' detail is ${job.status}/${job.conclusion}` }; break; }
      if (job.workflow_name !== workflow) { refusal = { code: 'wrong-workflow', detail: `job '${leg}' belongs to workflow '${job.workflow_name}', not '${workflow}'` }; break; }
      const sr = checkSteps(leg, job, step.remote);
      if (sr) { refusal = sr; break; }
      got.push({ name: leg, jobId: run.id, runId: job.run_id ?? null, commit, conclusion: 'success', url: run.html_url || null, completedAt: run.completed_at || null });
    }
    if (refusal) refusals.push({ stepId: step.id, job: step.remote.job, ...refusal });
    else attestations.push({ stepId: step.id, commit, conclusion: 'success', source: { kind: ATTESTATION_SOURCE_KIND, workflow, legs: got } });
  }
  return { commit, attestations, refusals };
}

/** Informational lines for a result (used by the closure CLI and the ship flow). */
export function describeAttestation(result) {
  const lines = [];
  for (const a of result.attestations) lines.push(`attested ${a.stepId} for ${a.commit.slice(0, 12)}: ${a.source.legs.map((l) => l.name).join(', ')} succeeded`);
  for (const r of result.refusals) lines.push(`NOT attested ${r.stepId} [${r.code}]: ${r.detail}`);
  return lines;
}
