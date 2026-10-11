// Attested-from-CI acceptance of locally skipped tests.
//
// THE PROBLEM. Some suites contain tests that need a host this machine is not: the Linux kernel-namespace backend cannot run on macOS, so
// those tests SKIP here, and a skipped required test counts as failed. They do run, and are required to pass, on the hosted `sandbox-linux`
// CI job (scripts/sandbox-linux-verify.mjs), which fails on any skip.
//
// WHAT THIS MODULE ALLOWS, AND NOTHING ELSE. A test that SKIPPED locally may be counted toward its criterion only when ALL of these hold,
// each checked here and each refusing with a typed code:
//   1. the commit is a full 40 character sha, equal to this checkout's HEAD, and the working tree has no tracked change (so the bytes the
//      hosted job tested are the bytes under verification);
//   2. a `sandbox-linux` check run exists for exactly that sha, in the `ci` workflow, completed with conclusion `success`, with the
//      script step itself successful (the existing release-attest reader decides this; it never reuses another commit's result);
//   3. that job's per-test report (artifact `sandbox-linux-test-report`) can be downloaded and is well formed: the right kind, bound to the
//      same commit and to the same workflow run, verdict VERIFIED, and a digest over its test list that matches;
//   4. every report entry with the skipped test's exact name, in the groups the profile names, is `pass`. A name that is absent, reported
//      skipped there, or reported failed there is refused.
// A test that FAILED locally is never looked up: a local failure is never overridden. A test with no attestation stays skipped, and a
// skipped required test still counts as failed.
//
// WHAT IT IS NOT. This is evidence from a hosted run, read through the `gh` CLI. It is not a claim that this host enforced anything, and the
// result is reported as its own source, "attested-from-ci: sandbox-linux@<sha>", beside the unchanged local skip count. It trusts GitHub's
// account of the job and the committed workflow, the same trust the existing release attestation places in them. Anyone who can write
// artifacts to the repository could forge a report, so this raises the cost of a false claim and makes it traceable to a run; it does not
// make it impossible.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { attestFromCi, classifyGhFailure } from '../../release-attest.mjs';
import { runBounded } from './proc.mjs';
import { getBounds } from './bounds.mjs';

export const ATTEST_SOURCE_PREFIX = 'attested-from-ci';
export const REPORT_KIND = 'sandbox-linux-test-report';
export const REPORT_FILE = 'sandbox-linux-test-report.json';
const SHA = /^[0-9a-f]{40}$/;
const STATUSES = new Set(['pass', 'skip', 'fail']);

export const sourceLabel = (job, commit) => `${ATTEST_SOURCE_PREFIX}: ${job}@${commit}`;

/** Every refusal code this module can produce, so a test can prove each is reachable. */
export const REFUSAL_CODES = Object.freeze([
  'bad-commit', 'working-tree-dirty', 'git-unavailable',
  'gh-unavailable', 'gh-unauthenticated', 'gh-not-found', 'gh-offline', 'gh-error', 'sha-unknown',
  'job-missing', 'job-not-completed', 'job-failure', 'job-cancelled', 'job-skipped', 'job-neutral', 'job-timed_out', 'job-no-conclusion',
  'sha-mismatch', 'job-detail-not-success', 'wrong-workflow', 'step-failed', 'required-step-not-successful', 'bad-response',
  'report-missing', 'report-malformed', 'report-wrong-kind', 'report-commit-mismatch', 'report-run-mismatch', 'report-not-verified', 'report-digest-mismatch',
  'test-absent-from-report', 'test-skipped-in-ci', 'test-failed-in-ci', 'no-config',
]);

/** A bounded, ASYNC gh runner (a synchronous one would freeze the controller's heartbeat). -> { code, out, err } */
export function boundedGh(cwd) {
  return async (args) => {
    const r = await runBounded({ argv: ['gh', ...args], cwd, wallMs: 120_000, graceMs: getBounds().killGraceSeconds * 1000, label: 'ci-attest:gh', tailBytes: 64 * 1024 * 1024, env: { ...process.env, NO_COLOR: '1', GH_PROMPT_DISABLED: '1' } });
    if (r.outcome === 'spawn-failed') return { code: null, out: '', err: `ENOENT: ${r.reason || 'gh could not be started'}` };
    if (r.outcome !== 'exited') return { code: null, out: '', err: `${r.outcome}${r.reason ? `: ${r.reason}` : ''} (timed out)` };
    return { code: r.exitCode, out: r.stdoutTail || '', err: r.stderrTail || '' };
  };
}

/** Real git facts for the checkout: { head, dirty } or { error }. */
export function realGit(cwd) {
  const run = (args) => spawnSync('git', args, { cwd, encoding: 'utf8', timeout: 60_000 });
  const h = run(['rev-parse', 'HEAD']);
  if (h.error || h.status !== 0) return { error: String(h.error?.message || h.stderr || 'git rev-parse failed').trim().slice(0, 160) };
  // `-uno`: untracked files do not change what the hosted job tested for any tracked path; a tracked change does.
  const s = run(['status', '--porcelain', '-uno']);
  if (s.error || s.status !== 0) return { error: String(s.error?.message || s.stderr || 'git status failed').trim().slice(0, 160) };
  return { head: h.stdout.trim(), dirty: s.stdout.trim().length > 0 };
}

/**
 * Build the per-test report the hosted job uploads (used by scripts/sandbox-linux-verify.mjs, so the writer and the reader below share
 * one definition). `tests`: [{ group, name, status: 'pass'|'skip'|'fail' }]. `verdict` is VERIFIED only when the job is about to exit 0.
 */
export function buildReport({ commit, testedSha = null, runId, runAttempt = null, backend, platform, tests, problems, now = new Date() }) {
  return {
    schema: 1, kind: REPORT_KIND, commit: commit || null, testedSha: testedSha || null, runId: runId || null, runAttempt: runAttempt || null, backend, platform, generatedAt: now.toISOString(),
    verdict: problems === 0 ? 'VERIFIED' : 'NOT VERIFIED', problems,
    testsSha256: createHash('sha256').update(JSON.stringify(tests)).digest('hex'), tests,
  };
}

/**
 * Validate a parsed per-test report against the commit and run it must be bound to. -> null when acceptable, else { code, detail }.
 * Pure: no I/O.
 */
export function validateReport(report, { commit, runId }) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) return { code: 'report-malformed', detail: 'the report is not a JSON object' };
  if (report.kind !== REPORT_KIND || report.schema !== 1) return { code: 'report-wrong-kind', detail: `kind ${JSON.stringify(report.kind)}, schema ${JSON.stringify(report.schema)}` };
  if (!Array.isArray(report.tests)) return { code: 'report-malformed', detail: 'the report has no tests array' };
  for (const t of report.tests) {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string' || !t.name || typeof t.group !== 'string' || !STATUSES.has(t.status)) return { code: 'report-malformed', detail: 'a test entry lacks a name, a group or a known status' };
  }
  if (typeof report.testsSha256 !== 'string' || createHash('sha256').update(JSON.stringify(report.tests)).digest('hex') !== report.testsSha256) return { code: 'report-digest-mismatch', detail: 'the digest over the test list does not match the list (the report was edited)' };
  if (report.commit !== commit) return { code: 'report-commit-mismatch', detail: `the report is bound to ${String(report.commit).slice(0, 12)}, not ${String(commit).slice(0, 12)}` };
  if (runId != null && String(report.runId) !== String(runId)) return { code: 'report-run-mismatch', detail: `the report names run ${report.runId}, the succeeded job belongs to run ${runId}` };
  if (report.verdict !== 'VERIFIED' || report.problems !== 0) return { code: 'report-not-verified', detail: `the report's verdict is ${JSON.stringify(report.verdict)} with ${JSON.stringify(report.problems)} problem(s)` };
  return null;
}

/** Look one skipped test name up in a validated report. -> { ok:true } | { ok:false, code, detail } */
export function lookupTest(report, name, groups) {
  const entries = report.tests.filter((t) => t.name === name && (!groups || groups.includes(t.group)));
  if (!entries.length) return { ok: false, code: 'test-absent-from-report', detail: 'the hosted report has no test with this name' };
  if (entries.some((t) => t.status === 'fail')) return { ok: false, code: 'test-failed-in-ci', detail: 'the hosted report lists this test as failed' };
  if (entries.some((t) => t.status === 'skip')) return { ok: false, code: 'test-skipped-in-ci', detail: 'the hosted report lists this test as skipped there too' };
  return { ok: true };
}

/**
 * Decide which of `skippedNames` a hosted `sandbox-linux` run covers.
 *   cfg: { job, workflow?, artifact, groups?, requiredStep }  (from the suite's `attestFromCi`)
 *   gh:  (args) => Promise<{code,out,err}>; git: () => { head, dirty } | { error }
 * -> { ok, source, commit, job, runId, jobUrl, reportSha256, covered: [name], uncovered: [{ name, code, detail }], refusal? }
 * `ok` is true only when every name is covered. A refusal at the run level leaves every name uncovered with that one code.
 */
export async function attestSkippedTests({ skippedNames, cfg, repoRoot, gh = boundedGh(repoRoot), git = () => realGit(repoRoot) }) {
  const all = (code, detail) => ({ ok: false, covered: [], uncovered: skippedNames.map((name) => ({ name, code, detail })), refusal: { code, detail } });
  if (!cfg || typeof cfg !== 'object' || !cfg.job || !cfg.artifact) return all('no-config', 'the suite declares no attestFromCi');
  const g = git();
  if (g.error) return all('git-unavailable', g.error);
  if (!SHA.test(g.head || '')) return all('bad-commit', 'HEAD is not a full 40 character sha');
  if (g.dirty) return all('working-tree-dirty', 'a tracked file differs from HEAD, so the hosted run did not test these bytes');
  const commit = g.head;

  const step = { id: `ci-attest:${cfg.job}`, remote: { job: cfg.job, legs: [cfg.job], requiredSteps: { [cfg.job]: cfg.requiredStep ? [cfg.requiredStep] : [] } } };
  let res;
  try { res = await attestFromCi({ steps: [step], commit, gh, workflow: cfg.workflow || 'ci' }); } catch (e) { return all('bad-response', `the hosted run could not be read: ${e.message}`); }
  if (res.refusals.length || !res.attestations.length) {
    const r = res.refusals[0] || { code: 'bad-response', detail: 'no attestation and no refusal' };
    // An unknown or never-pushed sha comes back from the check-runs endpoint as an error; give it its own code
    if (r.code === 'gh-error' && /No commit found|HTTP 422|Unprocessable/i.test(r.detail || '')) return all('sha-unknown', 'GitHub has no such commit: it was never pushed');
    if (r.code === 'gh-not-found') return all('sha-unknown', 'GitHub has no such commit or repository');
    return all(r.code, r.detail);
  }
  const leg = res.attestations[0].source.legs[0];
  if (leg.runId == null) return all('bad-response', 'the job detail names no workflow run, so its artifact cannot be located');

  const dir = mkdtempSync(join(tmpdir(), 'ci-attest-'));
  let report, reportBytes;
  try {
    const dl = await gh(['run', 'download', String(leg.runId), '-n', cfg.artifact, '-D', dir]);
    if (dl.code !== 0) {
      const c = classifyGhFailure(dl);
      return all(c === 'gh-error' || c === 'gh-not-found' ? 'report-missing' : c, String(dl.err || '').trim().slice(0, 200) || 'gh run download failed');
    }
    const file = join(dir, REPORT_FILE);
    if (!existsSync(file)) return all('report-missing', `the artifact ${cfg.artifact} did not contain ${REPORT_FILE}`);
    try { reportBytes = readFileSync(file); report = JSON.parse(reportBytes.toString('utf8')); } catch (e) { return all('report-malformed', `the report is not valid JSON: ${e.message}`); }
  } finally { rmSync(dir, { recursive: true, force: true }); }

  const bad = validateReport(report, { commit, runId: leg.runId });
  if (bad) return all(bad.code, bad.detail);

  const covered = []; const uncovered = [];
  for (const name of skippedNames) {
    const r = lookupTest(report, name, cfg.groups);
    if (r.ok) covered.push(name); else uncovered.push({ name, code: r.code, detail: r.detail });
  }
  return {
    ok: uncovered.length === 0, source: sourceLabel(cfg.job, commit), commit, job: cfg.job, runId: leg.runId, jobUrl: leg.url || null,
    reportSha256: createHash('sha256').update(reportBytes).digest('hex'), covered, uncovered,
  };
}

/**
 * The number of locally skipped tests that STILL count against a receipt: the local skip count less those a well-formed attestation
 * covers. `head` is the commit the attestation must name (undefined: not checked here; null: unknown, so any attestation is refused).
 * -> number. A receipt with no attestation, or a malformed one, keeps its full local skip count.
 */
export function uncoveredSkips(rc, head) {
  const skipped = rc?.counts?.skipped || 0;
  const covered = rc?.counts?.attestedSkipped || 0;
  if (!covered) return skipped;
  return attestationProblem(rc, head) ? skipped : Math.max(0, skipped - covered);
}

/** Why a receipt's attestation cannot be trusted, or null when it is consistent. Pure. */
export function attestationProblem(rc, head) {
  const a = rc?.attestation;
  const n = rc?.counts?.attestedSkipped || 0;
  if (!n) return a ? 'an attestation is present but covers no skipped test' : null;
  if (!a || typeof a !== 'object') return 'the receipt claims attested skips but carries no attestation';
  if (a.kind !== ATTEST_SOURCE_PREFIX) return 'the attestation is of an unknown kind';
  if (!SHA.test(a.commit || '')) return 'the attestation names no full commit sha';
  if (a.source !== sourceLabel(a.job, a.commit)) return 'the attestation source label does not match its job and commit';
  if (!a.runId || !a.reportSha256) return 'the attestation names no run or report digest';
  if (!Array.isArray(a.covered) || a.covered.length !== n) return `the attestation lists ${Array.isArray(a.covered) ? a.covered.length : 'no'} covered tests but the counts claim ${n}`;
  if (head === null) return 'the checkout commit is unknown, so the attestation cannot be bound to it';
  if (head !== undefined && a.commit !== head) return `the attestation is for ${a.commit.slice(0, 12)}, not ${String(head).slice(0, 12)}`;
  return null;
}
