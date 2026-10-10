// REL-001.AC03 / REL-003.AC03: a remote prerequisite is satisfied only by hosted CI evidence for the exact commit, read through an
// injected `gh` runner (these tests never touch the network or a real gh).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CLOSURE_STEPS, runClosure, evaluateClosureRecord, checkClosurePlan, main } from '../../../scripts/release-closure.mjs';
import { attestFromCi, classifyGhFailure, explainAttestation, describeAttestation } from '../../../scripts/release-attest.mjs';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG, COMMIT, NO_REMOTE_TOOLS, fakeExec } from '../helpers/closure-fixtures.js';

const OTHER = 'c'.repeat(40);
const HASKELL = CLOSURE_STEPS.find((s) => s.id === 'remote-haskell-toolchain');
const NIXOS = CLOSURE_STEPS.find((s) => s.id === 'remote-nixos-host');
const X86 = 'nixos-runtime (x86_64-linux)';
const ARM = 'nixos-runtime (aarch64-linux)';
const GHC = 'language-tools-ghc';

const ok = (name) => ({ name, conclusion: 'success' });
function stepsFor(leg) {
  const need = (HASKELL.remote.requiredSteps[leg] || NIXOS.remote.requiredSteps[leg] || []).flatMap((n) => (Array.isArray(n) ? [n[0]] : [n]));
  return need.map(ok);
}
/** A fake gh: `runs` are check runs, `jobs` are per-id job details. Records every call; never reaches a network. */
function fakeGh({ runs, jobs = {}, fail = null }) {
  const calls = [];
  const gh = (args) => {
    calls.push(args);
    if (fail) return fail;
    const url = args.find((a) => /^repos\//.test(a)) || '';
    if (/\/check-runs/.test(url)) return { code: 0, out: runs.map((r) => JSON.stringify(r)).join('\n'), err: '' };
    const m = /actions\/jobs\/(\d+)/.exec(url);
    if (m && jobs[m[1]]) return { code: 0, out: JSON.stringify(jobs[m[1]]), err: '' };
    return { code: 1, out: '', err: 'HTTP 404: Not Found' };
  };
  gh.calls = calls;
  return gh;
}
let nextId = 100;
/** A fully green world for both remote steps at `sha`; `mut(name, run, job)` may degrade one leg. */
function world(sha = COMMIT, mut = () => {}) {
  const runs = []; const jobs = {};
  for (const name of [GHC, X86, ARM]) {
    const id = nextId++;
    const run = { id, name, head_sha: sha, status: 'completed', conclusion: 'success', completed_at: '2026-10-10T00:00:00Z', html_url: `https://example.invalid/jobs/${id}` };
    const job = { id, run_id: 9, head_sha: sha, status: 'completed', conclusion: 'success', workflow_name: 'ci', steps: stepsFor(name) };
    mut(name, run, job);
    runs.push(run); jobs[id] = job;
  }
  return fakeGh({ runs, jobs });
}
const attest = (gh, commit = COMMIT) => attestFromCi({ steps: CLOSURE_STEPS, commit, gh });
const codeOf = (res, stepId) => res.refusals.find((r) => r.stepId === stepId)?.code;
const only = (leg, fn) => (name, run, job) => { if (name === leg) fn(run, job); };

test('[REL-001.AC03] a job that succeeded for the exact commit, in every matrix leg, yields an attestation', async () => {
  const res = await attest(world());
  assert.deepEqual(res.refusals, []);
  assert.deepEqual(res.attestations.map((a) => a.stepId).sort(), ['remote-haskell-toolchain', 'remote-nixos-host']);
  const nix = res.attestations.find((a) => a.stepId === 'remote-nixos-host');
  assert.equal(nix.commit, COMMIT);
  assert.equal(nix.conclusion, 'success');
  assert.deepEqual(nix.source.legs.map((l) => l.name), [X86, ARM], 'both matrix legs are named in the evidence');
  assert.equal(explainAttestation(NIXOS, nix, COMMIT), null);
});

test('[REL-001.AC03] a job that ran for a different sha produces no attestation', async () => {
  const res = await attest(world(COMMIT, only(GHC, (run) => { run.head_sha = OTHER; })));
  assert.equal(codeOf(res, 'remote-haskell-toolchain'), 'sha-mismatch');
  assert.ok(res.attestations.some((a) => a.stepId === 'remote-nixos-host'), 'the unaffected step is still attested');
  const detail = await attest(world(COMMIT, only(GHC, (run, job) => { job.head_sha = OTHER; })));
  assert.equal(codeOf(detail, 'remote-haskell-toolchain'), 'sha-mismatch', 'the job detail is checked as well as the listing');
});

test('[REL-001.AC03] an in-progress, cancelled, skipped, neutral or failed job produces no attestation', async () => {
  const cases = [
    ['in progress', (r) => { r.status = 'in_progress'; r.conclusion = null; }, 'job-not-completed'],
    ['queued', (r) => { r.status = 'queued'; r.conclusion = null; }, 'job-not-completed'],
    ['cancelled', (r) => { r.conclusion = 'cancelled'; }, 'job-cancelled'],
    ['skipped', (r) => { r.conclusion = 'skipped'; }, 'job-skipped'],
    ['neutral', (r) => { r.conclusion = 'neutral'; }, 'job-neutral'],
    ['failure', (r) => { r.conclusion = 'failure'; }, 'job-failure'],
    ['timed out', (r) => { r.conclusion = 'timed_out'; }, 'job-timed_out'],
  ];
  for (const [label, degrade, code] of cases) {
    const res = await attest(world(COMMIT, only(GHC, degrade)));
    assert.equal(codeOf(res, 'remote-haskell-toolchain'), code, label);
    assert.equal(res.attestations.some((a) => a.stepId === 'remote-haskell-toolchain'), false, `${label}: no attestation`);
  }
});

test('[REL-001.AC03] a job that does not exist for the commit produces no attestation', async () => {
  const res = await attest(fakeGh({ runs: [], jobs: {} }));
  assert.deepEqual(res.attestations, []);
  assert.deepEqual(res.refusals.map((r) => r.code), ['job-missing', 'job-missing']);
});

test('[REL-001.AC03] a partial matrix (one leg green, the other missing or red) produces no attestation', async () => {
  const red = await attest(world(COMMIT, only(ARM, (run) => { run.conclusion = 'failure'; })));
  assert.equal(codeOf(red, 'remote-nixos-host'), 'job-failure');
  const w = world();
  const withoutArm = (args) => { const r = w(args); return /check-runs/.test(args.join(' ')) ? { ...r, out: r.out.split('\n').filter((l) => !l.includes(ARM)).join('\n') } : r; };
  const missing = await attest(withoutArm);
  assert.equal(codeOf(missing, 'remote-nixos-host'), 'job-missing');
  assert.equal(missing.attestations.some((a) => a.stepId === 'remote-nixos-host'), false, 'one leg is never enough');
});

test('[REL-001.AC03] gh unavailable, unauthenticated or offline produces no attestation and a typed reason', async () => {
  const cases = [
    [{ code: null, out: '', err: 'ENOENT: spawn gh ENOENT' }, 'gh-unavailable'],
    [{ code: 4, out: '', err: 'To get started with the CLI, please run:  gh auth login' }, 'gh-unauthenticated'],
    [{ code: 1, out: '', err: 'error connecting to the API: could not resolve host' }, 'gh-offline'],
  ];
  for (const [fail, code] of cases) {
    const res = await attest(fakeGh({ runs: [], fail }));
    assert.deepEqual(res.attestations, [], code);
    assert.deepEqual(res.refusals.map((r) => r.code), [code, code]);
  }
  assert.equal(classifyGhFailure({ code: 1, out: '', err: 'something odd' }), 'gh-error');
  const garbage = await attest(() => ({ code: 0, out: 'not json', err: '' }));
  assert.deepEqual(garbage.attestations, [], 'an unparseable answer is a refusal, never a pass');
  const throwing = await attest(() => { throw new Error('boom'); });
  assert.deepEqual(throwing.attestations, []);
});

test('[REL-001.AC03] only a full 40 character sha is accepted; nothing is guessed from a ref', async () => {
  for (const bad of ['main', 'abc1234', '', undefined, 'A'.repeat(40)]) {
    const gh = world();
    const res = await attestFromCi({ steps: CLOSURE_STEPS, commit: bad, gh });
    assert.deepEqual(res.attestations, [], String(bad));
    assert.equal(res.refusals[0].code, 'bad-commit');
    assert.equal(gh.calls.length, 0, 'no call is made for a malformed commit');
  }
});

test('[REL-001.AC03] only the ci workflow can attest, and a failed or missing step in a green job refuses', async () => {
  const wf = await attest(world(COMMIT, only(GHC, (run, job) => { job.workflow_name = 'release'; })));
  assert.equal(codeOf(wf, 'remote-haskell-toolchain'), 'wrong-workflow');
  const noWf = await attest(world(COMMIT, only(GHC, (run, job) => { delete job.workflow_name; })));
  assert.equal(codeOf(noWf, 'remote-haskell-toolchain'), 'wrong-workflow', 'an unverifiable workflow is a refusal');
  const failedStep = await attest(world(COMMIT, only(GHC, (run, job) => { job.steps.push({ name: 'Some extra step', conclusion: 'failure' }); })));
  assert.equal(codeOf(failedStep, 'remote-haskell-toolchain'), 'step-failed');
  const missingStep = await attest(world(COMMIT, only(GHC, (run, job) => { job.steps = []; })));
  assert.equal(codeOf(missingStep, 'remote-haskell-toolchain'), 'required-step-not-successful');
});

test('[REL-001.AC03] continue-on-error: a tolerated first attempt may fail, but the guest must have passed in some attempt and the VM step must be green', async () => {
  const A1 = 'Emulated aarch64 NixOS guest, attempt 1 (runs the NIX-012 suite inside it)';
  const A2 = 'Emulated aarch64 NixOS guest, attempt 2 (only because attempt 1 failed)';
  const without = (job, n) => job.steps.filter((s) => s.name !== n);
  const retried = await attest(world(COMMIT, only(X86, (run, job) => { job.steps = without(job, A1).concat([{ name: A1, conclusion: 'failure' }, { name: A2, conclusion: 'success' }]); })));
  assert.ok(retried.attestations.some((a) => a.stepId === 'remote-nixos-host'), 'attempt 1 failed (tolerated) and attempt 2 passed');
  const bothFailed = await attest(world(COMMIT, only(X86, (run, job) => { job.steps = without(job, A1).concat([{ name: A1, conclusion: 'failure' }, { name: A2, conclusion: 'failure' }]); })));
  assert.equal(codeOf(bothFailed, 'remote-nixos-host'), 'step-failed');
  const noGuest = await attest(world(COMMIT, only(X86, (run, job) => { job.steps = without(job, A1); })));
  assert.equal(codeOf(noGuest, 'remote-nixos-host'), 'required-step-not-successful', 'the emulated guest never ran successfully');
  const vm = 'Controlled NixOS VM test (runs the NIX-012 suite inside a NixOS guest)';
  const noVm = await attest(world(COMMIT, only(X86, (run, job) => { job.steps = without(job, vm); })));
  assert.equal(codeOf(noVm, 'remote-nixos-host'), 'required-step-not-successful');
  // a job-level continue-on-error failure shows as a red job, and the job's own conclusion is what is read
  const jobLevel = await attest(world(COMMIT, only(X86, (run) => { run.conclusion = 'failure'; })));
  assert.equal(codeOf(jobLevel, 'remote-nixos-host'), 'job-failure');
});

test('[REL-001.AC03] the latest run of a re-run job decides, so an older success cannot hide a newer failure', async () => {
  const w = world();
  const wrapped = (args) => {
    const r = w(args);
    if (!/check-runs/.test(args.join(' '))) return r;
    const rows = r.out.split('\n').map((l) => JSON.parse(l));
    const g = rows.find((x) => x.name === GHC);
    return { ...r, out: [...rows, { ...g, id: g.id + 1000, conclusion: 'failure' }].map((x) => JSON.stringify(x)).join('\n') };
  };
  const res = await attest(wrapped);
  assert.equal(codeOf(res, 'remote-haskell-toolchain'), 'job-failure');
});

const recordFor = () => runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-attest-'), env: NO_REMOTE_TOOLS, exec: fakeExec() }).record;
const CLEAN = (record) => ({ commit: record.commit, tree: record.tree, dirtyPaths: [] });

test('[REL-001.AC03] the evaluator counts a remote step only through an attestation from hosted CI bound to the record commit', async () => {
  const record = recordFor();
  assert.equal(record.commit, COMMIT);
  const none = evaluateClosureRecord(record, CLEAN(record), { pkg: PKG });
  assert.equal(none.publishable, false, 'no attestations: unsupported and not counted, as before');
  assert.equal(none.remotePending.length, 2);
  const res = await attest(world());
  const yes = evaluateClosureRecord(record, CLEAN(record), { pkg: PKG, attestations: res.attestations });
  assert.equal(yes.localOk, true);
  assert.equal(yes.publishable, true);
  assert.deepEqual(yes.remotePending, []);
  const half = evaluateClosureRecord(record, CLEAN(record), { pkg: PKG, attestations: res.attestations.slice(0, 1) });
  assert.equal(half.publishable, false, 'both remote steps are needed');
  // the local gate must also hold: attestations never rescue a record whose local half is invalid
  const dirty = evaluateClosureRecord(record, { ...CLEAN(record), dirtyPaths: ['x'] }, { pkg: PKG, attestations: res.attestations });
  assert.equal(dirty.localOk, false);
  assert.equal(dirty.publishable, false);
});

test('[REL-001.AC03] an attestation for commit A cannot satisfy a record for commit B', async () => {
  const recordB = recordFor();
  const forA = (await attest(world(OTHER), OTHER)).attestations;
  assert.equal(forA.length, 2, 'control: A is attested');
  const v = evaluateClosureRecord(recordB, CLEAN(recordB), { pkg: PKG, attestations: forA });
  assert.equal(v.publishable, false);
  assert.equal(v.remotePending.length, 2);
  assert.match(v.remotePending[0].attestationRejected, /bound to commit cccccccccccc/);
  // relabelling the commit without the per-job evidence does not help either: each leg carries its own commit
  const relabelled = forA.map((a) => ({ ...a, commit: COMMIT }));
  assert.equal(evaluateClosureRecord(recordB, CLEAN(recordB), { pkg: PKG, attestations: relabelled }).publishable, false);
});

test('[REL-001.AC03] a hand-written or partial attestation does not satisfy the evaluator', async () => {
  const record = recordFor();
  const good = (await attest(world())).attestations;
  const judge = (atts) => evaluateClosureRecord(record, CLEAN(record), { pkg: PKG, attestations: atts }).publishable;
  const mapLegs = (a, f) => ({ ...a, source: { ...a.source, legs: a.source.legs.map(f) } });
  assert.equal(judge(good), true, 'control');
  assert.equal(judge(good.map((a) => ({ ...a, source: 'hosted-ci' }))), false, 'a bare string source is not evidence');
  assert.equal(judge(good.map((a) => ({ ...a, conclusion: 'failure' }))), false);
  assert.equal(judge(good.map((a) => (a.stepId === 'remote-nixos-host' ? { ...a, source: { ...a.source, legs: a.source.legs.slice(0, 1) } } : a))), false, 'a single matrix leg is not enough');
  assert.equal(judge(good.map((a) => mapLegs(a, (l) => ({ ...l, conclusion: 'cancelled' })))), false);
  assert.equal(judge(good.map((a) => mapLegs(a, (l) => ({ ...l, commit: OTHER })))), false);
  assert.equal(judge(good.map((a) => ({ ...a, stepId: 'foundation' }))), false);
});

test('[REL-001.AC03] the closure report and exit code reflect what hosted CI says, and a refusal is named', async () => {
  const record = recordFor();
  const dir = mkTestTmp('closure-attest-cli-');
  const file = path.join(dir, `${COMMIT.slice(0, 12)}.json`);
  fs.writeFileSync(file, JSON.stringify(record));
  const lines = [];
  const out = { write: (s) => lines.push(s) };
  assert.equal(await main(['--attest-from-ci', '--commit', COMMIT], { out, gh: world() }), 0);
  assert.match(lines.join(''), /every remote prerequisite is attested/);
  lines.length = 0;
  assert.equal(await main(['--attest-from-ci', '--commit', COMMIT], { out, gh: world(COMMIT, only(ARM, (run) => { run.conclusion = 'cancelled'; })) }), 1);
  assert.match(lines.join(''), /NOT attested remote-nixos-host \[job-cancelled\]/);
  lines.length = 0;
  assert.equal(await main(['--attest-from-ci', '--commit', COMMIT], { out, gh: fakeGh({ runs: [], fail: { code: null, out: '', err: 'ENOENT' } }) }), 1);
  assert.match(lines.join(''), /\[gh-unavailable\]/);
  // --verify refuses to attest a commit other than the record's
  lines.length = 0;
  assert.equal(await main(['--verify', file, '--attest-from-ci', '--commit', OTHER], { out, gh: world(OTHER) }), 2);
  assert.match(lines.join(''), /refusing to attest another commit/);
});

test('[REL-001.AC03] the plan declares its CI legs and they match the hosted CI workflow file', () => {
  const ci = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.deepEqual(checkClosurePlan({ pkg: PKG }).filter((p) => /legs/.test(p)), []);
  const stripped = CLOSURE_STEPS.map((s) => (s.remote ? { ...s, remote: { job: s.remote.job } } : s));
  assert.equal(checkClosurePlan({ pkg: PKG, steps: stripped }).filter((p) => /legs/.test(p)).length, 2, 'a remote step without legs is unsound');
  assert.match(ci, /^name: ci$/m, 'the attesting workflow name');
  assert.match(ci, /^ {2}language-tools-ghc:$/m);
  assert.match(ci, /name: nixos-runtime \(\$\{\{ matrix\.system \}\}\)/);
  for (const sys of ['x86_64-linux', 'aarch64-linux']) assert.match(ci, new RegExp(`system: ${sys}`));
  // every step name the attestation depends on exists in the workflow, so a rename cannot silently make it unattestable
  const names = new Set([...ci.matchAll(/^\s+- name: (.+)$/gm)].map((m) => m[1].trim()));
  const wanted = [...Object.values(HASKELL.remote.requiredSteps), ...Object.values(NIXOS.remote.requiredSteps), NIXOS.remote.toleratedFailedSteps].flat(2);
  for (const n of wanted) assert.ok(names.has(n), `ci.yml has a step named '${n}'`);
  assert.deepEqual(NIXOS.remote.legs, [X86, ARM], 'every listed matrix leg must be green');
});

test('[REL-001.AC03] describeAttestation never reports a refusal as attested', async () => {
  const res = await attest(world(COMMIT, only(GHC, (run) => { run.conclusion = 'failure'; })));
  const text = describeAttestation(res).join('\n');
  assert.match(text, /NOT attested remote-haskell-toolchain \[job-failure\]/);
  assert.match(text, /^attested remote-nixos-host/m);
});
