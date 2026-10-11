// Attested-from-CI acceptance of locally skipped tests (lib/ci-attest.mjs, wired into verifier.mjs and closure.mjs).
// `gh` and `git` are replaced by a fake that plays GitHub's side. What is under test is the consumer: what it asks for, and every way
// it must refuse. Both directions are pinned: a valid attestation counts, and each refusal reason, each forgery and a local failure do not.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MiniRepo } from './helpers.js';
import { loadManifest } from '../lib/manifest.mjs';
import { layout, evidenceKey } from '../lib/state.mjs';
import { TreeIndex } from '../lib/tree.mjs';
import { verifyRequirement } from '../lib/verifier.mjs';
import { checkEnvelope } from '../lib/evidence.mjs';
import { checkReceipts } from '../lib/closure.mjs';
import { evaluateFinal } from '../lib/final.mjs';
import { validateProfile } from '../lib/profile.mjs';
import {
  attestSkippedTests, buildReport, validateReport, uncoveredSkips, attestationProblem, sourceLabel, REFUSAL_CODES, REPORT_FILE,
} from '../lib/ci-attest.mjs';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SHA = 'c'.repeat(40);
const OTHER = 'd'.repeat(40);
const JOB = 'sandbox-linux';
const STEP = 'Sandbox escape suite and Linux control probes (fails if any required suite SKIPPED)';
const CFG = { job: JOB, workflow: 'ci', artifact: 'sandbox-linux-test-report', groups: ['linux-enforcement'], requiredStep: STEP };
const NS = '[HS-001.AC01] reads outside the allowed roots are blocked on the Linux namespace backend';
const NS2 = '[HS-001.AC02] a direct socket cannot bypass the policy on the Linux namespace backend';
const RUN_ID = 9001;

const tests = (over = {}) => [
  { group: 'linux-enforcement', name: NS, status: 'pass' },
  { group: 'linux-enforcement', name: NS2, status: 'pass' },
  { group: 'linux-enforcement', name: '[HS-001.AC01] the mount plan is built', status: 'pass' },
  ...(over.extra || []),
].map((t) => (over.set && over.set[t.name] ? { ...t, status: over.set[t.name] } : t)).filter((t) => !(over.drop || []).includes(t.name));

const report = (o = {}) => {
  const r = buildReport({ commit: SHA, runId: RUN_ID, backend: 'namespace', platform: 'linux', tests: o.tests || tests(), problems: o.problems ?? 0 });
  return { ...r, ...(o.patch || {}) };
};

/** A fake GitHub. Every knob shapes one thing the reader looks at. */
function fakeGh({
  head = SHA, runs, jobDetail = {}, rep = report(), reportRaw = null, noFile = false, downloadFail = null, checkRunsFail = null, jobsFail = null,
} = {}) {
  const calls = [];
  const gh = async (args) => {
    calls.push(args);
    if (args[0] === 'api' && args.includes('--paginate')) {
      if (checkRunsFail) return checkRunsFail;
      const rows = runs ?? [{ id: 555, name: JOB, head_sha: head, status: 'completed', conclusion: 'success', completed_at: 't', html_url: 'https://example.test/job/555' }];
      return { code: 0, out: rows.map((r) => JSON.stringify(r)).join('\n'), err: '' };
    }
    if (args[0] === 'api') {
      if (jobsFail) return jobsFail;
      return { code: 0, err: '', out: JSON.stringify({ head_sha: head, status: 'completed', conclusion: 'success', workflow_name: 'ci', run_id: RUN_ID, steps: [{ name: STEP, conclusion: 'success' }], ...jobDetail }) };
    }
    if (args[0] === 'run' && args[1] === 'download') {
      if (downloadFail) return downloadFail;
      if (!noFile) writeFileSync(join(args[args.indexOf('-D') + 1], REPORT_FILE), reportRaw ?? JSON.stringify(rep));
      return { code: 0, out: '', err: '' };
    }
    return { code: 1, out: '', err: 'unexpected call' };
  };
  return { gh, calls };
}
const git = (o = {}) => () => ({ head: SHA, dirty: false, ...o });
const go = (f, over = {}) => attestSkippedTests({ skippedNames: [NS], cfg: CFG, repoRoot: '/nonexistent', gh: f.gh, git: git(), ...over });

// ---------------------------------------------------------------- the valid path

test('[CI-ATTEST] a succeeded sandbox-linux job for the exact sha whose report lists the test as passed covers it', async () => {
  const f = fakeGh();
  const r = await go(f);
  assert.equal(r.ok, true);
  assert.deepEqual(r.covered, [NS]);
  assert.equal(r.source, `attested-from-ci: ${JOB}@${SHA}`);
  assert.equal(r.runId, RUN_ID);
  assert.match(r.reportSha256, /^[0-9a-f]{64}$/);
  assert.ok(f.calls.some((c) => c[0] === 'run' && c[1] === 'download' && c.includes('sandbox-linux-test-report')), 'it read the report artifact of the job\'s own run');
});

test('[CI-ATTEST] the writer and the reader share one definition: a report buildReport makes validates, and is bound to what it names', () => {
  const r = report();
  assert.equal(validateReport(r, { commit: SHA, runId: RUN_ID }), null);
  assert.equal(r.verdict, 'VERIFIED');
  assert.equal(buildReport({ commit: SHA, runId: 1, backend: 'x', platform: 'p', tests: [], problems: 2 }).verdict, 'NOT VERIFIED');
});

// ---------------------------------------------------------------- every refusal reason, typed

const refusals = [
  ['bad-commit', () => ({ over: { git: git({ head: 'abc123' }) } })],
  ['working-tree-dirty', () => ({ over: { git: git({ dirty: true }) } })],
  ['git-unavailable', () => ({ over: { git: () => ({ error: 'not a repository' }) } })],
  ['no-config', () => ({ over: { cfg: null } })],
  ['sha-unknown', () => ({ f: { checkRunsFail: { code: 1, out: '', err: 'gh: No commit found for SHA: ccc (HTTP 422)' } } })],
  ['gh-unavailable', () => ({ f: { checkRunsFail: { code: null, out: '', err: 'ENOENT: spawn gh' } } })],
  ['gh-unauthenticated', () => ({ f: { checkRunsFail: { code: 4, out: '', err: 'To get started with GitHub CLI, please run: gh auth login' } } })],
  ['gh-offline', () => ({ f: { checkRunsFail: { code: 1, out: '', err: 'dial tcp: lookup api.github.com: no such host; could not resolve host' } } })],
  ['gh-error', () => ({ f: { checkRunsFail: { code: 1, out: '', err: 'boom' } } })],
  ['bad-response', () => ({ f: { checkRunsFail: { code: 0, out: 'not json at all', err: '' } } })],
  ['job-missing', () => ({ f: { runs: [{ id: 1, name: 'corpus', head_sha: SHA, status: 'completed', conclusion: 'success' }] } })],
  ['job-missing', () => ({ f: { runs: [] } })],
  ['job-not-completed', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'in_progress', conclusion: null }] } })],
  ['job-failure', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'completed', conclusion: 'failure' }] } })],
  ['job-cancelled', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'completed', conclusion: 'cancelled' }] } })],
  ['job-skipped', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'completed', conclusion: 'skipped' }] } })],
  ['job-neutral', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'completed', conclusion: 'neutral' }] } })],
  ['sha-mismatch', () => ({ f: { runs: [{ id: 555, name: JOB, head_sha: OTHER, status: 'completed', conclusion: 'success' }] } })],
  ['sha-mismatch', () => ({ f: { jobDetail: { head_sha: OTHER } } })],
  ['job-detail-not-success', () => ({ f: { jobDetail: { conclusion: 'failure' } } })],
  ['wrong-workflow', () => ({ f: { jobDetail: { workflow_name: 'other' } } })],
  ['step-failed', () => ({ f: { jobDetail: { steps: [{ name: STEP, conclusion: 'success' }, { name: 'later', conclusion: 'failure' }] } } })],
  ['required-step-not-successful', () => ({ f: { jobDetail: { steps: [{ name: STEP, conclusion: 'skipped' }] } } })],
  ['bad-response', () => ({ f: { jobDetail: { run_id: null } } })],
  ['report-missing', () => ({ f: { downloadFail: { code: 1, out: '', err: 'no valid artifacts found to download' } } })],
  ['report-missing', () => ({ f: { noFile: true } })],
  ['report-malformed', () => ({ f: { reportRaw: '{not json' } })],
  ['report-malformed', () => ({ f: { reportRaw: JSON.stringify([1, 2]) } })],
  ['report-malformed', () => ({ f: { rep: { ...report(), tests: [{ group: 'linux-enforcement', name: NS, status: 'maybe' }] } } })],
  ['report-wrong-kind', () => ({ f: { rep: report({ patch: { kind: 'something-else' } }) } })],
  ['report-digest-mismatch', () => ({ f: { rep: report({ patch: { tests: tests({ set: { [NS]: 'pass' }, extra: [{ group: 'linux-enforcement', name: 'smuggled', status: 'pass' }] }) } }) } })],
  ['report-commit-mismatch', () => ({ f: { rep: report({ patch: { commit: OTHER } }) } })],
  ['report-run-mismatch', () => ({ f: { rep: report({ patch: { runId: 12345 } }) } })],
  ['report-not-verified', () => ({ f: { rep: report({ problems: 3 }) } })],
  ['report-not-verified', () => ({ f: { rep: report({ patch: { verdict: 'NOT VERIFIED' } }) } })],
  ['test-absent-from-report', () => ({ f: { rep: report({ tests: tests({ drop: [NS] }) }) } })],
  ['test-absent-from-report', () => ({ f: { rep: report({ tests: tests({ drop: [NS] }).concat([{ group: 'execution', name: NS, status: 'pass' }]) }) } })],
  ['test-skipped-in-ci', () => ({ f: { rep: report({ tests: tests({ set: { [NS]: 'skip' } }) }) } })],
  ['test-failed-in-ci', () => ({ f: { rep: report({ tests: tests({ set: { [NS]: 'fail' } }) }) } })],
];

for (const [code, make] of refusals) {
  test(`[CI-ATTEST] refused with ${code}: ${JSON.stringify(Object.keys(make().f || make().over || {}))} ${make().f ? JSON.stringify(Object.values(make().f)[0]).slice(0, 70) : ''}`, async () => {
    const m = make();
    const f = fakeGh(m.f || {});
    const r = await go(f, m.over || {});
    assert.equal(r.ok, false, 'nothing is covered');
    assert.deepEqual(r.covered, []);
    assert.equal(r.uncovered.length, 1);
    assert.equal(r.uncovered[0].code, code);
    assert.ok(REFUSAL_CODES.includes(code), `${code} is a declared code`);
  });
}

test('[CI-ATTEST] a duplicate name that is passing in one entry and skipped or failed in another is not covered', async () => {
  for (const status of ['skip', 'fail']) {
    const r = await go(fakeGh({ rep: report({ tests: tests().concat([{ group: 'linux-enforcement', name: NS, status }]) }) }));
    assert.equal(r.ok, false);
    assert.equal(r.uncovered[0].code, status === 'skip' ? 'test-skipped-in-ci' : 'test-failed-in-ci');
  }
});

test('[CI-ATTEST] only the names it is asked about are covered, per name', async () => {
  const f = fakeGh({ rep: report({ tests: tests({ set: { [NS2]: 'skip' } }) }) });
  const r = await go(f, { skippedNames: [NS, NS2, '[HS-001.AC01] never heard of'] });
  assert.equal(r.ok, false);
  assert.deepEqual(r.covered, [NS]);
  assert.deepEqual(r.uncovered.map((u) => [u.name === NS2 ? 'ns2' : 'other', u.code]), [['ns2', 'test-skipped-in-ci'], ['other', 'test-absent-from-report']]);
});

test('[CI-ATTEST] a hand-edited report is refused even when the edit is a single flipped status', async () => {
  const rep = report({ tests: tests({ set: { [NS]: 'skip' } }) });
  const forged = JSON.parse(JSON.stringify(rep));
  forged.tests.find((t) => t.name === NS).status = 'pass';
  const r = await go(fakeGh({ rep: forged }));
  assert.equal(r.uncovered[0].code, 'report-digest-mismatch');
});

// ---------------------------------------------------------------- the verifier end to end

const SUITE = (extra = '') => `import test from 'node:test';
test('[HS-001.AC01] the mount plan is built', () => {});
test(${JSON.stringify(NS)}, { skip: 'SKIPPED, NOT PASSED: needs the Linux namespace backend' }, () => {});
test(${JSON.stringify(NS2)}, { skip: 'SKIPPED, NOT PASSED: needs the Linux namespace backend' }, () => {});
${extra}`;
const REQS = [{ id: 'HS-001', weight: 2, criteria: ['one', 'two'] }];
const profileWith = (attest = CFG) => ({ suites: { 'suite-HS-001': { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/suite-HS-001.test.js'], timeoutSeconds: 30, ...(attest ? { attestFromCi: attest } : {}) } } });

async function ctxFor(src, { attest = CFG } = {}) {
  const repo = new MiniRepo(REQS, { profile: profileWith(attest), suiteSources: { 'suite-HS-001': src } });
  const i = await repo.init(); assert.equal(i.code, 0, i.stderr);
  const m = loadManifest(repo.root).manifest;
  const L = layout(repo.root, repo.runId());
  const tree = new TreeIndex(repo.root);
  const key = evidenceKey(repo.root);
  return { repo, m, key, base: { repoRoot: repo.root, L, manifest: m, tree, key, invoker: 'controller' }, req: m.requirements.find((r) => r.id === 'HS-001') };
}
const optsWith = (f, gitOver = {}) => ({ attest: { deps: { gh: f.gh, git: git(gitOver) } } });
const bothPass = () => fakeGh({ rep: report({ tests: tests() }) });

test('[CI-ATTEST] the manifest carries the suite\'s attestFromCi to its verification', async () => {
  const c = await ctxFor(SUITE());
  try { assert.deepEqual(c.req.verification.attestFromCi, CFG); } finally { await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: skipped locally, covered by a valid attestation -> verified, with the skip still counted and a labelled source', async () => {
  const c = await ctxFor(SUITE());
  try {
    const f = bothPass();
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'pass', JSON.stringify(evidence.limitations));
    assert.equal(evidence.counts.skipped, 2, 'the local skips are still reported as skipped');
    assert.equal(evidence.counts.attestedSkipped, 2);
    assert.equal(evidence.invoker, 'controller', 'this host still issued the receipt; the source of the skipped tests is labelled instead');
    const label = `attested-from-ci: ${JOB}@${SHA}`;
    assert.equal(evidence.attestation.source, label);
    assert.deepEqual(evidence.attestation.covered.sort(), [NS, NS2].sort());
    for (const cr of evidence.criteria) assert.equal(cr.state, 'pass');
    const ac1 = evidence.criteria.find((x) => x.id === 'HS-001.AC01');
    assert.equal(ac1.source, label);
    const nsAssertion = ac1.assertions.find((a) => a.name === NS);
    assert.equal(nsAssertion.skipped, true);
    assert.equal(nsAssertion.ok, false, 'it is not recorded as passing here');
    assert.equal(nsAssertion.attested, label);
    assert.equal(ac1.assertions.find((a) => a.name.includes('mount plan')).ok, true, 'the locally passing test stays a local pass');
    assert.ok(evidence.limitations.some((l) => /NOT run on this host/.test(l) && l.includes(SHA)));
    assert.equal(checkEnvelope(evidence, c.key).valid, true);
    assert.equal(uncoveredSkips(evidence, SHA), 0);
  } finally { await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: no attestFromCi in the suite -> the skip fails exactly as before and gh is never called', async () => {
  const c = await ctxFor(SUITE(), { attest: null });
  try {
    const f = bothPass();
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'fail');
    assert.match(evidence.reason, /skipped/);
    assert.equal(evidence.attestation, undefined);
    assert.equal(f.calls.length, 0);
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC01').state, 'fail');
  } finally { await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: LOOP_ATTEST_FROM_CI=0 switches the whole mechanism off', async () => {
  const c = await ctxFor(SUITE());
  const prev = process.env.LOOP_ATTEST_FROM_CI;
  process.env.LOOP_ATTEST_FROM_CI = '0';
  try {
    const f = bothPass();
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'fail');
    assert.equal(f.calls.length, 0);
  } finally { if (prev === undefined) delete process.env.LOOP_ATTEST_FROM_CI; else process.env.LOOP_ATTEST_FROM_CI = prev; await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: every refusal leaves the requirement failed, skipped counted, and names the typed reason', async () => {
  const cases = [
    ['job-failure', { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'completed', conclusion: 'failure' }] }, {}],
    ['job-not-completed', { runs: [{ id: 555, name: JOB, head_sha: SHA, status: 'in_progress', conclusion: null }] }, {}],
    ['test-absent-from-report', { rep: report({ tests: tests({ drop: [NS] }) }) }, {}],
    ['test-skipped-in-ci', { rep: report({ tests: tests({ set: { [NS]: 'skip' } }) }) }, {}],
    ['gh-unavailable', { checkRunsFail: { code: null, out: '', err: 'ENOENT' } }, {}],
    ['report-malformed', { reportRaw: 'garbage' }, {}],
    ['working-tree-dirty', {}, { dirty: true }],
    ['bad-commit', {}, { head: 'nothead' }],
  ];
  for (const [code, fo, gitOver] of cases) {
    const c = await ctxFor(SUITE());
    try {
      const { evidence } = await verifyRequirement(c.base, c.req, optsWith(fakeGh(fo), gitOver));
      assert.equal(evidence.result, 'fail', code);
      assert.equal(evidence.counts.skipped, 2, code);
      assert.ok(!evidence.counts.attestedSkipped || code.startsWith('test-'), `${code}: nothing is covered unless the report covered it`);
      assert.ok(evidence.limitations.some((l) => l.includes(`not attested [${code}]`)), `${code} named: ${JSON.stringify(evidence.limitations)}`);
      assert.ok(evidence.criteria.some((x) => x.state === 'fail'), code);
    } finally { await c.repo.cleanup(); }
  }
});

test('[CI-ATTEST] verification: a partly covered suite fails; only the covered criterion passes', async () => {
  const c = await ctxFor(SUITE());
  try {
    const f = fakeGh({ rep: report({ tests: tests({ drop: [NS2] }) }) });
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'fail');
    assert.equal(evidence.counts.attestedSkipped, 1);
    assert.equal(uncoveredSkips(evidence, SHA), 1);
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC01').state, 'pass');
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC02').state, 'fail');
  } finally { await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: a LOCAL failure is never overridden, and the attestation is not even consulted', async () => {
  const c = await ctxFor(SUITE(`test('[HS-001.AC01] a real local failure', () => { throw new Error('boom'); });\n`));
  try {
    const f = bothPass();
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'fail');
    assert.equal(f.calls.length, 0, 'a failing run does not look anything up');
    assert.equal(evidence.attestation, undefined);
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC01').state, 'fail');
    assert.ok(evidence.counts.fail > 0);
  } finally { await c.repo.cleanup(); }
});

test('[CI-ATTEST] verification: a todo test is not attestable, and a local failure of a test the CI report calls passing stays a failure', async () => {
  const c = await ctxFor(`import test from 'node:test';
test('[HS-001.AC01] the mount plan is built', () => {});
test(${JSON.stringify(NS)}, { todo: 'later' }, () => {});
test(${JSON.stringify(NS2)}, () => { throw new Error('fails here, passes there'); });
`);
  try {
    const f = bothPass();
    const { evidence } = await verifyRequirement(c.base, c.req, optsWith(f));
    assert.equal(evidence.result, 'fail');
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC02').state, 'fail');
    assert.equal(evidence.criteria.find((x) => x.id === 'HS-001.AC01').state, 'fail', 'a todo is not a skip');
  } finally { await c.repo.cleanup(); }
});

// ---------------------------------------------------------------- scoring: closure receipts and the final decision

const REC = (over = {}) => ({
  found: true, valid: true, fresh: true, invoker: 'controller', phase: 'final', createdAt: '2030-01-01T00:00:00.000Z', result: 'pass', blockerType: null,
  counts: { tests: 5, pass: 3, fail: 0, skipped: 2, attestedSkipped: 2 },
  attestation: { kind: 'attested-from-ci', source: sourceLabel(JOB, SHA), job: JOB, commit: SHA, runId: RUN_ID, reportSha256: 'e'.repeat(64), covered: [NS, NS2] },
  criteria: [{ id: 'HS-001.AC01', state: 'pass' }, { id: 'HS-001.AC02', state: 'pass' }], ...over,
});
const check = (rc, head = SHA) => checkReceipts({ requirements: [{ id: 'HS-001', criteria: [{ id: 'HS-001.AC01' }, { id: 'HS-001.AC02' }] }], receipts: new Map([['HS-001', { id: 'HS-001', ...rc }]]), phaseStartedAt: '2029-01-01T00:00:00.000Z', head });

test('[CI-ATTEST] closure: a consistent attested receipt bound to HEAD counts both criteria', () => {
  const r = check(REC());
  assert.deepEqual(r.unmet, []);
  assert.equal(r.passedCriteria, 2);
});

test('[CI-ATTEST] closure: a skip with no attestation still counts as failed (the old rule is intact)', () => {
  const r = check(REC({ counts: { tests: 5, pass: 3, fail: 0, skipped: 2 }, attestation: null }));
  assert.ok(r.unmet.some((u) => u.kind === 'criterion-skipped'));
  assert.equal(r.passedCriteria, 0);
});

test('[CI-ATTEST] closure: forged or inconsistent attestations are refused', () => {
  const bad = {
    'bound to another commit': REC({ attestation: { ...REC().attestation, commit: OTHER, source: sourceLabel(JOB, OTHER) } }),
    'label does not match its job and commit': REC({ attestation: { ...REC().attestation, source: sourceLabel(JOB, OTHER) } }),
    'covers fewer tests than the counts claim': REC({ attestation: { ...REC().attestation, covered: [NS] } }),
    'counts claim attested skips but carry none': REC({ attestation: null }),
    'unknown kind': REC({ attestation: { ...REC().attestation, kind: 'self-attested' } }),
    'no report digest': REC({ attestation: { ...REC().attestation, reportSha256: '' } }),
    'abbreviated commit': REC({ attestation: { ...REC().attestation, commit: SHA.slice(0, 12), source: sourceLabel(JOB, SHA.slice(0, 12)) } }),
  };
  for (const [why, rc] of Object.entries(bad)) {
    const r = check(rc);
    assert.ok(r.unmet.some((u) => u.kind === 'attestation-invalid'), why);
    assert.ok(r.unmet.some((u) => u.kind === 'criterion-skipped'), `${why}: the skips count against it again`);
    assert.equal(r.passedCriteria, 0, why);
  }
  assert.ok(check(REC(), null).unmet.some((u) => u.kind === 'attestation-invalid'), 'unknown HEAD: refused');
  assert.deepEqual(check(REC(), undefined).unmet, [], 'head not checked in this call (the early pass)');
});

test('[CI-ATTEST] closure: attested skips can never exceed the local skips, and a failed receipt stays failed', () => {
  assert.equal(uncoveredSkips({ counts: { skipped: 1, attestedSkipped: 5 }, attestation: { ...REC().attestation, covered: [1, 2, 3, 4, 5] } }, SHA), 0, 'clamped at zero, never negative');
  const r = check(REC({ result: 'fail', criteria: [{ id: 'HS-001.AC01', state: 'fail' }, { id: 'HS-001.AC02', state: 'pass' }] }));
  assert.ok(r.unmet.some((u) => u.kind === 'criterion-failed'));
});

test('[CI-ATTEST] final decision: a requirement is verified iff every skip is covered', () => {
  const run = (skipped) => evaluateFinal({ requirements: [{ id: 'A', result: 'pass', evidenceId: 'e', skipped, blockerType: null }], expectedRequirements: ['A'], gates: [], expectedGates: [], treeDigests: { before: 'd', afterEach: ['d'], after: 'd' } });
  assert.equal(run(uncoveredSkips(REC(), SHA)).verdict, 'all-required-criteria-verified');
  assert.equal(run(uncoveredSkips(REC({ attestation: null }), SHA)).verdict, 'incomplete');
});

test('[CI-ATTEST] attestationProblem is silent for a receipt that never used an attestation', () => {
  assert.equal(attestationProblem({ counts: { skipped: 3 } }, SHA), null);
  assert.match(attestationProblem({ counts: { skipped: 3 }, attestation: { kind: 'attested-from-ci' } }, SHA), /covers no skipped test/);
});

// ---------------------------------------------------------------- the profile

test('[CI-ATTEST] the shipped assurance profile declares the sandbox-linux attestation, and a malformed one is rejected', async () => {
  const { readFileSync } = await import('node:fs');
  const prof = JSON.parse(readFileSync(new URL('../profiles/assurance-differentiation.json', import.meta.url), 'utf8'));
  assert.equal(prof.suites.capabilities.attestFromCi.job, 'sandbox-linux');
  assert.deepEqual(prof.suites.capabilities.attestFromCi.groups, ['linux-enforcement']);
  assert.doesNotThrow(() => validateProfile(prof, REPO_ROOT));
  for (const bad of [{ job: '' , artifact: 'x' }, { job: 'j' }, { job: 'j', artifact: 'a', groups: [] }, 'nope']) {
    const p = JSON.parse(JSON.stringify(prof));
    p.suites.capabilities.attestFromCi = bad;
    assert.throws(() => validateProfile(p, REPO_ROOT), /attestFromCi/);
  }
});

test('[CI-ATTEST] the verifier hash covers the attestation module, so changing it makes earlier evidence stale', async () => {
  const { readFileSync } = await import('node:fs');
  assert.match(readFileSync(new URL('../lib/evidence.mjs', import.meta.url), 'utf8'), /'ci-attest\.mjs'/);
  void createHash;
});
