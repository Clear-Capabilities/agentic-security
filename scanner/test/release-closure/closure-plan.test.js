// REL-001.AC01: release checks run the applicable new suites and the existing controller, smoke, build,
// bundle-source, documentation and scorecard checks against an exact commit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  CLOSURE_STEPS, REQUIRED_AREAS, checkClosurePlan, runClosure, stepState, parseCounts, evaluateClosureRecord,
} from '../../../scripts/release-closure.mjs';
import { CHECKS, RELEASE_GROUPS, plannedCheckIds } from '../../../scripts/release-check.mjs';
import { CHECKS as PREPUSH_CHECKS } from '../../../scripts/pre-push-gate.mjs';
import { SCOPES } from '../../../scripts/run-unit-tests.mjs';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG, COMMIT, ALL_PRESENT, fakeExec } from '../helpers/closure-fixtures.js';

const run = (opts = {}) => runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-'), env: ALL_PRESENT, ...opts });

test('[REL-001.AC01] the plan names every new suite and the existing controller, smoke, build, bundle-source, documentation and scorecard checks', () => {
  assert.deepEqual(checkClosurePlan({ pkg: PKG }), [], 'the real plan is sound');
  const areas = new Set(CLOSURE_STEPS.map((s) => s.area));
  for (const a of REQUIRED_AREAS) assert.ok(a === 'build' ? areas.has('bundle-source') : areas.has(a), `area ${a} has a step`);
  const ids = CLOSURE_STEPS.map((s) => s.id);
  for (const id of ['foundation', 'evaluation', 'verification', 'deployment', 'invariants', 'capabilities', 'routing', 'portfolio', 'documentation-suite', 'release-closure-suite', 'controller', 'smoke', 'bundle-source', 'doc-drift', 'scorecard']) {
    assert.ok(ids.includes(id), `step ${id}`);
  }
  // the build step really is the build: check:bundle-source runs `npm run build` and compares
  assert.match(fs.readFileSync(path.join(REPO, 'scripts', 'check-bundle-source.mjs'), 'utf8'), /'npm', \['run', 'build'\]|run\('npm', \['run', 'build'\]\)/);
  assert.match(PKG.scripts['check:bundle-source'], /check-bundle-source\.mjs/);
});

test('[REL-001.AC01] running the plan executes every applicable step once, in the one commit, and records each', () => {
  const out = [];
  const exec = fakeExec({ out });
  const { record } = run({ exec });
  const local = CLOSURE_STEPS.filter((s) => !s.remote);
  for (const s of local) assert.equal(out.filter((x) => x === s.id).length, 1, `${s.id} ran exactly once`);
  assert.equal(record.commit, COMMIT);
  assert.equal(record.stable, true);
  assert.equal(record.steps.length, CLOSURE_STEPS.length, 'every planned step has a recorded result, run or not');
  for (const s of record.steps.filter((x) => x.state === 'pass')) {
    assert.match(s.log.sha256, /^[0-9a-f]{64}$/);
    assert.match(s.suiteVersion, /^sha256:[0-9a-f]{64}$/);
  }
  // git was read before and after: the commit is the same one the whole run was bound to
  const heads = exec.calls.filter((c) => c.cmd === 'git' && c.args[1] === 'HEAD');
  assert.ok(heads.length >= 2, 'HEAD is read before and after the run');
  assert.equal(evaluateClosureRecord(record, { commit: COMMIT, tree: record.tree, dirtyPaths: [] }, { pkg: PKG }).localOk, true);
});

test('[REL-001.AC01] a failing, skipped or zero-test step is not a pass, and one bad step fails the local gate', () => {
  assert.equal(stepState({ exitCode: 0, counts: { tests: 4, pass: 4, fail: 0, skipped: 0, todo: 0 }, expectTests: true }).state, 'pass');
  assert.equal(stepState({ exitCode: 1, counts: null, expectTests: true }).state, 'fail');
  assert.equal(stepState({ exitCode: 0, counts: { tests: 4, pass: 2, fail: 0, skipped: 2, todo: 0 }, expectTests: true }).state, 'incomplete');
  assert.equal(stepState({ exitCode: 0, counts: { tests: 4, pass: 3, fail: 0, skipped: 0, todo: 1 }, expectTests: true }).state, 'incomplete');
  assert.equal(stepState({ exitCode: 0, counts: { tests: 0, pass: 0, fail: 0, skipped: 0, todo: 0 }, expectTests: true }).state, 'fail');
  assert.equal(stepState({ exitCode: 0, counts: null, expectTests: true }).state, 'fail', 'a test step that printed no counts is not a pass');
  assert.equal(stepState({ exitCode: 0, counts: { tests: 4, pass: 3, fail: 1, skipped: 0, todo: 0 }, expectTests: true }).state, 'fail');
  assert.equal(stepState({ exitCode: null, signal: 'SIGKILL', counts: null, expectTests: false }).state, 'fail');
  assert.equal(stepState({ exitCode: null, timedOut: true, counts: null, expectTests: false }).state, 'fail');
  assert.equal(stepState({ exitCode: 0, counts: null, expectTests: false }).state, 'pass', 'a check script is judged by its exit code');
  assert.deepEqual(parseCounts('ℹ tests 3\nℹ pass 3\nℹ fail 0\nℹ skipped 0\nℹ todo 0\n'), { tests: 3, pass: 3, fail: 0, skipped: 0, todo: 0 });
  assert.equal(parseCounts('no counts'), null);

  for (const [label, opts] of [['fails', { fail: ['routing'] }], ['skips', { skipped: ['portfolio'] }], ['runs nothing', { zero: ['verification'] }]]) {
    const { record } = run({ exec: fakeExec(opts) });
    const v = evaluateClosureRecord(record, { commit: COMMIT, tree: record.tree, dirtyPaths: [] }, { pkg: PKG });
    assert.equal(v.localOk, false, `a step that ${label} fails the gate`);
    assert.ok(v.reasons.length >= 1);
  }
});

test('[REL-001.AC01] the plan check fails when an area, a script, a SCOPES entry or the group wiring is missing', () => {
  const without = (pred) => CLOSURE_STEPS.filter((s) => !pred(s));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: without((s) => s.area === 'controller') }).some((p) => /controller/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: without((s) => s.area === 'scorecard') }).some((p) => /scorecard/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: without((s) => s.area === 'bundle-source') }).some((p) => /build/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: without((s) => s.area === 'compat-core-language') }).some((p) => /compat-core-language/.test(p)));
  const scripts = { ...PKG.scripts }; delete scripts['test:routing'];
  assert.ok(checkClosurePlan({ pkg: { ...PKG, scripts } }).some((p) => /no script 'test:routing'/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, scopes: SCOPES.filter((s) => s !== 'routing') }).some((p) => /not in SCOPES/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, releaseGroups: { tests: ['test-suite'] } }).some((p) => /release-closure-gate/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: [...CLOSURE_STEPS, CLOSURE_STEPS[0]] }).some((p) => /duplicate step id/.test(p)));
  const noPrereq = CLOSURE_STEPS.map((s) => (s.remote ? { ...s, needs: {} } : s));
  assert.ok(checkClosurePlan({ pkg: PKG, steps: noPrereq }).some((p) => /could never be reported unsupported/.test(p)));
  assert.ok(checkClosurePlan({ pkg: PKG, ciJobs: ['test'] }).some((p) => /does not exist in .github\/workflows\/ci.yml/.test(p)));
  const ci = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  for (const s of CLOSURE_STEPS.filter((x) => x.remote)) assert.match(ci, new RegExp(`^  ${s.remote.job}:`, 'm'), `hosted CI job ${s.remote.job} exists`);
});

test('[REL-001.AC01] the release gate, its parallel group, the workflow leg and the pre-push static check all run the closure', () => {
  const check = CHECKS.find((c) => c.id === 'release-closure-gate');
  assert.ok(check, 'release-check.mjs registers release-closure-gate');
  assert.equal(check.slow, true, 'the full closure is a slow gate');
  assert.ok(plannedCheckIds().includes('release-closure-gate'));
  assert.ok(Object.values(RELEASE_GROUPS).flat().includes('release-closure-gate'), 'named in a release group so it is not left to `rest`');
  const group = Object.entries(RELEASE_GROUPS).find(([, ids]) => ids.includes('release-closure-gate'))[0];
  const wf = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'release.yml'), 'utf8');
  assert.match(wf, new RegExp(`group: ${group},`), `release.yml has a matrix leg for group ${group}`);
  assert.equal(PKG.scripts['release:closure:check'], 'node ../scripts/release-closure.mjs --run');
  assert.equal(PKG.scripts['release:closure:static'], 'node ../scripts/release-closure.mjs --static');
  const pre = PREPUSH_CHECKS.find((c) => c.id === 'release-closure-static');
  assert.ok(pre, 'the pre-push gate runs the cheap static half');
  assert.equal(pre.npmScript, 'release:closure:static');
  assert.equal(PKG.scripts['test:release-closure'].startsWith('node --test test/release-closure/'), true);
  assert.ok(SCOPES.includes('release-closure'), 'the new suite is part of npm test');
});
