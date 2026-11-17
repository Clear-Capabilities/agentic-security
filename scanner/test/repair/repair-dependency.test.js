// Verified remediation M4-02/M4-03: dependency repair, npm (FR-14). The lockfile and manifest are candidate files; the verifier checks
// the resolved graph and runs the application against the packages each revision resolves to. Packages are local tarballs in the
// fixture (synthetic packages written for these tests). A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { satisfies, checkResolution, materialize } from '../../src/repair/dependencies.js';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer, checkCandidate } from '../../src/repair/candidates.js';
import { validateProfile } from '../../src/repair/profile.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { npmLock } from '../helpers/npm-lock.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair', 'dep-files');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the dependency execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

const setup = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dep-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'dep:vulnlib', file: 'package.json' }, family: 'dependency', profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
  return { root, plan: p.plan, profile, files: Object.fromEntries(['src/app.mjs', 'package.json', 'package-lock.json'].map((f) => [f, fs.readFileSync(path.join(root, f), 'utf8')])) };
};

function variants(root, app) {
  const pkg = (deps) => `${JSON.stringify({ name: 'dep-files', version: '1.0.0', type: 'module', dependencies: deps }, null, 2)}\n`;
  const T = (n, v) => `vendor/packages/${n}-${v}.tgz`;
  const spec = (n, v) => `file:${T(n, v)}`;
  const lock = (deps, installed) => npmLock(root, { name: 'dep-files', version: '1.0.0' }, deps, installed);
  const adapted = app.replace("import { safeJoin } from 'vulnlib';", "import { resolveInside } from 'vulnlib';")
    .replace("    const file = safeJoin(filesRoot, name);\n", "    const file = resolveInside(filesRoot, name);\n    if (!file) { res.writeHead(404); res.end('no such file'); return; }\n");
  const tree = (vuln, other, nested) => {
    const deps = { otherlib: spec('otherlib', other), vulnlib: spec('vulnlib', vuln) };
    return { 'package.json': pkg(deps), 'package-lock.json': lock(deps, {
      'node_modules/otherlib': { version: other, tarball: T('otherlib', other), dependencies: { vulnlib: other === '1.0.0' ? '^1.0.0' : '^2.0.0' } },
      'node_modules/vulnlib': { version: vuln, tarball: T('vulnlib', vuln) },
      ...(nested ? { 'node_modules/otherlib/node_modules/vulnlib': { version: nested, tarball: T('vulnlib', nested) } } : {}),
    }) };
  };
  return {
    manifestOnly: { 'package.json': pkg({ otherlib: spec('otherlib', '1.0.0'), vulnlib: spec('vulnlib', '2.0.0') }) },
    noAdaptation: tree('2.0.0', '2.0.0'),
    transitiveLeft: { ...tree('2.0.0', '1.0.0', '1.0.0'), 'src/app.mjs': adapted },
    behaviourBreak: { ...tree('3.0.0', '2.0.0', '2.0.0'), 'src/app.mjs': adapted },
    correct: { ...tree('2.0.0', '2.0.0'), 'src/app.mjs': adapted },
  };
}

describe('[FR-14] dependency resolution and materialization (no execution)', () => {
  test('the npm range subset is evaluated exactly, and an unsupported range is unknown, never guessed', () => {
    assert.equal(satisfies('1.9.9', '<2.0.0'), true);
    assert.equal(satisfies('2.0.0', '^1.0.0'), false);
    assert.equal(satisfies('0.2.5', '^0.2.0'), true);
    assert.equal(satisfies('0.3.0', '^0.2.0'), false);
    assert.equal(satisfies('1.2.9', '~1.2.0'), true);
    assert.equal(satisfies('4.0.0', '>=2.0.0 <3.0.0 || 4.0.0'), true);
    assert.equal(satisfies('1.0.0', '1.x'), null);
  });

  test('[AC-14.2/AC-14.3] a stale lockfile, a transitive vulnerable copy, a tampered tarball and a package from elsewhere each fail resolution', () => {
    const s = setup();
    const v = variants(s.root, s.files['src/app.mjs']);
    const at = (files) => checkResolution(s.root, s.profile.dependency, { ...s.files, ...files });
    assert.equal(at({}).ok, false, 'the original resolves the vulnerable version');
    assert.match(at(v.manifestOnly).problems.join(' '), /lockfile is stale/);
    const t = at(v.transitiveLeft);
    assert.deepEqual(t.vulnerable.map((x) => [x.path, x.transitive]), [['node_modules/otherlib/node_modules/vulnlib', true]]);
    assert.equal(at(v.correct).ok, true, at(v.correct).problems.join('; '));
    const lock = JSON.parse(v.correct['package-lock.json']);
    lock.packages['node_modules/vulnlib'].resolved = 'https://registry.example/vulnlib-2.0.0.tgz';
    assert.match(at({ ...v.correct, 'package-lock.json': JSON.stringify(lock) }).problems.join(' '), /not from the declared package sources/);
    fs.appendFileSync(path.join(s.root, 'vendor', 'packages', 'vulnlib-2.0.0.tgz'), 'x');
    assert.match(at(v.correct).problems.join(' '), /does not match the integrity/);
  });

  test('materialization extracts exactly the packages the lockfile resolves, from their verified tarballs', () => {
    const s = setup();
    const v = variants(s.root, s.files['src/app.mjs']);
    const m = materialize(s.root, s.profile.dependency, { ...s.files, ...v.transitiveLeft });
    assert.match(m['node_modules/vulnlib/package.json'], /"version":"2\.0\.0"/);
    assert.match(m['node_modules/otherlib/node_modules/vulnlib/package.json'], /"version":"1\.0\.0"/);
  });

  test('a dependency repair may edit the manifest and the lockfile, never the test script; the profile must declare both files', () => {
    const s = setup();
    const v = variants(s.root, s.files['src/app.mjs']);
    assert.equal(checkCandidate(s.plan.contract, s.files, v.correct).ok, true);
    const withScript = JSON.parse(v.correct['package.json']); withScript.scripts = { test: 'true' };
    assert.match(checkCandidate(s.plan.contract, s.files, { ...v.correct, 'package.json': JSON.stringify(withScript) }).reasons.join(' '), /test script/);
    const bad = { ...s.profile, application: { ...s.profile.application, files: ['src/app.mjs'] } };
    assert.match(validateProfile(bad).join(' '), /must include package\.json and package-lock\.json/);
  });
});

describe('[FR-14] dependency repair, executed', () => {
  test('[AC-14.1/14.2/14.3/14.4] stale lockfile, transitive copy and behaviour break are rejected; an upgrade without its API adaptation is not verified; the adapted upgrade is', needs(async () => {
    const s = setup();
    const v = variants(s.root, s.files['src/app.mjs']);
    const items = [['manifestOnly', 1], ['noAdaptation', 1], ['transitiveLeft', 1], ['behaviourBreak', 2], ['correct', 3]].map(([k, round]) => ({ round, strategy: k, files: v[k] }));
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer(items)], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } } });
    const orig = r.record.obligationResults.find((o) => o.revision === 'original' && o.obligation === 'dependency-resolution');
    assert.equal(orig.observed, 'failed');
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    const res = (k, ob) => by[k].results.find((x) => x.obligation === ob)?.status;
    assert.equal(res('manifestOnly', 'dependency-resolution'), 'failed');
    assert.notEqual(by.noAdaptation.status, 'verified-for-contract');
    assert.equal(res('noAdaptation', 'filesystem-legitimate-requests'), 'inconclusive', 'the application no longer loads against the new API');
    assert.equal(res('transitiveLeft', 'dependency-resolution'), 'failed');
    assert.equal(res('transitiveLeft', 'filesystem-attacks-development'), 'passed', 'the transitive copy is not exercised by these requests: only resolution catches it');
    assert.equal(res('behaviourBreak', 'dependency-resolution'), 'passed');
    assert.equal(res('behaviourBreak', 'filesystem-legitimate-requests'), 'failed');
    assert.equal(by.correct.status, 'verified-for-contract', r.record.reasons.join('; '));
    const cx = r.record.counterexamples.find((x) => x.candidateId === by.transitiveLeft.candidateId);
    assert.equal(cx.property, 'dependency-resolution');
    assert.equal(cx.vulnerable[0].transitive, true);
  }));
});
