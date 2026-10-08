// Every hosted job that runs the FULL test suite (or the full release check, which runs it) must first relax the runner's user-namespace restriction.
//
// Why: the suite includes witnesses that execute inside a real confinement primitive, and a hosted Ubuntu runner restricts unprivileged user
// namespaces by default. Without the relaxation 7 X-009 tests fail ("a confinement primitive is required for witnesses to count"). That is exactly
// how the "Scanner F1 benchmark" workflow failed on every run for days: bench.yml ran `npm test` without the step ci.yml's test job has. A new
// workflow or job that runs the suite is the same mistake waiting to happen, so this checks every job in every workflow.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as yaml from 'js-yaml';

const WORKFLOWS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '.github', 'workflows');

// A step that runs the whole suite: `npm test`, `npm run test` (not a scoped `npm run test:xyz`), the runner itself, or the release check
// without --only (which picks a subset by id; --group is still allowed to need it, so it is not exempted).
const RUNS_FULL_SUITE = /(?:^|[\s;&|])npm test\b|npm run test(?![:\w-])|run-unit-tests\.mjs|release-check\.mjs(?![^\n]*--only)/;
const RELAXES_USERNS = /apparmor_restrict_unprivileged_userns/;

export function jobsNeedingConfinement(doc) {
  const out = [];
  for (const [id, job] of Object.entries((doc && doc.jobs) || {})) {
    const runs = (job.steps || []).map((s) => String(s.run || '')).join('\n');
    if (RUNS_FULL_SUITE.test(runs)) out.push({ id, relaxes: RELAXES_USERNS.test(runs) });
  }
  return out;
}

const files = fs.readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f));

test('every workflow job that runs the full suite relaxes the user-namespace restriction first', () => {
  assert.ok(files.length > 0);
  const missing = [];
  let checked = 0;
  for (const f of files) {
    const doc = yaml.load(fs.readFileSync(path.join(WORKFLOWS, f), 'utf8'));
    for (const j of jobsNeedingConfinement(doc)) { checked++; if (!j.relaxes) missing.push(`${f}: ${j.id}`); }
  }
  assert.ok(checked >= 2, `the check must actually find the jobs that run the suite (found ${checked})`);
  assert.deepEqual(missing, [], `these jobs run the full test suite without the user-namespace step: ${missing.join(', ')}`);
});

test('the detector itself: it finds an unprotected job, accepts a protected one, and ignores a job that only runs a scoped script', () => {
  const unprotected = yaml.load('jobs:\n  t:\n    steps:\n      - run: npm test\n');
  assert.deepEqual(jobsNeedingConfinement(unprotected), [{ id: 't', relaxes: false }]);
  const protectedJob = yaml.load('jobs:\n  t:\n    steps:\n      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n      - run: npm test\n');
  assert.deepEqual(jobsNeedingConfinement(protectedJob), [{ id: 't', relaxes: true }]);
  const scoped = yaml.load('jobs:\n  t:\n    steps:\n      - run: npm run test:language-tools\n');
  assert.deepEqual(jobsNeedingConfinement(scoped), [], 'a scoped script does not run the confinement witnesses');
  const partialCheck = yaml.load('jobs:\n  t:\n    steps:\n      - run: node scripts/release-check.mjs --no-cache --only bundle-integrity,package-contents\n');
  assert.deepEqual(jobsNeedingConfinement(partialCheck), [], 'an --only release check selects by id and does not run the suite');
  const full = yaml.load('jobs:\n  t:\n    steps:\n      - run: node ../scripts/release-check.mjs --no-cache\n');
  assert.deepEqual(jobsNeedingConfinement(full), [{ id: 't', relaxes: false }]);
});

test('removing the step from a copy of the real benchmark workflow is caught', () => {
  const src = fs.readFileSync(path.join(WORKFLOWS, 'bench.yml'), 'utf8');
  const stripped = src.replace(/^\s*sudo sysctl[^\n]*userns[^\n]*\n/gm, '').replace(/kernel\.apparmor_restrict_unprivileged_userns/g, 'x');
  assert.notEqual(stripped, src, 'the real workflow has the step to remove');
  const hit = jobsNeedingConfinement(yaml.load(stripped)).filter((j) => !j.relaxes).map((j) => j.id);
  assert.ok(hit.includes('synthetic-bench'), `the stripped copy must be flagged (got ${JSON.stringify(hit)})`);
});
