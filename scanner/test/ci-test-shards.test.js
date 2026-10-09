// ci.yml runs the test gate as four shards plus a bundle check, under the single required check name `test`.
//
// Branch protection and .github/required-checks.json require a check named exactly `test`. This pins, from the workflow text, that
// the name still exists and still means "the whole suite passed":
//   - `test` is an aggregator that needs the shard job and the bundle job;
//   - it runs with `if: always()` (otherwise a failed dependency SKIPS it, and a skipped required check reads as passing);
//   - it fails unless every dependency result is exactly `success` (a skipped or cancelled shard fails it);
//   - the shard matrix is 1..N with one N, every leg sets AGENTIC_SECURITY_TEST_SHARD from the matrix and runs `npm test`;
//   - fail-fast is off, the committed-bundle check runs exactly once and is not a shard step;
//   - every shard relaxes the user-namespace restriction before running the suite;
//   - the shard and bundle check-run names are classified in required-checks.json and equal what the matrix produces.
//
// Each invariant is a function over the workflow TEXT returning violations. The real file must yield none and, for every invariant,
// a mutated scratch copy of the text (made in memory, never written) must yield at least one: an assertion that cannot fail proves
// nothing. Same method as release-workflow-structure.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as yaml from 'js-yaml';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const CI = path.join(REPO, '.github', 'workflows', 'ci.yml');
const TIERS = path.join(REPO, '.github', 'required-checks.json');

const realText = () => fs.readFileSync(CI, 'utf8');
const realTiers = () => JSON.parse(fs.readFileSync(TIERS, 'utf8'));
const load = (t) => yaml.load(t);
const list = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);
const runs = (job) => list(job?.steps).map((s) => String(s.run ?? '')).join('\n');

/** The check-run names the shard job reports: its name template with each matrix value filled in. */
export function shardCheckNames(doc) {
  const job = doc.jobs?.['test-shard'];
  const template = String(job?.name ?? 'test-shard');
  return list(job?.strategy?.matrix?.shard).map((s) => template.replace(/\$\{\{\s*matrix\.shard\s*\}\}/g, String(s)));
}

const invariants = {
  aggregatorIsNamedTest(text) {
    const doc = load(text);
    const bad = [];
    const job = doc.jobs?.test;
    if (!job) return ['there is no job with the key `test`'];
    if (job.name !== undefined && job.name !== 'test') bad.push(`the aggregator job's check name is "${job.name}", not "test"`);
    for (const [key, j] of Object.entries(doc.jobs)) {
      if (key !== 'test' && j.name === 'test') bad.push(`job "${key}" also reports a check named "test"`);
    }
    return bad;
  },

  aggregatorNeedsShardsAndBundle(text) {
    const needs = list(load(text).jobs?.test?.needs);
    return ['test-shard', 'test-bundle'].filter((n) => !needs.includes(n)).map((n) => `test does not need ${n}`);
  },

  aggregatorRunsAlways(text) {
    const cond = String(load(text).jobs?.test?.if ?? '').replace(/\s+/g, '');
    return cond === 'always()' ? [] : [`test must run with \`if: always()\` (got "${cond}")`];
  },

  aggregatorFailsUnlessSuccess(text) {
    const job = load(text).jobs?.test;
    const bad = [];
    const body = runs(job);
    const env = list(job?.steps).map((s) => s.env || {}).reduce((a, e) => ({ ...a, ...e }), {});
    const vars = Object.entries(env);
    for (const need of ['test-shard', 'test-bundle']) {
      const hit = vars.find(([, v]) => String(v).replace(/\s+/g, '') === `\${{needs.${need}.result}}`);
      if (!hit) { bad.push(`the aggregator does not read needs.${need}.result`); continue; }
      if (!new RegExp(`\\[\\s*"\\$${hit[0]}"\\s*!=\\s*"success"\\s*\\]`).test(body)) bad.push(`the aggregator does not compare ${hit[0]} to exactly "success"`);
    }
    if (!/\|\|/.test(body)) bad.push('the aggregator must fail when EITHER result is not success (expected an || between the comparisons)');
    if (!/\bexit 1\b/.test(body)) bad.push('the aggregator has no `exit 1`');
    for (const s of list(job?.steps)) {
      if (s['continue-on-error'] === true) bad.push('the aggregator must not continue-on-error');
      if (s.if !== undefined) bad.push('an aggregator step is conditional, so it could be skipped');
    }
    if (job?.['continue-on-error'] === true) bad.push('the aggregator job must not continue-on-error');
    return bad;
  },

  shardMatrixIsOneToN(text) {
    const shards = list(load(text).jobs?.['test-shard']?.strategy?.matrix?.shard).map(String);
    if (!shards.length) return ['the shard matrix is empty or missing'];
    const m = /^(\d+)\/(\d+)$/.exec(shards[0]);
    if (!m) return [`shard "${shards[0]}" is not i/N`];
    const n = Number(m[2]);
    const want = Array.from({ length: n }, (_, i) => `${i + 1}/${n}`);
    return JSON.stringify(shards) === JSON.stringify(want) ? [] : [`shards ${JSON.stringify(shards)} are not exactly ${JSON.stringify(want)}`];
  },

  everyLegSetsTheShardAndRunsTheSuite(text) {
    const job = load(text).jobs?.['test-shard'];
    const bad = [];
    const step = list(job?.steps).find((s) => /^\s*npm test\s*$/.test(String(s.run ?? '')));
    if (!step) return ['the shard job has no `npm test` step'];
    if (String(step.env?.AGENTIC_SECURITY_TEST_SHARD ?? '').replace(/\s+/g, '') !== '${{matrix.shard}}') {
      bad.push('the `npm test` step does not set AGENTIC_SECURITY_TEST_SHARD from matrix.shard');
    }
    if (step.if !== undefined || step['continue-on-error'] === true) bad.push('the shard test step can be skipped or ignored');
    if (job?.['continue-on-error'] === true) bad.push('the shard job must not continue-on-error');
    return bad;
  },

  failFastIsOff(text) {
    return load(text).jobs?.['test-shard']?.strategy?.['fail-fast'] === false ? [] : ['test-shard must set fail-fast: false so every failing shard is visible'];
  },

  oneNEverywhere(text) {
    // The shard count N appears only in the matrix; no other place hardcodes a different i/N for the suite.
    const doc = load(text);
    const matrixN = new Set(list(doc.jobs?.['test-shard']?.strategy?.matrix?.shard).map((s) => String(s).split('/')[1]));
    const bad = [];
    if (matrixN.size !== 1) bad.push(`the matrix uses more than one N: ${[...matrixN].join(', ')}`);
    for (const [key, job] of Object.entries(doc.jobs)) {
      if (key === 'test-shard') continue;
      if (/AGENTIC_SECURITY_TEST_SHARD|--shard\b/.test(JSON.stringify(job))) bad.push(`job "${key}" also selects a test shard`);
    }
    return bad;
  },

  bundleCheckRunsExactlyOnceAndBlocks(text) {
    const doc = load(text);
    const bad = [];
    const hits = Object.entries(doc.jobs).filter(([, j]) => /git diff --exit-code dist\/agentic-security\.mjs dist\/agentic-security\.mjs\.sha256/.test(runs(j)));
    if (hits.length !== 1) return [`the committed-bundle check must appear in exactly one job (found ${hits.length})`];
    if (hits[0][0] !== 'test-bundle') bad.push(`the committed-bundle check is in "${hits[0][0]}", not test-bundle`);
    const steps = list(doc.jobs['test-bundle']?.steps);
    const idx = (re) => steps.findIndex((s) => re.test(String(s.run ?? '')));
    if (idx(/npm run build/) === -1 || idx(/git diff --exit-code/) < idx(/npm run build/)) bad.push('the bundle check must come after `npm run build`');
    for (const s of steps) if (s['continue-on-error'] === true || (s.if !== undefined && /git diff/.test(String(s.run ?? '')))) bad.push('the bundle check can be skipped or ignored');
    if (doc.jobs['test-bundle']?.['continue-on-error'] === true) bad.push('test-bundle must not continue-on-error');
    return bad;
  },

  everyShardRelaxesUserNamespaces(text) {
    // workflow-confinement.test.js already requires this of every job that runs the suite; this pins it for the shard job by name, so a
    // rename of the job or of its step cannot slip past a detector that no longer sees it.
    const steps = list(load(text).jobs?.['test-shard']?.steps);
    const relax = steps.findIndex((s) => /apparmor_restrict_unprivileged_userns/.test(String(s.run ?? '')));
    const suite = steps.findIndex((s) => /^\s*npm test\s*$/.test(String(s.run ?? '')));
    if (suite === -1) return ['the shard job has no `npm test` step'];
    if (relax === -1) return ['test-shard runs the suite without relaxing the user-namespace restriction'];
    return relax < suite ? [] : ['the user-namespace relaxation must come BEFORE the suite run'];
  },

  namesAreClassified(text, tiers = realTiers()) {
    const doc = load(text);
    const blocking = new Set(tiers.blocking || []);
    const bad = [];
    for (const n of [...shardCheckNames(doc), 'test', 'test-bundle']) {
      if (!blocking.has(n)) bad.push(`check run "${n}" is not in required-checks.json blocking`);
    }
    const listed = [...blocking].filter((n) => /^test-shard \(/.test(n));
    const actual = new Set(shardCheckNames(doc));
    for (const n of listed) if (!actual.has(n)) bad.push(`required-checks.json lists "${n}" but the workflow does not produce it`);
    return bad;
  },
};

// ----------------------------------------------------------- the real workflow
for (const [name, check] of Object.entries(invariants)) {
  test(`ci.yml invariant holds: ${name}`, () => {
    assert.deepEqual(check(realText()), []);
  });
}

test('the shard job produces test-shard (1/N)..(N/N) as check names', () => {
  const names = shardCheckNames(load(realText()));
  const n = names.length;
  assert.ok(n >= 2, 'sharding with fewer than two legs is not sharding');
  assert.deepEqual(names, Array.from({ length: n }, (_, i) => `test-shard (${i + 1}/${n})`));
});

test('the runner accepts every shard the matrix declares, and each one has files', async () => {
  const runner = await import('../../scripts/run-unit-tests.mjs');
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  const files = runner.unionFiles(pkg);
  const seen = [];
  for (const s of load(realText()).jobs['test-shard'].strategy.matrix.shard) {
    const shard = runner.parseShard(s);
    const mine = runner.assignShard(files, shard);
    assert.ok(mine.length > 0, `shard ${s} would have no files`);
    seen.push(...mine);
  }
  assert.deepEqual([...seen].sort(), [...files].sort(), 'the shards together run every file exactly once');
});

// ----------------------------------------------------------- each assertion can fail
function mutate(text, from, to) {
  assert.ok(text.includes(from), `mutation anchor not found: ${from}`);
  const out = text.replace(from, to);
  assert.notEqual(out, text);
  return out;
}

const mutations = [
  ['aggregatorIsNamedTest', (t) => mutate(t, '\n  test:\n    needs:', '\n  gate-test:\n    needs:')],
  ['aggregatorIsNamedTest', (t) => mutate(t, '\n  test:\n    needs:', '\n  test:\n    name: tests\n    needs:')],
  ['aggregatorIsNamedTest', (t) => mutate(t, '  test-bundle:\n    runs-on', '  test-bundle:\n    name: test\n    runs-on')],
  ['aggregatorNeedsShardsAndBundle', (t) => mutate(t, 'needs: [test-shard, test-bundle]', 'needs: [test-bundle]')],
  ['aggregatorNeedsShardsAndBundle', (t) => mutate(t, 'needs: [test-shard, test-bundle]', 'needs: [test-shard]')],
  ['aggregatorRunsAlways', (t) => mutate(t, '    if: always()\n    runs-on', '    runs-on')],
  ['aggregatorRunsAlways', (t) => mutate(t, '    if: always()\n    runs-on', '    if: success()\n    runs-on')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, '[ "$SHARDS_RESULT" != "success" ]', '[ "$SHARDS_RESULT" = "failure" ]')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, '[ "$SHARDS_RESULT" != "success" ] ||', '[ "$SHARDS_RESULT" != "success" ] &&')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, '[ "$BUNDLE_RESULT" != "success" ]', '[ "$BUNDLE_RESULT" = "failure" ]')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, '            exit 1\n          fi', '            true\n          fi')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, 'SHARDS_RESULT: ${{ needs.test-shard.result }}', 'SHARDS_RESULT: success')],
  ['aggregatorFailsUnlessSuccess', (t) => mutate(t, '      - name: Every shard and the bundle check must have succeeded\n', '      - name: Every shard and the bundle check must have succeeded\n        continue-on-error: true\n')],
  ['shardMatrixIsOneToN', (t) => mutate(t, "['1/4', '2/4', '3/4', '4/4']", "['1/4', '2/4', '4/4']")],
  ['shardMatrixIsOneToN', (t) => mutate(t, "['1/4', '2/4', '3/4', '4/4']", "['1/4', '2/4', '3/4', '4/5']")],
  ['shardMatrixIsOneToN', (t) => mutate(t, "['1/4', '2/4', '3/4', '4/4']", "['1/4', '1/4', '3/4', '4/4']")],
  ['everyLegSetsTheShardAndRunsTheSuite', (t) => mutate(t, 'AGENTIC_SECURITY_TEST_SHARD: ${{ matrix.shard }}', 'AGENTIC_SECURITY_TEST_SHARD: 1/4')],
  ['everyLegSetsTheShardAndRunsTheSuite', (t) => mutate(t, '        env:\n          AGENTIC_SECURITY_TEST_SHARD: ${{ matrix.shard }}\n        run: npm test', '        run: npm test')],
  ['everyLegSetsTheShardAndRunsTheSuite', (t) => mutate(t, '        run: npm test\n', '        run: npm run test:smoke\n')],
  ['failFastIsOff', (t) => mutate(t, 'fail-fast: false\n      matrix:\n        shard:', 'fail-fast: true\n      matrix:\n        shard:')],
  ['oneNEverywhere', (t) => mutate(t, '      - name: Build bundle\n', '      - name: Build bundle\n        env:\n          AGENTIC_SECURITY_TEST_SHARD: 1/2\n')],
  ['bundleCheckRunsExactlyOnceAndBlocks', (t) => mutate(t, '        run: git diff --exit-code dist/agentic-security.mjs dist/agentic-security.mjs.sha256\n', '        run: "true"\n')],
  ['bundleCheckRunsExactlyOnceAndBlocks', (t) => mutate(t, '      - name: Verify committed bundle matches source\n        run: git diff', '      - name: Verify committed bundle matches source\n        continue-on-error: true\n        run: git diff')],
  ['bundleCheckRunsExactlyOnceAndBlocks', (t) => mutate(t, '        run: npm test\n', '        run: npm test\n      - name: Verify committed bundle matches source\n        run: git diff --exit-code dist/agentic-security.mjs dist/agentic-security.mjs.sha256\n')],
  ['everyShardRelaxesUserNamespaces', (t) => mutate(t, 'kernel.apparmor_restrict_unprivileged_userns=0', 'kernel.something_else=0')],
  ['namesAreClassified', (t) => mutate(t, "['1/4', '2/4', '3/4', '4/4']", "['1/4', '2/4', '3/4', '4/4', '5/4']")],
  ['namesAreClassified', (t) => mutate(t, 'name: test-shard (${{ matrix.shard }})', 'name: shard ${{ matrix.shard }}')],
];

for (const [name, fn] of mutations) {
  test(`mutation is caught by ${name}: ${fn.toString().replace(/\s+/g, ' ').slice(0, 80)}`, () => {
    const violations = invariants[name](fn(realText()));
    assert.ok(violations.length > 0, `${name} did not notice the mutation`);
  });
}

test('namesAreClassified notices a shard name missing from required-checks.json, and a stale one', () => {
  const tiers = realTiers();
  assert.deepEqual(invariants.namesAreClassified(realText(), tiers), []);
  const missing = { ...tiers, blocking: tiers.blocking.filter((n) => n !== 'test-shard (3/4)') };
  assert.ok(invariants.namesAreClassified(realText(), missing).length > 0);
  const noTest = { ...tiers, blocking: tiers.blocking.filter((n) => n !== 'test') };
  assert.ok(invariants.namesAreClassified(realText(), noTest).length > 0);
  const stale = { ...tiers, blocking: [...tiers.blocking, 'test-shard (9/4)'] };
  assert.ok(invariants.namesAreClassified(realText(), stale).length > 0);
});
