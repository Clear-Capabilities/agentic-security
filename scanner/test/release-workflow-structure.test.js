// .github/workflows/release.yml runs the release gate as parallel jobs and
// publishes from a separate job. This pins the security-relevant STRUCTURE of
// that file by parsing it, not by grepping prose.
//
// Each invariant is a function over the workflow TEXT that returns a list of
// violations. The real file must yield none, and for every invariant a mutated
// scratch copy of the text (made inside the test, never written to disk) must
// yield at least one: an assertion that cannot fail proves nothing.
//
// What is protected:
//   - publish waits for the whole gate job, so it cannot start before every leg is green;
//   - `id-token: write` (the OIDC publish credential) exists on the publish job and nowhere else;
//   - the test shards are exactly 1..N with one shared N, and the legs cover every
//     release group (RELEASE_GROUPS plus `rest`), so no check can fall out of the release;
//   - every gate leg runs with --no-cache, never --allow-unverified-ci, and fails fast;
//   - the publish step is guarded by the tag and dry_run condition and carries no token;
//   - each leg's check-run name is classified `self`, or the hosted-CI check deadlocks on its siblings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { load } from '../src/util/yaml.js';
import { groupNames } from '../../scripts/release-check.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const WORKFLOW = path.join(REPO, '.github', 'workflows', 'release.yml');
const TIERS = path.join(REPO, '.github', 'required-checks.json');

const PUBLISH_GUARD = "startsWith(github.ref, 'refs/tags/v') && inputs.dry_run != true";
const PUBLISH_CMD = 'npm publish --ignore-scripts --provenance --access public';

const realText = () => fs.readFileSync(WORKFLOW, 'utf8');
const realTiers = () => JSON.parse(fs.readFileSync(TIERS, 'utf8'));

const asList = (v) => (Array.isArray(v) ? v : v == null ? [] : [v]);
const steps = (job) => asList(job?.steps);
const runsOf = (job) => steps(job).map((s) => String(s.run ?? ''));

/** Every `permissions` mapping in the document, with the path it sits at. */
function allPermissions(doc) {
  const found = [];
  const walk = (node, where) => {
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node)) {
      if (k === 'permissions') found.push({ where: `${where}.permissions`, value: v });
      else walk(v, `${where}.${k}`);
    }
  };
  walk(doc, '$');
  return found;
}

/** The check-run name each gate leg reports: the job's name template with matrix values filled in. */
function legNames(doc) {
  const gate = doc.jobs?.gate;
  const template = String(gate?.name ?? 'gate');
  return asList(gate?.strategy?.matrix?.include).map((leg) =>
    template.replace(/\$\{\{\s*matrix\.(\w+)\s*\}\}/g, (_, key) => String(leg[key] ?? '')));
}

// ---------------------------------------------------------------- invariants
const invariants = {
  publishNeedsGate(text) {
    const doc = load(text);
    return asList(doc.jobs?.publish?.needs).includes('gate') ? [] : ['publish does not `needs: gate`'];
  },

  idTokenOnlyOnPublish(text) {
    const doc = load(text);
    const bad = [];
    for (const { where, value } of allPermissions(doc)) {
      const hasToken = value && typeof value === 'object' && value['id-token'] === 'write';
      if (hasToken && where !== '$.jobs.publish.permissions') bad.push(`id-token: write at ${where}`);
    }
    if (doc.jobs?.publish?.permissions?.['id-token'] !== 'write') bad.push('publish lost id-token: write, so OIDC publishing cannot work');
    return bad;
  },

  gateLegsAreReadOnly(text) {
    const doc = load(text);
    const perms = doc.jobs?.gate?.permissions;
    if (!perms || typeof perms !== 'object') return ['the gate job must declare its own permissions'];
    const allowed = { contents: 'read', checks: 'read' };
    const bad = Object.entries(perms).filter(([k, v]) => allowed[k] !== v).map(([k, v]) => `gate permission ${k}: ${v}`);
    for (const k of Object.keys(allowed)) if (perms[k] !== 'read') bad.push(`gate lacks ${k}: read`);
    return bad;
  },

  shardsAreExactlyOneToN(text) {
    const doc = load(text);
    const legs = asList(doc.jobs?.gate?.strategy?.matrix?.include).filter((l) => l.group === 'tests');
    if (!legs.length) return ['no test-shard legs'];
    const specs = legs.map((l) => /^(\d+)\/(\d+)$/.exec(String(l.shard)));
    if (specs.some((m) => !m)) return ['a test leg has a malformed shard'];
    const totals = new Set(specs.map((m) => m[2]));
    if (totals.size !== 1) return [`legs disagree on N: ${[...totals].join(', ')}`];
    const n = Number([...totals][0]);
    const got = specs.map((m) => Number(m[1])).sort((a, b) => a - b);
    const want = Array.from({ length: n }, (_, i) => i + 1);
    return JSON.stringify(got) === JSON.stringify(want) ? [] : [`shards are ${got.join(',')}, expected 1..${n} once each`];
  },

  nonTestLegsAreNotSharded(text) {
    const doc = load(text);
    return asList(doc.jobs?.gate?.strategy?.matrix?.include)
      .filter((l) => l.group !== 'tests' && l.shard)
      .map((l) => `leg ${l.name} passes a shard but is not a test leg`);
  },

  legsCoverEveryGroup(text) {
    const doc = load(text);
    const have = new Set(asList(doc.jobs?.gate?.strategy?.matrix?.include).map((l) => l.group));
    const bad = [];
    for (const g of groupNames()) if (!have.has(g)) bad.push(`no gate leg runs group "${g}"`);
    for (const g of have) if (!groupNames().includes(g)) bad.push(`a leg runs unknown group "${g}"`);
    return bad;
  },

  everyGateLegPassesNoCacheAndItsGroup(text) {
    const doc = load(text);
    const gate = doc.jobs?.gate;
    const gateSteps = steps(gate).filter((s) => String(s.run ?? '').includes('release-check.mjs'));
    if (gateSteps.length !== 1) return [`expected exactly one release-check step in the gate job, found ${gateSteps.length}`];
    const [s] = gateSteps;
    const bad = [];
    if (!/--no-cache\b/.test(s.run)) bad.push('the gate step does not pass --no-cache');
    if (!/--group "\$GATE_GROUP"/.test(s.run)) bad.push('the gate step does not pass --group from the matrix');
    if (s.env?.GATE_GROUP !== '${{ matrix.group }}') bad.push('GATE_GROUP is not wired to matrix.group');
    if (s.env?.GATE_SHARD !== '${{ matrix.shard }}') bad.push('GATE_SHARD is not wired to matrix.shard');
    if (String(s.env?.AGENTIC_SECURITY_GATE_NO_CACHE) !== '1') bad.push('AGENTIC_SECURITY_GATE_NO_CACHE is not 1');
    return bad;
  },

  everyReleaseCheckInvocationPassesNoCache(text) {
    const doc = load(text);
    const bad = [];
    for (const [name, job] of Object.entries(doc.jobs || {})) {
      for (const run of runsOf(job)) {
        if (run.includes('release-check.mjs') && !/--no-cache\b/.test(run)) bad.push(`${name}: release-check without --no-cache`);
      }
    }
    return bad;
  },

  failFast(text) {
    const doc = load(text);
    return doc.jobs?.gate?.strategy?.['fail-fast'] === true ? [] : ['gate strategy.fail-fast is not true'];
  },

  noAllowUnverifiedCi(text) {
    const doc = load(text);
    const bad = [];
    for (const [name, job] of Object.entries(doc.jobs || {})) {
      for (const run of runsOf(job)) if (run.includes('--allow-unverified-ci')) bad.push(`${name} passes --allow-unverified-ci`);
    }
    return bad;
  },

  noNodeAuthToken(text) {
    return JSON.stringify(load(text)).includes('NODE_AUTH_TOKEN') ? ['NODE_AUTH_TOKEN is set; it would disable OIDC trusted publishing'] : [];
  },

  publishGuardAndCommand(text) {
    const doc = load(text);
    const bad = [];
    const publishSteps = steps(doc.jobs?.publish).filter((s) => /npm publish/.test(String(s.run ?? '')));
    if (publishSteps.length !== 1) return [`expected exactly one npm publish step, found ${publishSteps.length}`];
    const [p] = publishSteps;
    if (String(p.if).replace(/^\$\{\{\s*|\s*\}\}$/g, '') !== PUBLISH_GUARD) bad.push(`publish guard is "${p.if}"`);
    if (String(p.run).trim() !== PUBLISH_CMD) bad.push(`publish command is "${p.run}"`);
    const dry = steps(doc.jobs?.publish).filter((s) => /npm pack --dry-run/.test(String(s.run ?? '')));
    if (dry.length !== 1) bad.push('the dry-run step is missing');
    else if (String(dry[0].if).replace(/^\$\{\{\s*|\s*\}\}$/g, '') !== "!startsWith(github.ref, 'refs/tags/v') || inputs.dry_run == true") {
      bad.push(`dry-run guard is "${dry[0].if}"`);
    }
    // Nothing in the gate job may publish.
    for (const run of runsOf(doc.jobs?.gate)) if (/npm publish/.test(run)) bad.push('the gate job runs npm publish');
    return bad;
  },

  publishVerifiesTheArtifactBeforePublishing(text) {
    const doc = load(text);
    const list = steps(doc.jobs?.publish);
    const idx = (re) => list.findIndex((s) => re.test(String(s.run ?? '')));
    const order = [
      ['tag check', idx(/GITHUB_REF_NAME/)],
      ['build', idx(/npm run build/)],
      ['changelog sync', idx(/sync-scanner-changelog/)],
      ['artifact verification', idx(/release-check\.mjs --no-cache --only bundle-integrity,package-contents/)],
      ['publish', idx(/npm publish/)],
    ];
    const bad = order.filter(([, i]) => i === -1).map(([n]) => `publish job is missing the ${n} step`);
    if (bad.length) return bad;
    for (let i = 1; i < order.length; i++) {
      if (order[i][1] < order[i - 1][1]) bad.push(`${order[i][0]} must come after ${order[i - 1][0]}`);
    }
    const npmCheck = list.some((s) => /11/.test(String(s.run ?? '')) && /OIDC/.test(String(s.name ?? '')));
    if (!npmCheck) bad.push('publish job lost the npm >= 11.5.1 trusted-publishing check');
    return bad;
  },

  legNamesAreSelf(text, tiers = realTiers()) {
    const doc = load(text);
    const self = new Set(tiers.self || []);
    const bad = legNames(doc).filter((n) => !self.has(n)).map((n) => `leg check-run "${n}" is not under self in required-checks.json`);
    if (!self.has('publish')) bad.push('publish is not under self');
    return bad;
  },

  triggersAndDryRunDefault(text) {
    const doc = load(text);
    const bad = [];
    if (JSON.stringify(doc.on?.push?.tags) !== JSON.stringify(['v*'])) bad.push('the tag trigger changed');
    const dry = doc.on?.workflow_dispatch?.inputs?.dry_run;
    if (!dry || dry.default !== true || dry.type !== 'boolean') bad.push('workflow_dispatch dry_run must stay a boolean defaulting to true');
    if (doc.name !== 'release') bad.push('workflow name changed');
    return bad;
  },
};

// ------------------------------------------------------- the real workflow
test('the workflow file is still release.yml (the npm trusted publisher is bound to that name)', () => {
  assert.ok(fs.existsSync(WORKFLOW));
});

for (const [name, check] of Object.entries(invariants)) {
  test(`release.yml invariant holds: ${name}`, () => {
    assert.deepEqual(check(realText()), []);
  });
}

test('the shard count N is one value shared by every leg, and legs list matches 1..N', () => {
  const doc = load(realText());
  const shards = asList(doc.jobs.gate.strategy.matrix.include).filter((l) => l.group === 'tests').map((l) => l.shard);
  const n = Number(shards[0].split('/')[1]);
  assert.deepEqual(shards, Array.from({ length: n }, (_, i) => `${i + 1}/${n}`));
});

// ------------------------------------------------------- each assertion can fail
function mutate(text, from, to) {
  assert.ok(text.includes(from), `mutation anchor not found: ${from}`);
  const out = text.replace(from, to);
  assert.notEqual(out, text);
  return out;
}

const mutations = [
  ['publishNeedsGate', (t) => mutate(t, 'needs: [gate]', 'needs: []')],
  ['publishNeedsGate', (t) => mutate(t, 'needs: [gate]', 'needs: [rest]')],
  ['idTokenOnlyOnPublish', (t) => mutate(t, '    permissions:\n      contents: read\n      checks: read\n    strategy:',
    '    permissions:\n      contents: read\n      checks: read\n      id-token: write\n    strategy:')],
  ['idTokenOnlyOnPublish', (t) => mutate(t, 'permissions:\n  contents: read\n  checks: read', 'permissions:\n  contents: read\n  id-token: write\n  checks: read')],
  ['idTokenOnlyOnPublish', (t) => mutate(t, '      id-token: write # required', '      id-token: none # required')],
  ['gateLegsAreReadOnly', (t) => mutate(t, '    permissions:\n      contents: read\n      checks: read\n    strategy:',
    '    permissions:\n      contents: write\n      checks: read\n    strategy:')],
  ['shardsAreExactlyOneToN', (t) => mutate(t, "shard: '3/4'", "shard: '3/5'")],
  ['shardsAreExactlyOneToN', (t) => mutate(t, "          - { name: 'tests 2/4', group: tests, shard: '2/4' }\n", '')],
  ['shardsAreExactlyOneToN', (t) => mutate(t, "name: 'tests 4/4', group: tests, shard: '4/4'", "name: 'tests 4/4', group: tests, shard: '1/4'")],
  ['nonTestLegsAreNotSharded', (t) => mutate(t, "{ name: 'rest', group: rest, shard: '' }", "{ name: 'rest', group: rest, shard: '1/4' }")],
  ['legsCoverEveryGroup', (t) => mutate(t, "          - { name: 'rest', group: rest, shard: '' }\n", '')],
  ['legsCoverEveryGroup', (t) => mutate(t, "group: benches-b, shard: ''", "group: benches-c, shard: ''")],
  ['everyGateLegPassesNoCacheAndItsGroup', (t) => mutate(t, 'release-check.mjs --no-cache --group', 'release-check.mjs --group')],
  ['everyGateLegPassesNoCacheAndItsGroup', (t) => mutate(t, "GATE_GROUP: ${{ matrix.group }}", "GATE_GROUP: rest")],
  ['everyReleaseCheckInvocationPassesNoCache', (t) => mutate(t, 'release-check.mjs --no-cache --only', 'release-check.mjs --only')],
  ['failFast', (t) => mutate(t, 'fail-fast: true', 'fail-fast: false')],
  ['noAllowUnverifiedCi', (t) => mutate(t, '--no-cache --group', '--no-cache --allow-unverified-ci --group')],
  ['noAllowUnverifiedCi', (t) => mutate(t, '--no-cache --only', '--no-cache --allow-unverified-ci --only')],
  ['noNodeAuthToken', (t) => mutate(t, '          GH_TOKEN: ${{ github.token }}\n        run: npm publish',
    '          GH_TOKEN: ${{ github.token }}\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n        run: npm publish')],
  ['publishGuardAndCommand', (t) => mutate(t, " && inputs.dry_run != true\n        working-directory", "\n        working-directory")],
  ['publishGuardAndCommand', (t) => mutate(t, "if: startsWith(github.ref, 'refs/tags/v') && inputs.dry_run != true", 'if: always()')],
  ['publishGuardAndCommand', (t) => mutate(t, 'npm publish --ignore-scripts --provenance', 'npm publish --provenance')],
  ['publishGuardAndCommand', (t) => mutate(t, '          npm pack --dry-run', '          true')],
  ['publishVerifiesTheArtifactBeforePublishing', (t) => mutate(t, ' --only bundle-integrity,package-contents', ' --only bundle-integrity')],
  ['publishVerifiesTheArtifactBeforePublishing', (t) => mutate(t, 'name: Ensure npm supports trusted publishing (OIDC)', 'name: Noop')],
  ['triggersAndDryRunDefault', (t) => mutate(t, 'default: true', 'default: false')],
  ['triggersAndDryRunDefault', (t) => mutate(t, "      - 'v*'", "      - '*'")],
];

for (const [name, fn] of mutations) {
  test(`mutation is caught by ${name}: ${fn.toString().replace(/\s+/g, ' ').slice(0, 70)}`, () => {
    const violations = invariants[name](fn(realText()));
    assert.ok(violations.length > 0, `${name} did not notice the mutation`);
  });
}

test('legNamesAreSelf notices a leg missing from required-checks.json, and a missing publish entry', () => {
  const tiers = realTiers();
  assert.deepEqual(invariants.legNamesAreSelf(realText(), tiers), []);
  const withoutLeg = { ...tiers, self: tiers.self.filter((n) => n !== 'gate (rest)') };
  assert.ok(invariants.legNamesAreSelf(realText(), withoutLeg).length > 0);
  const withoutPublish = { ...tiers, self: tiers.self.filter((n) => n !== 'publish') };
  assert.ok(invariants.legNamesAreSelf(realText(), withoutPublish).length > 0);
  // A renamed leg (the matrix name changed, the tier file did not) is caught too.
  const renamed = mutate(realText(), "name: 'rest'", "name: 'misc'");
  assert.ok(invariants.legNamesAreSelf(renamed, tiers).length > 0);
});

test('legNames derives the check-run names the hosted-CI check will see', () => {
  const names = legNames(load(realText()));
  assert.ok(names.includes('gate (tests 1/4)'));
  assert.ok(names.includes('gate (rest)'));
  assert.equal(new Set(names).size, names.length, 'leg names must be unique');
});
