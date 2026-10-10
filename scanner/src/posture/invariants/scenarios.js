// Bounded stateful scenario generation (X-403).
//
// From one invariant this builds the adversarial sequences that could violate it, as plain data a business-state oracle run
// (`oracles/adapters.js`) can replay: synthetic tenants and actors, a seeded setup, a CONTROL sequence of legitimate operations,
// an ATTACK sequence, the forbidden outcomes to assert, and a cleanup. Five families, matching how business-state defects occur:
// cross-tenant access, privilege change, reordered workflow, duplicate request and concurrent operations.
//
// What is bounded, and where it is enforced:
//   actors        the generator uses at most `bounds.actors` of the contract's actors;
//   state depth   at most `bounds.depth` sequence items (a step or one parallel group) per sequence;
//   requests      at most `bounds.requests` operations in the attack sequence (the oracle also refuses more than 16 outright);
//   scheduling    a parallel group has at most 4 steps and a fixed, SEEDED start order, so the same seed always yields the same
//                 schedule; the oracle runs the attack twice and reports a disagreement as inconclusive, never as a verdict;
//   time          `bounds.timeBudgetMs` becomes the run's deadline in the replay manifest, capped by the oracle's own ceiling.
// Every bound has a hard ceiling (`HARD_BOUNDS`); a request over a ceiling or a non-integer is rejected, not silently clamped.
//
// Determinism. Given the same invariant, fixture, bounds and seed the output is byte-identical: ids are content hashes, the only
// randomness is a seeded generator, and there is no clock. The scenario pins the fixture digest, and `runScenario` builds the
// replay manifest (`replay/replay.js`) so the environment identity, toolchain and oracle logic digest are pinned the same way as
// every other replayed verification.
//
// Confinement. Scenarios are generated only for contracts scoped to a DISPOSABLE FIXTURE, from fixture files the caller supplies
// (the application under test is imported into the oracle's workspace; nothing here touches a running or shared system), and only
// when the `invariant-scenarios` feature is enabled. Anything the generator cannot build (a second tenant with a resource, an
// unprivileged actor, a transition to repeat) is returned as an explicit `unsupported` entry with its reason, never skipped.
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isPlainObject, isCommit } from '../assurance/schema-kit.js';
import { featureStatus, resolveAssuranceConfig } from '../assurance/config.js';
import { createReplayManifest, replayManifest } from '../replay/replay.js';
import { validateInvariant } from './schema.js';

const SCENARIO_SCHEMA = 'agentic-security/invariant-scenario';
export const FEATURE = 'invariant-scenarios';
export const SCENARIO_KINDS = Object.freeze(['cross-tenant-access', 'privilege-change', 'reordered-workflow', 'duplicate-request', 'concurrent-operations']);
export const HARD_BOUNDS = Object.freeze({ actors: 4, depth: 12, requests: 16, scenarios: 6, timeBudgetMs: 8000 });
const DEFAULT_BOUNDS = Object.freeze({ actors: 4, depth: 6, requests: 10, scenarios: 4, timeBudgetMs: 5000 });
const MAX_PARALLEL = 4;
const SCENARIO_ID_FIELDS = ['invariant', 'kind', 'seed', 'inputs', 'fixtureDigest'];

/** Which scenario families each invariant class gets. */
export const KINDS_BY_CLASS = Object.freeze({
  'tenant-isolation': ['cross-tenant-access'],
  'privilege-constraint': ['privilege-change'],
  'workflow-order': ['reordered-workflow'],
  'value-conservation': ['duplicate-request', 'concurrent-operations'],
  idempotency: ['duplicate-request', 'concurrent-operations'],
});

/** Validate and complete the bounds. Returns `{ ok, bounds, errors }`; nothing is clamped silently. */
export function resolveBounds(input = {}) {
  const errors = [];
  const bounds = { ...DEFAULT_BOUNDS };
  if (!isPlainObject(input)) return { ok: false, bounds, errors: ['bounds must be an object'] };
  for (const [k, v] of Object.entries(input)) {
    if (!(k in HARD_BOUNDS)) { errors.push(`unknown bound '${k}'`); continue; }
    if (!Number.isInteger(v) || v < 1) errors.push(`bound '${k}' must be a positive integer`);
    else if (v > HARD_BOUNDS[k]) errors.push(`bound '${k}' (${v}) exceeds the ceiling of ${HARD_BOUNDS[k]}`);
    else bounds[k] = v;
  }
  return { ok: errors.length === 0, bounds, errors };
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function permutation(n, rng) {
  const p = [...Array(n).keys()];
  for (let i = n - 1; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); [p[i], p[j]] = [p[j], p[i]]; }
  // never the identity for a group that exists to exercise an interleaving, when n > 1 and the draw landed on it, rotate once
  if (n > 1 && p.every((v, i) => v === i)) p.push(p.shift());
  return p;
}

// ---------------------------------------------------------------- building blocks

const stripUndefined = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));

function seedRecords(inv) {
  return inv.resources.map((r) => {
    const value = stripUndefined({ tenant: r.tenant ?? undefined, note: 'initial', marker: r.marker });
    for (const f of inv.forbidden) {
      if (f.op === 'sum-not-conserved' && r.key.startsWith(f.prefix)) value[f.field] = 100;
      if (f.op === 'transition-outside' && r.key.startsWith(f.prefix)) value[f.field] = f.allowed[0].from;
    }
    return { key: r.key, value };
  });
}

const resourceOf = (inv, id) => inv.resources.find((r) => r.id === id);
const step = (actor, action, key, payload = {}) => ({ actor, action, args: [key, stripUndefined(payload)] });
const tenantOfActor = (inv, id) => inv.actors.find((a) => a.id === id)?.tenant;

function legitSteps(inv, limit = 2, requestPrefix = 'req-control') {
  return inv.transitions.slice(0, limit).map((t, i) => {
    const r = resourceOf(inv, t.resource);
    return step(t.actors[0], t.action, r.key, { to: t.to, note: 'legitimate', amount: 10, requestId: `${requestPrefix}-${i + 1}` });
  });
}

function chainOf(forbidden) {
  // the allowed transitions as an ordered chain of states: from the first `from`, follow `to` to `from` links
  const next = new Map(forbidden.allowed.map((t) => [t.from, t.to]));
  const chain = [forbidden.allowed[0].from];
  while (next.has(chain[chain.length - 1]) && chain.length <= forbidden.allowed.length + 1) chain.push(next.get(chain[chain.length - 1]));
  return chain;
}

// Each builder returns { control, attack } or { unsupported: reason }.
const BUILDERS = {
  'cross-tenant-access'(inv, b) {
    if (!inv.transitions.length) return { unsupported: 'the contract declares no transition to attempt across tenants' };
    const t0 = inv.transitions[0];
    const steps = [];
    for (const a of inv.actors.slice(0, b.actors)) {
      for (const r of inv.resources) {
        if (r.tenant !== null && r.tenant !== a.tenant) steps.push(step(a.id, t0.action, r.key, { to: t0.to, note: 'cross-tenant', amount: 10, requestId: `req-x-${steps.length + 1}` }));
      }
    }
    if (!steps.length) return { unsupported: 'a cross-tenant scenario needs an actor and a resource owned by a different tenant' };
    return { control: legitSteps(inv, 1), attack: steps };
  },
  'privilege-change'(inv, b) {
    const f = inv.forbidden.find((x) => x.op === 'unauthorized-role-change');
    if (!f) return { unsupported: 'the contract has no unauthorized-role-change outcome' };
    const low = inv.actors.slice(0, b.actors).filter((a) => !f.allowedRoles.includes(a.role));
    const high = inv.actors.find((a) => f.allowedRoles.includes(a.role));
    if (!low.length || !high) return { unsupported: 'a privilege scenario needs an unprivileged actor and a privileged one' };
    const res = inv.resources[0];
    if (!res) return { unsupported: 'the contract declares no resource' };
    const attack = [];
    for (const a of low) for (const action of f.actions) attack.push(step(a.id, action, res.key, { note: 'escalation', amount: 10, requestId: `req-p-${attack.length + 1}` }));
    return { control: [step(high.id, f.actions[0], res.key, { note: 'legitimate', amount: 10, requestId: 'req-control-1' })], attack };
  },
  'reordered-workflow'(inv, b) {
    const f = inv.forbidden.find((x) => x.op === 'transition-outside');
    if (!f || !inv.transitions.length) return { unsupported: 'the contract has no workflow transition to reorder' };
    const t0 = inv.transitions[0];
    const res = inv.resources.find((r) => r.key.startsWith(f.prefix));
    if (!res) return { unsupported: 'no resource falls under the workflow prefix' };
    const chain = chainOf(f);
    if (chain.length < 2) return { unsupported: 'the allowed transitions form no chain to reorder' };
    const actor = t0.actors[0];
    const control = chain.slice(1).map((to, i) => step(actor, t0.action, res.key, { to, requestId: `req-control-${i + 1}` }));
    // skip a step when the chain is long enough, otherwise run the transition backwards
    const skipTo = chain.length >= 3 ? chain[chain.length - 1] : chain[0];
    return { control, attack: [step(actor, t0.action, res.key, { to: skipTo, requestId: 'req-reorder-1' })] };
  },
  'duplicate-request'(inv) {
    if (!inv.transitions.length) return { unsupported: 'the contract declares no transition to repeat' };
    const t0 = inv.transitions[0];
    const res = resourceOf(inv, t0.resource);
    const mk = (id) => step(t0.actors[0], t0.action, res.key, { to: t0.to, amount: 10, requestId: id });
    return { control: [mk('req-control-1'), mk('req-control-2')], attack: [mk('req-dup-1'), mk('req-dup-1')] };
  },
  'concurrent-operations'(inv, b, rng) {
    if (!inv.transitions.length) return { unsupported: 'the contract declares no transition to run concurrently' };
    const t0 = inv.transitions[0];
    const res = resourceOf(inv, t0.resource);
    const mk = (id) => step(t0.actors[0], t0.action, res.key, { to: t0.to, amount: 10, requestId: id });
    const width = Math.min(3, MAX_PARALLEL);
    return { control: [mk('req-control-1'), mk('req-control-2')], attack: [{ parallel: Array.from({ length: width }, () => mk('req-race-1')), schedule: permutation(width, rng) }] };
  },
};

const opCount = (items) => items.reduce((n, it) => n + (it.parallel ? it.parallel.length : 1), 0);

function limitsOf(inputs, timeBudgetMs, truncated) {
  const items = [...inputs.attack, ...inputs.control];
  return { actors: new Set(items.flatMap((it) => (it.parallel || [it]).map((x) => x.actor))).size, depth: inputs.attack.length, requests: opCount(inputs.attack), timeBudgetMs, truncated };
}

function determinismOf(inputs, seed) {
  return inputs.attack.some((it) => it.parallel)
    ? { scheduling: 'cooperative-fixed-start-order', seed, support: 'the oracle runs the attack twice; a disagreement is reported inconclusive' }
    : { scheduling: 'sequential', seed, support: 'deterministic by construction' };
}

/**
 * What a scenario would exercise, as plain data: every step of both sequences (parallel groups flattened) with its actor, action,
 * the record key it addresses and the target state it asks for. Used by coverage reporting; reads the scenario, runs nothing.
 */
export function exerciseOf(scenario) {
  const flat = (items) => items.flatMap((it) => (it.parallel || [it]).map((s) => ({
    actor: s.actor, action: s.action, key: typeof s.args?.[0] === 'string' ? s.args[0] : null, to: typeof s.args?.[1]?.to === 'string' ? s.args[1].to : null,
  })));
  return { control: flat(scenario.inputs.control), attack: flat(scenario.inputs.attack) };
}

/**
 * The scenario that has the same pinned invariant, fixture, entry, seed and budget as `base` but different `inputs` (shrinking
 * removes parts of a sequence; it never edits one). Limits, determinism and the content-hash id are recomputed from the new
 * inputs, so a derived scenario is exactly as self-describing as a generated one. Pure; the caller validates the inputs by
 * running them (the oracle refuses a malformed sequence).
 */
export function deriveScenario(base, inputs) {
  const derived = {
    ...base, inputs,
    limits: limitsOf(inputs, base.limits.timeBudgetMs, base.limits.truncated),
    determinism: determinismOf(inputs, base.seed),
  };
  derived.id = semanticId('iscn', derived, SCENARIO_ID_FIELDS);
  return derived;
}

function trim(items, b) {
  let out = items.slice(0, b.depth);
  while (out.length > 1 && opCount(out) > b.requests) out = out.slice(0, -1);
  return { items: out, truncated: out.length < items.length };
}

/**
 * Generate the bounded scenarios for one invariant.
 *
 * @param {object} invariant   a valid invariant document
 * @param {object} o
 * @param {{ files: object, digest?: string }} o.fixture  the disposable fixture's files (relative path to text); required
 * @param {number} [o.seed]    integer seed (default 1); the same seed gives the same scenarios
 * @param {object} [o.bounds]  see `HARD_BOUNDS`
 * @param {object} [o.config]  assurance config; the `invariant-scenarios` feature must be enabled
 * @returns {{ status: 'ok'|'disabled'|'blocked'|'unsupported'|'rejected', scenarios: object[], unsupported: object[], reason?: string, errors?: string[] }}
 */
export function generateScenarios(invariant, o = {}) {
  const none = (status, reason, extra = {}) => ({ status, scenarios: [], unsupported: [], reason, ...extra });
  const config = o.config || resolveAssuranceConfig({ env: process.env });
  const gate = featureStatus(config, FEATURE);
  if (gate.status !== 'ok') return none(gate.status, `${FEATURE} is not available: ${gate.reason}`, { gate });

  const valid = validateInvariant(invariant);
  if (!valid.ok) return none('rejected', 'the invariant is not valid', { errors: valid.errors.map((e) => `${e.path}: ${e.message}`) });
  const rb = resolveBounds(o.bounds);
  if (!rb.ok) return none('rejected', 'the bounds are not valid', { errors: rb.errors });
  const seed = o.seed === undefined ? 1 : o.seed;
  if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff) return none('rejected', 'the seed must be an integer from 0 to 4294967295', { errors: ['seed'] });

  // confinement: authorized disposable fixtures only
  if (invariant.scope.environment !== 'disposable-fixture') {
    return none('unsupported', `scenarios run only against a disposable fixture; this contract is scoped to '${invariant.scope.environment}', and nothing is generated for a shared or production system`);
  }
  const files = o.fixture?.files;
  if (!isPlainObject(files) || !(invariant.scope.entry in files)) {
    return none('unsupported', 'setup is unavailable: no disposable fixture files were supplied, or they do not contain the contract\'s entry file');
  }
  const fixtureDigest = digestOf(files);
  if (o.fixture.digest !== undefined && o.fixture.digest !== fixtureDigest) return none('rejected', 'the fixture does not match its stated digest', { errors: ['fixture.digest'] });

  const b = rb.bounds;
  const kinds = KINDS_BY_CLASS[invariant.class] || [];
  const scenarios = [];
  const unsupported = [];
  const rng = mulberry32(seed);
  for (const kind of kinds) {
    if (scenarios.length >= b.scenarios) { unsupported.push({ kind, reason: `the scenario bound of ${b.scenarios} was reached` }); continue; }
    const built = BUILDERS[kind](invariant, b, rng);
    if (built.unsupported) { unsupported.push({ kind, reason: built.unsupported }); continue; }
    const atk = trim(built.attack, b);
    const ctl = trim(built.control, b);
    const inputs = {
      export: invariant.scope.factory,
      invariant: { id: invariant.id, key: invariant.key, revision: invariant.revision, class: invariant.class },
      actors: invariant.actors.map((a) => ({ id: a.id, tenant: a.tenant, role: a.role })),
      markers: invariant.resources.filter((r) => r.marker && r.tenant !== null).map((r) => ({ tenant: r.tenant, marker: r.marker })),
      seed: seedRecords(invariant), control: ctl.items, attack: atk.items,
      forbidden: invariant.forbidden.map((f) => ({ ...f })), cleanup: [{ action: 'discard-world' }],
    };
    const scenario = {
      schema: SCENARIO_SCHEMA, schemaVersion: SCHEMA_VERSION, kind,
      invariant: inputs.invariant, seed, fixtureDigest, entry: invariant.scope.entry,
      inputs,
      limits: limitsOf(inputs, b.timeBudgetMs, atk.truncated || ctl.truncated),
      determinism: determinismOf(inputs, seed),
    };
    scenario.id = semanticId('iscn', scenario, SCENARIO_ID_FIELDS);
    scenarios.push(scenario);
  }
  if (!kinds.length) unsupported.push({ kind: null, reason: `no scenario family is defined for class '${invariant.class}'` });
  return { status: 'ok', scenarios, unsupported, bounds: b };
}

/**
 * Replay one generated scenario through the business-state oracle, via a replay manifest so the environment, toolchain and
 * oracle logic are pinned. Never throws. The result is exactly what `replayManifest` returned plus the scenario id.
 *
 * @param {object} scenario  from `generateScenarios`
 * @param {object} o
 * @param {object} o.fixture      { files }, the same files the scenario was generated from
 * @param {string} o.commit       exact 40 or 64 character commit the fixture belongs to (a decided verdict needs one)
 * @param {object} [o.config]     assurance config (both `invariant-scenarios` and `verification-oracles` must be enabled)
 * @param {object} [o.runOptions] test seams passed to the oracle runner
 */
export async function runScenario(scenario, o = {}) {
  const files = o.fixture?.files;
  if (!isPlainObject(scenario) || scenario.schema !== SCENARIO_SCHEMA || !isPlainObject(files) || digestOf(files) !== scenario.fixtureDigest) {
    return { scenarioId: scenario?.id ?? null, status: 'rejected', executed: false, outcome: null, record: null, receipt: null, errors: [{ code: 'FIXTURE_MISMATCH', path: 'fixture', message: 'the fixture is missing or does not match the scenario\'s pinned digest' }] };
  }
  if (!isCommit(o.commit)) {
    return { scenarioId: scenario.id, status: 'rejected', executed: false, outcome: null, record: null, receipt: null, errors: [{ code: 'BAD_COMMIT', path: 'commit', message: 'a scenario run is bound to an exact commit' }] };
  }
  const manifest = createReplayManifest({
    hypothesisId: scenario.id, commit: o.commit, fixtureFiles: files, oracleId: 'business-state', entry: scenario.entry, inputs: scenario.inputs,
    budgets: { timeoutMs: scenario.limits.timeBudgetMs },
  });
  const replay = await replayManifest({ manifest, fixtureFiles: files }, { config: o.config, runOptions: o.runOptions });
  return { scenarioId: scenario.id, manifestId: manifest.id, ...replay };
}
