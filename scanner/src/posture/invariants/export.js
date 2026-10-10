// Reproducible scenario export, without tenant secrets (X-407.AC03).
//
// A reviewer or another tool should be able to take a bounded scenario away, replay it on the same pinned fixture, and get the
// same verdict. This builds that package from generated scenarios, and keeps three promises:
//
//   - It carries no tenant secret. The fixture SOURCE is never exported (only its digest: the recipient already holds the
//     fixture, or cannot reproduce anyway); the scenario inputs are scanned for secret-looking keys and token shapes, and a
//     scenario that holds one is WITHHELD with the paths named (never the values), not exported with a hole in it, because a
//     scenario with a value removed is a different scenario and would not replay to the same digest.
//   - It is self-checking. Every scenario carries its content digest and its pinned fixture digest; `verifyScenarioExport`
//     recomputes them (and the replay manifest ids, when a commit was supplied) so an edited export is detected.
//   - It never claims more than it did. The package states that it is a bounded sample of one contract's behaviour, lists the
//     bounds that applied, the scenario families that could not be built, and says plainly that it is not a proof of
//     business-logic correctness.
//
// Gate: the `invariant-scenarios` feature, off by default. With it off nothing is built.
//
// `findSecrets` is shared with the regression artifact (`repair.js`), which embeds the fixture and the patch and therefore
// must refuse to embed a credential. It reports WHERE (file and kind), never WHAT. Pattern checks over text: a paraphrased or
// encoded secret is not caught, and the export is only as clean as the synthetic fixture it was generated from.
import { digestOf, semanticId } from '../assurance/identity.js';
import { SCHEMA_VERSION, isPlainObject } from '../assurance/schema-kit.js';
import { featureStatus, resolveAssuranceConfig } from '../assurance/config.js';
import { createReplayManifest } from '../replay/replay.js';
import { generateScenarios, HARD_BOUNDS, FEATURE } from './scenarios.js';
import { verifyLedger } from './lifecycle.js';
import { readJsonFile, readFixtureDir } from './project-input.js';

export const EXPORT_SCHEMA = 'agentic-security/invariant-scenario-export';
export const NOT_EXHAUSTIVE = 'This is a bounded sample of one contract on one disposable fixture. A clean result covers only the scenarios listed here; it is not a proof of business-logic correctness.';

const SECRET_KEY = /secret|token|passw|api[_-]?key|authorization|cookie|credential|private[_-]?key|ssn/i;
const SECRET_SHAPES = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key block'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'cloud access key id'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, 'source host token'],
  [/\bsk-[A-Za-z0-9_-]{10,}/, 'secret key token'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, 'chat token'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/, 'signed web token'],
  [/\b(?:password|passwd|secret|api[_-]?key|token|authorization|bearer)\b["']?\s*[:=]\s*["'][^"'\s]{6,}["']/i, 'credential assignment'],
];

/** Secret-looking content in a map of file name to text. Names the file and the kind; never returns the matched text. */
export function findSecrets(files) {
  const out = [];
  for (const [file, text] of Object.entries(isPlainObject(files) ? files : {})) {
    if (typeof text !== 'string') continue;
    for (const [re, kind] of SECRET_SHAPES) if (re.test(text)) out.push({ where: file, kind });
  }
  return out;
}

/** Secret-looking keys or values anywhere in a JSON-able value. Returns paths and kinds, never the values. */
export function findSecretsIn(value, path = '$', out = []) {
  if (typeof value === 'string') {
    for (const [re, kind] of SECRET_SHAPES) if (re.test(value)) { out.push({ where: path, kind }); break; }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => findSecretsIn(v, `${path}[${i}]`, out));
  } else if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY.test(k) && v !== null && v !== undefined && v !== '' && typeof v !== 'boolean') out.push({ where: `${path}.${k}`, kind: 'secret-looking field' });
      else findSecretsIn(v, `${path}.${k}`, out);
    }
  }
  return out;
}

const copy = (v) => JSON.parse(JSON.stringify(v));

/**
 * Build the export for one invariant. Never throws.
 *
 * @param {object} p
 * @param {object} p.invariant  a valid invariant document
 * @param {object} p.fixture    { files } of the disposable fixture (used for its digest and the entry check only; never exported)
 * @param {object} [p.ledger]   the approval ledger: only a ledger that verifies can say a contract is approved
 * @param {string} [p.commit]   exact commit; with it the replay manifests are included, without it they are listed as needed
 * @param {number} [p.seed]
 * @param {object} [p.bounds]
 * @param {object} [p.config]   assurance config
 * @param {object} [p.signer]   ledger signer (test seam)
 * @returns {{ status: 'ok'|'disabled'|'unsupported'|'rejected'|'blocked', reason?: string, export?: object, withheld?: object[] }}
 */
export function exportScenarios(p = {}) {
  const config = p.config || resolveAssuranceConfig({ env: process.env });
  const gate = featureStatus(config, FEATURE);
  if (gate.status !== 'ok') return { status: 'disabled', reason: `${FEATURE} is not available: ${gate.reason}` };
  const gen = generateScenarios(p.invariant, { fixture: p.fixture, seed: p.seed, bounds: p.bounds, config });
  if (gen.status !== 'ok') return { status: gen.status, reason: gen.reason, errors: gen.errors };

  // the identifying text that travels with the export is checked too: a credential pasted into a contract's name must not leave
  const meta = findSecretsIn({ name: p.invariant.name, key: p.invariant.key, application: p.invariant.scope.application }, 'invariant');
  if (meta.length) return { status: 'blocked', reason: 'secret-looking content in the contract\'s name, key or application', withheld: [{ scenarioId: null, kind: null, reason: 'secret-looking content in the contract metadata', where: meta }] };

  const withheld = [];
  const scenarios = [];
  for (const s of gen.scenarios) {
    const hits = findSecretsIn(s.inputs, 'inputs');
    if (hits.length) { withheld.push({ scenarioId: s.id, kind: s.kind, reason: 'secret-looking content in the scenario inputs', where: hits }); continue; }
    const doc = copy(s);
    const entry = { scenario: doc, digest: digestOf(doc) };
    if (p.commit) {
      try { entry.manifest = createReplayManifest({ hypothesisId: s.id, commit: p.commit, fixtureFiles: p.fixture.files, oracleId: 'business-state', entry: s.entry, inputs: s.inputs, budgets: { timeoutMs: s.limits.timeBudgetMs } }); } catch { entry.manifest = null; }
    }
    scenarios.push(entry);
  }
  if (!scenarios.length && withheld.length) return { status: 'blocked', reason: 'every scenario was withheld because it held secret-looking content', withheld };

  let approval = { state: 'unrecorded', source: 'no ledger supplied' };
  if (p.ledger) {
    const v = verifyLedger(p.ledger, { signer: p.signer });
    approval = v.ok ? { state: v.states[p.invariant.id] || 'unrecorded', source: 'verified approval ledger' } : { state: 'unverified', source: 'the approval ledger does not verify' };
  }
  const body = {
    schema: EXPORT_SCHEMA, schemaVersion: SCHEMA_VERSION,
    invariant: { id: p.invariant.id, key: p.invariant.key, revision: p.invariant.revision, class: p.invariant.class, name: p.invariant.name },
    approval: { ...approval, documentClaims: p.invariant.review?.state ?? null },
    fixture: { digest: gen.scenarios[0]?.fixtureDigest ?? digestOf(p.fixture.files), entry: p.invariant.scope.entry, included: false, note: 'the fixture source is not exported: replay needs the fixture whose digest is listed' },
    oracle: { id: 'business-state', version: '1' },
    bounds: { applied: gen.bounds, hard: HARD_BOUNDS },
    scenarios,
    notBuilt: gen.unsupported,
    withheld,
    secretsExported: false,
    claims: { exhaustive: false, statement: NOT_EXHAUSTIVE },
    reproduce: p.commit
      ? 'replay each manifest against the fixture with the listed digest (replayManifest), then compare the outcome with an executed run'
      : 'supply an exact commit to obtain replay manifests; the scenario documents alone pin the fixture digest, the seed and the inputs',
  };
  body.id = semanticId('sexp', { ...body, scenarioDigests: scenarios.map((e) => e.digest) }, ['invariant', 'fixture', 'scenarioDigests', 'bounds']);
  return { status: 'ok', export: body, withheld };
}

/**
 * Check an export: every scenario digest, content-addressed id and fixture pin recomputes, no secret-looking content is present,
 * and (given the fixture files) the pinned digest matches. Never throws.
 */
export function verifyScenarioExport(doc, { fixtureFiles } = {}) {
  const errors = [];
  const fail = (code, message) => errors.push({ code, message });
  try {
    if (!isPlainObject(doc) || doc.schema !== EXPORT_SCHEMA) return { ok: false, errors: [{ code: 'malformed', message: 'not a scenario export' }] };
    if (doc.claims?.exhaustive !== false || typeof doc.claims?.statement !== 'string') fail('overclaim', 'an export must state that it is not exhaustive');
    if (doc.secretsExported !== false) fail('secrets-flag', 'the export must record that no secret was exported');
    for (const e of doc.scenarios || []) {
      if (digestOf(e.scenario) !== e.digest) fail('scenario-tampered', `scenario ${e.scenario?.id} does not match its digest`);
      if (e.scenario?.fixtureDigest !== doc.fixture?.digest) fail('fixture-pin-mismatch', `scenario ${e.scenario?.id} pins a different fixture than the export`);
      if (e.manifest && e.manifest.fixture?.digest !== doc.fixture?.digest) fail('manifest-fixture-mismatch', `the manifest for ${e.scenario?.id} pins a different fixture`);
      const leaked = findSecretsIn(e.scenario?.inputs, 'inputs');
      if (leaked.length) fail('secret-in-export', `scenario ${e.scenario?.id} holds secret-looking content at ${leaked.map((l) => l.where).join(', ')}`);
    }
    if (fixtureFiles !== undefined && digestOf(fixtureFiles) !== doc.fixture?.digest) fail('fixture-mismatch', 'the supplied fixture does not match the digest the export pins');
    if (doc.fixture?.included !== false) fail('fixture-included', 'the export must not include the fixture source');
  } catch (e) {
    fail('malformed', `the check could not complete: ${String(e?.message || e).slice(0, 120)}`);
  }
  return { ok: errors.length === 0, errors };
}

/**
 * The CLI and MCP entry: build an export from files already resolved (and confined) to absolute paths by the caller.
 * Reads the contract, the fixture directory and, optionally, the ledger through the bounded readers in `project-input.js`.
 * Never throws; every failure is a typed status with its reason.
 */
export function exportFromFiles({ invariantPath, fixturePath, ledgerPath, commit, seed, bounds, config, signer } = {}) {
  const inv = readJsonFile(invariantPath);
  if (!inv.ok) return { status: 'rejected', reason: `the invariant file: ${inv.reason}` };
  const fx = readFixtureDir(fixturePath);
  if (!fx.ok) return { status: 'rejected', reason: `the fixture directory: ${fx.errors.join('; ')}` };
  let ledger;
  if (ledgerPath) {
    const l = readJsonFile(ledgerPath);
    if (!l.ok) return { status: 'rejected', reason: `the ledger file: ${l.reason}` };
    ledger = l.value;
  }
  if (commit !== undefined && !/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(String(commit))) return { status: 'rejected', reason: 'commit must be an exact 40 or 64 character hex id' };
  return exportScenarios({ invariant: inv.value, fixture: { files: fx.files }, ledger, commit, seed, bounds, config, signer });
}
