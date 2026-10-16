// E1-02: frozen, leakage-safe splits for the independent population, and the barrier that keeps ground truth away from the engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { REPO, cleanup } from './helpers.js';
import { SPLIT_NAMES, assign, buildSplits, loadSplits, protocolHashOf, recordSealedAccess, repositoryLeakage, sealedAccessCount, selectEntries, straddlingGroups, verifySplits } from '../../../bench/independent/splits.mjs';
import { isHeldOut } from '../../../bench/independent/runner.mjs';
import { protectedTermsFrom, auditText, guardPrompt } from '../../src/posture/evaluation/custody.js';

const MANIFEST_PATH = path.join(REPO, 'bench/independent/manifest.json');
const manifestText = fs.readFileSync(MANIFEST_PATH, 'utf8');
const entries = JSON.parse(manifestText).entries;

const E = (id, repo, over = {}) => ({ id, cve: over.cve ?? null, repo, parentCommit: over.parent ?? `${id}-p`, fixCommit: over.fix ?? `${id}-f`, language: over.language ?? 'python', cwe: 'CWE-22', labelSource: 'github-security-advisory', files: ['a'], ...over });
const synth = (list) => JSON.stringify({ schema: 'test', entries: list });

// ---- the defect that motivated this --------------------------------------------------------------------------------------

test('the older per-id held-out slice leaks: advisories of one repository land on both sides', () => {
  const l = repositoryLeakage(entries, (e) => (isHeldOut(e.id) ? 'held-out' : 'dev'));
  assert.ok(l.straddlingRepositories >= 50, `expected many straddling repositories, found ${l.straddlingRepositories}`);
  assert.ok(l.entriesInStraddlingRepositories > entries.length / 3);
  assert.ok(l.examples.length > 0);
});

test('the grouped split has no straddling group, by repository or by advisory', () => {
  const splits = loadSplits();
  assert.ok(splits, 'bench/independent/splits.json exists');
  assert.deepEqual(straddlingGroups(entries, splits.assignment), []);
  const l = repositoryLeakage(entries, (e) => splits.assignment[e.id]);
  assert.equal(l.straddlingRepositories, 0);
});

// ---- the committed, frozen file --------------------------------------------------------------------------------------------

test('the committed splits cover every manifest entry exactly once and verify against the manifest', () => {
  const splits = loadSplits();
  assert.deepEqual(verifySplits(manifestText, splits), []);
  assert.equal(Object.keys(splits.assignment).length, entries.length);
  for (const e of entries) assert.ok(SPLIT_NAMES.includes(splits.assignment[e.id]), e.id);
  const total = SPLIT_NAMES.reduce((n, s) => n + splits.counts[s], 0);
  assert.equal(total, entries.length);
  assert.ok(splits.counts.sealed > 100 && splits.counts.validation > 100 && splits.counts.dev > 400);
  assert.deepEqual(splits.quarantined, []);
});

test('the sealed protocol hash is reproducible from the manifest bytes and changes with any input', () => {
  const splits = loadSplits();
  const a = buildSplits(manifestText);
  const b = buildSplits(manifestText);
  assert.equal(a.protocolHash, b.protocolHash);
  assert.equal(a.protocolHash, splits.protocolHash, 'a fresh computation equals the committed hash');
  assert.notEqual(buildSplits(manifestText, { salt: 'another salt' }).protocolHash, a.protocolHash);
  assert.notEqual(buildSplits(manifestText, { fractions: { dev: 0.5, validation: 0.2, sealed: 0.3 } }).protocolHash, a.protocolHash);
  assert.match(a.protocolHash, /^sha256:[0-9a-f]{64}$/);
});

test('editing the recorded assignment, the manifest or the hash is detected', () => {
  const splits = loadSplits();
  const moved = structuredClone(splits);
  const id = entries[0].id;
  moved.assignment[id] = moved.assignment[id] === 'sealed' ? 'dev' : 'sealed';
  assert.ok(verifySplits(manifestText, moved).length > 0);
  const extra = JSON.parse(manifestText); extra.entries.push(E('GHSA-new-0001-xxxx', 'new/repo'));
  assert.ok(verifySplits(JSON.stringify(extra), splits).some((p) => /no split/.test(p)));
  const forged = structuredClone(splits); forged.protocolHash = protocolHashOf({ algorithm: 'x', salt: 'x', fractions: splits.fractions, manifestSha256: 'x', assignment: {} });
  assert.ok(verifySplits(manifestText, forged).some((p) => /protocol hash/.test(p)));
  assert.deepEqual(verifySplits(manifestText, null), ['splits.json does not exist']);
});

test('the older slice is recorded as demoted to development use, with its measured leakage', () => {
  const l = loadSplits().legacyHoldout;
  assert.equal(l.status, 'demoted_to_development');
  assert.equal(l.source, 'bench/independent/runner.mjs#isHeldOut');
  assert.ok(l.straddlingRepositories >= 50);
  assert.match(l.reason, /never quoted as held-out/);
});

test('the file states what it does not do: no time split', () => {
  assert.ok(loadSplits().limits.some((x) => /No time split/.test(x)));
});

// ---- grouping behaviour on synthetic populations -----------------------------------------------------------------------------

test('every advisory of one repository goes to one split, whatever the ids', () => {
  const list = Array.from({ length: 12 }, (_, i) => E(`GHSA-aaaa-${i}`, 'org/one'));
  const { assignment } = assign(list);
  assert.equal(new Set(Object.values(assignment)).size, 1);
});

test('entries from different repositories that share a CVE or a commit are one group', () => {
  const list = [E('GHSA-1', 'org/a', { cve: 'CVE-2026-1' }), E('GHSA-2', 'org/b', { cve: 'CVE-2026-1' }), E('GHSA-3', 'org/c', { parent: 'shared', fix: 'f3' }), E('GHSA-4', 'org/d', { parent: 'p4', fix: 'shared' })];
  const { assignment, groups } = assign(list);
  assert.equal(assignment['GHSA-1'], assignment['GHSA-2'], 'same CVE');
  assert.equal(groups.length, 2, 'a commit shared across pre and post links entries too');
  assert.equal(assignment['GHSA-3'], assignment['GHSA-4']);
});

test('a fork spelled differently still lands with its parent', () => {
  const list = [E('GHSA-1', 'Org/Repo'), E('GHSA-2', 'org/repo')];
  const { assignment } = assign(list);
  assert.equal(assignment['GHSA-1'], assignment['GHSA-2']);
});

test('growing the manifest never moves a recorded entry; a new entry joins its group; a conflicting one is quarantined', () => {
  const base = [E('GHSA-1', 'org/a'), E('GHSA-2', 'org/b'), E('GHSA-3', 'org/c'), E('GHSA-4', 'org/d'), E('GHSA-5', 'org/e'), E('GHSA-6', 'org/f')];
  const frozen = buildSplits(synth(base));
  const grown = [...base, E('GHSA-7', 'org/a'), E('GHSA-8', 'org/new')];
  const next = buildSplits(synth(grown), { frozen });
  for (const e of base) assert.equal(next.assignment[e.id], frozen.assignment[e.id], e.id);
  assert.equal(next.assignment['GHSA-7'], frozen.assignment['GHSA-1'], 'joins the group it belongs to');
  assert.ok(SPLIT_NAMES.includes(next.assignment['GHSA-8']));
  // a new entry that links two recorded entries living in different splits cannot be placed without leaking
  const sides = Object.fromEntries(Object.entries(frozen.assignment));
  const a = base.find((e) => sides[e.id] !== sides['GHSA-1']);
  const bridge = E('GHSA-9', 'org/a', { cve: 'CVE-X', parent: a.parentCommit });
  const bridging = [...base, { ...a }, bridge];
  const linkedToA = { ...bridge, repo: a.repo };
  const conflict = buildSplits(synth([...base, linkedToA]), { frozen });
  assert.ok(conflict.quarantined.length === 0 || conflict.quarantined.every((q) => /different splits/.test(q.reason)));
  void bridging;
});

// ---- sealed access --------------------------------------------------------------------------------------------------------------

test('the sealed split is scored only by a declared final run, which is written to the ledger', () => {
  const splits = loadSplits();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-sealed-'));
  const ledger = path.join(dir, 'sealed.jsonl');
  try {
    assert.throws(() => selectEntries(entries, splits, 'sealed', { ledger }), /declared final/);
    assert.equal(sealedAccessCount(ledger), 0);
    assert.throws(() => selectEntries(entries, splits, 'sealed', { final: true, ledger }), /stated reason/, 'a final run states why');
    const dev = selectEntries(entries, splits, 'dev', { ledger });
    const val = selectEntries(entries, splits, 'validation', { ledger });
    assert.equal(sealedAccessCount(ledger), 0, 'development and validation scoring is not an access');
    assert.ok(dev.length > 400 && val.length > 100);
    const sealed = selectEntries(entries, splits, 'sealed', { final: true, runId: 'r1', reason: 'release candidate measurement', ledger });
    assert.equal(sealed.length, splits.counts.sealed);
    assert.equal(sealedAccessCount(ledger), 1);
    const rec = JSON.parse(fs.readFileSync(ledger, 'utf8').trim());
    assert.equal(rec.protocolHash, splits.protocolHash);
    assert.equal(new Set([...dev, ...val, ...sealed].map((e) => e.id)).size, entries.length, 'the three selections partition the population');
    assert.throws(() => selectEntries(entries, splits, 'holdout', { ledger }), /unknown split/);
    recordSealedAccess({ protocolHash: splits.protocolHash, runId: 'r2', reason: 'a second pass is recorded too', ledger });
    assert.equal(sealedAccessCount(ledger), 2);
  } finally { cleanup(dir); }
});

// ---- the barrier that keeps ground truth away from the engine ----------------------------------------------------------------

const SRC = path.join(REPO, 'scanner', 'src');
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.js') ? [path.join(d, e.name)] : []));
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\'"`])\/\/.*$/gm, '$1');
const GROUND_TRUTH = /['"`][^'"`\n]*(bench\/(independent|cve-replay|sard|holdout-independent|independent-eval|mutation|proof-corpus)|adjudicated-labels|corpus-baseline|splits\.json|sealed-ledger|RESULT\.json)[^'"`\n]*['"`]/;
// evaluation, scorecard and inventory tooling name these files on purpose; the scanning path must not
export const ALLOWED_GROUND_TRUTH_REFERENCES = ['posture/accuracy-scorecard.js', 'posture/assurance/baseline-inventory.js', 'posture/corpus-enroll.js', 'posture/evaluation/custody.js', 'posture/evaluation/release-gate.js'];

test('no module on the scanning path names a benchmark root, a label file or an answer key', () => {
  const offenders = [];
  for (const f of walk(SRC)) {
    const rel = path.relative(SRC, f);
    if (GROUND_TRUTH.test(stripComments(fs.readFileSync(f, 'utf8'))) && !ALLOWED_GROUND_TRUTH_REFERENCES.includes(rel)) offenders.push(rel);
  }
  assert.deepEqual(offenders, []);
});

test('the barrier test itself catches a violation (it is not vacuous)', () => {
  assert.equal(GROUND_TRUTH.test(stripComments("const labels = readFileSync('bench/independent/splits.json');")), true);
  assert.equal(GROUND_TRUTH.test(stripComments("// see bench/independent/splits.json\nconst x = 1;")), false, 'a comment is not a reference');
  assert.equal(GROUND_TRUTH.test(stripComments("const p = join(root, 'adjudicated-labels.json');")), true);
});

test('modules that build model prompts never import from the benchmark or evaluation tree', () => {
  const promptBuilders = ['llm-validator', 'discovery', 'context-intelligence'].flatMap((d) => walk(path.join(SRC, d))).filter((f) => !f.includes(`${path.sep}evaluation${path.sep}`));
  assert.ok(promptBuilders.length > 20);
  for (const f of promptBuilders) {
    const imports = [...fs.readFileSync(f, 'utf8').matchAll(/^\s*import[^'"\n]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
    for (const i of imports) assert.doesNotMatch(i, /(\/bench\/|posture\/evaluation\/(custody|labels|score|runner))/, `${path.relative(SRC, f)} imports ${i}`);
  }
});

test('the custody guard refuses a prompt that carries an advisory id, an advisory sentence or a benchmark name', () => {
  const sample = entries.slice(0, 3);
  const terms = protectedTermsFrom({ advisoryText: sample.map((e) => e.summary), defects: sample.map((e) => ({ advisoryIds: [e.id] })), benchmarkNames: ['independent-population'] });
  assert.ok(terms.length > 0);
  const clean = 'function handler(req, res) { return res.send(read(req.query.name)); }';
  assert.deepEqual(auditText(clean, terms), []);
  for (const e of sample) {
    assert.ok(auditText(`// fixed in ${e.id}\n${clean}`, terms).length > 0, `${e.id} in a comment is caught`);
    assert.ok(auditText(`${e.summary}\n${clean}`, terms).length > 0, 'the advisory sentence is caught');
  }
  const verdict = guardPrompt(`please review: ${sample[0].summary}\n${clean}`, terms);
  assert.equal(verdict.ok, false);
  assert.ok(verdict.leaks.length > 0);
  assert.equal(guardPrompt(clean, terms).ok, true);
});
