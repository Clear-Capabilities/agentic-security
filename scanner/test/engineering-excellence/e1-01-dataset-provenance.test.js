// E1-01: dataset provenance audit. No fact is invented; a missing one is counted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { REPO, makeRoot, cleanup } from './helpers.js';
import { LABEL_CONFIDENCE, REQUIRED_FACTS, auditIndependent, buildAudit, factsOfIndependentEntry, lookupLicenses, renderMarkdown, verifyUpstream } from '../../../scripts/engineering-excellence/dataset-audit.mjs';

const sha = (c) => c.repeat(40).slice(0, 40);
const ENTRY = { id: 'GHSA-aaaa-bbbb-cccc', cve: 'CVE-2026-1', cwe: 'CWE-22', labelSource: 'github-security-advisory', repo: 'org/repo', parentCommit: sha('a'), fixCommit: sha('b'), language: 'python', files: ['x.py'], severity: 'high' };

async function rootWith(entries, sidecar = null, splits = null) {
  const { root } = await makeRoot();
  fs.mkdirSync(path.join(root, 'bench', 'independent'), { recursive: true });
  fs.writeFileSync(path.join(root, 'bench', 'independent', 'manifest.json'), JSON.stringify({ schema: 'test@1', entries }));
  if (sidecar) fs.writeFileSync(path.join(root, 'bench', 'independent', 'provenance.sidecar.json'), JSON.stringify(sidecar));
  if (splits) fs.writeFileSync(path.join(root, 'bench', 'independent', 'splits.json'), JSON.stringify(splits));
  return root;
}

test('the nine required facts are exactly the ones the PRD names', () => {
  assert.deepEqual([...REQUIRED_FACTS], ['sourceProject', 'commitBefore', 'commitAfter', 'advisory', 'language', 'scope', 'license', 'labelConfidence', 'acquisitionChecksum', 'split']);
  assert.ok(LABEL_CONFIDENCE.includes('adjudicated') && LABEL_CONFIDENCE.includes('synthetic'));
});

test('a fact the manifest does not carry is null: licence, acquisition checksum and split are never defaulted', () => {
  const f = factsOfIndependentEntry(ENTRY, { licenses: {}, splits: {}, acquisition: {} });
  assert.equal(f.sourceProject, 'org/repo');
  assert.equal(f.commitBefore, sha('a'));
  assert.deepEqual(f.advisory, { id: 'GHSA-aaaa-bbbb-cccc', cve: 'CVE-2026-1', cwe: 'CWE-22', source: 'github-security-advisory' });
  assert.equal(f.labelConfidence, 'third_party_advisory');
  assert.equal(f.license, null);
  assert.equal(f.acquisitionChecksum, null);
  assert.equal(f.split, null);
  const withSide = factsOfIndependentEntry(ENTRY, { licenses: { 'org/repo': { spdx: 'MIT' } }, splits: {}, acquisition: { [ENTRY.id]: 'sha256:abc' } }, { assignment: { [ENTRY.id]: 'sealed' } });
  assert.equal(withSide.license.spdx, 'MIT');
  assert.equal(withSide.acquisitionChecksum, 'sha256:abc');
  assert.equal(withSide.split, 'sealed');
});

test('a commit that is not a full SHA, or a missing repository, makes the entry unavailable rather than guessed', async () => {
  const root = await rootWith([ENTRY, { ...ENTRY, id: 'GHSA-bad1', parentCommit: 'HEAD~1' }, { ...ENTRY, id: 'GHSA-bad2', repo: '' }, { ...ENTRY, id: 'GHSA-bad3', labelSource: '' }]);
  try {
    const a = auditIndependent(root);
    assert.equal(a.entries, 4);
    assert.equal(a.reconstructableFromUpstream, 1);
    assert.equal(a.unavailableCount, 3);
    const why = Object.fromEntries(a.unavailable.map((u) => [u.id, u.why]));
    assert.deepEqual(why['GHSA-bad1'], ['commitBefore']);
    assert.deepEqual(why['GHSA-bad2'], ['sourceProject']);
    assert.deepEqual(why['GHSA-bad3'], ['advisory']);
    assert.equal(a.factCoverage.commitBefore, 3);
    assert.equal(a.completeEntries, 0, 'no entry has licence, checksum and split yet');
  } finally { cleanup(root); }
});

test('an entry with every fact is complete; duplicate ids are reported', async () => {
  const root = await rootWith([ENTRY, ENTRY], { licenses: { 'org/repo': { spdx: 'MIT' } }, splits: {}, acquisition: { [ENTRY.id]: 'sha256:1' } }, { assignment: { [ENTRY.id]: 'dev' } });
  try {
    const a = auditIndependent(root);
    assert.equal(a.completeEntries, 2);
    assert.deepEqual(a.duplicateIds, [ENTRY.id]);
    assert.equal(a.licenseSummary.looked, 1);
  } finally { cleanup(root); }
});

test('a missing manifest is reported unavailable, not an empty success', async () => {
  const { root } = await makeRoot();
  try {
    const a = auditIndependent(root);
    assert.equal(a.status, 'unavailable');
    assert.match(a.reason, /manifest\.json is missing/);
  } finally { cleanup(root); }
});

test('the opt-in licence lookup records the host answer, marks no licence as NOASSERTION, caches, and records failures without defaulting', async () => {
  const root = await rootWith([ENTRY, { ...ENTRY, id: 'GHSA-2', repo: 'org/nolicense' }, { ...ENTRY, id: 'GHSA-3', repo: 'org/broken' }]);
  try {
    const calls = [];
    const run = (repo) => { calls.push(repo); if (repo === 'org/broken') throw new Error('HTTP 404'); return repo === 'org/nolicense' ? 'none' : 'MIT'; };
    const r = lookupLicenses(root, { run });
    assert.equal(r.looked, 3);
    assert.equal(r.failed.length, 1);
    const side = JSON.parse(fs.readFileSync(path.join(root, 'bench/independent/provenance.sidecar.json'), 'utf8'));
    assert.equal(side.licenses['org/repo'].spdx, 'MIT');
    assert.equal(side.licenses['org/nolicense'].spdx, 'NOASSERTION');
    assert.equal(side.licenses['org/broken'], undefined, 'a failed lookup is not recorded as a licence');
    const again = lookupLicenses(root, { run: (repo) => { calls.push(`again:${repo}`); return 'MIT'; } });
    assert.equal(again.looked, 1, 'only the failed repository is retried');
  } finally { cleanup(root); }
});

test('the opt-in upstream check distinguishes a commit that is gone from an error, and reuses what it has seen', async () => {
  const root = await rootWith([ENTRY, { ...ENTRY, id: 'GHSA-gone', language: 'go', fixCommit: sha('c') }, { ...ENTRY, id: 'GHSA-err', language: 'ruby' }]);
  try {
    const run = (repo, commit) => { if (commit === sha('c')) { const e = new Error('nope'); e.stderr = 'HTTP 404: Not Found'; throw e; } if (repo === 'org/repo' && commit === sha('b') && false) return ''; return commit; };
    const flaky = (repo, commit) => { throw new Error('connection reset'); };
    const r1 = verifyUpstream(root, { perLanguage: 1, run: (repo, commit) => (commit === sha('a') || commit === sha('b') ? (repo === 'x' ? flaky() : run(repo, commit)) : run(repo, commit)) });
    assert.equal(r1.checked, 3);
    assert.equal(r1.missing, 1);
    assert.equal(r1.ok, 2);
    const side = JSON.parse(fs.readFileSync(path.join(root, 'bench/independent/provenance.sidecar.json'), 'utf8'));
    assert.equal(side.upstreamVerified['GHSA-gone'].fix, 'missing');
    const r2 = verifyUpstream(root, { perLanguage: 1, run: () => { throw new Error('connection reset'); } });
    assert.equal(r2.checked, 3, 'recorded results are kept, not overwritten by a later error');
    assert.equal(r2.missing, 1);
  } finally { cleanup(root); }
});

// ---- the committed audit ---------------------------------------------------------------------------------------------------

test('the real independent population: counts, repositories, licences and split coverage', () => {
  const a = auditIndependent(REPO);
  assert.equal(a.status, 'audited');
  assert.ok(a.entries >= 1000);
  assert.ok(a.repositories >= 400);
  assert.equal(a.reconstructableFromUpstream, a.entries);
  assert.equal(a.duplicateIds.length, 0);
  assert.equal(a.factCoverage.split, a.entries, 'every entry has a split');
  assert.equal(a.factCoverage.license, a.entries, 'every repository was looked up');
  assert.equal(a.factCoverage.acquisitionChecksum, 0, 'nothing has been fetched yet, so no checksum is claimed');
  assert.ok(a.licenseSummary.noLicenseAsserted > 0, 'repositories that assert no licence are counted');
  assert.ok(a.upstreamSample.sampled >= 30 && a.upstreamSample.missingUpstream === 0, JSON.stringify(a.upstreamSample));
  assert.equal(a.splitProtocolHash, JSON.parse(fs.readFileSync(path.join(REPO, 'bench/independent/splits.json'), 'utf8')).protocolHash);
});

test('the regression net is classified as a regression net that cannot support an accuracy claim', () => {
  const c = buildAudit(REPO).populations.cveReplay;
  assert.equal(c.role, 'regression');
  assert.equal(c.usableForAccuracyClaims, false);
  assert.ok(c.entries >= 200);
  assert.ok(c.bySourceTier['synthetic-shape-of-disclosed-cve'] > c.entries * 0.9);
});

test('the committed report is what the checkout produces now', () => {
  const dir = path.join(REPO, 'docs', 'engineering-excellence');
  const committed = fs.readFileSync(path.join(dir, 'DATASET_PROVENANCE.md'), 'utf8');
  const fresh = renderMarkdown(buildAudit(REPO));
  assert.equal(committed.trim(), fresh.trim(), 'run: node scripts/engineering-excellence/dataset-audit.mjs');
  assert.match(committed, /Entries with all nine facts: \*\*0\*\* of/);
  assert.match(committed, /none is filled in by guesswork/);
});
