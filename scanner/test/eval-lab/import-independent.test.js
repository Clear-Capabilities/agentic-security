// The importer from the independent real-code population into an Eval Lab dataset (PRD 6, requirement 3): hunk-based expected spans,
// licence and split rules, the sealed split refused, custody-safe workspaces, and a dataset the lab itself accepts.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { importIndependent, changedRegion } from '../../../scripts/eval-lab/import-independent.mjs';
import { loadDatasetFile, PERMITTED_LICENSES } from '../../src/posture/evaluation/lab/dataset.js';

const write = (root, rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };

test('the expected span is the hunk that removes the dangerous code, not the whole stretch between the first and last edit', () => {
  const oldT = ['import a', '', 'function f(x) {', '  danger(x);', '  more();', '}', '', 'tail'].join('\n');
  const newT = ['import a', 'import b', '', 'function f(x) {', '  safe(x);', '  more();', '}', '', 'tail changed'].join('\n');
  const r = changedRegion(oldT, newT);
  assert.deepEqual(r.old, { startLine: 4, endLine: 4, approximate: false }); assert.deepEqual(r.new, { startLine: 5, endLine: 5 }); assert.equal(r.hunks, 3);
  const bigger = changedRegion('a\nb\nc\nd\ne', 'a\nX\nY\nd\ne\nF');
  assert.deepEqual(bigger.old, { startLine: 2, endLine: 3, approximate: false }, 'the hunk removing the most lines wins');
});

test('an addition-only fix has an approximate span at the line it follows; an identical file has no region; a huge change is too large to localize', () => {
  const add = changedRegion('a\nb\nc', 'a\nb\nguard()\nc');
  assert.deepEqual(add.old, { startLine: 2, endLine: 2, approximate: true }); assert.deepEqual(add.new, { startLine: 3, endLine: 3 });
  assert.equal(changedRegion('same', 'same'), null);
  const big = changedRegion(Array.from({ length: 400 }, (_, i) => `old${i}`).join('\n'), Array.from({ length: 400 }, (_, i) => `new${i}`).join('\n'));
  assert.equal(big.tooLarge, true);
  const del = changedRegion('a\nbad\nc', 'a\nc');
  assert.deepEqual(del.old, { startLine: 2, endLine: 2, approximate: false }); assert.equal(del.new, null, 'a pure deletion leaves nothing in the fixed file');
});

function population() {
  const dir = mkTestTmp('indep-'); 
  const entries = [
    { id: 'GHSA-aaaa-0001-aaaa', cve: 'CVE-1', cwe: 'CWE-89', repo: 'acme/ok', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/db.js'], language: 'javascript' },
    { id: 'GHSA-bbbb-0002-bbbb', cve: 'CVE-2', cwe: 'CWE-79', repo: 'acme/ok', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/x.js'], language: 'javascript' },
    { id: 'GHSA-cccc-0003-cccc', cve: 'CVE-3', cwe: 'CWE-22', repo: 'acme/unlicensed', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/y.js'], language: 'javascript' },
    { id: 'GHSA-dddd-0004-dddd', cve: 'CVE-4', cwe: 'CWE-78', repo: 'acme/ok', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/z.js'], language: 'javascript' },
    { id: 'GHSA-eeee-0005-eeee', cve: 'CVE-5', cwe: 'CWE-94', repo: 'acme/ok', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/s.js'], language: 'javascript' },
    { id: 'GHSA-ffff-0006-ffff', cve: 'CVE-6', cwe: 'CWE-89', repo: 'acme/ok', fixCommit: 'f'.repeat(40), parentCommit: 'e'.repeat(40), files: ['lib/p.py'], language: 'python' },
  ];
  write(dir, 'manifest.json', JSON.stringify({ schema: 'x', entries }));
  write(dir, 'splits.json', JSON.stringify({ assignment: { 'GHSA-aaaa-0001-aaaa': 'dev', 'GHSA-bbbb-0002-bbbb': 'dev', 'GHSA-cccc-0003-cccc': 'dev', 'GHSA-dddd-0004-dddd': 'dev', 'GHSA-eeee-0005-eeee': 'sealed', 'GHSA-ffff-0006-ffff': 'dev' } }));
  write(dir, 'provenance.sidecar.json', JSON.stringify({ licenses: { 'acme/ok': { spdx: 'MIT' }, 'acme/unlicensed': { spdx: 'NOASSERTION' } } }));
  const pair = (id, file, pre, post) => { write(dir, `cache/${id}/pre/${file}`, pre); write(dir, `cache/${id}/post/${file}`, post); };
  pair('GHSA-aaaa-0001-aaaa', 'lib/db.js', "const q = 'SELECT ' + id;\ndb.run(q);\n// see GHSA-aaaa-0001-aaaa\n", "const q = 'SELECT ?';\ndb.run(q, [id]);\n// see GHSA-aaaa-0001-aaaa\n");
  pair('GHSA-cccc-0003-cccc', 'lib/y.js', 'a\n', 'b\n');
  pair('GHSA-eeee-0005-eeee', 'lib/s.js', 'a\n', 'b\n');
  pair('GHSA-ffff-0006-ffff', 'lib/p.py', 'a\n', 'b\n');
  // GHSA-bbbb has no cache; GHSA-dddd has identical trees
  pair('GHSA-dddd-0004-dddd', 'lib/z.js', 'same\n', 'same\n');
  return dir;
}

test('only licensed, cached, localizable dev entries are imported; every skip has a reason; the dataset passes the lab\'s own validation', () => {
  const dir = population(); const out = path.join(mkTestTmp('indep-out-'), 'ds');
  const r = importIndependent({ independentDir: dir, split: 'dev', language: 'javascript', out, permittedLicenses: PERMITTED_LICENSES, now: '2026-10-18T00:00:00Z' });
  assert.equal(r.ok, true, r.reason); assert.equal(r.pairs, 1); assert.equal(r.entries, 2);
  const reasons = Object.fromEntries(r.skipped.map((s) => [s.id, s.reason]));
  assert.match(reasons['GHSA-bbbb-0002-bbbb'], /not in the local cache/);
  assert.match(reasons['GHSA-cccc-0003-cccc'], /licence NOASSERTION is not on the permitted list/);
  assert.match(reasons['GHSA-dddd-0004-dddd'], /no changed file/);
  assert.ok(!('GHSA-eeee-0005-eeee' in reasons) && !('GHSA-ffff-0006-ffff' in reasons), 'a sealed entry and another language are not even considered');
  const loaded = loadDatasetFile(r.manifestFile);
  assert.equal(loaded.ok, true, loaded.errors?.join());
  const v = loaded.manifest.entries.find((e) => e.kind === 'vulnerable');
  assert.deepEqual(v.expectedSpan, { file: 'lib/db.js', startLine: 1, endLine: 2 }); assert.equal(v.cwe, 'CWE-89');
  assert.equal(loaded.manifest.dataset.leakagePolicy.mode, 'enforce'); assert.equal(loaded.manifest.dataset.split, 'dev');
  const ws = path.join(path.dirname(r.manifestFile), v.workspace.dir);
  assert.match(fs.readFileSync(path.join(ws, 'lib/db.js'), 'utf8'), /SELECT ' \+ id/);
  assert.ok(!fs.existsSync(path.join(ws, 'dataset.json')), 'labels live in the manifest, not in the workspace');
});

test('the sealed split cannot be exported at all, and bad options are refused', () => {
  const dir = population(); const out = path.join(mkTestTmp('indep-out-'), 'ds');
  const sealed = importIndependent({ independentDir: dir, split: 'sealed', language: 'javascript', out, permittedLicenses: PERMITTED_LICENSES });
  assert.equal(sealed.ok, false); assert.match(sealed.reason, /never exported into a dataset an arm can run on/);
  assert.equal(fs.existsSync(out), false, 'nothing was written');
  assert.match(importIndependent({ independentDir: dir, split: 'dev', language: '', out, permittedLicenses: PERMITTED_LICENSES }).reason, /--language is required/);
  assert.match(importIndependent({ independentDir: dir, split: 'dev', language: 'javascript', out, scope: 'everything', permittedLicenses: PERMITTED_LICENSES }).reason, /--scope/);
  assert.match(importIndependent({ independentDir: '/nonexistent', split: 'dev', language: 'javascript', out, permittedLicenses: PERMITTED_LICENSES }).reason, /cannot read the independent population/);
});
