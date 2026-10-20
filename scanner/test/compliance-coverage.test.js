// The compliance coverage maps are generated from the framework files, so a map cannot disagree with what the engine assesses.
// Both directions: the repository passes, and each way it could drift (a stale page, a missing page, a wrong README count, an edited
// framework file) is caught.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkCoverage, loadFrameworks, statsOf, expectedFiles, HAND_WRITTEN, SUMMARY_PAGE } from '../../scripts/compliance-coverage.mjs';
import { mkTestTmp } from './helpers/tmp.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

function copy() {
  const dir = mkTestTmp('agsec-compliance-cov-');
  fs.cpSync(path.join(REPO, 'scanner/src/posture/compliance-frameworks'), path.join(dir, 'scanner/src/posture/compliance-frameworks'), { recursive: true });
  fs.cpSync(path.join(REPO, 'docs/compliance'), path.join(dir, 'docs/compliance'), { recursive: true });
  fs.copyFileSync(path.join(REPO, 'README.md'), path.join(dir, 'README.md'));
  return dir;
}

test('the repository: every bundled framework has a per-control map and nothing is stale', () => {
  assert.deepEqual(checkCoverage(REPO), []);
  const fws = loadFrameworks(REPO);
  assert.equal(fws.length, 10);
  for (const fw of fws) {
    const page = HAND_WRITTEN[fw.id] ?? `${fw.id}-coverage.md`;
    assert.ok(fs.existsSync(path.join(REPO, 'docs/compliance', page)), `${fw.id} has a map`);
  }
});

test('every control of a generated framework is on its page, with its mapping or the words that a person attests', () => {
  for (const [rel, text] of Object.entries(expectedFiles(REPO))) {
    if (path.basename(rel) === SUMMARY_PAGE) continue;
    const fw = loadFrameworks(REPO).find((f) => rel.endsWith(`${f.id}-coverage.md`));
    for (const c of fw.controls) assert.ok(text.includes(`\`${c.id}\``), `${fw.id} lists ${c.id}`);
    assert.equal(statsOf(fw).controls, fw.controls.length);
  }
});

test('a stale page is caught', () => {
  const dir = copy();
  const p = path.join(dir, 'docs/compliance/gdpr-coverage.md');
  fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('Art.5', 'Art.99'));
  assert.ok(checkCoverage(dir).some((f) => f.file.endsWith('gdpr-coverage.md') && /stale/.test(f.message)));
});

test('a missing page and a missing summary are caught', () => {
  const dir = copy();
  fs.rmSync(path.join(dir, 'docs/compliance/ccpa-coverage.md'));
  fs.rmSync(path.join(dir, 'docs/compliance', SUMMARY_PAGE));
  const found = checkCoverage(dir);
  assert.ok(found.some((f) => f.file.endsWith('ccpa-coverage.md') && /missing/.test(f.message)));
  assert.ok(found.some((f) => f.file.endsWith(SUMMARY_PAGE) && /missing/.test(f.message)));
});

test('a framework file that changes without regenerating the maps is caught', () => {
  const dir = copy();
  const p = path.join(dir, 'scanner/src/posture/compliance-frameworks/gdpr.json');
  const d = JSON.parse(fs.readFileSync(p, 'utf8'));
  d.controls.pop();
  fs.writeFileSync(p, JSON.stringify(d));
  const found = checkCoverage(dir);
  assert.ok(found.some((f) => /gdpr-coverage\.md|COVERAGE\.md/.test(f.file) && /stale/.test(f.message)));
});

test('a wrong README count is caught, and so is a framework added without a map', () => {
  const dir = copy();
  const r = path.join(dir, 'README.md');
  fs.writeFileSync(r, fs.readFileSync(r, 'utf8').replace(/for 10 bundled frameworks/, 'for 11 bundled frameworks'));
  assert.ok(checkCoverage(dir).some((f) => f.file === 'README.md' && /11/.test(f.message)));
  const added = copy();
  const fwDir = path.join(added, 'scanner/src/posture/compliance-frameworks');
  fs.writeFileSync(path.join(fwDir, 'new-law.json'), JSON.stringify({ id: 'new-law', name: 'A New Law', controls: [{ id: 'S1', summary: 'x', codeTestable: 'no', mapsTo: [] }] }));
  assert.ok(checkCoverage(added).some((f) => /new-law-coverage\.md/.test(f.file) && /missing/.test(f.message)));
});
