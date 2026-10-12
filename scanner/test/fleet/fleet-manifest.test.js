import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { validateFleetManifest, loadFleetManifest, parseDuration, starterManifestYaml } from '../../src/posture/fleet/fleet-manifest.js';

function mkTmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'fm-')); }

test('validateFleetManifest: a well-formed manifest resolves repo paths and defaults workers/timeout', () => {
  const dir = mkTmp();
  fs.mkdirSync(path.join(dir, 'a'));
  const r = validateFleetManifest({ organization: 'acme', repositories: [{ id: 'a', path: './a' }] }, { baseDir: dir });
  assert.equal(r.ok, true);
  assert.equal(r.manifest.workers, 4);
  assert.equal(r.manifest.perRepoTimeoutMs, 20 * 60000);
  assert.equal(r.manifest.repositories[0].path, path.resolve(dir, 'a'));
});

test('validateFleetManifest: refuses an unknown top-level key, a duplicate id, a non-kebab id, and a missing path', () => {
  const dir = mkTmp();
  fs.mkdirSync(path.join(dir, 'a'));
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: './a' }], bogus: 1 }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: './a' }, { id: 'a', path: './a' }] }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'Bad_ID', path: './a' }] }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: './does-not-exist' }] }, { baseDir: dir }).ok, false);
});

test('validateFleetManifest: workers out of range, bad duration, non-array repositories', () => {
  const dir = mkTmp();
  fs.mkdirSync(path.join(dir, 'a'));
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: './a' }], workers: 0 }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: [{ id: 'a', path: './a' }], perRepoTimeout: 'soon' }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest({ organization: 'x', repositories: 'nope' }, { baseDir: dir }).ok, false);
  assert.equal(validateFleetManifest(null, { baseDir: dir }).ok, false);
});

test('parseDuration: s/m/h suffixes and a bare number of seconds', () => {
  assert.equal(parseDuration('30s'), 30000);
  assert.equal(parseDuration('5m'), 300000);
  assert.equal(parseDuration('1h'), 3600000);
  assert.equal(parseDuration(10), 10000);
  assert.equal(parseDuration('nonsense', 'fallback'), 'fallback');
});

test('loadFleetManifest: reads real YAML from disk and resolves paths relative to the manifest file, not cwd', () => {
  const dir = mkTmp();
  fs.mkdirSync(path.join(dir, 'repo-a'));
  fs.writeFileSync(path.join(dir, 'fleet.yaml'), 'organization: acme\nrepositories:\n  - id: repo-a\n    path: ./repo-a\n');
  const r = loadFleetManifest(path.join(dir, 'fleet.yaml'));
  assert.equal(r.ok, true);
  assert.equal(r.manifest.repositories[0].path, path.resolve(dir, 'repo-a'));
});

test('loadFleetManifest: a missing file and invalid YAML are both reported, not thrown', () => {
  assert.equal(loadFleetManifest('/nonexistent/fleet.yaml').ok, false);
  const dir = mkTmp();
  fs.writeFileSync(path.join(dir, 'bad.yaml'), ': not: valid: yaml: at all: [[[');
  assert.equal(loadFleetManifest(path.join(dir, 'bad.yaml')).ok, false);
});

test('starterManifestYaml parses back to a valid manifest', () => {
  const dir = mkTmp();
  fs.writeFileSync(path.join(dir, 'fleet.yaml'), starterManifestYaml('acme'));
  const r = loadFleetManifest(path.join(dir, 'fleet.yaml'));
  assert.equal(r.ok, true);
  assert.equal(r.manifest.organization, 'acme');
});
