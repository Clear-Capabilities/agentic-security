import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { bumpVersion, planSteps, VERSION_FILES } from '../../scripts/release-prepare.mjs';
import { mkTestTmp } from './helpers/tmp.js';

test('bumpVersion replaces every occurrence and reports a file that had none', () => {
  const dir = mkTestTmp('release-prepare-');
  writeFileSync(join(dir, 'a.json'), '{"version":"1.2.3","dep":"1.2.3","other":"1.2.30"}');
  writeFileSync(join(dir, 'b.md'), 'nothing here');
  const counts = bumpVersion(dir, '1.2.3', '1.2.4', ['a.json', 'b.md']);
  assert.equal(counts['a.json'], 3, 'a substring match is counted too, which is why the caller reviews the diff');
  assert.equal(counts['b.md'], 0);
  assert.match(readFileSync(join(dir, 'a.json'), 'utf8'), /"version":"1.2.4"/);
  assert.equal(readFileSync(join(dir, 'b.md'), 'utf8'), 'nothing here');
});

test('bumpVersion refuses anything that is not X.Y.Z', () => {
  assert.throws(() => bumpVersion('.', '1.2', '1.3.0', []), /X\.Y\.Z/);
  assert.throws(() => bumpVersion('.', '1.2.3', 'latest', []), /X\.Y\.Z/);
});

test('the plan regenerates before it verifies, and --no-tests drops only the suites', () => {
  const all = planSteps().map((s) => s.name);
  const gen = planSteps({ tests: false }).map((s) => s.name);
  assert.deepEqual(all.slice(0, gen.length), gen);
  assert.ok(all.length > gen.length);
  assert.ok(gen.indexOf('build the bundle') < gen.indexOf('regenerate the scorecard'));
  assert.ok(gen.indexOf('record inventory test runs') < gen.indexOf('render the inventory'));
  assert.ok(gen.indexOf('regenerate the regression report') < gen.indexOf('regenerate the final report'));
});

test('the version files are the ones the release check compares', () => {
  assert.ok(VERSION_FILES.includes('scanner/package.json') && VERSION_FILES.includes('scanner/package-lock.json'));
});

test('bumpVersion leaves historical version text alone in the files that carry prose', () => {
  const dir = mkTestTmp('release-prepare-');
  writeFileSync(join(dir, 'CLAUDE.md'), '**Version:** 1.2.3  \n\nA note (since 1.2.3) and "the 1.2.3 release failed" stay as written.\n');
  writeFileSync(join(dir, 'README.md'), '[![Version](https://img.shields.io/badge/version-1.2.3-blue)]()\nSince 1.2.3 this works.\n');
  mkdirSync(join(dir, 'scanner'), { recursive: true });
  writeFileSync(join(dir, 'scanner/package-lock.json'), '{"version": "1.2.3", "packages": {"": {"version": "1.2.3"}, "node_modules/x": {"version": "1.2.30"}}}');
  const counts = bumpVersion(dir, '1.2.3', '1.2.4', ['CLAUDE.md', 'README.md', 'scanner/package-lock.json']);
  assert.deepEqual(counts, { 'CLAUDE.md': 1, 'README.md': 1, 'scanner/package-lock.json': 2 });
  const claude = readFileSync(join(dir, 'CLAUDE.md'), 'utf8');
  assert.match(claude, /\*\*Version:\*\* 1\.2\.4/);
  assert.match(claude, /\(since 1\.2\.3\)/); assert.match(claude, /the 1\.2\.3 release failed/);
  assert.match(readFileSync(join(dir, 'README.md'), 'utf8'), /badge\/version-1\.2\.4-blue[\s\S]*Since 1\.2\.3 this works/);
  assert.match(readFileSync(join(dir, 'scanner/package-lock.json'), 'utf8'), /"1\.2\.30"/, 'a longer version that merely starts with the old one is not touched');
});
