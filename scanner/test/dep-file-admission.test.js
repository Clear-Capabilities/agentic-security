// PRD F3.1 — the dependency files a real project actually has must reach the
// SCA parsers.
//
// Every case here was found by `bench/sca-replay`, the first instrument that
// ever scored this engine's SCA against third-party labels, and every one is
// the same failure shape the project has now hit four times: a parser exists,
// is wired into the dispatch table, is covered by unit tests — and is never
// invoked, because the file never gets admitted. `rate-limit.js`,
// `k8s-admission` and `install-script` were the earlier three.
//
// What the bench measured, before any of this was fixed:
//
//   ecosystem     recall
//   npm             0.91%   (2 of 219 labelled vulnerable versions)
//   Go              2.73%   (15 of 549)
//   Packagist       0%      (0 of 21)
//   PyPI           60%      (18 of 30)
//
// Three admission defects account for nearly all of it:
//
//   1. `readTree` skipped ANY file over 500 KB before deciding what kind of
//      file it was. npm/cli's package-lock.json is 666 KB, next.js's
//      pnpm-lock.yaml is 910 KB, magento2's composer.lock is 501 KB. On every
//      project big enough for supply-chain risk to matter, the lockfile was
//      dropped and SCA silently fell back to whatever exact versions happened
//      to appear in package.json — i.e. DIRECT dependencies only. The
//      headline SCA claim is transitive reachability; the transitive tree was
//      not being read at all.
//
//   2. `go.sum` was not in DEP_FILE_NAMES even though `_parseGoSum` exists and
//      is wired into `parseManifests`. `go.mod` alone lists direct requires;
//      go.sum carries the resolved graph.
//
//   3. Python requirements files are `requirements/dev.txt`,
//      `requirements-dev.txt`, `requirements/base.txt` at least as often as
//      they are `requirements.txt`. Only the exact basename was admitted, and
//      `parseManifests` keyed its parser table on basename too, so even an
//      admitted `dev.txt` had no parser.
//
// The size cap stays where it matters. Code files are still capped at 500 KB —
// that cap protects the expensive analysis path, and nothing here touches it.
// Manifests are read by line-oriented and JSON parsers, so a separate, much
// larger cap costs a parse rather than an AST walk.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { readTree } from '../src/runScan.js';
import { parseManifests } from '../src/engine.js';

async function tree(files) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dep-admit-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(dir, rel);
    await fsp.mkdir(path.dirname(p), { recursive: true });
    await fsp.writeFile(p, body);
  }
  return dir;
}

// A package-lock large enough to exceed the old 500 KB cap, carrying one
// package whose presence is easy to assert.
function bigPackageLock() {
  const packages = { '': { name: 'big', version: '1.0.0' } };
  for (let i = 0; i < 9000; i++) {
    packages[`node_modules/filler-package-with-a-long-name-${i}`] = {
      version: '1.0.0', resolved: `https://registry.example.com/filler-${i}/-/filler-${i}-1.0.0.tgz`,
      integrity: 'sha512-' + 'A'.repeat(86) + '==',
    };
  }
  packages['node_modules/lodash'] = { version: '4.17.15' };
  return JSON.stringify({ name: 'big', version: '1.0.0', lockfileVersion: 3, packages });
}

test('a lockfile over 500 KB is still admitted — code files are not', async () => {
  const lock = bigPackageLock();
  assert.ok(lock.length > 500_000, `fixture must exceed the code cap, got ${lock.length}`);
  const bigCode = '// filler\n'.repeat(60_000);
  assert.ok(bigCode.length > 500_000);

  const dir = await tree({
    'package.json': '{"name":"big","version":"1.0.0"}',
    'package-lock.json': lock,
    'huge.js': bigCode,
  });
  const { fileContents, depFileContents } = await readTree(dir);

  assert.ok(depFileContents['package-lock.json'], 'a large lockfile must be admitted');
  assert.equal(depFileContents['package-lock.json'].length, lock.length, 'and admitted whole, not truncated');
  // The code cap is deliberately unchanged: it guards the analysis path.
  assert.ok(!fileContents['huge.js'], 'a large CODE file must still be skipped');

  const comps = parseManifests(depFileContents);
  const lodash = comps.find((c) => c.name === 'lodash');
  assert.ok(lodash, 'the transitive package inside the large lockfile must be enumerated');
  assert.equal(lodash.version, '4.17.15');
  await fsp.rm(dir, { recursive: true, force: true });
});

test('go.sum is admitted and its resolved graph enumerated', async () => {
  // go.mod lists what this module requires; go.sum lists what was actually
  // resolved, including the transitive set. Only the latter answers "what am I
  // shipping".
  const dir = await tree({
    'go.mod': 'module example.com/m\n\ngo 1.19\n\nrequire github.com/gogo/protobuf v1.3.1\n',
    'go.sum': [
      'github.com/gogo/protobuf v1.3.1 h1:DqDEcV5aeaTmdFBePNpYsp3FlcVH/2ISVVM9Qf8=',
      'github.com/gogo/protobuf v1.3.1/go.mod h1:SlYgWuQ5SjCEi6WLHjHCa1yvBfUnHcTbrrZtXPKa29o=',
      'gopkg.in/yaml.v2 v2.2.8 h1:obN1ZagJSUGI0Ek/LBmuj4SNLPfIny3KsKFopxRdj10=',
      'gopkg.in/yaml.v2 v2.2.8/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=',
    ].join('\n') + '\n',
  });
  const { depFileContents } = await readTree(dir);
  assert.ok(depFileContents['go.sum'], 'go.sum must be admitted — _parseGoSum has always existed');

  const comps = parseManifests(depFileContents);
  const names = new Set(comps.map((c) => c.name));
  assert.ok(names.has('gopkg.in/yaml.v2'), 'a transitive module present only in go.sum must be enumerated');
  await fsp.rm(dir, { recursive: true, force: true });
});

test('requirements files are admitted and parsed under their real names', async () => {
  // All three shapes are ordinary in the wild. `requirements/dev.txt` is what
  // pallets/flask ships, and it scored 0 of 11 labelled vulnerabilities.
  const body = 'jinja2==2.11.3\nclick==8.0.0\n';
  const dir = await tree({
    'requirements.txt': 'requests==2.25.0\n',
    'requirements-dev.txt': 'certifi==2020.12.5\n',
    'requirements/dev.txt': body,
  });
  const { depFileContents } = await readTree(dir);
  assert.ok(depFileContents['requirements.txt']);
  assert.ok(depFileContents['requirements-dev.txt'], 'requirements-dev.txt must be admitted');
  assert.ok(depFileContents[path.join('requirements', 'dev.txt')], 'requirements/dev.txt must be admitted');

  const comps = parseManifests(depFileContents);
  const byName = new Map(comps.map((c) => [c.name, c.version]));
  assert.equal(byName.get('requests'), '2.25.0');
  assert.equal(byName.get('certifi'), '2020.12.5', 'requirements-dev.txt must reach a parser');
  assert.equal(byName.get('jinja2'), '2.11.3', 'requirements/dev.txt must reach a parser');
  assert.equal(byName.get('click'), '8.0.0');
  await fsp.rm(dir, { recursive: true, force: true });
});

test('a .txt that is not a requirements file is not treated as one', async () => {
  // The negative control. Widening admission by pattern is only safe if the
  // pattern is narrow — `notes.txt` reaching the PyPI parser would invent
  // components out of prose.
  const dir = await tree({
    'notes.txt': 'lodash==1.0.0 is what we should use\n',
    'docs/readme.txt': 'flask==2.0.0\n',
  });
  const { depFileContents } = await readTree(dir);
  assert.ok(!depFileContents['notes.txt'], 'an arbitrary .txt must not be admitted as a manifest');
  assert.ok(!depFileContents[path.join('docs', 'readme.txt')]);
  await fsp.rm(dir, { recursive: true, force: true });
});

test('an absurdly large manifest is still refused', async () => {
  // The dep cap is larger, not absent. Reading an unbounded file into memory
  // to parse it is how a scan becomes a denial of service against its own host.
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dep-admit-huge-'));
  const p = path.join(dir, 'package-lock.json');
  const chunk = Buffer.alloc(1024 * 1024, 0x20);
  const fd = fs.openSync(p, 'w');
  for (let i = 0; i < 11; i++) fs.writeSync(fd, chunk);   // 11 MB
  fs.closeSync(fd);
  const { depFileContents } = await readTree(dir);
  assert.ok(!depFileContents['package-lock.json'], 'an 11 MB manifest must still be refused');
  await fsp.rm(dir, { recursive: true, force: true });
});

// ─── Version fidelity: what reaches the advisory query ──────────────────────
//
// The other half of the Go recall problem, and it was in a place no lockfile
// test would look: both Go parsers truncated the version before anything could
// use it, and `queryOSV` truncated it again.
//
//   v0.0.0-20210903162142-ad29c8ab022f   →   0.0.0
//   v2.7.1+incompatible                  →   2.7.1
//
// A Go pseudo-version's leading `0.0.0` is a placeholder. Cutting the rest off
// does not shorten the version, it names a DIFFERENT and nonexistent one — and
// every pseudo-versioned module in a tree collapses onto the same key. The
// advisory database was being asked about releases that do not exist.
//
// It matters beyond matching: a component's recorded version is what lands in
// the emitted SBOM, and an SBOM that says `golang.org/x/net@0.0.0` is wrong in
// a document other people are supposed to rely on.

test('Go pseudo-versions and +incompatible builds survive parsing intact', async () => {
  const goMod = [
    'module example.com/m', '', 'go 1.19', '',
    'require (',
    '\tgolang.org/x/net v0.0.0-20210903162142-ad29c8ab022f',
    '\tgithub.com/docker/distribution v2.7.1+incompatible',
    '\tgopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect',
    ')', '',
  ].join('\n');
  const comps = parseManifests({ 'go.mod': goMod });
  const byName = new Map(comps.map((c) => [c.name, c.version]));
  assert.equal(byName.get('golang.org/x/net'), '0.0.0-20210903162142-ad29c8ab022f');
  assert.equal(byName.get('github.com/docker/distribution'), '2.7.1+incompatible');
  assert.equal(byName.get('gopkg.in/yaml.v3'), '3.0.0-20210107192922-496545a6307b');

  // Distinct pseudo-versions must stay distinct — the truncation collapsed
  // them all to `0.0.0`, so a whole tree became one component.
  const goSum = [
    'golang.org/x/net v0.0.0-20210903162142-ad29c8ab022f h1:AAA=',
    'golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 h1:BBB=',
  ].join('\n');
  const versions = new Set(parseManifests({ 'go.sum': goSum }).map((c) => c.version));
  assert.equal(versions.size, 2, 'two different pseudo-versions must not collapse to one');
});
