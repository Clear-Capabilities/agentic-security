// SCA deprecated-component detection — unit tests for queryRegistries PyPI path.
//
// The engine uses globalThis.fetch; we replace it before import so every call
// in queryRegistries routes through the stub.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Stub fetch before the engine module loads.
const STUBS = new Map();
globalThis.fetch = async (url) => {
  for (const [pattern, payload] of STUBS) {
    if (url.includes(pattern)) {
      return { ok: true, json: async () => payload };
    }
  }
  return { ok: false, status: 404, json: async () => ({}) };
};

// These tests exercise the registry-metadata lookup itself, so they run ONLINE with `fetch` stubbed above: only queryRegistries is called
// (never the OSV, KEV or EPSS paths), so nothing else can fire. They used to set OFFLINE to keep those quiet, which only worked because the
// registry lookups ignored offline mode; they no longer do (see test/haskell/haskell-live-feed-scan.test.js, which pins that offline mode
// makes no registry request and that online it still does).
delete process.env.AGENTIC_SECURITY_OFFLINE;

const { queryRegistries } = await import('../src/engine.js');

const pypiComp = (name, version) => ({ ecosystem: 'pypi', name, version, filePath: 'requirements.txt' });
const npmComp  = (name, version) => ({ ecosystem: 'npm',  name, version, filePath: 'package.json' });

// ── PyPI: yanked release ──────────────────────────────────────────────────────
test('PyPI yanked release is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('pypi.org/pypi/yanked-pkg/json', {
    info: { version: '2.0.0', license: 'MIT', classifiers: [], description: '' },
    releases: {
      '1.0.0': [{ yanked: true, yanked_reason: 'Critical security flaw' }],
      '2.0.0': [{ yanked: false }],
    },
  });

  const map = await queryRegistries([pypiComp('yanked-pkg', '1.0.0')]);
  const info = map.get('pypi:yanked-pkg');
  assert.ok(info, 'registry entry created');
  assert.equal(info.versions['1.0.0']?.deprecated, 'Critical security flaw');
  assert.equal(info.versions['2.0.0']?.deprecated, undefined, 'non-yanked version not deprecated');
});

// ── PyPI: yanked with no reason text ─────────────────────────────────────────
test('PyPI yanked release with no reason uses fallback message', async () => {
  STUBS.clear();
  STUBS.set('pypi.org/pypi/no-reason/json', {
    info: { version: '1.0.0', license: '', classifiers: [], description: '' },
    releases: { '1.0.0': [{ yanked: true, yanked_reason: '' }] },
  });

  const map = await queryRegistries([pypiComp('no-reason', '1.0.0')]);
  const dep = map.get('pypi:no-reason').versions['1.0.0']?.deprecated;
  assert.ok(dep && dep.length > 0, 'fallback deprecation message set');
});

// ── PyPI: inactive Development Status classifier ──────────────────────────────
test('PyPI inactive-classifier package marks all versions deprecated', async () => {
  STUBS.clear();
  STUBS.set('pypi.org/pypi/inactive-pkg/json', {
    info: {
      version: '3.0.0', license: 'MIT',
      classifiers: ['Development Status :: 7 - Inactive'],
      description: 'Old package',
    },
    releases: { '1.0.0': [{}], '2.0.0': [{}], '3.0.0': [{}] },
  });

  const map = await queryRegistries([pypiComp('inactive-pkg', '1.0.0')]);
  const info = map.get('pypi:inactive-pkg');
  assert.ok(info.versions['1.0.0']?.deprecated, 'v1 deprecated via classifier');
  assert.ok(info.versions['2.0.0']?.deprecated, 'v2 deprecated via classifier');
  assert.ok(info.versions['3.0.0']?.deprecated, 'v3 deprecated via classifier');
});

// ── PyPI: description-prefix deprecation ──────────────────────────────────────
test('PyPI package with deprecated description prefix is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('pypi.org/pypi/desc-dep/json', {
    info: {
      version: '0.9.0', license: 'BSD',
      classifiers: [],
      description: 'DEPRECATED: use newpkg instead',
    },
    releases: { '0.9.0': [{}] },
  });

  const map = await queryRegistries([pypiComp('desc-dep', '0.9.0')]);
  const dep = map.get('pypi:desc-dep').versions['0.9.0']?.deprecated;
  assert.ok(dep, 'deprecated via description prefix');
});

// ── PyPI: normal active package not flagged ───────────────────────────────────
test('PyPI active package is not marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('pypi.org/pypi/active-pkg/json', {
    info: {
      version: '5.0.0', license: 'MIT',
      classifiers: ['Development Status :: 5 - Production/Stable'],
      description: 'A fine library',
    },
    releases: { '5.0.0': [{ yanked: false }] },
  });

  const map = await queryRegistries([pypiComp('active-pkg', '5.0.0')]);
  const info = map.get('pypi:active-pkg');
  assert.equal(info.versions['5.0.0']?.deprecated, undefined);
});

// ── Packagist: abandoned with replacement ─────────────────────────────────────
test('Packagist abandoned package with replacement is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('packagist.org/packages/vendor/old-pkg.json', {
    package: {
      abandoned: 'vendor/new-pkg',
      versions: { '1.0.0': {}, '2.0.0': {} },
    },
  });

  const map = await queryRegistries([{ ecosystem: 'packagist', name: 'vendor/old-pkg', version: '1.0.0', filePath: 'composer.json' }]);
  const info = map.get('packagist:vendor/old-pkg');
  assert.ok(info.versions['1.0.0']?.deprecated?.includes('vendor/new-pkg'), 'replacement referenced in message');
  assert.ok(info.versions['2.0.0']?.deprecated, 'all versions marked');
});

test('Packagist abandoned package without replacement is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('packagist.org/packages/vendor/dead-pkg.json', {
    package: { abandoned: true, versions: { '1.0.0': {} } },
  });

  const map = await queryRegistries([{ ecosystem: 'packagist', name: 'vendor/dead-pkg', version: '1.0.0', filePath: 'composer.json' }]);
  assert.ok(map.get('packagist:vendor/dead-pkg').versions['1.0.0']?.deprecated);
});

test('Packagist active package is not deprecated', async () => {
  STUBS.clear();
  STUBS.set('packagist.org/packages/vendor/active.json', {
    package: { abandoned: false, versions: { '3.0.0': {} } },
  });

  const map = await queryRegistries([{ ecosystem: 'packagist', name: 'vendor/active', version: '3.0.0', filePath: 'composer.json' }]);
  assert.equal(map.get('packagist:vendor/active').versions['3.0.0']?.deprecated, undefined);
});

// ── crates.io: yanked version ─────────────────────────────────────────────────
test('crates.io yanked version is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('crates.io/api/v1/crates/bad-crate', {
    crate: { newest_version: '2.0.0' },
    versions: [
      { num: '1.0.0', yanked: true },
      { num: '2.0.0', yanked: false },
    ],
  });

  const map = await queryRegistries([{ ecosystem: 'cargo', name: 'bad-crate', version: '1.0.0', filePath: 'Cargo.toml' }]);
  const info = map.get('cargo:bad-crate');
  assert.ok(info.versions['1.0.0']?.deprecated, 'yanked version deprecated');
  assert.equal(info.versions['2.0.0']?.deprecated, undefined, 'current version not deprecated');
  assert.equal(info.latestVersion, '2.0.0');
});

test('crates.io non-yanked crate is not deprecated', async () => {
  STUBS.clear();
  STUBS.set('crates.io/api/v1/crates/good-crate', {
    crate: { newest_version: '1.0.0' },
    versions: [{ num: '1.0.0', yanked: false }],
  });

  const map = await queryRegistries([{ ecosystem: 'cargo', name: 'good-crate', version: '1.0.0', filePath: 'Cargo.toml' }]);
  assert.equal(map.get('cargo:good-crate').versions['1.0.0']?.deprecated, undefined);
});

// ── RubyGems: yanked version ──────────────────────────────────────────────────
test('RubyGems yanked version is marked deprecated', async () => {
  STUBS.clear();
  STUBS.set('rubygems.org/api/v1/versions/bad-gem.json', [
    { number: '0.9.0', yanked: true, prerelease: false },
    { number: '1.0.0', yanked: false, prerelease: false },
  ]);

  const map = await queryRegistries([{ ecosystem: 'rubygems', name: 'bad-gem', version: '0.9.0', filePath: 'Gemfile' }]);
  const info = map.get('rubygems:bad-gem');
  assert.ok(info.versions['0.9.0']?.deprecated, 'yanked version deprecated');
  assert.equal(info.versions['1.0.0']?.deprecated, undefined);
  assert.equal(info.latestVersion, '1.0.0', 'latest is the first non-yanked non-prerelease');
});

// ── pub.dev: discontinued package ────────────────────────────────────────────
test('pub.dev discontinued package marks all versions deprecated', async () => {
  STUBS.clear();
  STUBS.set('pub.dev/api/packages/old-flutter-pkg', {
    isDiscontinued: true,
    replacedBy: 'new-flutter-pkg',
    latest: { version: '1.2.0' },
    versions: [{ version: '1.0.0' }, { version: '1.2.0' }],
  });

  const map = await queryRegistries([{ ecosystem: 'pub', name: 'old-flutter-pkg', version: '1.0.0', filePath: 'pubspec.yaml' }]);
  const info = map.get('pub:old-flutter-pkg');
  assert.ok(info.versions['1.0.0']?.deprecated?.includes('new-flutter-pkg'), 'replacement in message');
  assert.ok(info.versions['1.2.0']?.deprecated, 'all versions marked');
});

test('pub.dev discontinued without replacedBy uses generic message', async () => {
  STUBS.clear();
  STUBS.set('pub.dev/api/packages/gone-pkg', {
    isDiscontinued: true,
    replacedBy: null,
    latest: { version: '1.0.0' },
    versions: [{ version: '1.0.0' }],
  });

  const map = await queryRegistries([{ ecosystem: 'pub', name: 'gone-pkg', version: '1.0.0', filePath: 'pubspec.yaml' }]);
  assert.ok(map.get('pub:gone-pkg').versions['1.0.0']?.deprecated);
});

test('pub.dev active package is not deprecated', async () => {
  STUBS.clear();
  STUBS.set('pub.dev/api/packages/active-pkg', {
    isDiscontinued: false,
    replacedBy: null,
    latest: { version: '2.0.0' },
    versions: [{ version: '2.0.0' }],
  });

  const map = await queryRegistries([{ ecosystem: 'pub', name: 'active-pkg', version: '2.0.0', filePath: 'pubspec.yaml' }]);
  assert.equal(map.get('pub:active-pkg').versions['2.0.0']?.deprecated, undefined);
});

// ── Maven Central: outdated version ──────────────────────────────────────────
test('Maven component behind latest is flagged as outdated', async () => {
  STUBS.clear();
  STUBS.set('search.maven.org/solrsearch/select', {
    response: { docs: [{ latestVersion: '6.1.6', g: 'org.springframework', a: 'spring-core' }] },
  });

  const map = await queryRegistries([{
    ecosystem: 'maven', name: 'spring-core', group: 'org.springframework',
    version: '5.3.39', filePath: 'pom.xml',
  }]);
  const info = map.get('maven:org.springframework/spring-core');
  assert.ok(info, 'registry entry created');
  assert.equal(info.latestVersion, '6.1.6');
  const vd = info.versions['5.3.39'];
  assert.ok(vd?.outdated, 'installed version marked outdated');
  assert.ok(vd.outdated.includes('6.1.6'), 'latest version in message');
  assert.ok(vd.outdated.includes('mvn versions:use-latest-versions'), 'fix command in message');
});

test('Maven component already at latest is not flagged', async () => {
  STUBS.clear();
  STUBS.set('search.maven.org/solrsearch/select', {
    response: { docs: [{ latestVersion: '6.1.6', g: 'org.springframework', a: 'spring-core' }] },
  });

  const map = await queryRegistries([{
    ecosystem: 'maven', name: 'spring-core', group: 'org.springframework',
    version: '6.1.6', filePath: 'pom.xml',
  }]);
  const info = map.get('maven:org.springframework/spring-core');
  assert.equal(info.versions['6.1.6']?.outdated, undefined, 'current version not flagged');
});

test('Maven component with unknown latest (empty docs) is not flagged', async () => {
  STUBS.clear();
  STUBS.set('search.maven.org/solrsearch/select', {
    response: { docs: [] },
  });

  const map = await queryRegistries([{
    ecosystem: 'maven', name: 'internal-lib', group: 'com.example',
    version: '1.0.0', filePath: 'pom.xml',
  }]);
  assert.ok(!map.get('maven:com.example/internal-lib'), 'no entry for unknown artifact');
});

// ── npm: deprecated version still detected (regression guard) ─────────────────
test('npm deprecated version is detected', async () => {
  STUBS.clear();
  STUBS.set('registry.npmjs.org/bad-pkg', {
    'dist-tags': { latest: '2.0.0' },
    license: 'MIT',
    versions: {
      '1.0.0': { deprecated: 'Use good-pkg instead' },
      '2.0.0': {},
    },
  });

  const map = await queryRegistries([npmComp('bad-pkg', '1.0.0')]);
  const info = map.get('npm:bad-pkg');
  assert.equal(info.versions['1.0.0'].deprecated, 'Use good-pkg instead');
  assert.equal(info.versions['2.0.0']?.deprecated, undefined, 'current version not deprecated');
});
