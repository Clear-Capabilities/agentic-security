// R8 — container-image OS-package inventory tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDpkgStatus, parseApkInstalled, extractImagePackages } from '../src/sca/image-packages.js';

const DPKG = `Package: bash
Status: install ok installed
Version: 5.1-2ubuntu3

Package: libc6
Status: install ok installed
Version: 2.35-0ubuntu3

Package: oldpkg
Status: deinstall ok config-files
Version: 1.0`;

const APK = `P:musl
V:1.2.4-r2
A:x86_64

P:busybox
V:1.36.1-r5`;

test('parseDpkgStatus: installed packages only, name+version', () => {
  const p = parseDpkgStatus(DPKG);
  assert.equal(p.length, 2, 'deinstalled package excluded');
  assert.deepEqual(p[0], { name: 'bash', version: '5.1-2ubuntu3', ecosystem: 'Debian' });
  assert.ok(p.some(x => x.name === 'libc6' && x.version === '2.35-0ubuntu3'));
});

test('parseApkInstalled: P:/V: blocks', () => {
  const p = parseApkInstalled(APK);
  assert.equal(p.length, 2);
  assert.deepEqual(p[0], { name: 'musl', version: '1.2.4-r2', ecosystem: 'Alpine' });
});

test('extractImagePackages: matches image DB paths, emits components with purls', () => {
  const comps = extractImagePackages({
    'rootfs/var/lib/dpkg/status': DPKG,
    'rootfs/lib/apk/db/installed': APK,
    'src/app.js': 'console.log(1)', // ignored
  });
  assert.equal(comps.length, 4);
  const bash = comps.find(c => c.name === 'bash');
  assert.equal(bash.ecosystem, 'Debian');
  assert.equal(bash.purl, 'pkg:deb/debian/bash@5.1-2ubuntu3');
  assert.equal(bash.isOsPackage, true);
  assert.ok(comps.find(c => c.name === 'musl').purl.startsWith('pkg:apk/alpine/'));
});

test('extractImagePackages: no image DBs → no components', () => {
  assert.equal(extractImagePackages({ 'package.json': '{}' }).length, 0);
});
