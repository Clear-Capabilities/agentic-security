// Hermetic tests for the proof-corpus bench libraries. No network access.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectLicenceText, detectLicence } from '../../bench/proof-corpus/lib/licence.mjs';

function tmpRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'proofcorpus-'));
}

test('detectLicenceText: identifies permissive licences', () => {
  assert.equal(detectLicenceText('MIT License\n\nPermission is hereby granted, free of charge'), 'MIT');
  assert.equal(detectLicenceText('Apache License\nVersion 2.0, January 2004'), 'Apache-2.0');
});

test('detectLicenceText: identifies copyleft and network-copyleft licences', () => {
  assert.equal(detectLicenceText('GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991'), 'GPL-2.0');
  assert.equal(detectLicenceText('GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007'), 'GPL-3.0');
  assert.equal(detectLicenceText('GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007'), 'AGPL-3.0');
});

test('detectLicenceText: identifies source-available licences', () => {
  assert.equal(detectLicenceText('Business Source License 1.1\n\nParameters'), 'BUSL-1.1');
  assert.equal(detectLicenceText('Functional Source License, Version 1.1, ALv2 Future License'), 'FSL-1.1');
});

test('detectLicenceText: identifies LGPL licences', () => {
  assert.equal(detectLicenceText('GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007'), 'LGPL-3.0');
  assert.equal(detectLicenceText('GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999'), 'LGPL-2.1');
});

test('detectLicenceText: distinguishes BSD-3-Clause from BSD-2-Clause', () => {
  const bsd3 = 'Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. Redistributions of source code must retain the above copyright notice. 2. Redistributions in binary form must reproduce the above copyright notice. 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.';
  assert.equal(detectLicenceText(bsd3), 'BSD-3-Clause');
  const bsd2 = 'Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. Redistributions of source code must retain the above copyright notice. 2. Redistributions in binary form must reproduce the above copyright notice.';
  assert.equal(detectLicenceText(bsd2), 'BSD-2-Clause');
});

test('detectLicenceText: identifies ISC licence', () => {
  assert.equal(detectLicenceText('ISC License\n\nPermission to use, copy, modify, and/or distribute this software'), 'ISC');
});

test('detectLicenceText: identifies MPL-2.0', () => {
  assert.equal(detectLicenceText('Mozilla Public License Version 2.0\n\n1. Definitions'), 'MPL-2.0');
});

test('detectLicenceText: returns null on unrecognised or empty text', () => {
  assert.equal(detectLicenceText('This is a readme about cats.'), null);
  assert.equal(detectLicenceText(''), null);
  assert.equal(detectLicenceText(null), null);
});

test('detectLicence: reads a LICENSE file from the repo root', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT License\n\nPermission is hereby granted, free of charge');
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'MIT');
  assert.equal(r.source, 'file');
  assert.equal(r.file, 'LICENSE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: falls back to the package.json license field', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ license: 'AGPL-3.0' }));
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'AGPL-3.0');
  assert.equal(r.source, 'package-json');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: a LICENSE file wins over package.json', () => {
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'COPYING'), 'GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ license: 'MIT' }));
  const r = detectLicence(dir);
  assert.equal(r.spdx, 'GPL-2.0');
  assert.equal(r.source, 'file');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectLicence: reports none for a repo with no licence and never throws', () => {
  const dir = tmpRepo();
  const r = detectLicence(dir);
  assert.equal(r.spdx, null);
  assert.equal(r.source, 'none');
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(detectLicence('/nonexistent/path/xyz').source, 'none');
});

import { cacheRoot, repoDir, currentCommit, ensureClone } from '../../bench/proof-corpus/lib/clone.mjs';

test('cacheRoot: honours the env override', () => {
  const prev = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  try {
    process.env.AGENTIC_SECURITY_PROOF_CACHE = '/tmp/custom-cache';
    assert.equal(cacheRoot(), '/tmp/custom-cache');
    delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    assert.ok(cacheRoot().endsWith(path.join('.claude', 'agentic-security', 'proof-corpus-cache')));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    else process.env.AGENTIC_SECURITY_PROOF_CACHE = prev;
  }
});

test('repoDir: places each target in its own directory under the cache root', () => {
  const prev = process.env.AGENTIC_SECURITY_PROOF_CACHE;
  try {
    process.env.AGENTIC_SECURITY_PROOF_CACHE = '/tmp/custom-cache';
    assert.equal(repoDir('ghost'), path.join('/tmp/custom-cache', 'ghost'));
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_PROOF_CACHE;
    else process.env.AGENTIC_SECURITY_PROOF_CACHE = prev;
  }
});

test('repoDir: rejects ids that would escape the cache root', () => {
  assert.throws(() => repoDir('../escape'), /invalid target id/i);
  assert.throws(() => repoDir('a/b'), /invalid target id/i);
  assert.throws(() => repoDir(''), /invalid target id/i);
});

test('currentCommit: returns null for a directory that is not a git repo', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'notgit-'));
  assert.equal(currentCommit(dir), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ensureClone: refuses an unpinned target and names the fix', () => {
  assert.throws(
    () => ensureClone({ id: 'ghost', url: 'https://example.invalid/x.git', commit: null }),
    /--refresh-pins/,
  );
});
