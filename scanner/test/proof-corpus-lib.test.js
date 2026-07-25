// Hermetic tests for the proof-corpus bench libraries. No network access.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { detectLicenceText, detectLicence } from '../../bench/proof-corpus/lib/licence.mjs';
import { bundlePath, verifyBundle, runRepoScan, _verifyBundleAt } from '../../bench/proof-corpus/lib/scan.mjs';

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

import { readIrStats, coverageSummary } from '../../bench/proof-corpus/lib/irstats.mjs';

test('readIrStats: returns null for a missing or malformed file', () => {
  assert.equal(readIrStats('/nonexistent/stats.json'), null);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irread-'));
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, '{not json');
  assert.equal(readIrStats(bad), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('readIrStats: round-trips a written sidecar', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irread-'));
  const f = path.join(dir, 'stats.json');
  fs.writeFileSync(f, JSON.stringify({ languages: { go: { inScope: 3, parsed: 2, functions: 9, failures: [] } } }));
  const s = readIrStats(f);
  assert.equal(s.languages.go.parsed, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('coverageSummary: computes rounded percentages per language', () => {
  const stats = {
    languages: {
      javascript: { inScope: 10, parsed: 9, functions: 40, failures: [] },
      cpp: { inScope: 500, parsed: 0, functions: 0, failures: [] },
    },
    callGraph: { functions: 12, edges: 30, resolvedEdges: 20, unresolvedEdges: 10 },
    totals: { inScope: 510, parsed: 9, functions: 40 },
  };
  const s = coverageSummary(stats);
  assert.equal(s.byLanguage.javascript.pct, 90);
  assert.equal(s.byLanguage.cpp.pct, 0, 'a supported-on-paper language at 0% must read as 0, not null');
  assert.equal(s.totals.pct, 2);
  assert.equal(s.callGraph.resolvedEdges, 20);
});

test('coverageSummary: pct is null when a language has no files in scope', () => {
  const s = coverageSummary({ languages: { ruby: { inScope: 0, parsed: 0, functions: 0, failures: [] } } });
  assert.equal(s.byLanguage.ruby.pct, null);
});

test('coverageSummary: tolerates null input', () => {
  const s = coverageSummary(null);
  assert.deepEqual(s.byLanguage, {});
  assert.equal(s.totals.pct, null);
  assert.equal(s.callGraph.functions, 0);
});

test('bundlePath: points at the committed bundle', () => {
  assert.ok(bundlePath().endsWith(path.join('scanner', 'dist', 'agentic-security.mjs')));
});

test('verifyBundle: the committed bundle matches its sha256 sidecar', () => {
  const r = verifyBundle();
  assert.equal(r.ok, true, `bundle verification failed: ${r.reason} — run "npm run build"`);
  assert.match(r.sha, /^[0-9a-f]{64}$/);
});

test('_verifyBundleAt: detects a corrupted sidecar against a copied bundle', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proofbundle-'));
  const bundle = path.join(dir, 'agentic-security.mjs');
  fs.copyFileSync(bundlePath(), bundle);
  fs.copyFileSync(bundlePath() + '.sha256', bundle + '.sha256');

  // Sanity check: the untouched copy must verify clean before we corrupt it.
  const clean = _verifyBundleAt(bundle);
  assert.equal(clean.ok, true);

  // Corrupt the sidecar (flip its recorded hash) and confirm detection.
  fs.writeFileSync(bundle + '.sha256', '0'.repeat(64) + '  agentic-security.mjs\n');
  const corrupted = _verifyBundleAt(bundle);
  assert.equal(corrupted.ok, false);
  assert.match(corrupted.reason, /npm run build/, 'reason must point at the fix (rebuilding)');
  assert.match(corrupted.sha, /^[0-9a-f]{64}$/, 'still reports the actual sha it computed');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('runRepoScan: scans a fixture, emits SARIF, and reports metrics', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'proofscan-'));
  const statsPath = path.join(out, 'stats.json');
  const sarifPath = path.join(out, 'run.sarif');
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const r = await runRepoScan({ dir: fixture, statsPath, sarifPath, timeoutMs: 180_000 });
  assert.equal(r.timedOut, false);
  assert.ok(typeof r.exitCode === 'number');
  // Exit 4 is the lockfile-verification refusal. Seeing it here means someone
  // reintroduced --deterministic, which never scans on an unlocked tree.
  assert.notEqual(r.exitCode, 4, `scan refused before running: ${r.stderrTail}`);
  assert.ok(r.wallMs > 0);
  assert.ok(fs.existsSync(statsPath), 'the scan must produce the IR-stats sidecar');
  const stats = JSON.parse(fs.readFileSync(statsPath, 'utf8'));
  assert.ok(stats.languages.javascript.parsed >= 1);
  const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
  assert.ok(Array.isArray(sarif.runs), 'SARIF must be captured whole from stdout');
  fs.rmSync(out, { recursive: true, force: true });
});

test('runRepoScan: produces byte-identical SARIF across two runs', async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'proofdet-'));
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const a = path.join(out, 'a.sarif');
  const b = path.join(out, 'b.sarif');
  await runRepoScan({ dir: fixture, sarifPath: a, timeoutMs: 180_000 });
  await runRepoScan({ dir: fixture, sarifPath: b, timeoutMs: 180_000 });
  assert.equal(fs.readFileSync(a, 'utf8'), fs.readFileSync(b, 'utf8'));
  fs.rmSync(out, { recursive: true, force: true });
});

test('runRepoScan: reports a timeout rather than hanging', async () => {
  const fixture = path.resolve('test/fixtures/vulnerable-js');
  const r = await runRepoScan({ dir: fixture, timeoutMs: 1 });
  assert.equal(r.timedOut, true);
});

test('manifest: is valid, complete, and internally consistent', () => {
  const manifestPath = path.resolve('../bench/proof-corpus/manifest.json');
  const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(m.targets.length, 10, 'the corpus is ten targets');

  const ids = m.targets.map(t => t.id);
  assert.equal(new Set(ids).size, 10, 'target ids are unique');

  for (const t of m.targets) {
    assert.match(t.id, /^[a-z0-9][a-z0-9._-]*$/, `${t.id}: id must be cache-path safe`);
    assert.match(t.url, /^https:\/\/github\.com\/.+\.git$/, `${t.id}: url must be an https git url`);
    assert.ok(typeof t.ref === 'string' && t.ref.length > 0, `${t.id}: ref required`);
    assert.ok(t.commit === null || /^[0-9a-f]{40}$/.test(t.commit), `${t.id}: commit must be null or a full SHA`);
    assert.ok(['breadth', 'deep'].includes(t.tier), `${t.id}: tier must be breadth or deep`);
    assert.ok(Array.isArray(t.expectedLanguages) && t.expectedLanguages.length > 0, `${t.id}: expectedLanguages required`);
    assert.ok(Number.isInteger(t.timeBudgetS) && t.timeBudgetS > 0, `${t.id}: timeBudgetS required`);
    assert.ok(t.scope === null || Array.isArray(t.scope), `${t.id}: scope must be null or an array`);
  }

  const deep = m.targets.filter(t => t.tier === 'deep').map(t => t.id).sort();
  assert.deepEqual(deep, ['discourse', 'grafana', 'jenkins', 'superset'], 'Tier-1 set matches the PRD');
});
