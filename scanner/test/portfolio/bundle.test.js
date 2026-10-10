// X-702: portable, content-addressed evidence bundle and its offline verifier. SYNTHETIC fixtures only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  exportBundle, verifyBundle, importBundle, checkLogicalName, findSecret, bundleDigestOf, INDEX_FILE, BLOB_DIR, BUNDLE_LIMITS,
} from '../../src/posture/portfolio/bundle.js';
import { digestOfBytes } from '../../src/posture/assurance/identity.js';
import { RECEIPTS, exportSynthetic, syntheticManifest } from './helpers.js';

const codes = (r) => r.errors.map((e) => e.code);
const blobOf = (dir, name) => {
  const idx = JSON.parse(fs.readFileSync(path.join(dir, INDEX_FILE), 'utf8'));
  const e = idx.entries.find((x) => x.name === name);
  return { e, file: path.join(dir, BLOB_DIR, e.digest.slice(7)), idx };
};

describe('[X-702.AC01] the bundle carries sanitized findings, provenance, replay manifests, toolchain identities and integrity metadata', () => {
  test('[X-702.AC01] every role is present, findings are reduced to the closed field set, and the verifier needs nothing but the directory', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    const out = exportSynthetic(dir);
    assert.match(out.bundleDigest, /^sha256:[0-9a-f]{64}$/);
    const v = verifyBundle(dir);
    assert.deepEqual(v.errors, []);
    assert.equal(v.ok, true);
    const roles = new Set(v.entries.map((e) => e.role));
    for (const r of ['manifest', 'findings', 'provenance', 'replay-manifest', 'toolchain', 'receipt']) assert.ok(roles.has(r), `role ${r}`);
    const f = JSON.parse(fs.readFileSync(blobOf(dir, 'findings.json').file, 'utf8'));
    assert.equal(f[0].id, 'F1');
    assert.equal('snippet' in f[0], false, 'source snippets stay behind');
    assert.equal(JSON.stringify(f).includes('SECRET-SOURCE-TEXT'), false);
    assert.equal(v.network, false);
  });

  test('[X-702.AC01] negative: a bundle with no provenance or toolchain role fails verification (MISSING_ROLE)', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const idxFile = path.join(dir, INDEX_FILE);
    const idx = JSON.parse(fs.readFileSync(idxFile, 'utf8'));
    idx.entries = idx.entries.filter((e) => e.role !== 'toolchain');
    fs.writeFileSync(idxFile, JSON.stringify(idx));
    assert.ok(codes(verifyBundle(dir)).includes('MISSING_ROLE'));
  });
});

describe('[X-702.AC02] the offline verifier validates evidence and states the prerequisites for optional runtime replay', () => {
  test('[X-702.AC02] replay prerequisites are disclosed, replay is not attempted, and the verifier source uses no network module', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const v = verifyBundle(dir);
    assert.equal(v.replay.attempted, false);
    const codesSeen = v.replay.prerequisites.map((p) => p.code);
    for (const c of ['source-at-commit', 'toolchain-identities', 'confinement-backend', 'node-runtime']) assert.ok(codesSeen.includes(c), c);
    assert.match(v.replay.prerequisites.find((p) => p.code === 'confinement-backend').statement, /unverified/);
    assert.match(v.replay.statement, /offline/);
    const src = fs.readFileSync(new URL('../../src/posture/portfolio/bundle.js', import.meta.url), 'utf8');
    assert.equal(/from 'node:(?:http|https|net|dgram|dns|tls|child_process)'|\bfetch\(/.test(src), false);
  });

  test('[X-702.AC02] a clean verifier run in a fresh process with the network module poisoned still verifies', async () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const { spawnSync } = await import('node:child_process');
    const code = `
      import net from 'node:net'; import http from 'node:http'; import https from 'node:https';
      for (const m of [net, http, https]) { for (const k of Object.keys(m)) { if (typeof m[k] === 'function' && /^(connect|request|get|createConnection)$/.test(k)) m[k] = () => { throw new Error('NETWORK USED'); }; } }
      const { verifyBundle } = await import(${JSON.stringify(new URL('../../src/posture/portfolio/bundle.js', import.meta.url).href)});
      const v = verifyBundle(${JSON.stringify(dir)});
      console.log(JSON.stringify({ ok: v.ok, network: v.network }));`;
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), { ok: true, network: false });
  });

  test('[X-702.AC02] negative: a manifest the index was not built for, and a manifest that fails validation, are each reported', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const { idx } = blobOf(dir, 'manifest.json');
    idx.manifestDigest = 'sha256:' + '0'.repeat(64);
    fs.writeFileSync(path.join(dir, INDEX_FILE), JSON.stringify(idx));
    const c = codes(verifyBundle(dir));
    assert.ok(c.includes('BUNDLE_DIGEST_MISMATCH') || c.includes('MANIFEST_MISMATCH'), c.join());
  });
});

describe('[X-702.AC03] export and import enforce size, path and secret limits; missing or modified artifacts fail integrity validation', () => {
  test('[X-702.AC03] a modified blob fails with DIGEST_MISMATCH and a missing blob with MISSING_BLOB', () => {
    const a = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(a);
    fs.appendFileSync(blobOf(a, 'findings.json').file, ' ');
    assert.ok(codes(verifyBundle(a)).includes('SIZE_MISMATCH') || codes(verifyBundle(a)).includes('DIGEST_MISMATCH'));
    const same = blobOf(a, 'provenance.json');
    fs.writeFileSync(same.file, Buffer.alloc(same.e.size, 0x20));
    assert.ok(codes(verifyBundle(a)).includes('DIGEST_MISMATCH'), 'same-size tamper');
    const b = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(b);
    fs.rmSync(blobOf(b, 'toolchain.json').file);
    assert.ok(codes(verifyBundle(b)).includes('MISSING_BLOB'));
    assert.equal(verifyBundle(b).ok, false);
  });

  test('[X-702.AC03] a receipt the manifest cites but the bundle lacks is MISSING_EVIDENCE, and importing a bad bundle writes nothing', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const idxFile = path.join(dir, INDEX_FILE);
    const idx = JSON.parse(fs.readFileSync(idxFile, 'utf8'));
    idx.entries = idx.entries.filter((e) => !(e.role === 'receipt' && e.name.includes('0001')));
    idx.bundleDigest = bundleDigestOf(idx); // re-seal, so only the missing evidence can be the reason
    fs.writeFileSync(idxFile, JSON.stringify(idx));
    assert.deepEqual(codes(verifyBundle(dir)), ['MISSING_EVIDENCE']);
    const dest = path.join(mkTestTmp('x702-'), 'out');
    const r = importBundle({ from: dir, to: dest });
    assert.equal(r.ok, false);
    assert.equal(fs.existsSync(dest), false);
  });

  test('[X-702.AC03] path limits: traversal, absolute, backslash and odd characters are rejected as logical names', () => {
    for (const bad of ['../x', '/etc/passwd', 'a/../b', 'a\\b', 'a b', '', 'a\0b', '.hidden/../x', 'x'.repeat(BUNDLE_LIMITS.maxNameLength + 1)]) assert.ok(checkLogicalName(bad), JSON.stringify(bad));
    for (const good of ['manifest.json', 'replay/rm-1.json', 'receipts/vrec_0001.json']) assert.equal(checkLogicalName(good), null);
  });

  test('[X-702.AC03] import: a tampered index with a traversal name is refused, a good bundle materializes under logical names, and an existing file is never overwritten', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const dest = path.join(mkTestTmp('x702-'), 'out');
    const ok = importBundle({ from: dir, to: dest });
    assert.equal(ok.ok, true);
    assert.ok(fs.existsSync(path.join(dest, 'manifest.json')));
    assert.ok(fs.existsSync(path.join(dest, 'replay', 'rm-1.json')));
    const again = importBundle({ from: dir, to: dest });
    assert.equal(again.ok, false);
    assert.equal(again.errors[0].code, 'DESTINATION_EXISTS');
    const evil = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(evil);
    const idx = JSON.parse(fs.readFileSync(path.join(evil, INDEX_FILE), 'utf8'));
    idx.entries[0].name = '../escape.json';
    fs.writeFileSync(path.join(evil, INDEX_FILE), JSON.stringify(idx));
    assert.ok(codes(verifyBundle(evil)).includes('BAD_ENTRY'));
    assert.equal(importBundle({ from: evil, to: path.join(mkTestTmp('x702-'), 'o2') }).ok, false);
  });

  test('[X-702.AC03] size limits: an oversized blob is refused at export and a symlinked blob is refused at verify', () => {
    const big = path.join(mkTestTmp('x702-'), 'b');
    assert.throws(() => exportSynthetic(big, { findings: [{ id: 'F', description: 'x'.repeat(10), file: 'a', line: 1 }], replayManifests: [{ id: 'huge', blob: Array.from({ length: 700 }, () => 'y'.repeat(8000)) }] }), /exceeds the \d+ byte limit/);
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir);
    const { file } = blobOf(dir, 'toolchain.json');
    const keep = fs.readFileSync(file);
    fs.rmSync(file);
    const target = path.join(path.dirname(dir), 'elsewhere.json');
    fs.writeFileSync(target, keep);
    fs.symlinkSync(target, file);
    assert.ok(codes(verifyBundle(dir)).includes('NOT_REGULAR'));
  });

  test('[X-702.AC03] secret filter: known secret shapes in findings are redacted at export; a secret in a field that cannot be redacted refuses the export; an injected secret blob is caught on verify', () => {
    const dir = path.join(mkTestTmp('x702-'), 'b');
    exportSynthetic(dir, { findings: [{ id: 'F2', severity: 'high', file: 'a.js', line: 1, vuln: 'v', cwe: 'CWE-798', description: 'key AKIAIOSFODNN7EXAMPLE and password = "hunter2hunter2" committed', family: 'secrets', parser: 'REGEX' }] });
    const f = fs.readFileSync(blobOf(dir, 'findings.json').file, 'utf8');
    assert.equal(findSecret(f), null);
    assert.ok(f.includes('[REDACTED-SECRET]'));
    assert.equal(f.includes('AKIAIOSFODNN7EXAMPLE'), false);
    // the manifest is signed content and is not rewritten: a secret in it refuses the export instead
    const dirty = syntheticManifest({ scope: { description: 'leaks ghp_abcdefghijklmnopqrstuvwxyz0123456789 here', mandatory: ['sast', 'invariants', 'replay'] } });
    assert.throws(() => exportSynthetic(path.join(mkTestTmp('x702-'), 'b'), { manifest: dirty }), /secret shape survived/);
    // a blob replaced AFTER export by one carrying a secret, with the index and bundle digest re-sealed to match, is still caught on verify
    const { e, file, idx } = blobOf(dir, 'toolchain.json');
    const evil = Buffer.from(JSON.stringify({ node: '24', token: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' }));
    const evilDigest = digestOfBytes(evil);
    fs.rmSync(file);
    fs.writeFileSync(path.join(dir, BLOB_DIR, evilDigest.slice(7)), evil);
    e.digest = evilDigest; e.size = evil.length;
    idx.entries = idx.entries.map((x) => (x.name === e.name ? e : x));
    idx.bundleDigest = bundleDigestOf(idx);
    fs.writeFileSync(path.join(dir, INDEX_FILE), JSON.stringify(idx));
    const v = verifyBundle(dir);
    assert.deepEqual(codes(v), ['SECRET_IN_BLOB']);
  });

  test('[X-702.AC03] exporting into a non-empty directory, with a receipt whose content differs from the bound digest, or without a cited receipt, is refused', () => {
    const dir = mkTestTmp('x702-');
    fs.writeFileSync(path.join(dir, 'stray'), 'x');
    assert.throws(() => exportSynthetic(dir), /non-empty directory/);
    const m = syntheticManifest();
    assert.throws(() => exportBundle({ outDir: path.join(mkTestTmp('x702-'), 'b'), manifest: m, provenance: {}, toolchain: {}, receipts: [{ id: RECEIPTS[0].id, content: { outcome: 'forged' } }, RECEIPTS[1]] }), /does not match the digest/);
    assert.throws(() => exportBundle({ outDir: path.join(mkTestTmp('x702-'), 'b'), manifest: m, provenance: {}, toolchain: {}, receipts: [RECEIPTS[0]] }), /was not supplied/);
  });
});
