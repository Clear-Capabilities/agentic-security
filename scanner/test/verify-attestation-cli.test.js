// `agentic-security verify-attestation` — dual-artifact dispatch.
//
// attestation.js ships two independent verifiers: verifyEvidenceBundle
// (per-finding, Ed25519, self-contained) and verifyRunAttestation
// (whole-run, per-install HMAC, needs a fresh scan to re-derive against).
// This CLI command only ever called the first — verifyRunAttestation had
// zero production callers anywhere in the repo. Fixed by auto-detecting
// which artifact was handed in (a bare run-attestation object, or a full
// last-scan.json carrying one under `.attestation`) and dispatching to a
// real re-scan-and-compare verification for that case.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'verify-att-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"verify-att-fixture"}');
  await fsp.writeFile(path.join(dir, 'app.js'), 'export function add(a, b) { return a + b; }\n');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('verify-attestation: a fresh scan reproduces its own attested digest (round-trip)', async () => {
  const p = await mkProject();
  try {
    const scanRun = spawnSync(process.execPath, [CLI, 'scan', p.dir, '--format', 'json'], { encoding: 'utf8' });
    assert.equal(scanRun.status, 0, `scan failed: ${scanRun.stderr}`);
    const lastScanPath = path.join(p.dir, '.agentic-security', 'last-scan.json');
    assert.ok(fs.existsSync(lastScanPath), 'expected last-scan.json to be written');
    const scan = JSON.parse(fs.readFileSync(lastScanPath, 'utf8'));
    assert.ok(scan.attestation && scan.attestation.digest, 'expected the scan to carry a run attestation');

    const verify = spawnSync(process.execPath, [CLI, 'verify-attestation', lastScanPath, '--against', p.dir], { encoding: 'utf8' });
    assert.equal(verify.status, 0, `expected exit 0; stdout=${verify.stdout} stderr=${verify.stderr}`);
    assert.match(verify.stdout, /VALID/);
    assert.match(verify.stdout, /reproduces the attested digest/);
  } finally { await p.cleanup(); }
});

test('verify-attestation: a tampered digest is rejected (exit 1)', async () => {
  const p = await mkProject();
  try {
    const scanRun = spawnSync(process.execPath, [CLI, 'scan', p.dir, '--format', 'json'], { encoding: 'utf8' });
    assert.equal(scanRun.status, 0, `scan failed: ${scanRun.stderr}`);
    const lastScanPath = path.join(p.dir, '.agentic-security', 'last-scan.json');
    const scan = JSON.parse(fs.readFileSync(lastScanPath, 'utf8'));
    scan.attestation.digest = scan.attestation.digest.replace(/^./, scan.attestation.digest[0] === 'a' ? 'b' : 'a');
    const tamperedPath = path.join(p.dir, 'tampered-attestation.json');
    fs.writeFileSync(tamperedPath, JSON.stringify(scan));

    const verify = spawnSync(process.execPath, [CLI, 'verify-attestation', tamperedPath, '--against', p.dir], { encoding: 'utf8' });
    assert.equal(verify.status, 1, `expected exit 1; stdout=${verify.stdout} stderr=${verify.stderr}`);
    assert.match(verify.stderr, /INVALID/);
  } finally { await p.cleanup(); }
});

test('verify-attestation: a bare attestation object (not a full scan) is also recognized', async () => {
  const p = await mkProject();
  try {
    const scanRun = spawnSync(process.execPath, [CLI, 'scan', p.dir, '--format', 'json'], { encoding: 'utf8' });
    assert.equal(scanRun.status, 0, `scan failed: ${scanRun.stderr}`);
    const scan = JSON.parse(fs.readFileSync(path.join(p.dir, '.agentic-security', 'last-scan.json'), 'utf8'));
    const barePath = path.join(p.dir, 'bare-attestation.json');
    fs.writeFileSync(barePath, JSON.stringify(scan.attestation));

    const verify = spawnSync(process.execPath, [CLI, 'verify-attestation', barePath, '--against', p.dir], { encoding: 'utf8' });
    assert.equal(verify.status, 0, `expected exit 0; stdout=${verify.stdout} stderr=${verify.stderr}`);
    assert.match(verify.stdout, /VALID/);
  } finally { await p.cleanup(); }
});

test('verify-attestation: an evidence bundle still routes to the original per-finding verifier (unchanged)', async () => {
  const p = await mkProject();
  try {
    // A bundle-shaped object (has neither .digest nor .attestation.digest)
    // must NOT be misrouted into the run-attestation path.
    const bundlePath = path.join(p.dir, 'not-an-attestation.json');
    fs.writeFileSync(bundlePath, JSON.stringify({ finding: { vuln: 'X' }, signature: 'deadbeef', evidence: {} }));
    const verify = spawnSync(process.execPath, [CLI, 'verify-attestation', bundlePath], { encoding: 'utf8' });
    // Falls through to the evidence-bundle verifier, which fails on this
    // synthetic input (no real signature/public key) — the point is it
    // takes the BUNDLE path, not the run-attestation path (which would
    // instead complain about a missing --against re-scan target or attempt
    // a scan). A stderr mentioning the public key / signature confirms it.
    assert.notEqual(verify.status, 0);
    assert.doesNotMatch(verify.stdout + verify.stderr, /Re-scanning/);
  } finally { await p.cleanup(); }
});
