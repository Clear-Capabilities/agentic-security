#!/usr/bin/env node
// Release gate: the release-assurance path works end to end, in both directions, over a project the repository ships.
//
//   scan examples/assurance-demo -> release-package build (ephemeral key) -> the independent offline verifier accepts it
//   a package with one finding's severity lowered      -> the verifier rejects it
//   a package whose stated verdict was changed         -> the verifier rejects it
//   a scan whose signature is gone                     -> build refuses to use it
//
// It uses the same `scripts/verify-release-package.mjs` a consumer would run, not the library the producer uses, so a defect in the producer
// cannot make the check agree with it. Nothing is written inside the repository; the project is copied to a temp directory first.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(REPO, 'scanner', 'bin', 'agentic-security.js');
const VERIFIER = path.join(REPO, 'scripts', 'verify-release-package.mjs');
const problems = [];
const expect = (cond, msg) => { if (!cond) problems.push(msg); };
const node = (file, args, cwd) => spawnSync(process.execPath, [file, ...args], { cwd, encoding: 'utf8', timeout: 300000, env: { ...process.env, NO_COLOR: '1' } });

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-assurance-'));
try {
  fs.cpSync(path.join(REPO, 'examples', 'assurance-demo'), dir, { recursive: true });
  const scan = node(CLI, ['scan', '.', '--format', 'json'], dir);
  expect([0, 1, 2, 3, 4].includes(scan.status) && fs.existsSync(path.join(dir, '.agentic-security', 'last-scan.json')), `the scan did not produce a last-scan.json (exit ${scan.status})`);

  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(dir, 'k.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const build = node(CLI, ['release-package', 'build', '.', '--private-key', 'k.pem', '--public-key-out', 'pub.pem', '--output', 'pkg.json'], dir);
  expect(build.status === 0, `release-package build exited ${build.status}: ${build.stderr.trim().slice(0, 300)}`);

  if (fs.existsSync(path.join(dir, 'pkg.json'))) {
    const ok = node(VERIFIER, ['pkg.json', '--public-key', 'pub.pem'], dir);
    expect(ok.status === 0, `the offline verifier rejected the package it was given (exit ${ok.status}): ${ok.stderr.trim().slice(0, 300)}`);
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'pkg.json'), 'utf8'));

    const lowered = structuredClone(pkg);
    const f = lowered.evidence.find(e => e.ref.kind === 'finding' && e.payload.severity !== 'info');
    f.payload.severity = 'info';
    fs.writeFileSync(path.join(dir, 'lowered.json'), JSON.stringify(lowered));
    expect(node(VERIFIER, ['lowered.json', '--public-key', 'pub.pem'], dir).status === 1, 'a package with a finding\'s severity lowered was accepted');

    const restated = structuredClone(pkg);
    const d = restated.policy.decisions.find(x => x.id === 'release-verdict');
    d.outcome = d.outcome === 'deployable' ? 'not_deployable' : 'deployable';
    fs.writeFileSync(path.join(dir, 'restated.json'), JSON.stringify(restated));
    expect(node(VERIFIER, ['restated.json', '--public-key', 'pub.pem'], dir).status === 1, 'a package with its stated verdict changed was accepted');

    const view = node(CLI, ['release-view', 'pkg.json', '--public-key', 'pub.pem', '--view', 'ciso'], dir);
    expect(view.status === 0 && /CISO VIEW/.test(view.stdout), `release-view did not render the CISO view of a verified package (exit ${view.status})`);
  }

  fs.rmSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), { force: true });
  const unsigned = node(CLI, ['release-package', 'build', '.', '--private-key', 'k.pem', '--output', 'unsigned.json'], dir);
  expect(unsigned.status === 1 && !fs.existsSync(path.join(dir, 'unsigned.json')), `build used a scan with no signature (exit ${unsigned.status})`);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

if (problems.length) {
  for (const p of problems) console.error(`release-assurance: ${p}`);
  process.exit(1);
}
console.log('release-assurance: a package built from a scan is accepted offline, and a lowered severity, a restated verdict and an unsigned scan are each refused');
