// Contract test for release assurance (docs/reference/release-assurance-contract.md): builds a package from a real scan with the real
// command and holds the package, the verdict and the verifier's codes to the page in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields, REPO } from '../helpers/contract-page.js';
import { releaseVerdict, verifyStatedVerdict } from '../../src/posture/assurance/release-verdict.js';
import { MANDATORY_KINDS } from '../../src/posture/assurance/release-package.js';

const SCANNER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const VERIFIER = path.join(REPO, 'scripts', 'verify-release-package.mjs');
const PAGE = readPage('docs/reference/release-assurance-contract.md');

const dir = mkTestTmp('agsec-release-contract-');
fs.cpSync(path.join(REPO, 'examples', 'assurance-demo'), dir, { recursive: true });
const run = (file, args) => spawnSync(process.execPath, [file, ...args], { cwd: dir, encoding: 'utf8', timeout: 300000, env: { ...process.env, NO_COLOR: '1' } });
run(CLI, ['scan', '.', '--format', 'json']);
fs.writeFileSync(path.join(dir, 'k.pem'), crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }));
const build = run(CLI, ['release-package', 'build', '.', '--private-key', 'k.pem', '--public-key-out', 'pub.pem', '--output', 'pkg.json']);
const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'pkg.json'), 'utf8'));

test('contract: build succeeds and the offline verifier accepts what it built', () => {
  assert.equal(build.status, 0, build.stderr);
  assert.equal(run(VERIFIER, ['pkg.json', '--public-key', 'pub.pem']).status, 0);
  assert.equal(run(CLI, ['release-package', 'verify', 'pkg.json', '--public-key', 'pub.pem']).status, 0);
  for (const code of ['`0`', '`1`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`), `exit ${code} is on the page`);
});

test('contract: the package has exactly the documented fields at every level', () => {
  sameFields(pkg, fieldsUnder(PAGE, 'Package'), 'package');
  sameFields(pkg.snapshot, fieldsUnder(PAGE, 'Snapshot'), 'snapshot');
  sameFields(pkg.evidence[0], fieldsUnder(PAGE, 'Evidence entry'), 'evidence entry');
  sameFields(pkg.findings[0], fieldsUnder(PAGE, 'Finding summary'), 'finding summary');
  sameFields(pkg.completeness, fieldsUnder(PAGE, 'Completeness'), 'completeness');
  sameFields(pkg.issuance, fieldsUnder(PAGE, 'Issuance'), 'issuance');
  sameFields(pkg.signature, fieldsUnder(PAGE, 'Signature'), 'signature');
  assert.equal(pkg.schema, 'agentic-security/release-package');
  assert.equal(pkg.schemaVersion, '1.0.0');
  assert.deepEqual([...MANDATORY_KINDS], ['scan-health', 'finding']);
  assert.equal(pkg.issuance.independentlyCertified, false);
  assert.equal(pkg.signature.domain, 'agentic-security/release-package@1');
});

test('contract: the verdict has the documented fields and values, and the stated verdict matches the recomputed one', () => {
  const v = releaseVerdict(pkg);
  sameFields(v, fieldsUnder(PAGE, 'Verdict result'), 'verdict result');
  assert.ok(['not_deployable', 'needs_review', 'deployable'].includes(v.verdict));
  for (const w of ['not_deployable', 'needs_review', 'deployable']) assert.ok(PAGE.includes(`\`${w}\``));
  sameFields(v.blockers[0], ['code', 'message', 'evidence'], 'blocker');
  assert.equal(verifyStatedVerdict(pkg).ok, true);
  assert.equal(pkg.policy.decisions.find(d => d.id === 'release-verdict').outcome, v.verdict);
});

test('contract: every reason code in the verdict source is on the page, and every code on the page is in the source', () => {
  const src = fs.readFileSync(path.join(SCANNER, 'src', 'posture', 'assurance', 'release-verdict.js'), 'utf8');
  const inSource = new Set((src.match(/'[A-Z]+(?:_[A-Z]+)+'/g) || []).map(s => s.slice(1, -1)));
  const onPage = new Set(fieldsUnder(PAGE, 'Reason codes'));
  assert.deepEqual([...inSource].sort(), [...onPage].sort());
});

test('contract: every code the verifier can produce is on the page, and every code on the page is produced', () => {
  const src = fs.readFileSync(path.join(SCANNER, 'src', 'posture', 'assurance', 'release-package-verify.js'), 'utf8');
  const inSource = new Set([...src.matchAll(/fail\('([A-Z]+)'/g)].map(m => m[1]).concat(src.includes("code: 'FORMAT'") ? ['FORMAT'] : []));
  const onPage = new Set(fieldsUnder(PAGE, 'Verifier rejection codes').length ? fieldsUnder(PAGE, 'Verifier rejection codes') : []);
  assert.deepEqual([...inSource].sort(), [...onPage].sort());
});

test('contract: a lowered severity, a restated verdict and a dropped record are each rejected with exit 1', () => {
  const write = (name, mutate) => { const p = structuredClone(pkg); mutate(p); fs.writeFileSync(path.join(dir, name), JSON.stringify(p)); return run(VERIFIER, [name, '--public-key', 'pub.pem']); };
  assert.equal(write('lowered.json', p => { p.evidence.find(e => e.ref.kind === 'finding' && e.payload.severity !== 'info').payload.severity = 'info'; }).status, 1);
  assert.equal(write('restated.json', p => { const d = p.policy.decisions.find(x => x.id === 'release-verdict'); d.outcome = d.outcome === 'deployable' ? 'not_deployable' : 'deployable'; }).status, 1);
  assert.equal(write('dropped.json', p => { p.evidence.pop(); }).status, 1);
  assert.equal(run(CLI, ['release-package', 'verify', 'lowered.json', '--public-key', 'pub.pem']).status, 1);
});

test('contract: a scan with no signature is not used as evidence, and nothing is written', () => {
  fs.rmSync(path.join(dir, '.agentic-security', 'last-scan.json.sig'), { force: true });
  const r = run(CLI, ['release-package', 'build', '.', '--private-key', 'k.pem', '--output', 'unsigned.json']);
  assert.equal(r.status, 1);
  assert.equal(fs.existsSync(path.join(dir, 'unsigned.json')), false);
  assert.equal(run(CLI, ['release-package', 'build', '.', '--output', 'x.json']).status, 2, 'a missing private key is a usage problem');
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Package');
  assert.throws(() => sameFields({ ...pkg, extra: 1 }, doc, 'package'));
  const { proves, ...rest } = pkg;
  assert.throws(() => sameFields(rest, doc, 'package'));
  assert.ok(proves);
});
