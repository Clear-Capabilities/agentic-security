// X-308 wiring: the operator entry point `agentic-security boundaries`.
//
// Nothing in the default scan builds a boundary context; this command is the one explicit, read-only, local-files-only way to,
// and it sits behind the `deployment-boundaries` feature, which is off by default. Exit codes: 0 report, 1 failed, 2 usage,
// 3 feature off or blocked.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { digestTree } from '../../src/posture/evaluation/runner.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', '..', 'bin', 'agentic-security.js');
const ABLATION = path.join(HERE, '..', 'fixtures', 'deployment-ablation', 'cases');
const KEY_HEX = 'ab'.repeat(32);
const ENABLE = { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' };

const FINDING = { id: 'f-1', severity: 'critical', file: 'services/api/handler.js', line: 4, vuln: 'Command Injection', cwe: 'CWE-78', family: 'command-injection', parser: 'REGEX', description: 'x', remediation: 'y' };

function run(args, { env = {}, cwd } = {}) {
  const base = { PATH: process.env.PATH, HOME: process.env.HOME, AGENTIC_SECURITY_HMAC_KEY: KEY_HEX };
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, env: { ...base, ...env }, encoding: 'utf8', timeout: 60000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function workspace(caseId = 'k8s-ingress-vs-internal', variant = 'exploitable') {
  const root = mkTestTmp('boundaries-cli-');
  const from = path.join(root, 'deploy');
  fs.cpSync(path.join(ABLATION, caseId, variant), from, { recursive: true });
  return { root, from };
}

function writeScan(root, findings = [FINDING], { sign = true, signature } = {}) {
  const file = path.join(root, 'last-scan.json');
  const body = JSON.stringify({ findings });
  fs.writeFileSync(file, body);
  fs.rmSync(`${file}.sig`, { force: true });
  if (sign) fs.writeFileSync(`${file}.sig`, signature ?? crypto.createHmac('sha256', Buffer.from(KEY_HEX, 'hex')).update(body).digest('hex'));
  return file;
}

test('[X-308.wiring] with the feature off the command refuses (exit 3), reads nothing and writes nothing', () => {
  const { root, from } = workspace();
  const out = path.join(root, 'report.json');
  const r = run(['boundaries', '--from', from, '--out', out, '--root', root]);
  assert.equal(r.code, 3);
  assert.match(r.err, /not run \(disabled\)/);
  assert.match(r.err, /AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES=1/);
  assert.equal(fs.existsSync(out), false, 'no report is written when the feature is off');
  assert.equal(r.out, '');
});

test('[X-308.wiring] the kill switch beats the enabling variable (exit 3, blocked)', () => {
  const { root, from } = workspace();
  const r = run(['boundaries', '--from', from, '--root', root], { env: { ...ENABLE, AGENTIC_SECURITY_NO_DEPLOYMENT_BOUNDARIES: '1' } });
  assert.equal(r.code, 3);
  assert.match(r.err, /blocked/);
});

test('[X-308.wiring] enabled, it builds the graph and attaches a context to each finding of a scan result (exit 0)', () => {
  const { root, from } = workspace();
  const scan = writeScan(root);
  const r = run(['boundaries', '--from', from, '--findings', scan, '--root', root, '--json'], { env: ENABLE });
  assert.equal(r.code, 0, r.err);
  const rep = JSON.parse(r.out);
  assert.equal(rep.schema, 'agentic-security/boundaries-report');
  assert.equal(rep.scanResult.integrity, 'verified');
  assert.equal(rep.findings.length, 1);
  assert.equal(rep.findings[0].boundaryContext.exposure.state, 'possible');
  assert.equal(rep.findings[0].boundaryView.binding.service.name, 'shop/api');
  assert.equal(rep.coverage.bound, 1);
  assert.match(rep.statement, /traffic coverage is not established/i);
  assert.ok(rep.graph.nodeCount > 0 && Array.isArray(rep.graph.files));
  assert.doesNotMatch(r.out, /\bsafe\b/i);
});

test('[X-308.wiring] the same finding against the internal-only deployment reports no path, never "safe"', () => {
  const { root, from } = workspace('k8s-ingress-vs-internal', 'non-exploitable');
  const r = run(['boundaries', '--from', from, '--findings', writeScan(root), '--root', root], { env: ENABLE });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /exposure NO PATH FOUND/);
  assert.match(r.out, /does not show that none exists/);
  assert.doesNotMatch(r.out, /\bsafe\b|\bprotected\b|\bunreachable\b/i);
});

test('[X-308.wiring] a finding with no service binding is reported as not assessed, and the missing bindings file is disclosed', () => {
  const { root, from } = workspace('k8s-finding-unbound', 'exploitable');
  const r = run(['boundaries', '--from', from, '--findings', writeScan(root), '--root', root, '--json'], { env: ENABLE });
  const rep = JSON.parse(r.out);
  assert.equal(rep.findings[0].boundaryContext.exposure.state, 'not-assessed');
  assert.ok(rep.notes.some((n) => /service-bindings\.json/.test(n)));
  assert.equal(rep.coverage.bound, 0);
});

test('[X-308.wiring] a scan result whose signature does not verify is refused (exit 1); an unsigned one is read and labelled', () => {
  const { root, from } = workspace();
  const bad = run(['boundaries', '--from', from, '--findings', writeScan(root, [FINDING], { signature: 'deadbeef'.repeat(8) }), '--root', root], { env: ENABLE });
  assert.equal(bad.code, 1);
  assert.match(bad.err, /signature that does not verify/);
  const unsigned = run(['boundaries', '--from', from, '--findings', writeScan(root, [FINDING], { sign: false }), '--root', root, '--json'], { env: ENABLE });
  assert.equal(unsigned.code, 0);
  const rep = JSON.parse(unsigned.out);
  assert.equal(rep.scanResult.integrity, 'unsigned');
  assert.ok(rep.notes.some((n) => /integrity was not verified/.test(n)));
});

test('[X-308.wiring] usage and input errors have their own exit codes (2 usage, 1 failed)', () => {
  const { root, from } = workspace();
  assert.equal(run(['boundaries', '--root', root], { env: ENABLE }).code, 2, 'no --from');
  assert.equal(run(['boundaries', '--from', from, '--out'], { env: ENABLE }).code, 2, '--out without a value');
  const missing = run(['boundaries', '--from', path.join(root, 'nope'), '--root', root], { env: ENABLE });
  assert.equal(missing.code, 1);
  assert.match(missing.err, /not a readable directory/);
  const empty = path.join(root, 'empty');
  fs.mkdirSync(empty);
  assert.equal(run(['boundaries', '--from', empty, '--root', root], { env: ENABLE }).code, 1, 'a directory with no configuration');
  const notScan = path.join(root, 'bad.json');
  fs.writeFileSync(notScan, '{not json');
  assert.equal(run(['boundaries', '--from', from, '--findings', notScan, '--root', root], { env: ENABLE }).code, 1);
});

test('[X-308.wiring] it is read-only: the deployment directory is unchanged and no state directory appears in the project', () => {
  const { root, from } = workspace();
  const before = digestTree(from);
  const r = run(['boundaries', '--from', from, '--findings', writeScan(root), '--root', root], { env: ENABLE, cwd: root });
  assert.equal(r.code, 0, r.err);
  assert.equal(digestTree(from), before);
  assert.equal(fs.existsSync(path.join(root, '.agentic-security')), false);
});

test('[X-308.wiring] --out writes the report to the named file only, and refuses a symbolic link', () => {
  const { root, from } = workspace();
  const out = path.join(root, 'report.json');
  const ok = run(['boundaries', '--from', from, '--findings', writeScan(root), '--root', root, '--json', '--out', out], { env: ENABLE });
  assert.equal(ok.code, 0, ok.err);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).schema, 'agentic-security/boundaries-report');
  const target = path.join(root, 'victim.txt');
  fs.writeFileSync(target, 'keep');
  const link = path.join(root, 'link.json');
  fs.symlinkSync(target, link);
  const refused = run(['boundaries', '--from', from, '--root', root, '--out', link], { env: ENABLE });
  assert.equal(refused.code, 1);
  assert.equal(fs.readFileSync(target, 'utf8'), 'keep', 'the symlink target was not overwritten');
});

test('[X-308.wiring] sanitized traces are correlated and staleness is reported apart from the paths', () => {
  const root = mkTestTmp('boundaries-cli-traces-');
  const from = path.join(root, 'deploy');
  fs.mkdirSync(from);
  fs.copyFileSync(path.join(HERE, 'fixtures', 'k8s-payments', 'manifests.yaml'), path.join(from, 'manifests.yaml'));
  const line = { ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'payments/api', tenant: 'acme' }, destination: { service: 'payments/ledger' }, outcome: 'ok' };
  fs.writeFileSync(path.join(from, 'traces.jsonl'), `${JSON.stringify(line)}\n`);
  const fresh = JSON.parse(run(['boundaries', '--from', from, '--root', root, '--json', '--now', '2026-03-10T00:00:00Z'], { env: ENABLE }).out);
  assert.equal(fresh.observation.status, 'correlated');
  assert.equal(fresh.observation.accepted, 1);
  assert.equal(fresh.observation.coverage.trafficCoverage, 'not-established');
  assert.equal(fresh.observation.coverage.stale.length, 0);
  const stale = JSON.parse(run(['boundaries', '--from', from, '--root', root, '--json', '--now', '2026-06-01T00:00:00Z'], { env: ENABLE }).out);
  assert.ok(stale.observation.coverage.stale.length > 0, 'an old trace is reported stale, not as current coverage');
  assert.ok(!JSON.stringify(stale).includes('token'));
});

test('[X-308.wiring] the usage text lists the command, and the usage of every other command is still there', () => {
  const r = run(['--help']);
  const text = `${r.out}${r.err}`;
  assert.match(text, /boundaries --from <dir>/);
  assert.match(text, /Exit: 0 ok, 1 failed, 2 usage, 3 feature off or blocked/);
  for (const cmd of ['scan [path]', 'explore [path]', 'federate declare', 'remediation list', 'governance propose-edit']) assert.ok(text.includes(cmd), cmd);
});
