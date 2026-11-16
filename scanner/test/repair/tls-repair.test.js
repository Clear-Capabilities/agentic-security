// FR-01 / AC-01.5: the TLS repair turns verification on at the named operation, keeps the declared private CA, and is judged by real
// handshakes in an isolated loopback environment: the declared trusted endpoint is accepted, an untrusted certificate is rejected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { planDeterministicFix } from '../../src/posture/deterministic-fix.js';

const opensslOk = spawnSync('openssl', ['version']).status === 0;

const CLIENT = "const https = require('https');\nconst fs = require('fs');\nexports.fetch = (port, caPath) => new Promise((resolve, reject) => {\n  const agent = new https.Agent({ rejectUnauthorized: false, ca: fs.readFileSync(caPath) });\n  https.get({ host: '127.0.0.1', port, path: '/', agent, servername: 'localhost' }, (r) => { let b = ''; r.on('data', (d) => { b += d; }); r.on('end', () => resolve(b)); }).on('error', reject);\n});\n";

function openssl(dir, args) { const r = spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' }); if (r.status !== 0) throw new Error(`openssl ${args.join(' ')}: ${r.stderr}`); }

function makeCerts(dir) {
  fs.writeFileSync(path.join(dir, 'san.cnf'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=test-private-ca']);
  openssl(dir, ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'srv.key', '-out', 'srv.csr', '-subj', '/CN=localhost']);
  openssl(dir, ['x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'srv.pem', '-days', '2', '-extfile', 'san.cnf']);
  openssl(dir, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'rogue.key', '-out', 'rogue.pem', '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']);
}

// Runs both handshakes in a child process against two loopback servers and prints the outcome of each.
const DRIVER = (clientPath, dir) => `const https = require('https'); const fs = require('fs'); const path = require('path');
const c = require(${JSON.stringify(clientPath)});
const d = ${JSON.stringify(dir)};
const serve = (k, p) => new Promise((r) => { const s = https.createServer({ key: fs.readFileSync(path.join(d, k)), cert: fs.readFileSync(path.join(d, p)) }, (q, s2) => s2.end('hello')); s.listen(0, '127.0.0.1', () => r(s)); });
(async () => {
  const good = await serve('srv.key', 'srv.pem'); const bad = await serve('rogue.key', 'rogue.pem');
  const out = {};
  try { out.trusted = await c.fetch(good.address().port, path.join(d, 'ca.pem')); } catch (e) { out.trusted = 'ERR:' + e.code; }
  try { out.untrusted = await c.fetch(bad.address().port, path.join(d, 'ca.pem')); } catch (e) { out.untrusted = 'ERR:' + e.code; }
  good.close(); bad.close();
  process.stdout.write(JSON.stringify(out));
})();`;

function handshake(dir, source) {
  const client = path.join(dir, `client-${Math.random().toString(36).slice(2)}.cjs`);
  fs.writeFileSync(client, source);
  const r = spawnSync(process.execPath, ['-e', DRIVER(client, dir)], { encoding: 'utf8', timeout: 20000, env: { PATH: process.env.PATH } });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

test('AC-01.5: the TLS repair accepts the declared trusted endpoint and rejects an untrusted certificate (executed handshakes)', { skip: opensslOk ? false : 'openssl is not available to mint the test certificates' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-repair-'));
  try {
    makeCerts(dir);
    const before = handshake(dir, CLIENT);
    assert.equal(before.trusted, 'hello');
    assert.equal(before.untrusted, 'hello', 'precondition: the original code accepts the rogue certificate');
    const plan = planDeterministicFix({ file: 'client.js', line: 4, cwe: 'CWE-295' }, CLIENT);
    assert.equal(plan.disposition, 'proposed');
    assert.match(plan.compatibility, /declared CA .* preserved/);
    assert.ok(plan.requiredObligations.includes('tls-trusted-endpoint-accepted'));
    const after = handshake(dir, plan.patch['client.js']);
    assert.equal(after.trusted, 'hello', 'the declared private CA still works');
    assert.match(after.untrusted, /^ERR:/, 'the untrusted certificate is rejected');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the TLS repair edits only the named setting and states the CA consequence when none is declared', () => {
  const src = "const a = new https.Agent({ rejectUnauthorized: false });\nconst b = new https.Agent({ rejectUnauthorized: false });\n";
  const plan = planDeterministicFix({ file: 'x.js', line: 2, cwe: 'CWE-295' }, src);
  assert.equal(plan.disposition, 'proposed');
  assert.deepEqual(plan.patch['x.js'].split('\n').slice(0, 2), ['const a = new https.Agent({ rejectUnauthorized: false });', 'const b = new https.Agent({ rejectUnauthorized: true });']);
  assert.match(plan.compatibility, /no private CA is declared/);
  assert.equal(planDeterministicFix({ file: 'x.js', cwe: 'CWE-295' }, src).disposition, 'needs-review', 'two settings and no line: which one is ambiguous');
});
