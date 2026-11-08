// Threat-model PRD FR-01 (TM-02): the scan scope reaches standard JSON, is bound to the scan record, agrees with the preview, and a
// qualified release check reconciles it with what ships.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildScanInventory, inventoryDigest } from '../../src/scope/inventory.js';
import { evaluateReleaseScope } from '../../src/scope/release-scope.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const SEEDED = "const { exec } = require('child_process');\nconst app = require('express')();\napp.get('/orders/export', (req, res) => { exec('tar czf out.tgz ' + req.query.name); res.send('ok'); });\n";

function repo() {
  const dir = mkTestTmp('scope-ev-');
  const git = (...a) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  git('init', '-q'); git('config', 'user.email', 't@example.invalid'); git('config', 'user.name', 't');
  fs.mkdirSync(path.join(dir, 'buck-out'), { recursive: true }); fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'buck-out/orders.js'), SEEDED);
  fs.writeFileSync(path.join(dir, 'src/clean.js'), 'module.exports = (a, b) => a + b;\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}\n');
  git('add', '-A'); git('commit', '-qm', 'init');
  return dir;
}
const run = (dir, ...flags) => spawnSync(process.execPath, [CLI, 'scan', dir, ...flags], { encoding: 'utf8', env: { ...process.env, AGENTIC_SECURITY_LLM_ENDPOINT: '', AGENTIC_SECURITY_NO_TELEMETRY: '1' }, maxBuffer: 64 * 1024 * 1024 });
const json = (r) => { const i = r.stdout.indexOf('{'); return JSON.parse(r.stdout.slice(i)); };

test('AC-01A: a tracked generated file stays excluded, the exclusion is in bundled JSON and the preview, and an inclusion changes the digest', { timeout: 240_000 }, () => {
  const dir = repo();
  const r = run(dir, '--respect-gitignore', '--format', 'json', '--no-state');
  assert.equal(r.status === 0 || r.status === 1, true, r.stderr.slice(-800));
  const rep = json(r);
  assert.ok(rep.scope, 'standard JSON carries the scope');
  assert.equal(rep.scope.skippedByReason['generated-default'], 1);
  assert.ok(rep.scope.skipped.some((s) => s.path === 'buck-out/orders.js' && s.reason === 'generated-default'));
  assert.match(rep.scope.inventoryDigest, /^[0-9a-f]{64}$/);
  assert.equal(rep.scanRecord.ignorePolicy.inventoryDigest, rep.scope.inventoryDigest, 'the scan record binds the scope');
  assert.ok(rep.scope.read && rep.scope.read.files >= 1, 'files read are recorded beside eligibility');
  assert.ok(!(rep.findings || []).some((f) => String(f.file).startsWith('buck-out/')), 'the excluded file was not analysed');

  const preview = spawnSync(process.execPath, [CLI, 'scan', dir, '--explain-scope'], { encoding: 'utf8' });
  assert.ok(preview.stdout.includes(`Inventory digest: ${rep.scope.inventoryDigest}`), 'the preview shows the same digest');
  assert.match(preview.stdout, /generated-default/);

  const inc = json(run(dir, '--respect-gitignore', '--include-path', 'buck-out/orders.js', '--format', 'json', '--no-state'));
  assert.ok(inc.scope.overrides.some((o) => o.path === 'buck-out/orders.js' && o.overrode === 'generated-default'));
  assert.notEqual(inc.scope.inventoryDigest, rep.scope.inventoryDigest, 'the override changes the digest');
  assert.ok(inc.findings.some((f) => f.file === 'buck-out/orders.js' && /CWE-78/.test(String(f.cwe))), 'the seeded finding appears once the file is in scope');
});

test('AC-01C: the digest covers every decision before caps, is stable on rerun, and moves when a decision moves', () => {
  const dir = mkTestTmp('scope-dg-');
  for (let i = 0; i < 30; i++) fs.writeFileSync(path.join(dir, `f${i}.js`), 'x\n');
  const a = buildScanInventory(dir, { respectGitignore: false });
  const b = buildScanInventory(dir, { respectGitignore: false });
  assert.equal(a.digest, b.digest, 'a stable rerun');
  assert.equal(inventoryDigest({ ...a, included: [...a.included].reverse() }), a.digest, 'order does not matter');
  const ex = buildScanInventory(dir, { respectGitignore: false, excludePaths: ['f7.js'] });
  assert.notEqual(ex.digest, a.digest);
  assert.equal(inventoryDigest({ ...a, skipped: [...a.skipped, { path: 'z', reason: 'symlink' }] }) === a.digest, false, 'a skipped entry beyond any display cap still moves the digest');
});

const REPORT = (over = {}) => ({
  scope: { inventoryDigest: 'd', included: ['src/app.js', 'src/routes.js'], skipped: [{ path: 'buck-out/', reason: 'generated-default' }] },
  routes: [{ method: 'GET', path: '/records/:id', file: 'src/routes.js', line: 3 }],
  scanRecord: { source: { commit: 'abc123', dirty: false } }, ...over,
});

test('AC-01B: shipped code outside the analysis, an unmatched critical route and a stale binding each keep the release check open', () => {
  const ok = evaluateReleaseScope(REPORT(), { shipped: [{ path: 'src/app.js' }], routes: [{ method: 'GET', path: '/records/{id}' }], artifact: { sourceCommit: 'abc123' } });
  assert.equal(ok.status, 'satisfied', JSON.stringify(ok.reasons));
  const shipped = evaluateReleaseScope(REPORT(), { shipped: [{ path: 'buck-out/orders.js' }], artifact: { sourceCommit: 'abc123' } });
  assert.equal(shipped.status, 'unresolved'); assert.equal(shipped.items[0].outcome, 'excluded'); assert.equal(shipped.items[0].reason, 'generated-default');
  const route = evaluateReleaseScope(REPORT(), { routes: [{ method: 'GET', path: '/admin/export' }], artifact: { sourceCommit: 'abc123' } });
  assert.deepEqual(route.reasons.map((r) => r.code), ['route-unknown']);
  assert.deepEqual(evaluateReleaseScope(REPORT(), { artifact: { sourceCommit: 'fff999' } }).reasons.map((r) => r.code), ['stale-binding']);
  assert.deepEqual(evaluateReleaseScope(REPORT({ scanRecord: { source: { commit: 'abc123', dirty: true } } }), { artifact: { sourceCommit: 'abc123' } }).reasons.map((r) => r.code), ['dirty-input']);
  // an exception counts only with an independent compensating control and an expiry in the future
  const now = Date.parse('2026-11-08T00:00:00Z');
  const ex = (c, expires) => evaluateReleaseScope(REPORT(), { shipped: [{ path: 'buck-out/orders.js' }], artifact: { sourceCommit: 'abc123' }, now, exceptions: [{ kind: 'file', target: 'buck-out/orders.js', compensatingControl: c, expires }] });
  assert.equal(ex({ id: 'waf-17', verifiedBy: 'appsec', independent: true }, '2026-12-01T00:00:00Z').status, 'satisfied');
  assert.equal(ex({ id: 'waf-17', verifiedBy: 'appsec', independent: true }, '2026-11-01T00:00:00Z').status, 'unresolved', 'expired');
  assert.equal(ex({ id: 'waf-17', verifiedBy: 'appsec' }, '2026-12-01T00:00:00Z').status, 'unresolved', 'not independently verified');
});

test('AC-01C: a legacy report with no scope stays readable and cannot satisfy the strict scope gate; an omitted list is unknown, not empty', () => {
  const legacy = evaluateReleaseScope({ findings: [], scanRecord: { source: { commit: 'abc123' } } }, { artifact: { sourceCommit: 'abc123' } });
  assert.equal(legacy.status, 'unresolved'); assert.equal(legacy.reasons[0].code, 'scope-missing');
  const big = evaluateReleaseScope(REPORT({ scope: { inventoryDigest: 'd', includedOmitted: true, skipped: [] } }), { shipped: [{ path: 'src/app.js' }], artifact: { sourceCommit: 'abc123' } });
  assert.equal(big.items[0].outcome, 'unknown'); assert.match(big.items[0].reason, /only counts/);
});
