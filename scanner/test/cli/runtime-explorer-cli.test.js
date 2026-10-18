// `explore . --runtime` and `runtime query vulnerable-functions-in-production`, through the real CLI (PRD 2 sections 5 and 6).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const FIXTURE_DIR = fileURLToPath(new URL('../fixtures/runtime-twin', import.meta.url));
const run = (cwd, args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', timeout: 90000, env: { ...process.env, XDG_CONFIG_HOME: path.join(cwd, '.cfg'), ...env } });

test('the runtime explorer page and the vulnerable-functions query, end to end', { timeout: 180000 }, (t) => {
  const fx = createGitFixture(); t.after(() => fx.cleanup());
  fx.writeFile('app.js', fs.readFileSync(path.join(FIXTURE_DIR, 'app', 'app.js'), 'utf8'));
  fx.writeFile('package.json', fs.readFileSync(path.join(FIXTURE_DIR, 'app', 'package.json'), 'utf8'));
  fx.commit('app');
  assert.ok(run(fx.root, ['scan', '.'], { AGENTIC_SECURITY_LINEAGE_DEEP: '1' }).status <= 3);

  // before any telemetry: the page says so and shows STATIC_ONLY; the query refuses to call that "nothing ran"
  const page0 = run(fx.root, ['explore', '.', '--runtime']);
  assert.equal(page0.status, 0, page0.stderr); assert.match(page0.stdout, /static page, no server/);
  const html0 = fs.readFileSync(path.join(fx.root, '.agentic-security', 'runtime-explorer.html'), 'utf8');
  assert.match(html0, /No telemetry was consulted/); assert.match(html0, /STATIC_ONLY/); assert.doesNotMatch(html0, /<script/i);
  const q0 = JSON.parse(run(fx.root, ['runtime', 'query', 'vulnerable-functions-in-production', '.']).stdout);
  assert.equal(q0.evaluated, false); assert.match(q0.reason, /not "no vulnerable function ran"/);

  const T = path.join(FIXTURE_DIR, 'telemetry');
  const win = ['--window-start', '2026-08-01T00:00:00.000Z', '--window-end', '2026-08-31T00:00:00.000Z', '--yes', '--environment', 'production'];
  for (const [adapter, file] of [['k8s-audit-log', 'k8s-audit-db-allowed.jsonl'], ['envoy-access-log', 'envoy-queue-denied.jsonl'], ['http-access-log', 'http-shadow-unmatched.jsonl']]) {
    assert.equal(run(fx.root, ['runtime', 'ingest', '.', '--adapter', adapter, '--input', path.join(T, file), ...win]).status, 0);
  }
  const out = path.join(fx.root, 'out', 'twin.html');
  const page = run(fx.root, ['runtime', 'explore', '.', '--environment', 'production', '--out', out]);
  assert.equal(page.status, 0, page.stderr);
  const html = fs.readFileSync(out, 'utf8');
  for (const id of ['static', 'runtime', 'both', 'risk', 'unexpected']) assert.match(html, new RegExp(`<section id="${id}">`));
  assert.match(html, /RUNTIME_OBSERVED/); assert.match(html, /RUNTIME_BLOCKED/); assert.match(html, /unknown-shadow-service\.internal/);
  assert.match(html, /Static evidence[\s\S]*Runtime evidence/);

  // a trace that exercises the finding's line: the query lists it, with the matcher's own basis
  fs.writeFileSync(path.join(fx.root, '.agentic-security', 'runtime-trace.jsonl'), JSON.stringify({ ts: new Date().toISOString(), kind: 'function-call', qid: 'handleCheckout', fileRel: 'app.js', line: 22, count: 5 }) + '\n');
  const q = JSON.parse(run(fx.root, ['runtime', 'query', 'vulnerable-functions-in-production', '.']).stdout);
  assert.equal(q.evaluated, true); assert.ok(q.counts.observed >= 1);
  assert.ok(q.findings.some((f) => f.file === 'app.js' && f.line === 22));
  assert.match(q.note, /not about reachability/);
  assert.equal(typeof q.counts.exploitCorrelated, 'number');
  assert.ok(q.findings.every((f) => f.exploitCorrelation && f.exploitCorrelation.correlated === false && /no proof record/.test(f.exploitCorrelation.basis)), 'with no proof and no hunt nothing is exploit-correlated, and it says why');
  assert.ok(!JSON.stringify(q).includes('"unsupported"'));
});
