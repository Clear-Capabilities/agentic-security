// Identity tokens through the real CLI (PRD 2): recorded only on request, as a keyed hash, with the raw identity absent from
// every persisted file; the identity query answers "evaluated" and never pretends an edge with no identity telemetry was clean.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const FIXTURE_DIR = fileURLToPath(new URL('../fixtures/runtime-twin', import.meta.url));
const run = (cwd, args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', timeout: 60000, env: { ...process.env, XDG_CONFIG_HOME: path.join(cwd, '.cfg'), ...env } });
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));

test('identity tokens: off by default, a keyed hash when asked, the raw identity never persisted', { timeout: 120000 }, (t) => {
  const fx = createGitFixture(); t.after(() => fx.cleanup());
  fx.writeFile('app.js', fs.readFileSync(path.join(FIXTURE_DIR, 'app', 'app.js'), 'utf8'));
  fx.writeFile('package.json', fs.readFileSync(path.join(FIXTURE_DIR, 'app', 'package.json'), 'utf8'));
  fx.commit('app');
  assert.ok(run(fx.root, ['scan', '.'], { AGENTIC_SECURITY_LINEAGE_DEEP: '1' }).status <= 3);
  const audit = path.join(fx.root, 'audit.jsonl');
  fs.writeFileSync(audit, '{"objectRef":{"apiVersion":"v1","resource":"user"},"verb":"create","responseStatus":{"code":200},"user":{"username":"alice.hunter@example.com"},"requestReceivedTimestamp":"2026-08-02T10:05:00.000Z"}\n');
  const win = ['--window-start', '2026-08-01T00:00:00.000Z', '--window-end', '2026-08-31T00:00:00.000Z', '--yes', '--environment', 'production', '--adapter', 'k8s-audit-log', '--input', audit];

  const plain = run(fx.root, ['runtime', 'ingest', '.', ...win]);
  assert.equal(plain.status, 0, plain.stderr);
  const store = path.join(fx.root, '.agentic-security', 'runtime-observations');
  const dump = () => walk(store).map((f) => fs.readFileSync(f, 'utf8')).join('\n');
  assert.doesNotMatch(dump(), /idt_|alice/, 'by default no identity is recorded in any form');

  fs.rmSync(store, { recursive: true, force: true });
  const tokened = run(fx.root, ['runtime', 'ingest', '.', ...win, '--record-identity-tokens']);
  assert.equal(tokened.status, 0, tokened.stderr);
  assert.match(dump(), /idt_[0-9a-f]{16}/);
  assert.doesNotMatch(dump(), /alice|hunter|example\.com/, 'the raw identity is in no persisted file');
  assert.doesNotMatch(tokened.stdout + tokened.stderr, /alice|hunter/, 'nor in the command output');

  const q = run(fx.root, ['runtime', 'query', 'identities-using-risky-paths', '.', '--environment', 'production']);
  assert.equal(q.status, 0, q.stderr);
  const r = JSON.parse(q.stdout);
  assert.equal(r.supported, true); assert.equal(r.evaluated, true); assert.deepEqual(r.identities, []);
  assert.match(r.note, /not evidence that no identity used them/);

  const none = run(fx.root, ['runtime', 'query', '--list', '.']);
  assert.match(none.stdout, /identities-using-risky-paths/); assert.match(none.stdout, /vulnerable-functions-in-production/);
});
