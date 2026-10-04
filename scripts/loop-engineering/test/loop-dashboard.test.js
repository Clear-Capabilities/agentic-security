// LOOP-004: live loopback dashboard and terminal status.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createDashboard } from '../lib/server.mjs';
import { buildStatus, renderStaticHtml } from '../lib/status.mjs';
import { formatPercent } from '../lib/progress.mjs';
import { writeLease, layout, appendEvent } from '../lib/state.mjs';
import { startTimeOf } from '../lib/procscan.mjs';
import { MiniRepo, sleep } from './helpers.js';

function get(url, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', reject); r.end();
  });
}

async function fixture(reqs, opts) {
  const repo = new MiniRepo(reqs, opts);
  const i = await repo.init();
  assert.equal(i.code, 0, i.stderr);
  const runId = repo.runId();
  const L = layout(repo.root, runId);
  // A disposable stand-in for the controller process: never the test process itself.
  const dummy = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
  await sleep(150);
  const pid = dummy.pid, start = startTimeOf(pid);
  const live = () => writeLease(L.leaseFile, { runId, pid, start, seq: 1, status: 'running', role: 'controller' });
  const realCleanup = repo.cleanup.bind(repo);
  repo.cleanup = async () => { dummy.kill('SIGKILL'); await sleep(100); await realCleanup(); };
  const setState = (fn) => { const s = JSON.parse(readFileSync(L.stateFile, 'utf8')); fn(s); writeFileSync(L.stateFile, JSON.stringify(s)); };
  return { repo, runId, L, live, setState, pid, start };
}

test('[LOOP-004.AC01] a verifier pass, fail and stale transition reaches the UI API within 5 seconds', async () => {
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }, { id: 'HS-002', weight: 3, criteria: ['b'] }]);
  const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: 0 });
  try {
    f.live(); f.setState((s) => { s.status = 'running'; });
    const api = async () => JSON.parse((await get(dash.url + '/api/status')).body);
    const row = (s, id) => s.requirements.find((r) => r.id === id);
    const until = async (pred, label) => { const t = Date.now(); for (;;) { const s = await api(); if (pred(s)) return Date.now() - t; if (Date.now() - t > 5000) throw new Error('UI did not reflect ' + label + ' within 5s'); await sleep(150); } };
    assert.equal((await api()).verifiedPercent, 0);
    // FAIL
    assert.equal((await f.repo.cli(['verify', '--requirement', 'HS-001'])).code, 1);
    await until((s) => row(s, 'HS-001').evidence?.result === 'fail', 'fail');
    // PASS
    writeFileSync(f.repo.path('flag-HS-001'), 'x');
    assert.equal((await f.repo.cli(['verify', '--requirement', 'HS-001'])).code, 0);
    const ms = await until((s) => row(s, 'HS-001').state === 'verified' && s.verifiedPercent === 40, 'pass');
    assert.ok(ms < 5000);
    // STALE: a relevant file changes after verification
    writeFileSync(f.repo.path('flag-HS-001'), 'changed');
    await until((s) => row(s, 'HS-001').state === 'stale' && s.verifiedPercent === 0, 'stale');
    const s = await api();
    assert.equal(row(s, 'HS-001').implementedButStale, true, 'shown as implemented but removed from the verified numerator');
  } finally { await dash.close(); await f.repo.cleanup(); }
});

test('[LOOP-004.AC01] heartbeat freshness and substantive-progress freshness are separate clocks in the API and the page', async () => {
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }]);
  const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: 0 });
  try {
    f.live();
    const old = new Date(Date.now() - 3600_000).toISOString();
    f.setState((s) => { s.status = 'running'; s.lastProgressAt = old; });
    const s = JSON.parse((await get(dash.url + '/api/status')).body);
    assert.ok(s.controller.lastHeartbeatAt, 'heartbeat clock');
    assert.equal(s.lastSubstantiveProgressAt, old, 'progress clock');
    assert.notEqual(s.controller.lastHeartbeatAt, s.lastSubstantiveProgressAt);
    assert.ok(Date.now() - Date.parse(s.controller.lastHeartbeatAt) < 5000, 'heartbeat is fresh while progress is an hour old');
    const page = (await get(dash.url + '/')).body;
    assert.match(page, /Heartbeat \(controller alive\)/);
    assert.match(page, /Last substantive progress/);
    for (const id of ['pct', 'cats', 'current', 'ops', 'rows', 'events', 'fcat', 'fstate', 'cmds', 'budget']) assert.match(page, new RegExp(`id="${id}"`), id);
  } finally { await dash.close(); await f.repo.cleanup(); }
});

test('[LOOP-004.AC02] blocked and stale work stay in the denominator and rounding can never show 100% early', async () => {
  assert.equal(formatPercent(219, 220), 99.5);
  assert.equal(formatPercent(21999, 22000), 99.9, 'would round to 100 but must not');
  assert.equal(formatPercent(219.99, 220), 99.9);
  assert.equal(formatPercent(220, 220), 100);
  assert.equal(formatPercent(0, 220), 0);
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }, { id: 'HS-002', weight: 3, criteria: ['b'] }, { id: 'HS-003', weight: 5, criteria: ['c'] }]);
  try {
    writeFileSync(f.repo.path('flag-HS-001'), 'x');
    await f.repo.cli(['verify', '--requirement', 'HS-001']);
    f.setState((s) => { s.status = 'blocked'; s.requirements['HS-002'] = { state: 'blocked', attempts: 3, blockers: [{ type: 'attempts-exhausted', detail: 'x' }] }; s.requirements['HS-003'] = { state: 'failed', attempts: 1, blockers: [] }; });
    const st = buildStatus(f.repo.root, f.runId);
    assert.equal(st.totalWeight, 10, 'denominator is the full frozen manifest');
    assert.equal(st.verifiedWeight, 2);
    assert.equal(st.verifiedPercent, 20);
    assert.equal(st.counts.blocked, 1); assert.equal(st.counts.failed, 1); assert.equal(st.counts.verified, 1);
    assert.equal(st.totalRequirements, 3);
    assert.equal(st.requirements.reduce((n, r) => n + r.weight, 0), st.totalWeight, 'rows reconcile with the manifest');
    assert.equal(st.totalCriteria, 3);
    writeFileSync(f.repo.path('flag-HS-001'), 'edited');
    const st2 = buildStatus(f.repo.root, f.runId);
    assert.equal(st2.verifiedPercent, 0); assert.equal(st2.totalWeight, 10); assert.equal(st2.counts.stale, 1);
  } finally { await f.repo.cleanup(); }
});

test('[LOOP-004.AC03] controller death is reported as crashed immediately, by the reader, not as running', async () => {
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }]);
  const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: 0 });
  try {
    writeLease(f.L.leaseFile, { runId: f.runId, pid: 2147483000, start: 'Thu Jan  1 00:00:00 1970', seq: 9, status: 'running', role: 'controller' });
    f.setState((s) => { s.status = 'running'; });
    const s = JSON.parse((await get(dash.url + '/api/status')).body);
    assert.equal(s.status, 'crashed');
    assert.equal(s.recordedStatus, 'running');
    assert.match(s.statusReason, /not alive/);
    // a live process with an old heartbeat is stale, not running
    writeLease(f.L.leaseFile, { runId: f.runId, pid: f.pid, start: f.start, seq: 9, status: 'running', role: 'controller' });
    const lease = JSON.parse(readFileSync(f.L.leaseFile, 'utf8')); lease.wallAt = Date.now() - 30000; writeFileSync(f.L.leaseFile, JSON.stringify(lease));
    await sleep(1100);
    const s2 = JSON.parse((await get(dash.url + '/api/status')).body);
    assert.equal(s2.status, 'stale');
  } finally { await dash.close(); await f.repo.cleanup(); }
});

test('[LOOP-004.AC03] a port conflict falls back within 5s; a dashboard failure leaves status --json and status.html', async () => {
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }]);
  const squatter = net.createServer(); await new Promise((r) => squatter.listen(0, '127.0.0.1', r));
  const busy = squatter.address().port;
  try {
    const t = Date.now();
    const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: busy });
    assert.ok(Date.now() - t < 5000);
    assert.notEqual(dash.port, busy);
    assert.deepEqual(dash.conflict, { requested: busy });
    assert.equal((await get(dash.url + '/api/status')).status, 200);
    await dash.close();
    // no dashboard at all: the CLI and static fallbacks still answer truthfully
    const cli = await f.repo.cli(['status', '--json']);
    assert.equal(JSON.parse(cli.stdout).runId, f.runId);
    const html = renderStaticHtml({ ...buildStatus(f.repo.root, f.runId), status: '<script>alert(1)</script>' });
    assert.ok(!html.includes('<script>alert(1)</script>'), 'static fallback escapes text');
    assert.match(html, /&lt;script&gt;/);
    await assert.rejects(() => createDashboard({ repoRoot: f.repo.root, runId: f.runId, host: '0.0.0.0', port: 0 }), /loopback only/);
  } finally { squatter.close(); await f.repo.cleanup(); }
});

test('[LOOP-004.AC03] foreign origins, forged Host headers, traversal, writes and HTML payloads are rejected or inert', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  const f = await fixture([{ id: 'HS-001', weight: 2, title: payload, criteria: ['a'] }]);
  const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: 0 });
  try {
    assert.equal((await get(dash.url + '/api/status', { headers: { Host: 'evil.example' } })).status, 421, 'DNS-rebinding Host');
    assert.equal((await get(dash.url + '/api/status', { headers: { Origin: 'http://evil.example' } })).status, 403, 'foreign origin');
    assert.equal((await get(dash.url + '/api/status', { headers: { Origin: dash.url } })).status, 200, 'same origin is fine');
    for (const m of ['POST', 'PUT', 'DELETE', 'PATCH']) assert.equal((await get(dash.url + '/api/status', { method: m })).status, 405, m);
    for (const p of ['/..%2f..%2f..%2fetc%2fpasswd', '/%2e%2e/%2e%2e/etc/passwd', '/api/logs/..%2f..%2fetc', '/api/logs/HS-999', '/package.json', '/api/stop', '/api/pause']) {
      const r = await get(dash.url + p);
      assert.ok([404].includes(r.status), `${p} -> ${r.status}`);
      assert.ok(!/root:|node_modules/.test(r.body));
    }
    const page = await get(dash.url + '/');
    assert.equal(page.status, 200);
    assert.ok(!page.body.includes('innerHTML'), 'the page never assigns HTML');
    assert.ok(!/<script[^>]+src=/i.test(page.body) && !/https?:\/\/(?!127\.0\.0\.1)/.test(page.body.replace(/http:\/\/www\.w3\.org[^"']*/g, '')), 'no remote scripts or resources');
    const csp = page.headers['content-security-policy'];
    assert.match(csp, /default-src 'none'/);
    const nonce = /nonce-([A-Za-z0-9+/=]+)/.exec(csp)[1];
    assert.ok(page.body.includes(`nonce="${nonce}"`));
    assert.match(page.headers['x-content-type-options'], /nosniff/);
    // the hostile title is data: present in JSON as text, never in the HTML shell
    const api = (await get(dash.url + '/api/status')).body;
    assert.ok(JSON.parse(api).requirements[0].title === payload);
    assert.ok(!page.body.includes(payload));
    const sse = await new Promise((resolve) => { const r = http.get(dash.url + '/api/events', (res) => { res.once('data', (d) => { r.destroy(); resolve({ status: res.statusCode, first: String(d) }); }); }); });
    assert.equal(sse.status, 200); assert.match(sse.first, /^data: /);
  } finally { await dash.close(); await f.repo.cleanup(); }
});

test('[LOOP-004.AC04] status and log tails redact secrets, never expose prompts, and identify the run and platform', async () => {
  const f = await fixture([{ id: 'HS-001', weight: 2, criteria: ['a'] }]);
  const dash = await createDashboard({ repoRoot: f.repo.root, runId: f.runId, port: 0 });
  try {
    const dir = join(f.L.attemptsDir, 'HS-001-01'); mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'prompt.txt'), 'PROMPT-MARKER-ZZZ do the thing');
    writeFileSync(join(dir, 'stream.log'), 'using key sk-ant-api03-abcdefghijklmnop and password=hunter2hunter2 and Bearer abcdefghijklmnopqrstuv\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\nAKIAABCDEFGHIJKLMNOP');
    appendEvent(f.L, 'note', { text: 'token=supersecretvalue123 and ghp_abcdefghijklmnopqrstuvwxyz0123' });
    const logs = JSON.parse((await get(dash.url + '/api/logs/HS-001')).body).tail;
    for (const secret of ['sk-ant-api03-abcdefghijklmnop', 'hunter2hunter2', 'abcdefghijklmnopqrstuv', 'MIIEabc', 'AKIAABCDEFGHIJKLMNOP']) assert.ok(!logs.includes(secret), `leaked ${secret}`);
    assert.match(logs, /REDACTED/);
    const status = (await get(dash.url + '/api/status')).body;
    assert.ok(!status.includes('supersecretvalue123') && !status.includes('ghp_abcdefghijklmnopqrstuvwxyz0123'));
    assert.ok(!status.includes('PROMPT-MARKER-ZZZ') && !logs.includes('PROMPT-MARKER-ZZZ'), 'prompts are not exposed');
    const s = JSON.parse(status);
    assert.equal(s.runId, f.runId); assert.equal(s.platform, process.platform);
    const cli = JSON.parse((await f.repo.cli(['status', '--json'])).stdout);
    assert.ok(!JSON.stringify(cli).includes('supersecretvalue123'));
    assert.equal(cli.runId, f.runId);
  } finally { await dash.close(); await f.repo.cleanup(); }
});
