// E5-03: PII/secret canaries never persist, retention applies, sampling and unknown status are disclosed, and collection is opt-in and offline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { ALLOWED_FIELDS, applyRetention, canaryHit, ingestRuntimeRecords, normalizeRecord, normalizeRoute } from '../../src/posture/runtime-trace-ingest.js';
import { annotateRuntimeCorrelation, samplingOf } from '../../src/posture/runtime-correlation.js';

function project() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e5-03-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  return root;
}
const traceText = (root) => { try { return fs.readFileSync(path.join(root, '.agentic-security', 'runtime-trace.jsonl'), 'utf8'); } catch { return ''; } };
const metaText = (root) => { try { return fs.readFileSync(path.join(root, '.agentic-security', 'runtime-trace.meta.json'), 'utf8'); } catch { return ''; } };
const ON = { collect: true };
const NOW = Date.parse('2026-06-01T00:00:00Z');

test('off by default: no policy, or collect not true, ingests nothing and writes nothing', () => {
  const root = project();
  try {
    const rec = [{ kind: 'route-hit', route: '/a' }];
    assert.equal(ingestRuntimeRecords(root, rec).ok, false);
    assert.equal(ingestRuntimeRecords(root, rec, { policy: { collect: 'yes' } }).ok, false);
    assert.match(ingestRuntimeRecords(root, rec).reason, /not enabled/);
    assert.equal(traceText(root), ''); assert.equal(metaText(root), '');
    fs.writeFileSync(path.join(root, '.agentic-security', 'runtime-policy.json'), JSON.stringify({ collect: true }));
    assert.equal(ingestRuntimeRecords(root, rec, { now: NOW }).ok, true, 'the policy file is read from the project, with no network');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('canaries in every position never reach the file: request bodies, headers, tokens, PII, PHI, card numbers, keys', () => {
  const root = project();
  const CANARY = { email: 'jane.doe@example.com', jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456', aws: 'AKIAABCDEFGHIJKLMNOP', ssn: '123-45-6789', card: '4111 1111 1111 1111', bearer: 'Bearer abcdef1234567890xyz', phi: 'diagnosis=diabetes-type-2-patient-4471' };
  try {
    const records = [
      // dropped by the allowlist, whatever they hold
      { kind: 'route-hit', route: '/orders', body: CANARY.email, headers: { authorization: CANARY.bearer }, user: CANARY.ssn, cookie: CANARY.jwt, host: 'prod-1', payload: CANARY.phi },
      // allowed field, canary value: the record is rejected
      { kind: 'route-hit', route: `/users/${CANARY.email}/orders` },
      { kind: 'route-hit', route: `/pay/${CANARY.card}` },
      { kind: 'function-call', qid: CANARY.jwt },
      { kind: 'function-call', fileRel: `uploads/${CANARY.aws}.txt` },
      { kind: 'route-hit', route: `/x/${CANARY.ssn}` },
      { kind: 'syscall', name: 'open' },
    ];
    const r = ingestRuntimeRecords(root, records, { policy: ON, now: NOW });
    assert.equal(r.ok, true);
    const persisted = traceText(root) + metaText(root);
    for (const [name, v] of Object.entries(CANARY)) assert.ok(!persisted.includes(v), `canary ${name} was persisted`);
    for (const frag of ['jane.doe', 'eyJhbGci', 'AKIAABC', '123-45-6789', '4111', 'abcdef1234567890', 'diabetes', 'authorization', 'prod-1']) assert.ok(!persisted.includes(frag), `fragment ${frag} was persisted`);
    assert.equal(r.accepted, 2, 'the route-hit with dropped fields and the syscall survive, rebuilt from the allowlist');
    assert.deepEqual(JSON.parse(traceText(root).split('\n')[0]), { kind: 'route-hit', route: '/orders', ts: new Date(NOW).toISOString() });
    assert.deepEqual(Object.keys(r.droppedFields).sort(), ['body', 'cookie', 'headers', 'host', 'payload', 'user']);
    assert.ok(r.rejected['canary:email'] >= 1 && r.rejected['canary:ssn'] >= 1 && r.rejected['canary:jwt'] >= 1 && r.rejected['canary:cloud-key'] >= 1);
    assert.equal(r.rejected['bad-route'], 1, 'a card number with spaces is not a path at all');
    assert.equal(Object.values(r.rejected).reduce((a, b) => a + b, 0), 5);
    // a card number that IS path-shaped is generalised to :id before anything is stored, and the Luhn canary catches it in a non-route field
    assert.equal(normalizeRecord({ kind: 'route-hit', route: '/pay/4111111111111111' }).record.route, '/pay/:id');
    assert.equal(canaryHit('order 4111 1111 1111 1111'), 'payment-card');
    assert.equal(canaryHit('order 4111 1111 1111 1112'), null, 'a digit run that fails the Luhn check is not a card');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a route keeps its path only: query, fragment and id-like segments are gone; non-paths are refused', () => {
  assert.equal(normalizeRoute('/users/42/orders/9f1c2d3e-0000-4000-8000-123456789abc?token=SECRET#frag'), '/users/:id/orders/:id');
  assert.equal(normalizeRoute('https://api.example.com/v1/items/77?q=jane@example.com'), '/v1/items/:id');
  assert.equal(normalizeRoute('/files/deadbeefdeadbeefdeadbeef'), '/files/:id');
  for (const bad of ['not a path', '/a b', '', 7, null, '/x<script>', 'javascript:alert(1)']) assert.equal(normalizeRoute(bad), null, String(bad));
  const n = normalizeRecord({ kind: 'route-hit', route: '/u/5?email=a@b.co' });
  assert.equal(n.record.route, '/u/:id');
});

test('values must fit their field; unknown kinds and malformed records are rejected, none throw', () => {
  const bad = [
    [{ kind: 'route-hit' }, 'route-hit-without-route'], [{ kind: 'function-call' }, 'function-call-without-symbol'], [{ kind: 'mystery' }, 'unknown-kind'],
    [{ kind: 'function-call', qid: 'has spaces and ;' }, 'bad-symbol'], [{ kind: 'function-call', fileRel: '../../etc/passwd' }, 'bad-file'], [{ kind: 'function-call', fileRel: '/abs/path.js' }, 'bad-file'],
    [{ kind: 'syscall', name: 'Open File' }, 'bad-name'], [{ kind: 'function-call', qid: 'a.b', line: -1 }, 'bad-line'], [{ kind: 'function-call', qid: 'a.b', count: 1.5 }, 'bad-count'],
    [{ kind: 'route-hit', route: '/a', ts: 'yesterday' }, 'bad-timestamp'], [{ kind: 'route-hit', route: '/a', commit: 'has space' }, 'bad-commit'],
    [null, 'not-an-object'], [[], 'not-an-object'], ['x', 'not-an-object'],
  ];
  for (const [rec, why] of bad) assert.equal(normalizeRecord(rec).rejected, why, JSON.stringify(rec));
  const ok = normalizeRecord({ kind: 'function-call', qid: 'com.acme.UserController.getUser', fileRel: 'src/UserController.java', line: 42, count: 9, commit: 'a'.repeat(40), environment: 'production' });
  assert.deepEqual(Object.keys(ok.record).sort(), ['commit', 'count', 'environment', 'fileRel', 'kind', 'line', 'qid']);
  for (const k of Object.keys(ok.record)) assert.ok(ALLOWED_FIELDS.includes(k));
  assert.equal(canaryHit('com.acme.UserController.getUser'), null); assert.equal(canaryHit('/users/:id/orders'), null);
  assert.equal(canaryHit('x'.repeat(60)), 'opaque-string');
});

test('retention: records older than the window are removed on ingest and by applyRetention; the count is disclosed', () => {
  const root = project();
  const day = 86400_000;
  try {
    ingestRuntimeRecords(root, [{ kind: 'route-hit', route: '/old', ts: new Date(NOW - 40 * day).toISOString() }, { kind: 'route-hit', route: '/recent', ts: new Date(NOW - 2 * day).toISOString() }], { policy: { collect: true, retentionDays: 30 }, now: NOW - 1 });
    // the file may be written with the old record present; the next write or an explicit pass removes it
    const r = ingestRuntimeRecords(root, [{ kind: 'route-hit', route: '/new', ts: new Date(NOW).toISOString() }], { policy: { collect: true, retentionDays: 30 }, now: NOW });
    const text = traceText(root);
    assert.ok(!text.includes('/old'), 'the 40-day-old record was removed'); assert.ok(text.includes('/recent') && text.includes('/new'));
    assert.equal(r.expired, 1); assert.equal(JSON.parse(metaText(root)).totals.expiredByRetention, 1);
    const later = applyRetention(root, { retentionDays: 1, now: NOW });
    assert.equal(later.removed, 1, '/recent is now outside a one-day window'); assert.ok(!traceText(root).includes('/recent'));
    assert.deepEqual(applyRetention(project(), { now: NOW }), { removed: 0, kept: 0 }, 'no file is not an error');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('sampling and unknown status are disclosed: a sampled or undeclared trace never says "not observed"', async () => {
  const finding = () => [{ id: 'f', severity: 'high', file: 'src/a.js', line: 10, scope: 'never.called' }];
  const run = async (opts) => {
    const root = project();
    try {
      ingestRuntimeRecords(root, [{ kind: 'function-call', qid: 'other.fn', fileRel: 'src/b.js', line: 1 }], { policy: ON, now: Date.now(), ...opts });
      const f = finding(); await annotateRuntimeCorrelation(root, f, {});
      return { f: f[0], meta: JSON.parse(metaText(root)) };
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  };
  const full = await run({ sampleRate: 1 });
  assert.equal(full.f.runtimeObserved, false); assert.equal(full.f.runtimeEvidence.state, 'not_observed_in_window'); assert.equal(full.f.runtimeEvidence.sampling.state, 'complete');
  const sampled = await run({ sampleRate: 0.05 });
  assert.equal(sampled.f.runtimeObserved, 'unknown', 'a 5% sample cannot show that something did not run'); assert.equal(sampled.f.runtimeEvidence.sampling.state, 'sampled'); assert.equal(sampled.f.runtimeEvidence.sampling.rate, 0.05);
  const undeclared = await run({});
  assert.equal(undeclared.f.runtimeObserved, 'unknown'); assert.equal(undeclared.f.runtimeEvidence.sampling.state, 'undisclosed'); assert.equal(undeclared.meta.samplingDisclosed, false);
  assert.equal(samplingOf(null).state, 'undisclosed');
  const seen = await (async () => { const root = project(); try { ingestRuntimeRecords(root, [{ kind: 'function-call', qid: 'never.called' }], { policy: ON, sampleRate: 0.05 }); const f = finding(); await annotateRuntimeCorrelation(root, f, {}); return f[0]; } finally { fs.rmSync(root, { recursive: true, force: true }); } })();
  assert.equal(seen.runtimeObserved, true, 'an observation is still an observation under sampling');
});

test('the meta record holds counts only, never a dropped or rejected value', () => {
  const root = project();
  try {
    ingestRuntimeRecords(root, [{ kind: 'route-hit', route: '/a', secretField: 'sk_live_abcdefghijklmnop' }, { kind: 'route-hit', route: '/u/me@x.com' }], { policy: ON, now: NOW });
    const meta = metaText(root);
    assert.ok(!meta.includes('sk_live') && !meta.includes('me@x.com'));
    const m = JSON.parse(meta); assert.equal(m.totals.droppedFields.secretField, 1); assert.equal(m.totals.rejected['canary:email'], 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
