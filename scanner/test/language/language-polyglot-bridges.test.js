// X-006: polyglot and deployment/configuration bridges. Tests are tagged [X-006.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePolyglotBridges, blastRadius } from '../../src/language/bridges.js';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'language-bridges');
function readTree(dir) {
  const out = {};
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else out[path.relative(dir, p)] = fs.readFileSync(p, 'utf8'); } };
  walk(dir);
  return out;
}
const result = () => analyzePolyglotBridges(readTree(DIR));
const find = (list, pred) => list.find(pred);

test('[X-006.AC01] Haskell HTTP client links to a JavaScript service with a labeled field path', () => {
  const r = result();
  const b = find(r.bridges, (x) => x.kind === 'http' && x.from.language === 'haskell' && x.to.language === 'javascript');
  assert.ok(b, 'http bridge exists');
  assert.equal(b.status, 'linked');
  assert.equal(b.from.root, 'haskell-client'); assert.equal(b.to.root, 'orders-api');
  assert.match(b.to.file, /orders-api\/server\.js$/); assert.ok(Number.isInteger(b.from.line) && Number.isInteger(b.to.line));
  assert.deepEqual(b.fields.map((f) => f.name), ['email']);
  assert.ok(b.clientOnlyFields.includes('sku'), 'a client-only field is not linked');
  assert.ok(b.serverOnlyFields.includes('quantity'));
  assert.ok(b.evidence.some((e) => /listener port 8080|port 8080/.test(e)));
});

test('[X-006.AC01] a queue bridge links Haskell AMQP to a Python consumer by literal name and the same broker technology', () => {
  const r = result();
  const b = find(r.bridges, (x) => x.kind === 'queue' && x.queue === 'orders-events');
  assert.ok(b); assert.equal(b.status, 'linked'); assert.equal(b.protocol, 'amqp');
  assert.deepEqual(b.fields.map((f) => f.name), ['orderId']);
  assert.ok(b.limitations.some((l) => /broker/.test(l)), 'broker identity limitation is disclosed');
});

test('[X-006.AC01] a store bridge links a Haskell INSERT to a Python SELECT over the same literal database', () => {
  const r = result();
  const b = find(r.bridges, (x) => x.kind === 'store');
  assert.ok(b); assert.equal(b.database, 'shop'); assert.deepEqual(b.fields.map((f) => f.name), ['customers.email']);
});

test('[X-006.AC01] a Nix environment variable is linked only to the application the service launches', () => {
  const r = result();
  const b = find(r.bridges, (x) => x.kind === 'env' && x.fields[0].name === 'DB_NAME');
  assert.ok(b); assert.equal(b.from.language, 'nix'); assert.equal(b.to.root, 'orders-api');
  assert.match(b.evidence[0], /orders-api/);
  assert.deepEqual(r.bridges.filter((x) => x.kind === 'env').map((x) => x.fields[0].name), ['DB_NAME']);
});

test('[X-006.AC02] a name-only match is a candidate, never a proven flow', () => {
  const r = result();
  assert.ok(find(r.candidates, (c) => c.kind === 'env' && c.evidence[0].includes('SHARED_MODE')), 'SHARED_MODE is a candidate');
  assert.ok(!r.bridges.some((x) => x.kind === 'env' && x.fields[0].name === 'SHARED_MODE'));
});

test('[X-006.AC02] ambiguous service mapping is a candidate', () => {
  const r = result();
  const c = find(r.candidates, (x) => x.kind === 'http' && /health/.test(x.evidence[0]));
  assert.ok(c); assert.match(c.reason, /ambiguous service mapping/); assert.equal(c.to.length, 2);
});

test('[X-006.AC02] dynamic, mismatched, and unsupported cases are gaps with reasons', () => {
  const r = result();
  const reasons = r.gaps.map((g) => g.reason).join('\n');
  assert.match(reasons, /dynamic endpoint/);
  assert.match(reasons, /schema mismatch: a service listens on port 8080 but declares no POST \/api\/refunds/);
  assert.match(reasons, /unsupported protocol "ws"/);
  assert.match(reasons, /different or unsupported protocol/, 'a kafka consumer and an amqp producer sharing one name do not link');
  assert.ok(!r.bridges.some((b) => /refunds|ws|legacy/.test(b.to.file + (b.queue || ''))));
});

test('[X-006.AC02] a comment that looks like a route declares nothing', () => {
  const r = result();
  assert.ok(!r.bridges.concat(r.candidates).some((x) => JSON.stringify(x).includes('/api/ghost')));
});

test('[X-006.AC03] blast radius follows evidenced data links only, inclusion is reported separately', () => {
  const r = result();
  const down = blastRadius(r, 'haskell-client');
  assert.deepEqual(down.roots, ['orders-api', 'reports', 'worker']);
  assert.ok(!down.roots.includes('billing'), 'an ambiguous candidate is never followed');
  assert.deepEqual(down.inclusions, []);
  const up = blastRadius(r, 'orders-api', { direction: 'upstream' });
  assert.deepEqual(up.roots, ['deploy', 'haskell-client']);
  const withInc = blastRadius(r, 'haskell-client', { includeInclusions: true });
  assert.ok(withInc.inclusions.every((i) => i.kind === 'service-includes-application'));
  assert.ok(r.inclusions.some((i) => i.service === 'orders-svc' && i.root === 'orders-api'), 'service inclusion is a separate record');
  assert.ok(r.bridges.every((b) => b.scope === 'static-source'));
});
