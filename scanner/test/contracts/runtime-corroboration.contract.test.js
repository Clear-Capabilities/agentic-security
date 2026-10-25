// Contract test for runtime corroboration (docs/reference/runtime-corroboration-contract.md).
//
// The adapters are tested against files the REAL tools wrote (test/fixtures/telemetry-packs, recorded by the hosted `telemetry-capture`
// job): the OpenTelemetry SDK's OTLP exporter, Envoy, nginx and a kind cluster's kube-apiserver audit log. The packs are checked against
// their manifest so a hand-edited one is caught, each adapter must parse its pack with no error and produce records the observation
// contract accepts, nothing that could carry a payload may survive into a record, and the decisions must follow the source's own
// outcomes. The status report, status values, edge states and adapter list are held to the page's tables in both directions, and the
// CLI is run end to end over the packs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  parseOtelJsonObservations, parseEnvoyAccessLogObservations, parseK8sAuditLogObservations, parseHttpAccessLogObservations, adapterFor,
} from '../../src/lineage/observation-adapters.js';
import { RUNTIME_OBSERVATION_VERSION, validateRuntimeObservation } from '../../src/lineage/runtime-observation.js';
import { matchObservationToGraph } from '../../src/lineage/observation-correlation.js';
import { observationId } from '../../src/lineage/ids.js';
import { computeRuntimeAssurance, RUNTIME_STATUS_VALUES } from '../../src/lineage/runtime-assurance.js';
import { EDGE_STATES } from '../../src/lineage/runtime-edge-states.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PACKS = path.join(HERE, '..', 'fixtures', 'telemetry-packs');
const APP = path.join(HERE, '..', 'fixtures', 'runtime-twin', 'app');
const CLI = path.join(HERE, '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/runtime-corroboration-contract.md');
const MANIFEST = JSON.parse(fs.readFileSync(path.join(PACKS, 'MANIFEST.json'), 'utf8'));
const read = (rel) => fs.readFileSync(path.join(PACKS, rel), 'utf8');
const lines = (rel) => read(rel).split('\n').filter(Boolean).map((l) => JSON.parse(l));

const ctx = (adapter) => ({
  version: RUNTIME_OBSERVATION_VERSION, adapter, source: `${adapter}:telemetry-pack`, environment: 'production',
  windowStart: '2026-10-20T00:00:00.000Z', windowEnd: '2026-10-21T00:00:00.000Z', importedAt: '2026-10-21T12:00:00.000Z', retention: { expiresAt: null },
});
const roundTrip = (draft) => validateRuntimeObservation({
  ...draft, id: observationId(draft, [JSON.stringify(draft.attributes)]), ...matchObservationToGraph({ nodes: [], edges: [], flows: [] }, draft),
});

const PACK = {
  'otel-json': { file: 'otel/traces.otlp.json', parse: parseOtelJsonObservations },
  'envoy-access-log': { file: 'envoy/access.jsonl', parse: parseEnvoyAccessLogObservations },
  'k8s-audit-log': { file: 'k8s/audit.jsonl', parse: parseK8sAuditLogObservations },
  'http-access-log': { file: 'http/access.jsonl', parse: parseHttpAccessLogObservations },
};
const parsed = (name) => PACK[name].parse(read(PACK[name].file), ctx(name));

test('contract: every pack matches its manifest entry (digest, size, a named tool and version, a Linux host), so a hand-edited pack is caught', () => {
  assert.equal(MANIFEST.packs.length, 4);
  assert.deepEqual(MANIFEST.packs.map((p) => p.source).sort(), ['envoy', 'http', 'k8s', 'otel']);
  for (const p of MANIFEST.packs) {
    const text = read(`${p.source}/${p.file}`);
    assert.equal(crypto.createHash('sha256').update(text).digest('hex'), p.sha256, `${p.source} digest`);
    assert.equal(Buffer.byteLength(text), p.bytes, `${p.source} size`);
    assert.ok(p.tool && p.version && p.command && p.recordedAt, `${p.source} names the tool that wrote it`);
    assert.match(p.host, /^linux-/, 'recorded on the hosted Linux runner');
  }
  const tampered = read('envoy/access.jsonl').replace('"UF"', '"OK"');
  assert.notEqual(crypto.createHash('sha256').update(tampered).digest('hex'), MANIFEST.packs.find((p) => p.source === 'envoy').sha256, 'the check can fail');
});

test('contract: each adapter parses the file the real tool wrote with no error, and every record passes the observation contract', () => {
  const expected = { 'otel-json': 3, 'envoy-access-log': 6, 'http-access-log': 4, 'k8s-audit-log': 79 };
  for (const name of Object.keys(PACK)) {
    const { drafts, errors } = parsed(name);
    assert.deepEqual(errors, [], `${name} errors`);
    assert.equal(drafts.length, expected[name], `${name} drafts`);
    for (const d of drafts) assert.deepEqual(roundTrip(d), { valid: true, errors: [] }, `${name}: ${JSON.stringify(d.attributes)}`);
  }
});

test('contract: nothing that could carry a payload survives into a record (ids, identities, addresses, agents, paths and queries)', () => {
  const dropped = {
    'otel-json': [...read('otel/traces.otlp.json').matchAll(/"(?:traceId|spanId)":"([0-9a-f]+)"/g)].map((m) => m[1]),
    'k8s-audit-log': (() => {
      const events = lines('k8s/audit.jsonl');
      // a name that is also some event's namespace or resource is legitimately in the output; everything else must be gone
      const kept = new Set(events.flatMap((e) => [e.objectRef?.namespace, e.objectRef?.resource]));
      return [...new Set(events.flatMap((e) => [e.auditID, e.user?.username, e.userAgent, e.requestURI, ...(e.sourceIPs || []), e.objectRef?.name]))].filter((v) => v && !kept.has(v));
    })(),
    'envoy-access-log': [],
    'http-access-log': [],
  };
  for (const [name, values] of Object.entries(dropped)) {
    const text = JSON.stringify(parsed(name).drafts);
    for (const v of values) assert.ok(!text.includes(v), `${name} kept ${v}`);
  }
  assert.ok(dropped['otel-json'].length >= 6 && dropped['k8s-audit-log'].length > 20, 'the check had real values to look for');
});

test('contract: OpenTelemetry spans become the destination, the store and the topic, with the service name', () => {
  const attrs = parsed('otel-json').drafts.map((d) => d.attributes);
  assert.ok(attrs.every((a) => a['service.name'] === 'orders-api'));
  assert.ok(attrs.some((a) => a['destination.host'] === 'api.payments.example' && a['destination.port'] === 443 && a['destination.scheme'] === 'https'));
  assert.ok(attrs.some((a) => a['destination.service'] === 'postgresql' && a['destination.host'] === 'db.internal'));
  assert.ok(attrs.some((a) => a['destination.service'] === 'orders-created'));
});

test('contract: Envoy flags decide only when they are an authorization outcome: no flag is allowed, UF and NR carry no decision, none is denied', () => {
  const raw = lines('envoy/access.jsonl');
  const decisions = parsed('envoy-access-log').drafts.map((d) => d.attributes['network.securityDecision']);
  assert.deepEqual(raw.map((r) => r.response_flags), ['-', '-', '-', '-', 'UF', 'NR']);
  assert.deepEqual(decisions, ['allowed', 'allowed', 'allowed', 'allowed', undefined, undefined]);
  assert.ok(!decisions.includes('denied'), 'a failed upstream and a missing route are not denials');
});

test('contract: Kubernetes decisions follow the response code on the real audit log: 401 and 403 denied, below 400 allowed, 404 and 409 no claim', () => {
  const raw = lines('k8s/audit.jsonl').map((e) => e.responseStatus.code);
  const decisions = parsed('k8s-audit-log').drafts.map((d) => d.attributes['network.securityDecision']);
  assert.equal(decisions.length, raw.length);
  raw.forEach((code, i) => {
    const want = code < 400 ? 'allowed' : (code === 401 || code === 403) ? 'denied' : undefined;
    assert.equal(decisions[i], want, `event ${i} with code ${code}`);
  });
  assert.ok(raw.includes(403) && raw.includes(404) && raw.includes(409), 'the export holds a denial and the operational errors a naive rule would call denials');
  assert.equal(decisions.filter((d) => d === 'denied').length, raw.filter((c) => c === 403 || c === 401).length);
});

test('contract: the nginx access log yields the host, the upstream and the scheme, and the path and query it never wrote stay out', () => {
  const attrs = parsed('http-access-log').drafts.map((d) => d.attributes);
  assert.deepEqual(attrs.map((a) => a['destination.host']), ['127.0.0.1', 'shop.example', 'api.example', 'shop.example']);
  assert.ok(attrs.every((a) => a['destination.scheme'] === 'http' && /:\d+$/.test(a['destination.service'])));
  assert.ok(!JSON.stringify(attrs).includes('token='));
});

test('contract: the adapters on the page are the ones that exist, and a name that is not on it is refused', () => {
  const documented = fieldsUnder(PAGE, 'Adapters');
  assert.deepEqual([...documented].sort(), ['envoy-access-log', 'http-access-log', 'k8s-audit-log', 'native-jsonl', 'otel-json']);
  for (const name of documented) assert.ok(adapterFor(name), name);
  for (const bad of ['otlp', 'OTEL-JSON', 'fluentd', '']) assert.equal(adapterFor(bad), null, bad);
  assert.deepEqual(Object.keys(PACK).sort(), documented.filter((n) => n !== 'native-jsonl').sort(), 'every pack-tested adapter is documented');
});

test('contract: the status report has exactly the documented fields, and the values and their conditions are the documented ones', () => {
  const now = '2026-10-21T00:00:00.000Z';
  const rec = (obs, over = {}) => [{ windowStart: '2026-10-20T00:00:00.000Z', windowEnd: '2026-10-21T00:00:00.000Z', importedAt: '2026-10-20T23:00:00.000Z', observations: obs, ...over }];
  const ob = (matchMethod, last = '2026-10-20T22:00:00.000Z') => ({ matchMethod, lastObservedAt: last });
  const evaluated = { evaluated: true };
  const none = computeRuntimeAssurance({ importRecords: null, correlation: null, now });
  sameFields(none, fieldsUnder(PAGE, 'Status report'), 'status report');
  assert.throws(() => sameFields({ ...none, extra: 1 }, fieldsUnder(PAGE, 'Status report'), 'x'));
  assert.deepEqual([...RUNTIME_STATUS_VALUES].sort(), fieldsUnder(PAGE, 'Runtime status').sort());
  assert.equal(none.runtimeStatus, 'unavailable');
  assert.equal(none.missingTelemetry, true);
  assert.equal(computeRuntimeAssurance({ importRecords: rec([ob('destination_literal')]), correlation: evaluated, now }).runtimeStatus, 'complete');
  assert.equal(computeRuntimeAssurance({ importRecords: rec([ob('destination_literal'), ob('unmatched')]), correlation: evaluated, now }).runtimeStatus, 'partial');
  assert.equal(computeRuntimeAssurance({ importRecords: rec([ob('destination_literal', '2026-08-01T00:00:00.000Z')]), correlation: evaluated, now }).runtimeStatus, 'partial', 'stale telemetry');
  assert.equal(computeRuntimeAssurance({ importRecords: rec([]), correlation: evaluated, now }).runtimeStatus, 'partial', 'an import with no observations');
  assert.equal(computeRuntimeAssurance({ importRecords: rec([ob('destination_literal')]), correlation: { evaluated: false }, now }).runtimeStatus, 'unavailable', 'nothing was correlated');
  const partial = computeRuntimeAssurance({ importRecords: rec([ob('unmatched')]), correlation: evaluated, now });
  assert.ok(partial.limitations.length >= 1 && partial.mappingPercentage === 0);
});

test('contract: the edge states on the page are the six the implementation derives', () => {
  assert.deepEqual([...EDGE_STATES].sort(), fieldsUnder(PAGE, 'Edge states').sort());
  assert.equal(EDGE_STATES.length, 6);
});

// ---------------------------------------------------------------------------------------------------- the command, over the real packs
const run = (cwd, a, env = {}) => spawnSync(process.execPath, [CLI, ...a], { cwd, encoding: 'utf8', timeout: 120000, env: { ...process.env, ...env } });

test('contract: the command exits 0, 1 and 2 as documented, and every real pack imports end to end with its unmatched records counted, not dropped', () => {
  for (const code of ['`0`', '`1`', '`2`']) assert.ok(PAGE.includes(`| ${code} |`), code);
  const fx = createGitFixture();
  try {
    fx.writeFile('app.js', fs.readFileSync(path.join(APP, 'app.js'), 'utf8'));
    fx.writeFile('package.json', fs.readFileSync(path.join(APP, 'package.json'), 'utf8'));
    fx.commit('app');
    const noGraph = run(fx.root, ['runtime', 'status', '.']);
    assert.equal(noGraph.status, 1, 'no scanned graph');
    assert.equal(run(fx.root, ['scan', '.'], { AGENTIC_SECURITY_LINEAGE_DEEP: '1' }).status <= 3, true);
    const status = run(fx.root, ['runtime', 'status', '.']);
    assert.equal(status.status, 0, status.stderr);
    assert.equal(JSON.parse(status.stdout).runtimeStatus, 'unavailable');
    const window = ['--window-start', '2026-10-20T00:00:00.000Z', '--window-end', '2026-10-21T00:00:00.000Z'];
    const bad = run(fx.root, ['runtime', 'ingest', '.', '--adapter', 'fluentd', '--input', path.join(PACKS, 'envoy/access.jsonl'), ...window, '--yes']);
    assert.equal(bad.status, 2, 'an adapter that is not documented');
    let total = 0;
    for (const [name, p] of Object.entries(PACK)) {
      const r = run(fx.root, ['runtime', 'ingest', '.', '--adapter', name, '--input', path.join(PACKS, p.file), '--environment', 'production', ...window, '--yes']);
      assert.equal(r.status, 0, `${name}: ${r.stderr}`);
      const out = JSON.parse(r.stdout);
      assert.equal(out.recordCount, parsed(name).drafts.length, `${name} records`);
      assert.equal(out.matched + out.unmatched, out.recordCount, `${name}: nothing is dropped`);
      assert.equal(out.written, true);
      total += out.recordCount;
    }
    const after = JSON.parse(run(fx.root, ['runtime', 'status', '.', '--environment', 'production']).stdout);
    assert.equal(after.totalObservationCount, total);
    assert.equal(after.runtimeStatus, 'partial', 'real exports of systems unrelated to the scanned code leave unmatched observations');
    assert.ok(after.unmatchedObservationCount > 0 && after.mappingPercentage < 100);
  } finally { fx.cleanup(); }
});
