// Tests for entrypoint-inventory.js — attack-surface completeness inventory
// (addition #2). Enumerates every attacker-reachable entry point across a
// codebase and assigns each a disposition, producing an auditable coverage
// ledger.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildEntrypointInventory,
  annotateEntrypointCoverage,
} from '../src/posture/entrypoint-inventory.js';

// ── Fixture: five distinct entry-point surfaces ────────────────────────────
// Four are discovered by regex over fileContents; the fifth (HTTP) is supplied
// out-of-band via opts.routes, mirroring how the engine hands routes to
// annotators. Each source file is crafted to trigger exactly ONE surface type
// so the byType ledger is unambiguous.
const KAFKA_FILE = 'src/consumers/OrderConsumer.java';
const CLI_FILE = 'src/cli.js';
const ENV_FILE = 'src/config.js';
const UPLOAD_FILE = 'src/routes/upload.js';
const ROUTE_FILE = 'src/routes/users.js';

const files = {
  [KAFKA_FILE]: [
    '@Service',
    'public class OrderConsumer {',
    '  @KafkaListener(topics = "orders")',
    '  public void handle(String message) {',
    '    orderService.process(message);',
    '  }',
    '}',
  ].join('\n'),
  [CLI_FILE]: [
    'const args = process.argv.slice(2);',
    'run(args);',
  ].join('\n'),
  [ENV_FILE]: 'export const secret = process.env.SECRET;',
  [UPLOAD_FILE]: [
    "import multer from 'multer';",
    "const upload = multer({ dest: 'uploads/' });",
  ].join('\n'),
};

const routes = [
  {
    method: 'GET', path: '/users/:id', file: ROUTE_FILE, line: 12,
    handler: 'getUser', params: ['id'], hasAuth: false,
  },
];

test('entrypoint-inventory: discovers all five surface types', () => {
  const inv = buildEntrypointInventory(files, { routes });
  for (const t of ['http', 'queue', 'cli', 'env', 'upload']) {
    assert.ok(inv.entrypoints.some(e => e.type === t), `${t} surface missing`);
  }
  // The Kafka listener is a queue entrypoint on the right file/line.
  const q = inv.entrypoints.find(e => e.type === 'queue');
  assert.equal(q.file, KAFKA_FILE);
  assert.equal(q.line, 3);
});

test('entrypoint-inventory: coverage.byType + total are exact', () => {
  const inv = buildEntrypointInventory(files, { routes });
  assert.equal(inv.coverage.total, 5);
  assert.deepEqual(inv.coverage.byType, {
    http: 1, queue: 1, cron: 0, cli: 1, env: 1, upload: 1, webhook: 0,
  });
});

test('entrypoint-inventory: every entrypoint has the required fields', () => {
  const inv = buildEntrypointInventory(files, { routes });
  const TYPES = new Set(['http', 'queue', 'cron', 'cli', 'env', 'upload', 'webhook']);
  for (const e of inv.entrypoints) {
    assert.ok(TYPES.has(e.type), `bad type ${e.type}`);
    assert.ok(typeof e.file === 'string' && e.file.length, 'file');
    assert.ok(Number.isInteger(e.line), 'line');
    assert.ok(typeof e.name === 'string' && e.name.length, 'name');
    assert.ok(['authenticated', 'unauthenticated'].includes(e.trust), `trust ${e.trust}`);
    assert.ok(typeof e.disposition === 'string' && e.disposition.length, 'disposition');
  }
});

test('entrypoint-inventory: default disposition is traced-safe', () => {
  const inv = buildEntrypointInventory(files, { routes });
  assert.equal(inv.entrypoints.find(e => e.type === 'queue').disposition, 'traced-safe');
  assert.equal(inv.coverage.finding, 0);
});

test('entrypoint-inventory: a finding on the consumer file flips its disposition to finding', () => {
  const findings = [{ file: KAFKA_FILE, line: 4, vuln: 'Unsafe deserialization', severity: 'high' }];
  const inv = buildEntrypointInventory(files, { routes, findings });
  const q = inv.entrypoints.find(e => e.type === 'queue');
  assert.equal(q.disposition, 'finding');
  assert.equal(inv.coverage.finding, 1);
  // The other four surfaces have no finding on their file.
  assert.equal(inv.coverage.total, 5);
  assert.equal(inv.coverage.tracedSafe + inv.coverage.noInput + inv.coverage.notReachable, 4);
});

test('entrypoint-inventory: accepts a Map as well as a plain object', () => {
  const map = new Map(Object.entries(files));
  const inv = buildEntrypointInventory(map, { routes });
  assert.equal(inv.coverage.total, 5);
  assert.equal(inv.coverage.byType.upload, 1);
});

test('entrypoint-inventory: a route whose path contains webhook is typed webhook', () => {
  const inv = buildEntrypointInventory({}, {
    routes: [{ method: 'POST', path: '/stripe/webhook', file: 'src/pay.js', line: 3 }],
  });
  assert.equal(inv.entrypoints.length, 1);
  assert.equal(inv.entrypoints[0].type, 'webhook');
  assert.equal(inv.coverage.byType.webhook, 1);
  assert.equal(inv.coverage.byType.http, 0);
});

test('entrypoint-inventory: a /webhook string literal is discovered from file content', () => {
  const inv = buildEntrypointInventory({
    'src/hooks.js': "app.post('/webhook/github', githubHandler);",
  }, {});
  assert.ok(inv.entrypoints.some(e => e.type === 'webhook'));
});

test('entrypoint-inventory: cron surfaces (@Scheduled, cron.schedule, setInterval) are discovered', () => {
  const inv = buildEntrypointInventory({
    'a.java': '@Scheduled(fixedRate = 1000)\nvoid tick() {}',
    'b.js': "cron.schedule('* * * * *', job);",
    'c.js': 'setInterval(poll, 5000);',
  }, {});
  assert.equal(inv.coverage.byType.cron, 3);
});

test('entrypoint-inventory: a nearby auth token marks the entrypoint authenticated', () => {
  const inv = buildEntrypointInventory({
    'src/admin.js': [
      "import { requireAuth } from './mw.js';",
      'const args = process.argv.slice(2);',
    ].join('\n'),
  }, {});
  assert.equal(inv.entrypoints.find(e => e.type === 'cli').trust, 'authenticated');
});

test('entrypoint-inventory: null / empty inputs give a zeroed ledger', () => {
  const ZERO = { http: 0, queue: 0, cron: 0, cli: 0, env: 0, upload: 0, webhook: 0 };
  for (const inv of [
    buildEntrypointInventory(null),
    buildEntrypointInventory({}),
    buildEntrypointInventory(undefined, undefined),
  ]) {
    assert.deepEqual(inv.entrypoints, []);
    assert.equal(inv.coverage.total, 0);
    assert.deepEqual(inv.coverage.byType, ZERO);
    assert.equal(inv.coverage.tracedSafe, 0);
    assert.equal(inv.coverage.finding, 0);
  }
});

// ── annotateEntrypointCoverage ─────────────────────────────────────────────

test('annotateEntrypointCoverage: never throws on an empty scan', () => {
  assert.doesNotThrow(() => annotateEntrypointCoverage({}));
  const scan = {};
  annotateEntrypointCoverage(scan);
  assert.ok(scan.entrypointInventory);
  assert.equal(scan.entrypointInventory.coverage.total, 0);
  assert.deepEqual(scan.entrypointInventory.entrypoints, []);
});

test('annotateEntrypointCoverage: tolerates null / undefined / non-object', () => {
  assert.doesNotThrow(() => annotateEntrypointCoverage(null));
  assert.doesNotThrow(() => annotateEntrypointCoverage(undefined));
  assert.doesNotThrow(() => annotateEntrypointCoverage(42));
});

test('annotateEntrypointCoverage: builds from scan.fileContents/routes/findings', () => {
  const scan = {
    fileContents: files,
    routes,
    findings: [{ file: KAFKA_FILE, line: 4, vuln: 'x', severity: 'high' }],
  };
  const out = annotateEntrypointCoverage(scan);
  assert.equal(out, scan, 'returns the same scan object');
  assert.equal(scan.entrypointInventory.coverage.total, 5);
  assert.equal(scan.entrypointInventory.coverage.finding, 1);
});

test('annotateEntrypointCoverage: reads the _fileContents alias', () => {
  const scan = { _fileContents: files, routes: [] };
  annotateEntrypointCoverage(scan);
  // four regex-discovered surfaces (no routes passed here)
  assert.equal(scan.entrypointInventory.coverage.total, 4);
});
