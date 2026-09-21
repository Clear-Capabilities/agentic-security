// Next-gen taint capability #7 — cross-service schema-driven taint rebuild.
//
// `dataflow/cross-service-taint.js` runs BY DEFAULT (opt-out only, via
// AGENTIC_SECURITY_NO_CROSS_SERVICE=1) but was found, via direct
// reproduction, to be a complete structural no-op for its own stated
// purpose:
//
//   1. `upstreamTaintContract`'s HTTP path matcher did a crude substring
//      check (`expose.route.includes(edge.path)`), but the module's OWN
//      header comment documents the two sides using DIFFERENT placeholder
//      syntaxes (`:userId` on `exposes[].route`, `{userId}` on
//      `edges[].path`) — that substring check could never succeed on the
//      exact example it exists to describe.
//   2. `annotateCrossServiceFindings` matched declared field names against
//      `f.source.snippet`/`f.source.expr`/`f.snippet` — fields that never
//      exist on a real finding (the real shape, from `engine.js`, is
//      `f.source = {file, line, label}`). Every real IR-TAINT finding
//      produced `sourceExpr = ''`, so nothing could ever match.
//   3. Even had #2 worked, `report/index.js`'s `normalizeFindings`
//      allowlist never named `crossService`/`_severityBumpReason`, so the
//      annotation (though not the bare `severity` value it changed) was
//      silently dropped before reaching any report output.
//
// The sole pre-existing test (`test/world-class-modules.test.js`) never
// caught any of this: it fed a hand-fabricated `{snippet: 'process(amount)'}`
// finding no real detector produces, and only exercised the Kafka path,
// never HTTP.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';
import {
  upstreamTaintContract,
  annotateCrossServiceFindings,
  runCrossServiceTaint,
  _internals,
} from '../src/dataflow/cross-service-taint.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-cst-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

// ─── _pathTemplateMatches ────────────────────────────────────────────────

test('_pathTemplateMatches: matches :param against {param} (the module\'s own documented example)', () => {
  assert.equal(_internals._pathTemplateMatches('GET /balances/:userId', '/balances/{userId}'), true);
});

test('_pathTemplateMatches: matches identical literal paths with no params', () => {
  assert.equal(_internals._pathTemplateMatches('POST /charges', '/charges'), true);
});

test('_pathTemplateMatches: a different literal segment does not match', () => {
  assert.equal(_internals._pathTemplateMatches('GET /balances/:userId', '/invoices/{userId}'), false);
});

test('_pathTemplateMatches: a different segment count does not match', () => {
  assert.equal(_internals._pathTemplateMatches('GET /balances/:userId', '/balances/{userId}/history'), false);
});

test('_pathTemplateMatches: strips a query string off the edge path before comparing', () => {
  assert.equal(_internals._pathTemplateMatches('GET /balances/:userId', '/balances/{userId}?verbose=1'), true);
});

test('_pathTemplateMatches: false on missing input, never throws', () => {
  assert.equal(_internals._pathTemplateMatches(null, '/x'), false);
  assert.equal(_internals._pathTemplateMatches('GET /x', null), false);
});

// ─── upstreamTaintContract: HTTP ────────────────────────────────────────

test('upstreamTaintContract: resolves an HTTP contract end-to-end (regression for the substring-match bug)', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'GET /balances/:userId', taints: ['pathParam.userId'] }] },
      ledger: { consumes: [{ source: 'payments-balance', fields: ['userId'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'http', path: '/balances/{userId}' }],
  });
  const contracts = upstreamTaintContract(graph, graph.services.ledger);
  assert.equal(contracts.length, 1);
  assert.equal(contracts[0].upstreamService, 'payments');
  assert.equal(contracts[0].via, 'http');
});

test('upstreamTaintContract: resolves a Kafka contract (pre-existing, unaffected by the HTTP fix)', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'POST /charges', taints: ['amount'] }] },
      ledger: { consumes: [{ source: 'events.charge_created', fields: ['amount'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'kafka', topic: 'events.charge_created' }],
  });
  const contracts = upstreamTaintContract(graph, graph.services.ledger);
  assert.equal(contracts.length, 1);
  assert.equal(contracts[0].via, 'kafka');
});

// ─── annotateCrossServiceFindings: real finding shapes ──────────────────

test('annotateCrossServiceFindings: HTTP transport correlates via provenance, not the nonexistent snippet/expr fields', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'GET /balances/:userId', taints: ['pathParam.userId'] }] },
      ledger: { consumes: [{ source: 'x', fields: ['userId'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'http', path: '/balances/{userId}' }],
  });
  const findings = [{ severity: 'medium', sourceProvenance: 'url-param' }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 1);
  assert.equal(r.bumped, 1);
  assert.equal(findings[0].crossService.from, 'payments');
  assert.equal(findings[0].crossService.precision, 'transport');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0]._severityBumpReason, 'cross-service-from:payments');
});

test('annotateCrossServiceFindings: HTTP transport checks the whole source chain, not only the primary source', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'GET /balances/:userId', taints: ['pathParam.userId'] }] },
      ledger: { consumes: [{ source: 'x', fields: ['userId'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'http', path: '/balances/{userId}' }],
  });
  const findings = [{ severity: 'medium', sourceProvenance: 'env', chain: [{ provenance: 'env' }, { provenance: 'url-param' }] }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 1);
});

test('annotateCrossServiceFindings: an unrelated provenance does not match (negative control)', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'GET /balances/:userId', taints: ['pathParam.userId'] }] },
      ledger: { consumes: [{ source: 'x', fields: ['userId'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'http', path: '/balances/{userId}' }],
  });
  const findings = [{ severity: 'medium', sourceProvenance: 'env' }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 0);
  assert.equal(findings[0].crossService, undefined);
  assert.equal(findings[0].severity, 'medium');
});

test('annotateCrossServiceFindings: Kafka fallback matches on the real source.label/chain[].label shape', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'POST /charges', taints: ['amount'] }] },
      ledger: { consumes: [{ source: 'events.charge_created', fields: ['amount'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'kafka', topic: 'events.charge_created' }],
  });
  const findings = [{ severity: 'medium', source: { label: 'amount' }, chain: [{ label: 'amount' }] }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 1);
  assert.equal(findings[0].crossService.matchedField, 'amount');
  assert.equal(findings[0].crossService.precision, 'field');
});

test('annotateCrossServiceFindings: field-name regex escaping does not over-match on a multi-dot field (regression for the single-dot-escape bug)', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'POST /charges', taints: ['a.b.c'] }] },
      ledger: { consumes: [{ source: 'x', fields: [] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'kafka', topic: 'x' }],
  });
  // "aXbYc" would wrongly satisfy `a.b.c` as a regex if only the FIRST dot
  // were escaped (leaving the second `.` as a live "any character" match).
  const findings = [{ severity: 'medium', source: { label: 'aXbYc' } }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 0, 'a multi-dot field name must not match via an unescaped regex metacharacter');
});

test('annotateCrossServiceFindings: severity never exceeds critical', () => {
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'GET /x/:id', taints: ['id'] }] },
      ledger: { consumes: [{ source: 'x', fields: ['id'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'http', path: '/x/{id}' }],
  });
  const findings = [{ severity: 'critical', sourceProvenance: 'url-param' }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 1);
  assert.equal(r.bumped, 0);
  assert.equal(findings[0].severity, 'critical');
});

// ─── End-to-end: the real pipeline ───────────────────────────────────────

test('end-to-end: a real HTTP-sourced cross-service finding is annotated, bumped, and survives to the report layer', async () => {
  const dir = mkTmp('e2e-http', {
    'package.json': JSON.stringify({ name: 'ledger' }),
    '.agentic-security/services.yml': `
services:
  payments:
    exposes:
      - { route: "POST /charges", taints: ["request.amount"] }
  ledger:
    consumes:
      - { source: "payments-charges", fields: ["amount"] }
edges:
  - { from: "payments", to: "ledger", via: "http", path: "/charges" }
`,
    'src/app.js': `const db = require('db');
module.exports = (req, res) => {
  const amount = req.body.amount;
  db.query('UPDATE ledger SET amount=' + amount);
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const findings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
    assert.ok(findings.length >= 1, 'expected at least one IR-TAINT finding');
    const before = findings[0].severity;
    const r = runCrossServiceTaint(dir, findings);
    assert.equal(r.annotated, 1, `expected the real finding to be annotated. Result: ${JSON.stringify(r)}`);
    assert.equal(findings[0].crossService.from, 'payments');
    assert.equal(findings[0].crossService.precision, 'transport');
    const ladder = ['info', 'low', 'medium', 'high', 'critical'];
    if (ladder.indexOf(before) < ladder.length - 1) {
      assert.equal(findings[0].severity, ladder[ladder.indexOf(before) + 1]);
    }
    scan.findings = findings;
    const normalized = normalizeFindings(scan);
    assert.ok(normalized[0].crossService, 'crossService must survive normalizeFindings, not be silently dropped');
    assert.equal(normalized[0].crossService.from, 'payments');
    assert.equal(normalized[0]._severityBumpReason, findings[0]._severityBumpReason);
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('end-to-end precision: a finding with no cross-service source is never annotated', async () => {
  const dir = mkTmp('e2e-clean', {
    'package.json': JSON.stringify({ name: 'ledger' }),
    '.agentic-security/services.yml': `
services:
  payments:
    exposes:
      - { route: "POST /charges", taints: ["request.amount"] }
  ledger:
    consumes:
      - { source: "payments-charges", fields: ["amount"] }
edges:
  - { from: "payments", to: "ledger", via: "http", path: "/charges" }
`,
    'src/app.js': `const db = require('db');
module.exports = () => {
  const amount = process.env.AMOUNT;
  db.query('UPDATE ledger SET amount=' + amount);
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const findings = (scan.findings || []).filter((f) => f.parser === 'IR-TAINT');
    const r = runCrossServiceTaint(dir, findings);
    assert.equal(r.annotated, 0, 'an env-sourced finding must not be attributed to an HTTP cross-service edge');
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
