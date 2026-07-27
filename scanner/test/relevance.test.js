// Tests for relevance.js — threat-model-first scoping (R6) + attack-surface-
// forward reachability (R9).
//
// Contract under test is recall-preserving, mirroring falsification.js and
// dataflow/proof-gate.js: the annotator may re-rank (exploitability) and label
// (relevance / entrypointReachable), but it must NEVER drop a finding and
// NEVER touch severity. "Unreachable" requires positive evidence; absence of
// evidence is null / 'unknown'.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { annotateRelevance, _internals } from '../src/posture/relevance.js';

const { scoreRelevance } = _internals;

// ── Fixture: a two-hop repo ────────────────────────────────────────────────
//   routes/users.js   — HTTP route (entry point) + a finding in-file
//   services/user.js  — imported by the route → reachable indirectly
//   jobs/report.js    — imported by nothing → positively unreachable
const ROUTE_FILE = 'src/routes/users.js';
const SERVICE_FILE = 'src/services/user.js';
const ORPHAN_FILE = 'src/jobs/report.js';

const fileContents = {
  [ROUTE_FILE]: [
    "import { getUser } from '../services/user.js';",
    "app.get('/users/:id', async (req, res) => {",
    '  const row = await getUser(req.params.id);',
    '  res.send(row);',
    '});',
  ].join('\n'),
  [SERVICE_FILE]: [
    "import { db } from '../db.js';",
    'export function getUser(id) {',
    '  return db.query(`SELECT * FROM users WHERE id = ${id}`);',
    '}',
  ].join('\n'),
  [ORPHAN_FILE]: [
    'export function buildReport(id) {',
    '  return db.query(`SELECT * FROM reports WHERE id = ${id}`);',
    '}',
  ].join('\n'),
  'src/db.js': 'export const db = { query: () => {} };',
};

const routes = [{
  method: 'GET', path: '/users/:id', file: ROUTE_FILE, line: 2,
  handler: 'getUser', params: ['id'], hasAuth: false,
}];

const entrypointInventory = {
  entrypoints: [
    { type: 'http', file: ROUTE_FILE, line: 2, name: 'GET /users/:id', trust: 'unauthenticated', disposition: 'finding' },
  ],
};

function mkFinding(file, line, over = {}) {
  return {
    id: `f-${file}-${line}`,
    severity: 'high',
    file,
    line,
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    description: 'string-concatenated query',
    remediation: 'parameterize',
    parser: 'IR-TAINT',
    family: 'sql-injection',
    exploitability: 0.6,
    exploitabilityTier: 'high',
    exploitabilityFactors: ['taint'],
    ...over,
  };
}

const ctx = () => ({ fileContents, routes, entrypointInventory });

// ── R9: entry-point reachability ──────────────────────────────────────────

test('relevance: a finding in an entry-point file is direct + reachable', () => {
  const f = mkFinding(ROUTE_FILE, 3);
  annotateRelevance([f], ctx());
  assert.equal(f.entrypointReachable, true);
  assert.equal(f.relevanceTier, 'direct');
  assert.ok(f.relevance > 0.6, `expected high relevance, got ${f.relevance}`);
  assert.ok(f.relevanceFactors.some(s => /entry point/i.test(s)));
});

test('relevance: a finding reached only via an import from an entry point is indirect', () => {
  const f = mkFinding(SERVICE_FILE, 3);
  annotateRelevance([f], ctx());
  assert.equal(f.entrypointReachable, true);
  assert.equal(f.relevanceTier, 'indirect');
});

test('relevance: a file no entry point can reach is unreachable — with evidence', () => {
  const f = mkFinding(ORPHAN_FILE, 2);
  annotateRelevance([f], ctx());
  assert.equal(f.entrypointReachable, false);
  assert.equal(f.relevanceTier, 'unreachable');
  assert.ok(f.relevance < 0.35, `expected low relevance, got ${f.relevance}`);
});

test('relevance: absence of evidence is unknown/null, never unreachable', () => {
  // No inventory and no file contents → nothing can be established.
  const f = mkFinding(ORPHAN_FILE, 2);
  annotateRelevance([f], {});
  assert.equal(f.entrypointReachable, null);
  assert.equal(f.relevanceTier, 'unknown');
  assert.notEqual(f.relevanceTier, 'unreachable');

  // Inventory present but the finding's file was never read → still unknown.
  const g = mkFinding('src/never/read.js', 5);
  annotateRelevance([g], ctx());
  assert.equal(g.entrypointReachable, null);
  assert.equal(g.relevanceTier, 'unknown');
});

test('relevance: an unresolved intra-repo import blocks any unreachable verdict', () => {
  // The route imports a relative path that is not in fileContents, so the
  // import graph is provably incomplete — no negative verdict is admissible.
  const fc = {
    [ROUTE_FILE]: "import { x } from './missing-module.js';\napp.get('/a', h);",
    [ORPHAN_FILE]: fileContents[ORPHAN_FILE],
  };
  const f = mkFinding(ORPHAN_FILE, 2);
  annotateRelevance([f], { fileContents: fc, routes, entrypointInventory });
  assert.equal(f.entrypointReachable, null);
  assert.equal(f.relevanceTier, 'unknown');
});

// ── R6: threat-model relevance ────────────────────────────────────────────

test('relevance: a modelled STRIDE threat + asset raises relevance over the same finding without one', () => {
  const threatModel = {
    assets: [{ name: 'identity', file: SERVICE_FILE, line: 2, category: 'identity', exposure: 'public-api' }],
    trustBoundaries: [],
    stride: { tampering: [{ vuln: 'SQL Injection', file: SERVICE_FILE, line: 3, severity: 'high' }] },
  };
  const modelled = mkFinding(SERVICE_FILE, 3);
  const bare = mkFinding(SERVICE_FILE, 3);
  annotateRelevance([modelled], { ...ctx(), threatModel });
  annotateRelevance([bare], ctx());
  assert.ok(
    modelled.relevance > bare.relevance,
    `threat-modelled finding (${modelled.relevance}) should outrank un-modelled (${bare.relevance})`,
  );
  assert.ok(modelled.relevanceFactors.some(s => /stride|asset/i.test(s)));
});

// ── The differentiation proof: re-ranking actually separates ──────────────

test('relevance: two identical findings differing only in entry-point reachability get different relevance AND exploitability', () => {
  const reachable = mkFinding(SERVICE_FILE, 3);
  const orphan = mkFinding(ORPHAN_FILE, 2);
  // Identical in every scored respect except which file they sit in.
  assert.equal(reachable.severity, orphan.severity);
  assert.equal(reachable.exploitability, orphan.exploitability);
  assert.equal(reachable.cwe, orphan.cwe);

  annotateRelevance([reachable, orphan], ctx());

  assert.notEqual(reachable.relevanceTier, orphan.relevanceTier);
  assert.ok(
    reachable.relevance > orphan.relevance,
    `entry-point-reachable (${reachable.relevance}) must outrank unreachable (${orphan.relevance})`,
  );
  assert.ok(
    reachable.exploitability > orphan.exploitability,
    `re-rank must move exploitability: ${reachable.exploitability} vs ${orphan.exploitability}`,
  );
});

// ── Recall-preserving contract ────────────────────────────────────────────

test('relevance: never mutates severity', () => {
  const findings = [mkFinding(ROUTE_FILE, 3), mkFinding(SERVICE_FILE, 3), mkFinding(ORPHAN_FILE, 2)];
  const before = findings.map(f => f.severity);
  annotateRelevance(findings, ctx());
  assert.deepEqual(findings.map(f => f.severity), before);
});

test('relevance: never drops a finding', () => {
  const findings = [mkFinding(ROUTE_FILE, 3), mkFinding(ORPHAN_FILE, 2), mkFinding('src/db.js', 1)];
  const ids = findings.map(f => f.id);
  const out = annotateRelevance(findings, ctx());
  assert.equal(findings.length, 3);
  assert.deepEqual(findings.map(f => f.id), ids);
  assert.equal(out, findings);
});

test('relevance: an unreachable finding keeps a non-zero exploitability floor', () => {
  const f = mkFinding(ORPHAN_FILE, 2);
  annotateRelevance([f], ctx());
  assert.equal(f.relevanceTier, 'unreachable');
  assert.ok(f.exploitability > 0, 'demotion must never zero a finding out');
  assert.equal(f.severity, 'high');
});

test('relevance: degrades without throwing on absent/garbage input', () => {
  assert.doesNotThrow(() => annotateRelevance(null, null));
  assert.doesNotThrow(() => annotateRelevance(undefined, undefined));
  assert.doesNotThrow(() => annotateRelevance([null, 1, 'x'], {}));
  const f = mkFinding(ROUTE_FILE, 3);
  assert.doesNotThrow(() => annotateRelevance([f], { fileContents: 'not-an-object', entrypointInventory: 7 }));
  assert.equal(f.relevanceTier, 'unknown');
  assert.equal(f.entrypointReachable, null);
});

test('relevance: accepts a Map for fileContents', () => {
  const map = new Map(Object.entries(fileContents));
  const f = mkFinding(SERVICE_FILE, 3);
  annotateRelevance([f], { fileContents: map, routes, entrypointInventory });
  assert.equal(f.relevanceTier, 'indirect');
});

test('relevance: derives entry points from routes when no inventory is supplied', () => {
  const f = mkFinding(ROUTE_FILE, 3);
  annotateRelevance([f], { fileContents, routes });
  assert.equal(f.relevanceTier, 'direct');
  assert.equal(f.entrypointReachable, true);
});

test('scoreRelevance: pure scorer returns tier + factors without mutating', () => {
  const f = mkFinding(ROUTE_FILE, 3);
  const snapshot = JSON.stringify(f);
  const r = scoreRelevance(f, {
    entryFiles: new Set([ROUTE_FILE]),
    reachableFiles: new Set([ROUTE_FILE]),
    graphComplete: true,
    knownFiles: new Set(Object.keys(fileContents)),
    unauthEntryFiles: new Set([ROUTE_FILE]),
  });
  assert.equal(r.tier, 'direct');
  assert.equal(r.reachable, true);
  assert.ok(Array.isArray(r.factors) && r.factors.length > 0);
  assert.equal(JSON.stringify(f), snapshot);
});
