//
// cross-repo-link-wiring.test.js — M5 deliverable #8 (FR-304 "declared"
// half), graph-attachment wiring. Real-code proof that
// `opts.crossRepoLinks` — graph-builder.js's SIXTH additive hook of the
// `opts.buildRecipientProfile`/`opts.correlateObservations` shape — is
// wired correctly: composes additively, is byte-identical when omitted
// (mirroring `M2A1/hook-1`'s own precedent, per this package's own
// CLAUDE.md), and (via coverage.js's default wiring) drops a stale
// declaration whose local.nodeId no longer resolves against the current
// graph while keeping a valid one, reporting the drop via console.error
// rather than silently keeping it. index.js's own existence-gated
// single-load-per-call wiring is proven end to end.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { crossRepoLinkId } from '../../src/lineage/ids.js';
import { CROSS_REPO_LINK_VERSION, CROSS_REPO_LINKS_FILENAME } from '../../src/lineage/cross-repo-link.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

const SOURCE = 'function h(req, res){ const pw = req.body.password; res.send(pw); }';

function sinkNodeOf(graph) {
  const n = graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(n, 'fixture must produce a real sink node');
  return n;
}

function fakeRecord(overrides = {}) {
  const inputs = {
    localGraphId: 'dfg:local:c1:default', localGraphDigest: 'ld', localNodeId: 'node:sink:placeholder',
    remoteGraphId: 'dfg:remote:c2:default', remoteGraphDigest: 'rd', remoteNodeId: 'node:source:placeholder',
    relationship: 'data_flow',
  };
  return {
    id: crossRepoLinkId(inputs),
    version: CROSS_REPO_LINK_VERSION,
    provenance: 'manual',
    relationship: 'data_flow',
    local: { graphId: inputs.localGraphId, graphDigest: inputs.localGraphDigest, nodeId: inputs.localNodeId },
    remote: { repository: 'remote-svc', sourceFile: '/tmp/remote.json', graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId },
    rationale: 'test',
    declaredBy: 'tester',
    declaredAt: '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

// ── graph-builder.js: no-op when omitted, composes when supplied ────────

test('cross-repo-link-wiring/1: graph.crossRepoLinks is always [] when opts.crossRepoLinks is omitted', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const r = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(r.graph.crossRepoLinks, []);
});

test('cross-repo-link-wiring/1b: omitting opts.crossRepoLinks leaves every other field byte-identical to a run with a no-op hook', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const baseline = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  const withNoopHook = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinks: () => [] });
  assert.deepEqual(baseline.graph, withNoopHook.graph);
});

test('cross-repo-link-wiring/2: opts.crossRepoLinks, when it returns records, populates graph.crossRepoLinks (sorted by id)', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const recordA = fakeRecord({ id: 'crosslink:aaaa' });
  const recordB = fakeRecord({ id: 'crosslink:bbbb' });
  const r = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinks: () => [recordB, recordA] });
  assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:aaaa', 'crosslink:bbbb']);
});

test('cross-repo-link-wiring/3: opts.crossRepoLinks receives the REAL, finished graph — can look up a real node id in graph.nodes', () => {
  const cg = irOf({ 'a.js': SOURCE });
  let seenNodeIds = null;
  buildDataFlowGraph(cg, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    crossRepoLinks: (graph) => { seenNodeIds = graph.nodes.map((n) => n.id); return []; },
  });
  assert.ok(Array.isArray(seenNodeIds) && seenNodeIds.length > 0, 'the hook must see the real, populated node array, never an empty envelope');
});

// ── coverage.js: default hook drops a stale record, keeps a valid one ──

test('cross-repo-link-wiring/4: coverage.js\'s default hook drops a record whose local.nodeId is not in the current graph, keeps one that is', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  const realNodeId = sinkNodeOf(probe).id;
  const staleRecord = fakeRecord({ id: 'crosslink:stale', local: { graphId: 'g', graphDigest: 'd', nodeId: 'node:sink:this-node-was-removed' } });
  const validRecord = fakeRecord({ id: 'crosslink:valid', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
  const originalError = console.error;
  const errors = [];
  console.error = (msg) => errors.push(msg);
  let built;
  try {
    built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinkRecords: [staleRecord, validRecord] });
  } finally { console.error = originalError; }
  assert.deepEqual(built.graph.crossRepoLinks.map((x) => x.id), ['crosslink:valid']);
  assert.ok(errors.some((m) => m.includes('crosslink:stale')), 'the drop must be reported, never silent');
});

test('cross-repo-link-wiring/5: coverage.js installs NO default hook when opts.crossRepoLinkRecords is undefined — graph.crossRepoLinks stays []', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(built.graph.crossRepoLinks, []);
});

// ── index.js: single-load-per-call, existence-gated ─────────────────────

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-crosslink-wiring-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

test('cross-repo-link-wiring/6: buildLineageGraph with NO cross-repo-links.json — graph.crossRepoLinks stays [] end to end', async () => {
  const dir = await tmpProject();
  try {
    const r = buildLineageGraph(irOf({ 'a.js': SOURCE }), { repository: 'r', scanRoot: dir });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/7: buildLineageGraph with a real, valid cross-repo-links.json declares the link end to end', async () => {
  const dir = await tmpProject();
  try {
    const cg = irOf({ 'a.js': SOURCE });
    const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
    const realNodeId = sinkNodeOf(probe).id;
    const record = fakeRecord({ id: 'crosslink:real', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), JSON.stringify({ links: [record] }));
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, generatedAt: '1970-01-01T00:00:00.000Z' });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:real']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/8: buildLineageGraph with a malformed cross-repo-links.json degrades to [] rather than crashing the scan', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), '{not valid json');
    const r = buildLineageGraph(irOf({ 'a.js': SOURCE }), { repository: 'r', scanRoot: dir });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/9: buildLineageGraph with a cross-repo-links.json containing one malformed and one valid entry keeps only the valid one', async () => {
  const dir = await tmpProject();
  try {
    const cg = irOf({ 'a.js': SOURCE });
    const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
    const realNodeId = sinkNodeOf(probe).id;
    const valid = fakeRecord({ id: 'crosslink:ok', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
    const malformed = { id: 'not-a-real-id', bogus: true };
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), JSON.stringify({ links: [malformed, valid] }));
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, generatedAt: '1970-01-01T00:00:00.000Z' });
    assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:ok']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
