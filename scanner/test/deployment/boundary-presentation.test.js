// X-307: present boundary coverage and provenance. The JSON report, the Markdown and terminal reports and the MCP finding
// explanation all show the same boundary view because they call one projection. Each criterion is tested in both directions:
// the surfaces agree and carry the caveats, AND a disagreement, a lost caveat, a leaked secret or a changed old schema is caught.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { toJSON, toCLI, toMarkdown, normalizeFindings, boundaryBlock } from '../../src/report/index.js';
import { createServer } from '../../src/mcp/server.js';
import { signLastScan } from '../../src/posture/integrity.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { projectVerification } from '../../src/posture/verification/projection.js';
import {
  projectBoundaryContext, filterBoundaryView, boundaryFields, boundaryCoverage, attachBoundaryContext, validateBoundaryContext, VIEW_SCHEMA,
} from '../../src/lineage/deployment/projection.js';
import { analyzeFindingBoundaries } from '../../src/lineage/deployment/attack-paths.js';
import { importTraceLines, correlateObservations, applyCorrelation } from '../../src/lineage/deployment/trace-correlation.js';
import { buildBoundaryGraph } from '../../src/lineage/deployment/boundary-graph.js';
import { META, scanInput, FINDING as COMPAT_FINDING } from '../fixtures/verification-compat/inputs.mjs';
import { ingestOne, nodeByName } from './helpers.js';
import { node, edge, graphOf, baseline, FINDING, BINDINGS, recordFor, SRC } from './path-helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const clone = (o) => JSON.parse(JSON.stringify(o));
const boundaryCompat = () => JSON.parse(fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'boundary-compat', 'report.v0.json'), 'utf8'));
const verificationCompat = (n) => JSON.parse(fs.readFileSync(path.join(SCANNER, 'test', 'fixtures', 'verification-compat', n), 'utf8'));

const contextFor = (graph, o = {}) => analyzeFindingBoundaries({ graph, finding: o.finding ?? FINDING, bindings: BINDINGS, records: o.records ?? [] }).context;
const defaultContext = (o) => contextFor(graphOf({ nodes: baseline().nodes, edges: baseline().edges }), o);

/** A scan input whose one finding carries `ctx`, with the compat finding's identity so it can be joined to a record. */
function scanWith(ctx, extra = {}) {
  const scan = scanInput();
  scan.findings[0] = { ...scan.findings[0], boundaryContext: ctx, ...extra };
  return scan;
}

async function mcpExplain(jsonOut) {
  const root = mkTestTmp('as-x307-');
  const state = path.join(root, '.agentic-security');
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x307"}');
  const body = JSON.stringify(jsonOut);
  fs.writeFileSync(path.join(state, 'last-scan.json'), body);
  fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: root });
  const r = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'explain_finding', arguments: { finding_id: COMPAT_FINDING.id } } });
  return JSON.parse(r.result.content[0].text);
}

describe('[X-307.AC01] reports expose an inspectable path, environment, provenance, freshness and uncovered boundaries per finding', () => {
  test('[X-307.AC01] the view carries every part: path with edges and sources, environment, provenance, freshness, uncovered boundaries', () => {
    const b = baseline({ routeSource: SRC('k8s/ingress.yaml'), grantSource: SRC('iam/roles.yaml') });
    const seen = { provenance: 'runtime-observation', pathState: 'runtime-supported', observationInterval: { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' }, completeness: 'sampled' };
    const g = graphOf({ nodes: b.nodes, edges: [...b.edges, edge('routes-to', b.route, b.api, seen)] });
    const p = projectBoundaryContext(contextFor(g));
    assert.equal(p.ok, true);
    const v = p.view;
    assert.equal(v.schema, VIEW_SCHEMA);
    const exposure = v.paths.find((x) => x.kind === 'exposure');
    assert.deepEqual(exposure.environments, ['prod']);
    assert.deepEqual(exposure.provenance, ['runtime-observation', 'static-config']);
    assert.ok(exposure.hops[0].edges.some((e) => e.source?.file === 'k8s/ingress.yaml'), 'the configuration file behind a hop is named');
    assert.ok(exposure.hops[0].edges.some((e) => e.observationInterval), 'and so is the observation window');
    assert.match(exposure.freshness.statement, /1 network hop\(s\) were observed up to 2026-01-02/);
    assert.equal(exposure.coverage.trafficCoverage, 'not-established');
    const impact = v.paths.find((x) => x.kind === 'impact');
    assert.ok(impact.uncoveredBoundaries.length > 0, 'identity and unobserved crossings are listed as not covered');
    assert.ok(v.uncovered.some((u) => u.type === 'identity'));
    assert.match(v.text.join('\n'), /freshness:/);
    assert.match(v.text.join('\n'), /environment: prod; tenants: none; provenance:/);
    assert.match(v.text.join('\n'), /Not established:/);
    // identical input, identical view: no clock, no randomness
    assert.deepEqual(projectBoundaryContext(clone(contextFor(g))).view, v);
  });

  test('[X-307.AC01] the JSON report, the Markdown report, the terminal report and MCP show the same boundary view', async () => {
    const ctx = defaultContext();
    const scan = scanWith(ctx);
    const json = clone(toJSON(scan, META));
    const finding = json.findings[0];
    const reference = projectBoundaryContext(ctx).view;
    assert.deepEqual(finding.boundaryView, reference);
    assert.deepEqual(finding.boundaryContext, ctx);
    const mcp = await mcpExplain(json);
    assert.deepEqual(mcp.boundaryView, reference, 'MCP explain_finding');
    const n = reference.text.length;
    const cli = toCLI(scan, { color: false }).split('\n');
    const i = cli.findIndex((l) => l.startsWith('        Deployment boundaries:'));
    assert.ok(i >= 0);
    assert.deepEqual(cli.slice(i, i + n).map((l) => l.slice(8)), reference.text, 'terminal report');
    const md = toMarkdown(scan, META).split('\n');
    const j = md.findIndex((l) => l.startsWith('Deployment boundaries:'));
    assert.ok(j >= 0);
    assert.deepEqual(md.slice(j, j + n), reference.text, 'Markdown report');
    assert.ok(md.some((l) => l.includes('<summary>Deployment boundaries</summary>')));
    assert.equal(json.boundaryCoverage.total, 1);
    assert.match(cli.join('\n'), /Deployment boundaries: 1 finding\(s\) with context; 1 bound to a service/);
  });

  test('[X-307.AC01] a surface that edited the view would be caught: the block is exactly the projection text, and control characters are stripped', () => {
    const ctx = defaultContext();
    const finding = normalizeFindings(scanWith(ctx))[0];
    assert.deepEqual(boundaryBlock(finding), projectBoundaryContext(ctx).view.text);
    const tampered = { ...finding, boundaryView: { ...finding.boundaryView, text: ['  line\u001b[31m with escape'] } };
    assert.equal(boundaryBlock(tampered)[0].includes('\u001b'), false);
    assert.equal(boundaryBlock({}), null);
  });

  test('[X-307.AC01] the text never calls a partial result safe, protected or unreachable, in any state', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const a = node('service', 'shop/api', { tenant: 'acme' });
    const t = node('service', 'shop/t', { tenant: 'globex' });
    const db = node('resource', 'db/x', { trustZone: 'privileged' });
    const b = baseline();
    const seen = { provenance: 'runtime-observation', pathState: 'runtime-supported', observationInterval: { start: '2026-01-01T00:00:00Z', end: '2026-01-02T00:00:00Z' }, completeness: 'sampled' };
    const graphs = {
      possible: graphOf({ nodes: b.nodes, edges: b.edges }),
      blocked: graphOf({ nodes: b.nodes, edges: [...b.edges, edge('network-denies', b.api, b.ledger, { effect: 'deny' })] }),
      unresolved: graphOf({ nodes: [route, a, t, db], edges: [edge('routes-to', route, a), edge('calls', a, t), edge('network-allows', t, db)] }),
      observed: graphOf({ nodes: b.nodes, edges: [...b.edges, edge('routes-to', b.route, b.api, seen), edge('calls', b.api, b.ledger, seen)] }),
      none: graphOf({ nodes: [node('service', 'shop/api')], edges: [] }),
    };
    const states = new Set();
    const lines = [];
    for (const [name, g] of Object.entries(graphs)) {
      const ctx = contextFor(g, { records: [recordFor('trusted')] });
      for (const p of ctx.paths) states.add(p.state);
      const v = projectBoundaryContext(ctx).view;
      lines.push(...v.text);
      assert.ok(v.text.length > 3, name);
    }
    lines.push(...projectBoundaryContext(contextFor(graphs.possible, { finding: { ...FINDING, file: 'tools/x.js' } })).view.text);
    assert.deepEqual([...states].sort(), ['blocked', 'possible', 'runtime-supported', 'unresolved']);
    const all = lines.join('\n');
    assert.doesNotMatch(all, /\b(safe|safety|protected|secure[sd]?|unreachable|mitigated|harmless|not exploitable)\b/i);
    assert.match(all, /not shown to exist|does not show|not established|not exercised|configuration only/i);
    assert.match(projectBoundaryContext(contextFor(graphs.none)).view.text.join('\n'), /NO PATH FOUND\. no path from an exposed entry point was found in the supplied configuration; this does not show that none exists/);
  });

  test('[X-307.AC01] an invalid context yields errors and no view: a made-up field, a missing field or a wrong schema is never shown', () => {
    const ctx = defaultContext();
    for (const bad of [{ ...ctx, extra: 1 }, { ...ctx, schema: 'other' }, (() => { const c = { ...ctx }; delete c.exposure; return c; })(), null, [], 'x']) {
      const r = projectBoundaryContext(bad);
      assert.equal(r.ok, false);
      assert.equal(r.view, null);
      assert.ok(r.errors.length > 0);
    }
    const f = boundaryFields({ ...ctx, extra: 1 });
    assert.equal(f.boundaryView, null);
    assert.ok(f.boundaryViewErrors.length);
    assert.deepEqual(boundaryFields(null), {});
    assert.equal(validateBoundaryContext(ctx).ok, true);
  });

  test('[X-307.AC01] previous output schemas are unchanged when no finding carries a context (pinned against a capture of the earlier code)', async () => {
    const prev = boundaryCompat();
    const cur = clone(toJSON(scanInput(), META));
    assert.deepEqual(Object.keys(cur).sort(), prev.reportJson.topLevelKeys);
    assert.deepEqual(clone(normalizeFindings(scanInput())[0]), prev.reportJson.finding);
    assert.equal(toMarkdown(scanInput(), META), prev.markdown);
    const mcpPrev = verificationCompat('mcp-explain-finding.v0.json').payload;
    assert.deepEqual(await mcpExplain(cur), mcpPrev);
  });

  test('[X-307.AC01] with a context the change is additive: every previous value is kept and only the boundary fields and run accounting are added', () => {
    const prev = boundaryCompat();
    const withCtx = clone(toJSON(scanWith(defaultContext()), META));
    for (const k of prev.reportJson.topLevelKeys) assert.ok(k in withCtx, k);
    assert.deepEqual(Object.keys(withCtx).filter((k) => !prev.reportJson.topLevelKeys.includes(k)), ['boundaryCoverage']);
    const f = withCtx.findings[0];
    for (const [k, v] of Object.entries(prev.reportJson.finding)) assert.deepEqual(f[k], v, k);
    assert.deepEqual(Object.keys(f).filter((k) => !(k in prev.reportJson.finding)).sort(), ['boundaryContext', 'boundaryView']);
  });

  test('[X-307.AC01] the feature flag gates the only producer: off leaves findings (and so every output) untouched, on attaches', () => {
    const root = mkTestTmp('as-x307-flag-');
    const findings = [clone(COMPAT_FINDING)];
    const graph = graphOf({ nodes: baseline().nodes, edges: baseline().edges });
    const args = { findings, graph, bindings: [{ pathPrefix: 'src/', service: 'shop/api' }] };
    const off = attachBoundaryContext({ config: resolveAssuranceConfig({ scanRoot: root, env: {} }), ...args });
    assert.equal(off.status, 'disabled');
    assert.equal(off.findings, findings, 'the same array, not a copy');
    assert.equal(JSON.stringify(toJSON({ findings: off.findings, filesScanned: 1, linesScanned: 1 }, META)), JSON.stringify(toJSON({ findings: [clone(COMPAT_FINDING)], filesScanned: 1, linesScanned: 1 }, META)));
    const killed = attachBoundaryContext({ config: resolveAssuranceConfig({ scanRoot: root, env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1', AGENTIC_SECURITY_NO_DEPLOYMENT_BOUNDARIES: '1' } }), ...args });
    assert.equal(killed.status, 'blocked');
    assert.equal(killed.findings, findings);
    const on = attachBoundaryContext({ config: resolveAssuranceConfig({ scanRoot: root, env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' } }), ...args });
    assert.equal(on.status, 'ok');
    assert.equal(on.findings[0].boundaryContext.binding.status, 'bound');
    assert.notEqual(on.findings[0], findings[0], 'the input finding is not mutated');
    assert.equal('boundaryContext' in findings[0], false);
    const out = clone(toJSON({ findings: on.findings, filesScanned: 1, linesScanned: 1 }, META));
    assert.equal(out.findings[0].boundaryView.exposure.state, 'possible');
  });

  test('[X-307.AC01] run accounting counts bound and unbound findings and ignores invalid contexts without throwing', () => {
    const bound = defaultContext();
    const unbound = contextFor(graphOf({ nodes: baseline().nodes, edges: baseline().edges }), { finding: { ...FINDING, file: 'tools/x.js' } });
    const c = boundaryCoverage([bound, unbound, { schema: 'nope' }, null]);
    assert.equal(c.total, 3);
    assert.equal(c.bound, 1);
    assert.equal(c.unbound, 1);
    assert.equal(c.invalid, 1);
    assert.match(c.lines[0], /traffic coverage is not established/);
    assert.equal(boundaryCoverage([]).total, 0);
  });
});

describe('[X-307.AC02] users can filter by service, repository, environment and tenant without losing scope and missing-data warnings', () => {
  // db1 (tenant acme, repository infra-a) is reached through svc-a; db2 (tenant globex, repository infra-b) through svc-b.
  function filterable() {
    const route = node('route', 'edge/x', { trustZone: 'public', repository: 'edge-repo' });
    const api = node('service', 'shop/api', { repository: 'shop-repo' });
    const sa = node('service', 'svc-a', { repository: 'infra-a' });
    const sb = node('service', 'svc-b', { repository: 'infra-b' });
    const db1 = node('resource', 'db/one', { trustZone: 'privileged', tenant: 'acme', repository: 'infra-a' });
    const db2 = node('resource', 'db/two', { trustZone: 'privileged', tenant: 'globex', repository: 'infra-b' });
    const gaps = [{ code: 'unresolved-identity', subject: 'sa/ghost', file: 'k8s/x.yaml', message: 'sa/ghost is not defined' }];
    const g = graphOf({
      nodes: [route, api, sa, sb, db1, db2], gaps,
      edges: [edge('routes-to', route, api), edge('calls', api, sa), edge('calls', api, sb), edge('network-allows', sa, db1), edge('network-allows', sb, db2)],
    });
    return projectBoundaryContext(contextFor(g)).view;
  }

  test('[X-307.AC02] each filter narrows the paths, and every filter keeps the scope, the uncovered boundaries and all earlier warnings', () => {
    const v = filterable();
    const impact = v.paths.filter((p) => p.kind === 'impact');
    assert.equal(impact.length, 2);
    const cases = [
      [{ service: 'svc-a' }, ['db/one']], [{ service: 'svc-b' }, ['db/two']],
      [{ repository: 'infra-a' }, ['db/one']], [{ repository: 'infra-b' }, ['db/two']],
      [{ tenant: 'acme' }, ['db/one']], [{ tenant: 'globex' }, ['db/two']],
      [{ environment: 'prod' }, ['db/one', 'db/two']],
      [{ service: 'svc-a', tenant: 'globex' }, []],
    ];
    for (const [filter, targets] of cases) {
      const f = filterBoundaryView(v, filter);
      assert.deepEqual(f.paths.filter((p) => p.kind === 'impact').map((p) => p.target.name).sort(), targets, JSON.stringify(filter));
      assert.deepEqual(f.scope.repositories, v.scope.repositories);
      assert.deepEqual(f.scope.tenants, v.scope.tenants);
      assert.deepEqual(f.scope.environments, v.scope.environments);
      assert.equal(f.scope.totalPathCount, v.scope.totalPathCount, 'the unfiltered total is kept');
      assert.deepEqual(f.uncovered, v.uncovered);
      for (const w of v.warnings) assert.ok(f.warnings.includes(w), `a warning was lost: ${w}`);
      assert.deepEqual(f.exposure, v.exposure);
      assert.deepEqual(f.graph, v.graph);
      assert.equal(f.scope.hiddenPathCount, v.paths.length - f.paths.length);
    }
    assert.ok(v.warnings.some((w) => /gap\(s\) \(unresolved-identity\)/.test(v.warnings.join(' ') && w)), 'the missing-data warning exists to be kept');
  });

  test('[X-307.AC02] a filter says how many paths it hid, and a filter that matches nothing does not claim nothing exists', () => {
    const v = filterable();
    const f = filterBoundaryView(v, { service: 'svc-a' });
    assert.ok(f.warnings.some((w) => /^Filter: 2 of 3 path\(s\) are hidden by the filter; hidden paths are not shown to be absent\.$/.test(w)));
    assert.match(f.text.join('\n'), /Paths: 1 shown of 3 \(filter service=svc-a; 2 hidden\)/);
    const none = filterBoundaryView(v, { environment: 'staging' });
    assert.equal(none.paths.length, 0);
    assert.ok(none.warnings.some((w) => /no path matches the filter; that says nothing about paths outside it/.test(w)));
    assert.doesNotMatch(none.text.join('\n'), /\b(safe|protected|no such path exists)\b/i);
    // an unfiltered view reports no filter, and an empty filter hides nothing
    assert.equal(v.filter, null);
    const empty = filterBoundaryView(v, {});
    assert.equal(empty.paths.length, v.paths.length);
    assert.equal(empty.scope.hiddenPathCount, 0);
    assert.equal(empty.warnings.some((w) => w.startsWith('Filter: ')), false);
  });

  test('[X-307.AC02] filtering a filtered view recomputes from the full total and never accumulates a stale warning', () => {
    const v = filterable();
    const once = filterBoundaryView(v, { service: 'svc-a' });
    const twice = filterBoundaryView(once, { repository: 'infra-a' });
    assert.equal(twice.warnings.filter((w) => w.startsWith('Filter: ')).length, 1);
    assert.equal(twice.scope.totalPathCount, v.scope.totalPathCount);
  });

  test('[X-307.AC02] filters work through the report field helper, and the filtered text is the same renderer', () => {
    const g = graphOf({ nodes: baseline().nodes, edges: baseline().edges });
    const c = contextFor(g);
    const f = boundaryFields(c, { filter: { service: 'shop/ledger' } }).boundaryView;
    assert.equal(f.filter.service, 'shop/ledger');
    assert.ok(f.scope.hiddenPathCount >= 0);
    assert.deepEqual(f.text, filterBoundaryView(projectBoundaryContext(c).view, { service: 'shop/ledger' }).text);
  });
});

describe('[X-307.AC03] JSON and MCP graph and path records share stable ids with verification records and carry no secrets or trace payloads', () => {
  test('[X-307.AC03] the boundary record names the hypothesis and the verification record by the same ids the verification view uses', async () => {
    const rec = recordFor('trusted', { hypothesisId: COMPAT_FINDING.stableId });
    const finding = { ...COMPAT_FINDING, file: 'services/api/handler.js' };
    const ctx = analyzeFindingBoundaries({ graph: graphOf({ nodes: baseline().nodes, edges: baseline().edges }), finding, bindings: BINDINGS, records: [rec] }).context;
    const scan = scanInput();
    scan.findings[0] = { ...scan.findings[0], file: finding.file, boundaryContext: ctx, verificationRecord: rec };
    const json = clone(toJSON(scan, META));
    const f = json.findings[0];
    assert.equal(f.boundaryView.hypothesisId, rec.hypothesisId);
    assert.deepEqual(f.boundaryView.verificationRecordIds, [rec.id]);
    assert.equal(f.verificationView.recordId, f.boundaryView.verificationRecordIds[0], 'one id joins the two records');
    assert.ok(f.boundaryView.paths.every((p) => p.exploitability.recordId === rec.id));
    const mcp = await mcpExplain(json);
    assert.equal(mcp.verificationView.recordId, mcp.boundaryView.verificationRecordIds[0]);
    assert.deepEqual(mcp.boundaryView.paths.map((p) => p.id), f.boundaryView.paths.map((p) => p.id));
    assert.equal(projectVerification(rec).view.recordId, rec.id);
    // a record for another hypothesis is not joined
    const other = analyzeFindingBoundaries({ graph: graphOf({ nodes: baseline().nodes, edges: baseline().edges }), finding, bindings: BINDINGS, records: [recordFor('trusted', { hypothesisId: 'someone-else' })] }).context;
    assert.deepEqual(projectBoundaryContext(other).view.verificationRecordIds, []);
  });

  test('[X-307.AC03] path ids and edge ids in the record are the graph\'s own, unchanged by projection or JSON round trip', () => {
    const g = graphOf({ nodes: baseline().nodes, edges: baseline().edges });
    const ctx = contextFor(g);
    const v = projectBoundaryContext(clone(ctx)).view;
    const ids = new Set(g.edges.map((e) => e.id));
    assert.deepEqual(v.paths.map((p) => p.id), ctx.paths.map((p) => p.id));
    for (const p of v.paths) {
      for (const id of p.supportingEdgeIds) assert.ok(ids.has(id));
      for (const h of p.hops) for (const e of h.edges) assert.ok(ids.has(e.id));
    }
    assert.equal(v.graph.digest, g.digest);
    assert.equal(v.contextId, ctx.id);
    assert.deepEqual(clone(v), v);
  });

  test('[X-307.AC03] configuration secrets and raw trace payloads never reach the context, the view or any report', () => {
    const g0 = ingestOne('k8s-payments/manifests.yaml', { repository: 'payments', as: 'm.yaml' });
    const secrets = ['hunter2-super-secret', 'should-never-appear'];
    const trace = JSON.stringify({
      ts: '2026-03-09T10:00:00Z', environment: 'prod', source: { service: 'payments/api', tenant: 'acme' }, destination: { service: 'payments/ledger' },
      outcome: 'ok', authorization: 'Bearer abcdefghijklmnopqrstuvwxyz', body: 'card=4111111111111111', headers: { cookie: 'session=topsecretcookie' },
    });
    const imported = importTraceLines(trace, { environment: 'prod' });
    assert.equal(imported.status, 'ok');
    const corr = correlateObservations(g0, imported.set, { now: '2026-03-10T00:00:00Z' });
    const g = applyCorrelation(g0, corr).graph;
    assert.ok(g, 'the correlated graph is valid');
    const finding = { ...FINDING, file: 'services/payments/api/x.js' };
    const ctx = analyzeFindingBoundaries({ graph: g, finding, bindings: [{ pathPrefix: 'services/payments/api/', service: 'payments/api' }] }).context;
    assert.ok(ctx.paths.length > 0, 'a real path was analysed');
    const scan = scanInput();
    scan.findings[0] = { ...scan.findings[0], boundaryContext: ctx };
    const everything = [JSON.stringify(ctx), JSON.stringify(projectBoundaryContext(ctx).view), JSON.stringify(toJSON(scan, META)), toMarkdown(scan, META), toCLI(scan, { color: false })].join('\n');
    for (const s of [...secrets, 'Bearer', 'abcdefghijklmnop', '4111111111111111', 'topsecretcookie', 'session=']) {
      assert.equal(everything.includes(s), false, `leaked: ${s}`);
    }
    assert.ok(nodeByName(g, 'payments/api', 'service'), 'the topology itself is still there');
  });

  test('[X-307.AC03] a context carrying a credential-shaped string, a payload-shaped string or a control character is refused, not shown', () => {
    const base = defaultContext();
    const poisoned = [
      (c) => { c.warnings = [...c.warnings, 'password=hunter2']; },
      (c) => { c.paths[0].assumptions = [...c.paths[0].assumptions, 'token: abcdef123456']; },
      (c) => { c.finding.vuln = 'Bearer abcdefghijklmnopqrstuv'; },
      (c) => { c.uncovered = [...c.uncovered, { type: 'gap', detail: '-----BEGIN RSA PRIVATE KEY-----', pathId: null }]; },
      (c) => { c.binding.reason = 'AKIAABCDEFGHIJKLMNOP'; },
      (c) => { c.warnings = [...c.warnings, 'x'.repeat(5000)]; },
      (c) => { c.warnings = [...c.warnings, 'line\u0000break']; },
    ];
    for (const mutate of poisoned) {
      const c = clone(base);
      mutate(c);
      const r = projectBoundaryContext(c);
      assert.equal(r.ok, false);
      assert.equal(r.view, null);
      assert.doesNotMatch(JSON.stringify(r.errors), /hunter2|abcdef123456|PRIVATE KEY|AKIA/, 'the refusal does not echo the value');
      assert.equal(boundaryFields(c).boundaryView, null);
    }
    assert.equal(projectBoundaryContext(clone(base)).ok, true, 'the unpoisoned context still projects');
  });

  test('[X-307.AC03] an edge attribute the graph grammar admits but that looks like a credential is still refused when a context is projected', () => {
    const route = node('route', 'edge/x', { trustZone: 'public' });
    const api = node('service', 'shop/api');
    const db = node('resource', 'db/x', { trustZone: 'privileged' });
    const hostile = edge('network-allows', api, db, { attrs: { note: 'password=hunter2' } });
    const g = buildBoundaryGraph({ repository: 'repo', nodes: [route, api, db], edges: [edge('routes-to', route, api), hostile], sources: [SRC('cfg/default.yaml')] });
    assert.equal(g.ok, true, 'the metadata grammar admits this value');
    const ctx = analyzeFindingBoundaries({ graph: g.graph, finding: FINDING, bindings: BINDINGS }).context;
    assert.ok(JSON.stringify(ctx).includes('hunter2'), 'it reached the context');
    const r = projectBoundaryContext(ctx);
    assert.equal(r.ok, false);
    assert.equal(r.view, null);
    assert.doesNotMatch(JSON.stringify(r.errors), /hunter2/);
    const scan = scanWith(ctx);
    const json = clone(toJSON(scan, META));
    assert.equal(json.findings[0].boundaryView, null, 'the report shows no view rather than the secret');
    assert.equal(JSON.stringify(json).includes('hunter2'), false, 'and does not echo the refused context either');
    assert.equal('boundaryContext' in json.findings[0], false);
    assert.ok(json.findings[0].boundaryViewErrors.length);
    assert.equal(boundaryBlock(json.findings[0]), null);
  });

  test('[X-307.AC03] the SARIF-style previous exports are untouched: toJSON without a context carries no boundary key anywhere', () => {
    const text = JSON.stringify(toJSON(scanInput(), META));
    assert.equal(/boundary/i.test(text), false);
  });
});
