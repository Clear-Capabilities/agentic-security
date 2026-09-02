//
// recipient-wiring.test.js — Milestone 4, FR-506 (Third-Party and
// Cross-Border Intelligence), Task 3. Real-code proof that
// `opts.buildRecipientProfile` — the THIRD hook of `graph-builder.js`'s own
// `opts.resolveDestination`/`opts.resolveTransitProtection` shape — is
// wired correctly: composes additively, is byte-identical when omitted
// (mirroring `M2A1/hook-1`'s own precedent, per this package's own
// CLAUDE.md), dedups two sink sites resolving to the same recipient, and
// (via `coverage.js`'s default wiring) produces a real recipient profile on
// a real parsed fixture reaching an AI-provider sink — sub-project 8b's own
// "patient_record → anthropic.messages.create" fixture shape.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildDataFlowGraph, enumerateSinkSites } from '../../src/lineage/graph-builder.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { resolveDestination } from '../../src/lineage/resolve-destination.js';
import { buildRecipientProfile, RECIPIENT_CONFIG_FILENAME } from '../../src/lineage/recipient-registry.js';
import { validateRecipientProfile } from '../../src/lineage/recipient-profile.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

// Sub-project 8b's own real fixture shape (test/cli/dataflow-export-privacy.test.js's
// PHI_SOURCE), reused verbatim: a PHI field reaching a real, catalog-matched
// `anthropic.messages.create()` AI-provider sink.
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

// A two-call-site variant of the same fixture — two distinct functions,
// each independently calling anthropic.messages.create() — for the dedup
// proof: two sites, one recipient, contributingGraphIds merged.
const TWO_SITE_SOURCE = `
function summarizePatientA(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({ model: 'claude-3', messages: [{ role: 'user', content: patientRecord }] });
}
function summarizePatientB(anthropic, params) {
  const notes = params.arguments.patient_record;
  anthropic.messages.create({ model: 'claude-3', messages: [{ role: 'user', content: notes }] });
}
`;

// ── opts.buildRecipientProfile: no-op when omitted ──────────────────────

test('recipient-wiring/1: opts.buildRecipientProfile is a no-op when omitted — graph.recipientProfiles stays [] (mirrors M2A1/hook-1\'s own precedent)', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const r = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  // graph.recipientProfiles is always present (possibly empty), never
  // undefined — the hook's own absence still yields the field, just empty.
  assert.deepEqual(r.graph.recipientProfiles, []);
});

test('recipient-wiring/1b: omitting opts.buildRecipientProfile leaves every other field byte-identical to a run with a no-op hook', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const baseline = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  const withNoopHook = buildDataFlowGraph(cg, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    buildRecipientProfile: () => null,
  });
  assert.deepEqual(baseline.graph, withNoopHook.graph);
});

// ── opts.buildRecipientProfile: real composition + real profile ─────────

test('recipient-wiring/2: a real buildRecipientProfile hook populates graph.recipientProfiles on a real AI-provider sink', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const built = buildDataFlowGraph(cg, {
    repository: 'r',
    generatedAt: '1970-01-01T00:00:00.000Z',
    resolveDestination,
    buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  assert.equal(built.graph.recipientProfiles.length, 1, 'expected exactly one recipient profile');
  const profile = built.graph.recipientProfiles[0];
  assert.equal(profile.provider, 'anthropic');
  assert.equal(profile.fieldEvidence.provider.factType, 'code_inferred');
  assert.deepEqual(profile.contributingGraphIds.length, 1);
  // fix-round-1, B3: contributingGraphIds must contain a REAL, stable
  // graph node id (node:<kind>:<hex>, minted by ids.js's nodeId) — never
  // a CFG-parse-local counter value like "n6" (parser-js.js's own
  // _nodeIdSeq), which made --filter a permanent no-op.
  assert.match(profile.contributingGraphIds[0], /^node:[a-z-]+:[0-9a-f]{12}$/);
  assert.ok(
    built.graph.nodes.some((n) => n.id === profile.contributingGraphIds[0]),
    'expected contributingGraphIds[0] to be a real id from graph.nodes[]',
  );
  const { valid, errors } = validateRecipientProfile(profile);
  assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
});

test('recipient-wiring/3: two sink sites resolving to the SAME recipient dedup into one record, merging contributingGraphIds', () => {
  const cg = irOf({ 'a.js': TWO_SITE_SOURCE });
  const { sites } = enumerateSinkSites(cg);
  assert.equal(sites.length, 2, 'expected two distinct sink sites in the fixture');

  const built = buildDataFlowGraph(cg, {
    repository: 'r',
    generatedAt: '1970-01-01T00:00:00.000Z',
    resolveDestination,
    buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  assert.equal(built.graph.recipientProfiles.length, 1, 'expected the two sites to dedup onto one recipient record');
  const profile = built.graph.recipientProfiles[0];
  // fix-round-1, B3: contributingGraphIds now holds the REAL, stable graph
  // node id (`sinkNodeFor(site).id`), not the old CFG-parse-local
  // `site.nodeId` counter. A graph node's identity is a REGISTRY DECISION
  // (kind, subtypeKey, coverageStatus, externality) — never a call site
  // (see this package's own graph-builder.js §6-§8 header) — so these two
  // sink sites (both `anthropic.messages.create()`, identical decision
  // shape) correctly collide onto the SAME graph node, and the merged
  // contributingGraphIds set is length 1, not 2 (the pre-fix test's own
  // "2 distinct nodeIds" expectation reflected the bug: `site.nodeId`
  // spuriously differed per call site even when the underlying registry
  // decision, and therefore the real node, was identical).
  assert.equal(profile.contributingGraphIds.length, 1, 'expected both sites to collide onto the one real sink node they share');
  const [id] = profile.contributingGraphIds;
  assert.match(id, /^node:[a-z-]+:[0-9a-f]{12}$/);
  assert.ok(built.graph.nodes.some((n) => n.id === id), `expected ${id} to be a real id from graph.nodes[]`);
});

// ── fix-round-1, B2: graphDigest reflects real graph content ────────────

test('fix-round-1/B2: two genuinely different fixtures produce DIFFERENT graphDigest values on their recipient profiles', () => {
  // TWO_SITE_SOURCE has different function bodies (two call sites) than
  // PHI_SOURCE (one call site) — genuinely different graphs, so their
  // recipientProfiles[0].graphDigest must differ. Before the B2 fix,
  // buildRecipientProfile's opts.buildRecipientProfile(site, graph) hook
  // ran while graph.nodes/.edges/.flows/.dataElements were still the
  // still-empty emptyGraphEnvelope() shape, so computeGraphDigest(graph)
  // hashed the same constant content regardless of the real fixture.
  const cgA = irOf({ 'a.js': PHI_SOURCE });
  const builtA = buildDataFlowGraph(cgA, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    resolveDestination, buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  const cgB = irOf({ 'a.js': TWO_SITE_SOURCE });
  const builtB = buildDataFlowGraph(cgB, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    resolveDestination, buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  assert.equal(builtA.graph.recipientProfiles.length, 1);
  assert.equal(builtB.graph.recipientProfiles.length, 1);
  const digestA = builtA.graph.recipientProfiles[0].graphDigest;
  const digestB = builtB.graph.recipientProfiles[0].graphDigest;
  assert.notEqual(digestA, '(no graph)');
  assert.notEqual(digestB, '(no graph)');
  assert.notEqual(digestA, digestB, 'expected two genuinely different graphs to produce different graphDigest values');
});

// ── fix-round-1, M6: order-dependent dedup no longer drops facts ────────

test('fix-round-1/M6: a later site\'s non-null facts fill in fields the first-seen site left empty, on dedup to the same recipient', () => {
  const cg = irOf({ 'a.js': TWO_SITE_SOURCE });
  const { sites } = enumerateSinkSites(cg);
  assert.equal(sites.length, 2, 'expected two distinct sink sites in the fixture');

  // A synthetic hook simulating the exact M6 scenario: two sites resolve
  // to the SAME recipient id (same recipientKey/graphId/graphDigest), but
  // only the SECOND site's resolution carries technicalEndpoint/legalEntity
  // — e.g. because only that call site's destination happened to resolve
  // to a literal. Before the fix, the merge only unioned
  // contributingGraphIds and silently kept the FIRST site's all-null facts
  // forever, even though the second site had real values to offer.
  let callCount = 0;
  const hook = (site, graph) => {
    callCount += 1;
    const base = {
      id: 'recipient:synthetic-test:fixed-id',
      graphId: graph.graphId ?? '(no graph)',
      graphDigest: '(no graph)',
      recipientKey: 'synthetic-test',
      technicalEndpoint: null, provider: 'synthetic', serviceType: 'ai-model-provider',
      legalEntity: null, processorRole: null, servicePurpose: null, subprocessorChain: [],
      processingCountries: [], dataResidencyCommitment: null, observedRegion: null,
      dpaStatus: null, transferMechanism: null, transferImpactReviewStatus: null,
      retentionCommitment: null,
      fieldEvidence: { provider: { factType: 'code_inferred', source: 'test' }, serviceType: { factType: 'code_inferred', source: 'test' } },
      contributingGraphIds: [], confidence: null, owner: null, reviewDate: null, conflicts: [], expiration: null,
    };
    if (callCount === 2) {
      return {
        ...base,
        technicalEndpoint: 'https://real-endpoint.example.com',
        legalEntity: 'Real Corp',
        fieldEvidence: {
          ...base.fieldEvidence,
          technicalEndpoint: { factType: 'code_inferred', source: 'test' },
          legalEntity: { factType: 'declared', source: 'test' },
        },
      };
    }
    return base;
  };

  const built = buildDataFlowGraph(cg, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    buildRecipientProfile: hook,
  });
  assert.equal(callCount, 2, 'expected the hook to run once per site');
  assert.equal(built.graph.recipientProfiles.length, 1, 'expected both sites to dedup onto one record');
  const profile = built.graph.recipientProfiles[0];
  assert.equal(profile.technicalEndpoint, 'https://real-endpoint.example.com', 'expected the second site\'s technicalEndpoint to survive the merge');
  assert.equal(profile.legalEntity, 'Real Corp', 'expected the second site\'s legalEntity to survive the merge');
  assert.equal(profile.fieldEvidence.technicalEndpoint.factType, 'code_inferred');
  assert.equal(profile.fieldEvidence.legalEntity.factType, 'declared');
  // Both sites are the identical `anthropic.messages.create()` shape, so
  // (per recipient-wiring/3's own note) they collide onto ONE real sink
  // node — contributingGraphIds is length 1, not 2. The hook itself still
  // ran twice (asserted above via callCount), proving the merge itself
  // (not just node collision) is what's under test here.
  assert.equal(profile.contributingGraphIds.length, 1);
});

test('recipient-wiring/4: a site with no destination at all still resolves a recipient via framework alone (AC-07 shape)', () => {
  // resolveDestination is deliberately OMITTED here — site.destination
  // stays undefined for every site, proving the hook does not require a
  // resolved destination to produce a real profile (an anthropic SDK call
  // resolves via site.entry.framework regardless).
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const built = buildDataFlowGraph(cg, {
    repository: 'r',
    generatedAt: '1970-01-01T00:00:00.000Z',
    buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  assert.equal(built.graph.recipientProfiles.length, 1);
  assert.equal(built.graph.recipientProfiles[0].provider, 'anthropic');
});

test('recipient-wiring/5: the hook composes with resolveDestination/resolveSiteDecision, all three applying to the same site', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const built = buildDataFlowGraph(cg, {
    repository: 'r',
    generatedAt: '1970-01-01T00:00:00.000Z',
    resolveDestination,
    resolveSiteDecision: () => undefined,
    buildRecipientProfile: (site, graph) => buildRecipientProfile(site, graph, {}),
  });
  assert.equal(built.graph.recipientProfiles.length, 1);
});

// ── coverage.js: default opts.buildRecipientProfile wiring ──────────────

test('recipient-wiring/6: buildGraphWithCoverage wires a default buildRecipientProfile closing over opts.recipientConfig', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const recipientConfig = {
    recipients: {
      anthropic: { legalEntity: 'Anthropic PBC', processorRole: 'processor', dpaStatus: 'in_place', processingCountries: ['US'] },
    },
  };
  const built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', recipientConfig });
  assert.equal(built.graph.recipientProfiles.length, 1);
  const profile = built.graph.recipientProfiles[0];
  assert.equal(profile.provider, 'anthropic');
  assert.equal(profile.legalEntity, 'Anthropic PBC');
  assert.equal(profile.fieldEvidence.legalEntity.factType, 'declared');
  assert.deepEqual(profile.processingCountries, ['US']);
});

test('recipient-wiring/7: buildGraphWithCoverage with no recipientConfig at all still produces a catalog-only profile, never throws', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.equal(built.graph.recipientProfiles.length, 1);
  assert.equal(built.graph.recipientProfiles[0].provider, 'anthropic');
  assert.equal(built.graph.recipientProfiles[0].legalEntity, null);
});

test('recipient-wiring/8: a caller-supplied opts.buildRecipientProfile override wins over buildGraphWithCoverage\'s own default', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const built = buildGraphWithCoverage(cg, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    buildRecipientProfile: () => null,
  });
  assert.deepEqual(built.graph.recipientProfiles, []);
});

test('recipient-wiring/9: a fixture reaching nothing recipient-worthy produces an empty (not fabricated) recipientProfiles array', () => {
  const cg = irOf({ 'a.js': "function h(req, res){ const pw = req.body.password; res.send(pw); }" });
  const built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(built.graph.recipientProfiles, []);
});

// ── index.js: the config-file-loaded-once discipline ─────────────────────
// Mirrors G1/1b/G1/7's own real, established precedent for
// `privacySinkPolicy` — an outcome-based end-to-end proof against a real
// file on disk (not a call-count spy: no such spy exists anywhere in this
// package for `loadPrivacySinkPolicy`/`loadPrivacyGovernanceConfig` either,
// confirmed by reading policy-verdict.test.js directly — `loadRecipientConfig`
// mirrors THAT precedent, not `scanTransitEvidence`'s Proxy-based one).

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-recipient-wiring-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

async function writeRecipientConfig(dir, obj) {
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, '.agentic-security', RECIPIENT_CONFIG_FILENAME), JSON.stringify(obj, null, 2));
}

test('recipient-wiring/10: buildLineageGraph with NO scanRoot recipient-profiles.json still produces a catalog-only profile end to end', async () => {
  const dir = await tmpProject();
  try {
    const cg = irOf({ 'a.js': PHI_SOURCE });
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, deterministic: true });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.recipientProfiles.length, 1);
    assert.equal(r.graph.recipientProfiles[0].provider, 'anthropic');
    assert.equal(r.graph.recipientProfiles[0].legalEntity, null);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('recipient-wiring/11: buildLineageGraph end to end — a real recipient-profiles.json on disk is loaded once and drives real declared fields', async () => {
  const dir = await tmpProject();
  try {
    await writeRecipientConfig(dir, {
      recipients: { anthropic: { legalEntity: 'Anthropic PBC', processorRole: 'processor', dpaStatus: 'in_place', processingCountries: ['US'] } },
    });
    const cg = irOf({ 'a.js': PHI_SOURCE });
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, deterministic: true });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.recipientProfiles.length, 1);
    const profile = r.graph.recipientProfiles[0];
    assert.equal(profile.provider, 'anthropic');
    assert.equal(profile.legalEntity, 'Anthropic PBC');
    assert.equal(profile.fieldEvidence.legalEntity.factType, 'declared');
    const { valid, errors } = validateRecipientProfile(profile);
    assert.equal(valid, true, `expected a valid RecipientProfile, got: ${JSON.stringify(errors)}`);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('recipient-wiring/12: buildLineageGraph with no opts.scanRoot at all never throws and produces a catalog-only profile', () => {
  const cg = irOf({ 'a.js': PHI_SOURCE });
  const r = buildLineageGraph(cg, { repository: 'r', deterministic: true });
  assert.equal(r.status, 'complete');
  assert.equal(r.graph.recipientProfiles.length, 1);
  assert.equal(r.graph.recipientProfiles[0].legalEntity, null);
});

test('recipient-wiring/13: a malformed recipient-profiles.json on disk degrades gracefully (catalog-only), never crashes the scan', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', RECIPIENT_CONFIG_FILENAME), '{not valid json');
    const cg = irOf({ 'a.js': PHI_SOURCE });
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, deterministic: true });
    assert.equal(r.status, 'complete');
    assert.equal(r.graph.recipientProfiles.length, 1);
    assert.equal(r.graph.recipientProfiles[0].legalEntity, null);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
