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
  assert.equal(profile.contributingGraphIds.length, 2, 'expected both sites\' nodeIds merged');
  assert.equal(new Set(profile.contributingGraphIds).size, 2, 'expected two DISTINCT nodeIds, not a duplicate');
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
