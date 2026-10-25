// DAG-08: Nix configuration / generated-script scope through links; static Nix and declared links are never runtime-observed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nixGeneratedScriptScopes, bindNixValueToApplication, contributeNixConfigLineage, NIX_SCOPE } from '../../src/lineage/nix-view.js';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { linkEvidence, isDeclaredNotObserved } from '../../src/lineage/cross-repo-link.js';
import { correlateObservations } from '../../src/lineage/observation-correlation.js';
import { deriveEdgeStates } from '../../src/lineage/runtime-edge-states.js';
import { attributeEvidence, evidenceItem } from '../../src/lineage/boundary-contract.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const load = (d) => Object.fromEntries(readdirSync(join(FIX, d)).filter((f) => f.endsWith('.nix')).map((f) => [f, readFileSync(join(FIX, d, f), 'utf8')]));

test('Nix-to-generated-script scope keeps the original Nix location and the generated-script location', () => {
  const scopes = nixGeneratedScriptScopes(load('nix-script-taint/service-env'));
  assert.ok(scopes.length >= 1);
  for (const s of scopes) {
    assert.equal(s.originalLocation.file, 'configuration.nix');
    assert.ok(s.originalLocation.line > 0);
    assert.equal(s.generatedLocation.generated, true);
    assert.ok(s.generatedLocation.line > 0);
    assert.deepEqual(s.scope, NIX_SCOPE);
    assert.equal(s.scope.runtime, false);
    assert.equal(s.application.entersRuntime, false);
  }
  // the original line (in the Nix file) differs from the generated line (inside the script body)
  const rm = scopes.find((s) => s.rule === 'nix-service-env-shell');
  assert.notEqual(rm.originalLocation.line, rm.generatedLocation.line);
});

test('a Nix value never enters application runtime by name or by an unverified binding', () => {
  const [s] = nixGeneratedScriptScopes(load('nix-script-taint/service-env'));
  assert.equal(bindNixValueToApplication(s, null).application.entersRuntime, false);
  assert.equal(bindNixValueToApplication(s, { site: { file: 'app.js', function: 'main' } }).application.entersRuntime, false);
  assert.equal(bindNixValueToApplication(s, { verified: true, site: { file: 'app.js', function: 'main' } }).application.entersRuntime, false, 'needs a named verifier');
  assert.equal(bindNixValueToApplication(s, { verified: true, verifiedBy: 'ops', site: { file: 'app.js' } }).application.entersRuntime, false, 'needs a function');
  const ok = bindNixValueToApplication(s, { verified: true, verifiedBy: 'ops', site: { file: 'app.js', function: 'main' } });
  assert.equal(ok.application.entersRuntime, true);
  assert.equal(ok.application.observed, false, 'even a verified binding is a declaration');
  assert.equal(ok.scope.scope, 'static-configuration', 'the configuration scope is kept');
});

test('static Nix lineage never becomes a runtime-observed flow, with or without an observation store', () => {
  const graph = emptyGraphEnvelope({ graphId: 'g' });
  contributeNixConfigLineage(graph, load('nix-secrets/store'), { repository: 'r' });
  assert.ok(graph.flows.length > 0);
  assert.ok(graph.flows.every((f) => f.analysis && f.analysis.runtime === false));
  for (const obs of [null, []]) {
    const corr = correlateObservations(graph, obs, {});
    assert.equal(corr.observedFlowIds.length, 0);
    assert.ok(Object.values(corr.byFlow).every((e) => e.layer !== 'runtime_observed'));
    const states = deriveEdgeStates(graph, corr, obs || []);
    assert.equal(states.counts.RUNTIME_OBSERVED, 0);
    assert.ok(Object.values(states.byEdge).every((e) => !e.states.includes('RUNTIME_OBSERVED')));
  }
});

test('a declared cross-repo link is a manual assertion and carries the Nix static scope unchanged', () => {
  const link = {
    id: 'crosslink:abc', version: '1.0.0', provenance: 'manual', relationship: 'data_flow',
    local: { graphId: 'g', graphDigest: 'd', nodeId: 'node:x' }, remote: { graphId: 'h', graphDigest: 'e', nodeId: 'node:y', repository: 'infra', sourceFile: 'configuration.nix' },
    scope: { remote: { target: 'cleaner', config: 'services.cleaner', analysis: { language: 'nix', scope: 'static-configuration', runtime: false }, limitations: ['static configuration'] } },
    evidence: { declared: true, observed: false }, declaredBy: 'ross', declaredAt: '2026-01-01T00:00:00Z',
  };
  const ev = linkEvidence(link);
  assert.equal(ev.kind, 'manual-assertion');
  assert.equal(ev.observed, false);
  assert.equal(ev.staticConfigurationOnly, true);
  assert.deepEqual(ev.scope.remote.analysis, { language: 'nix', scope: 'static-configuration', runtime: false });
  assert.equal(attributeEvidence([ev]).observed, false);
  assert.equal(isDeclaredNotObserved(link), true);
  assert.equal(isDeclaredNotObserved({ ...link, evidence: { declared: true, observed: true } }), false);
  assert.throws(() => evidenceItem('observed-connection-from-link-guess'));
});
