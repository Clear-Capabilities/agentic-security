// X-007: scan health, assurance and deployment verdict parity for Haskell and Nix. Tests are tagged [X-007.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessLanguageAssurance, REQUIRED_CAPABILITIES } from '../../src/language/assurance.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';
import { evaluateAssuranceMode } from '../../src/pipeline/assurance-mode.js';
import { toShipVerdict } from '../../src/report/index.js';
import { createHaskellAdapter } from '../../src/language/haskell-adapter.js';
import { createNixAdapter } from '../../src/language/nix-adapter.js';
import { AdvisoryDb } from '../../src/language/haskell-sca.js';
import { resolveNixosConfig } from '../../src/language/nixos-module-resolver.js';

const HS = 'module Main where\nmain :: IO ()\nmain = putStrLn "ok"\n';
const NIX = '{ config, pkgs, ... }: { services.openssh.enable = true; }\n';
const CABAL = 'cabal-version: 2.4\nname: demo\nversion: 0.1\nexecutable demo\n  main-is: Main.hs\n  build-depends: base, aeson >=2.0\n';
const base = () => ({ 'src/Main.hs': HS, 'configuration.nix': NIX, 'demo.cabal': CABAL });
const freshDb = () => new AdvisoryDb({ records: [], generatedAt: new Date().toISOString(), now: Date.now() });
const FINDING = { id: 'f1', severity: 'low', file: 'src/Main.hs', line: 1, vuln: 'x', cwe: 'CWE-1', description: 'd', remediation: 'r', parser: 'T', family: 'f' };
const health = (a, extra = {}) => computeScanHealth({ languageCoverage: a.languageCoverage, ...extra });
const assess = (o = {}) => assessLanguageAssurance({ files: base(), advisoryDb: freshDb(), findings: [FINDING], ...o });

test('[X-007.AC01] a clean run is complete and its ledger reconciles', async () => {
  const a = await assess();
  assert.equal(a.ledger.reconciled, true);
  assert.deepEqual(a.conditions, []);
  assert.equal(health(a).status, 'complete');
  assert.equal(a.languageCoverage.optionalModes['nix-eval'].status, 'not_selected');
});

test('[X-007.AC01] a timeout shows in health, the other file is still analysed, findings are retained', async () => {
  const hung = { ...createHaskellAdapter(), analyze: () => new Promise(() => {}) };
  const a = await assess({ adapters: [hung, createNixAdapter()], timeoutMs: 25 });
  assert.ok(a.conditions.some((c) => /timed out/.test(c)));
  assert.equal(a.ledger.byAnalyzer['language:haskell-parse'].timedOut, 1);
  assert.equal(a.ledger.byAnalyzer['language:nix-parse'].analyzed, 1, 'the Nix file is unaffected');
  assert.equal(a.ledger.reconciled, true);
  assert.equal(a.retained.findings, 1); assert.equal(a.retained.findingsRef[0], FINDING);
  assert.equal(health(a).status, 'partial');
});

test('[X-007.AC01] a corrupt grammar is reported, not treated as clean', async () => {
  const a = await assess({ adapters: [createHaskellAdapter({ grammarSource: () => ({ keywords: 'nope' }) }), createNixAdapter()] });
  assert.ok(a.conditions.some((c) => /grammar unavailable or corrupt/.test(c)));
  assert.equal(a.languageCoverage.capabilities.haskell.parser.status, 'failed');
});

test('[X-007.AC01] a malformed manifest, a stale feed and a partial effective config each appear', async () => {
  const bad = await assess({ files: { ...base(), 'demo.cabal': 'name: demo\nexecutable x\n  build-depends: base >>>> 2 &&& \n' } });
  assert.ok(bad.conditions.some((c) => /malformed Haskell manifest|manifest/i.test(c)), JSON.stringify(bad.conditions));
  const stale = await assess({ advisoryDb: new AdvisoryDb({ records: [], generatedAt: '2020-01-01T00:00:00Z', now: Date.parse('2026-10-01'), maxAgeDays: 30 }) });
  assert.ok(stale.conditions.some((c) => /advisory snapshot is stale/.test(c)));
  const none = await assess({ advisoryDb: null });
  assert.ok(none.conditions.some((c) => /no Hackage advisory snapshot is loaded/.test(c)));
  const report = resolveNixosConfig({ files: { 'configuration.nix': '{ config, ... }: { imports = [ ./missing.nix ]; }' }, entry: 'configuration.nix' });
  const unresolved = await assess({ effectiveConfigs: [{ ...report, completeness: 'partial', unresolved: [{ kind: 'import' }], truncated: [] }] });
  assert.ok(unresolved.conditions.some((c) => /effective NixOS configuration .* is partial/.test(c)));
});

test('[X-007.AC01] a disabled required analyzer is a condition; counts reconcile', async () => {
  const a = await assess({ disabled: ['haskell:taint'] });
  assert.ok(a.conditions.some((c) => /required analyzer "haskell:taint" is disabled/.test(c)));
  assert.equal(a.languageCoverage.capabilities.haskell.taint.status, 'disabled');
  assert.deepEqual(Object.keys(a.languageCoverage.capabilities.haskell), [...REQUIRED_CAPABILITIES.haskell]);
  const t = a.languageCoverage.totals;
  assert.equal(t.analyzed + t.excluded + t.unresolved + t.failed + t.timedOut + t.missingGrammar, 2, 'one Haskell and one Nix file, each counted exactly once');
});

test('[X-007.AC02] zero findings plus incomplete required analysis is never safe to deploy or a strict pass', async () => {
  const a = await assess({ findings: [], disabled: ['haskell:sca'] });
  const scanHealth = health(a);
  assert.equal(scanHealth.status, 'partial');
  const strict = evaluateAssuranceMode('strict', scanHealth, []);
  assert.equal(strict.ok, false); assert.match(strict.reason, /fully complete scan/);
  const verdict = toShipVerdict({ findings: [], scanHealth }, { color: false });
  assert.match(verdict, /Scan incomplete/); assert.doesNotMatch(verdict, /Safe to deploy/);
  // documented semantics for the other modes are unchanged: they report, they do not gate
  assert.equal(evaluateAssuranceMode('advisory', scanHealth, []).ok, true);
  assert.equal(evaluateAssuranceMode('standard', scanHealth, []).ok, true);
  const clean = health(await assess({ findings: [] }));
  assert.equal(evaluateAssuranceMode('strict', clean, []).ok, true);
  assert.match(toShipVerdict({ findings: [], scanHealth: clean }, { color: false }), /Safe to deploy/);
});

test('[X-007.AC02] an expected static limit (opaque boundary) is listed, not a failure, and is not hidden', async () => {
  const th = '{-# LANGUAGE TemplateHaskell #-}\nmodule T where\nimport Language.Haskell.TH\nx = $(litE (integerL 1))\n';
  const a = await assess({ files: { ...base(), 'src/T.hs': th } });
  assert.ok(a.limitations.length >= 1, 'the Template Haskell boundary is disclosed');
  assert.ok(a.limitations.some((l) => l.kind === 'opaque-boundary'));
  assert.ok(a.limitations.every((l) => l.kind === 'opaque-boundary' || l.kind === 'unmodeled-imports'), 'only limits, never a condition');
  assert.ok(a.conditions.every((c) => !/opaque/.test(c)), 'an expected limit is not a condition');
  assert.equal(a.ledger.byAnalyzer['language:haskell-parse'].unresolved, 1, 'the file stays unresolved in the ledger');
  assert.equal(a.ledger.reconciled, true);
});

test('[X-007.AC03] a failed optional resolver keeps static results; an absent mode is never reported as run', async () => {
  const failed = await assess({ optional: { 'nix-eval': { selected: true, result: { status: 'failed', reason: 'sandbox probe failed' } } } });
  assert.ok(failed.conditions.some((c) => /optional mode "nix-eval" failed .* static results are retained/.test(c)));
  assert.equal(failed.optionalModes['nix-eval'].ran, false);
  assert.equal(failed.retained.findings, 1, 'the static finding survives');
  assert.equal(failed.ledger.byAnalyzer['language:nix-parse'].analyzed, 1, 'the static scan still ran');
  const missing = await assess({ optional: { 'cabal-plan': { selected: true } } });
  assert.equal(missing.optionalModes['cabal-plan'].status, 'not_run'); assert.equal(missing.optionalModes['cabal-plan'].ran, false);
  assert.ok(missing.conditions.some((c) => /selected but did not run/.test(c)));
  const unselected = await assess();
  for (const m of Object.values(unselected.optionalModes)) { assert.equal(m.ran, false); assert.equal(m.status, 'not_selected'); }
  const ok = await assess({ optional: { 'nix-eval': { selected: true, result: { status: 'ok', ran: true } } } });
  assert.equal(ok.optionalModes['nix-eval'].ran, true); assert.deepEqual(ok.conditions, []);
});
