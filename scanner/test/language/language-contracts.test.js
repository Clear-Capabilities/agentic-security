// CORE-003: pipeline, schema and capability contracts.
// Suite "language-contracts" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EVIDENCE_KINDS, registerLanguageProducer, isRegisteredLanguageProducer, _resetLanguageProducersForTests,
  validateLanguageFinding, validateLanguageComponent, withLanguageMetadata,
  runLanguageAnalysis, reconcileLanguageLedger, languageHealth,
} from '../../src/language/contracts.js';
import { computeScanHealth } from '../../src/pipeline/scan-health.js';
import { validateGraph } from '../../src/lineage/validate.js';
import { isRegisteredProducer } from '../../src/pipeline/producer-registry.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const lineageDir = path.join(here, '../../src/lineage');
const flagship = () => JSON.parse(fs.readFileSync(path.join(lineageDir, 'fixtures/flagship-graph.json'), 'utf8'));
const schema = () => JSON.parse(fs.readFileSync(path.join(lineageDir, 'dataflow-graph.schema.json'), 'utf8'));

const legacyFinding = {
  id: 'SAST-1', severity: 'high', file: 'src/a.js', line: 3, vuln: 'x', cwe: 'CWE-89',
  description: 'd', remediation: 'r', parser: 'REGEX', family: 'sql-injection',
};

beforeEach(() => { _resetLanguageProducersForTests(); });

function registerHs() {
  return registerLanguageProducer({ id: 'language:haskell-sast', language: 'haskell', capability: 'sast', evidenceKinds: ['source'] });
}

test('[CORE-003.AC01] new findings, components and graphs validate; legacy outputs stay readable', () => {
  registerHs();
  // A legacy finding with no language fields still passes (no required field was added).
  assert.deepEqual(validateLanguageFinding(legacyFinding), { valid: true, errors: [] });

  const enriched = withLanguageMetadata(legacyFinding, {
    language: 'haskell', capability: 'sast', producer: 'language:haskell-sast',
    evidenceKind: 'source', scope: { target: 'lib:app', configuration: 'release', component: null },
    uncertainty: [{ kind: 'unresolved-import' }], originalLocation: { line: 12, column: 4, file: 'src/App.lhs' },
  });
  assert.deepEqual(validateLanguageFinding(enriched), { valid: true, errors: [] });
  // The legacy required fields and taxonomy fields survive enrichment untouched.
  for (const k of Object.keys(legacyFinding)) assert.equal(enriched[k], legacyFinding[k]);
  // A detector-set value wins over supplied metadata.
  assert.equal(withLanguageMetadata({ ...legacyFinding, language: 'nix' }, { language: 'haskell' }).language, 'nix');

  // Each new field is actually checked.
  for (const bad of [
    { language: 'cobol' }, { capability: 'magic' }, { evidenceKind: 'vibes' },
    { scope: 'x' }, { uncertainty: [{ kind: 'nope' }] }, { originalLocation: { line: 0 } },
    { producer: 'language:not-registered' },
  ]) {
    assert.equal(validateLanguageFinding({ ...legacyFinding, ...bad }).valid, false, JSON.stringify(bad));
  }
  // Removing a legacy required field fails: parser and family are not optional.
  const { parser, ...noParser } = legacyFinding;
  assert.equal(validateLanguageFinding(noParser).valid, false);

  assert.equal(validateLanguageComponent({ name: 'aeson', version: '2.1', language: 'haskell', evidenceKind: 'lock' }).valid, true);
  assert.equal(validateLanguageComponent({ name: 'aeson' }).valid, true);
  assert.equal(validateLanguageComponent({ version: '1' }).valid, false);
  assert.equal(validateLanguageComponent({ name: 'x', evidenceKind: 'bogus' }).valid, false);

  // Graph: the real schema file's required keys and the real lifecycle validator.
  const base = flagship();
  assert.equal(validateGraph(base).valid, true, JSON.stringify(validateGraph(base).errors));
  const g = structuredClone(base);
  g.coverage = {
    ...g.coverage,
    languages: [
      { language: 'haskell', filesAnalyzed: 2, filesExpected: 3, tier: 'unknown', evidenceKinds: ['source', 'lock'] },
      { language: 'nix', filesAnalyzed: 1, filesExpected: 1, tier: 'unknown', evidenceKinds: ['config', 'generated-script'] },
    ],
  };
  const res = validateGraph(g);
  assert.equal(res.valid, true, JSON.stringify(res.errors));
  const s = schema();
  for (const k of s.required) assert.ok(k in g, `graph is missing schema-required key ${k}`);
  assert.equal(s.properties.coverage.type, 'object');
  // Old outputs: the pre-change graph (no language block) is still valid and unchanged.
  assert.equal(base.coverage.languages === undefined || Array.isArray(base.coverage.languages), true);

  // Scan health: old shape is byte-identical without the new input, and keeps every prior key.
  const before = computeScanHealth({ scanMeta: { filesScanned: 2 } });
  assert.equal('languageCoverage' in before, false);
  for (const k of ['schemaVersion', 'status', 'files', 'analyzers', 'deepAnalysis', 'lineageAnalysis', 'annotatorErrorCount', 'freshness', 'conditions']) {
    assert.ok(k in before, k);
  }
  assert.equal(before.status, 'complete');
});

test('[CORE-003.AC02] per-file and per-analyzer counts reconcile to real inputs; Nix evidence kinds stay distinct', async () => {
  registerHs();
  registerLanguageProducer({ id: 'language:nix-config', language: 'nix', capability: 'config', evidenceKinds: ['config', 'generated-script'] });
  const files = {
    'src/Main.hs': 'module Main where\n',
    'src/Lib.hs': 'module Lib where\n',
    'default.nix': '{ }\n',
    'dist-newstyle/build/Gen.hs': 'module Gen where\n', // excluded build output
    'README.md': '# not a language input\n',
    'app.cabal': 'name: app\n', // manifest, not an analyzer input
  };
  const seen = [];
  const adapters = [
    { id: 'language:haskell-sast', language: 'haskell', analyze: (f) => { seen.push(f); return { findings: [] }; } },
    { id: 'language:nix-config', language: 'nix', analyze: () => ({ findings: [] }) },
  ];
  const run = await runLanguageAnalysis({ files, adapters });
  assert.deepEqual(seen.sort(), ['src/Lib.hs', 'src/Main.hs']);
  assert.deepEqual(run.ledger.discoveredFiles, ['default.nix', 'src/Lib.hs', 'src/Main.hs']);
  assert.deepEqual(run.ledger.excludedFiles, ['dist-newstyle/build/Gen.hs']);
  assert.equal(run.ledger.byAnalyzer['language:haskell-sast'].analyzed, 2);
  assert.equal(run.ledger.byAnalyzer['language:nix-config'].analyzed, 1);
  assert.deepEqual(reconcileLanguageLedger(run.ledger, files), { ok: true, errors: [] });
  assert.equal(languageHealth(run).totals.excluded, 1);

  // Reconciliation is not vacuous: a tampered ledger and a missing input are caught.
  const bad = structuredClone(run.ledger);
  bad.byAnalyzer['language:haskell-sast'].analyzed = 5;
  assert.equal(reconcileLanguageLedger(bad, files).ok, false);
  assert.equal(reconcileLanguageLedger(run.ledger, { ...files, 'src/Extra.hs': 'x' }).ok, false);

  // Nix generated-script vs config vs runtime evidence remain distinct kinds.
  const kinds = ['generated-script', 'config', 'runtime'];
  for (const k of kinds) assert.ok(EVIDENCE_KINDS.includes(k));
  assert.equal(new Set(kinds).size, 3);
  const mk = (kind) => withLanguageMetadata({ ...legacyFinding, file: 'default.nix' }, { language: 'nix', evidenceKind: kind });
  const out = kinds.map(mk);
  for (const f of out) assert.equal(validateLanguageFinding(f).valid, true);
  assert.equal(new Set(out.map((f) => f.evidenceKind)).size, 3);
  // A producer may not claim a kind it never declared at registration.
  assert.throws(() => registerLanguageProducer({ id: 'language:x', language: 'nix', capability: 'config', evidenceKinds: ['telepathy'] }));
});

test('[CORE-003.AC03] missing grammar, exception, unresolved branch and timeout reach scan health; unregistered producers cannot affect findings', async () => {
  registerHs();
  const files = {
    'a/Grammarless.hs': 'x', 'b/Throws.hs': 'x', 'c/Branchy.hs': 'x', 'd/Slow.hs': 'x', 'e/Fine.hs': 'x',
  };
  const finding = { ...legacyFinding, file: 'e/Fine.hs' };
  const adapters = [
    {
      id: 'language:haskell-sast', language: 'haskell',
      hasGrammar: () => true,
      analyze: (f) => {
        if (f === 'b/Throws.hs') throw new Error('adapter blew up');
        if (f === 'c/Branchy.hs') return { findings: [], unresolved: [{ line: 7, reason: 'dynamic dispatch' }] };
        if (f === 'd/Slow.hs') return new Promise(() => {}); // never settles
        if (f === 'e/Fine.hs') return { findings: [finding] };
        return { findings: [] };
      },
    },
  ];
  // Missing grammar is observable per file: same adapter id, grammar probe fails for one file only.
  const probe = { ...adapters[0], hasGrammar: () => false };
  const noGrammar = await runLanguageAnalysis({ files: { 'a/Grammarless.hs': 'x' }, adapters: [probe] });
  assert.equal(noGrammar.ledger.byFile['a/Grammarless.hs']['language:haskell-sast'], 'missing_grammar');
  assert.deepEqual(noGrammar.outcomes.map((o) => o.kind), ['missing-grammar']);

  const run = await runLanguageAnalysis({ files: { ...files, 'a/Grammarless.hs': 'x' }, adapters, timeoutMs: 40 });
  const status = (f) => run.ledger.byFile[f]['language:haskell-sast'];
  assert.equal(status('b/Throws.hs'), 'failed');
  assert.equal(status('c/Branchy.hs'), 'unresolved');
  assert.equal(status('d/Slow.hs'), 'timed_out');
  assert.equal(status('e/Fine.hs'), 'analyzed');
  const kinds = run.outcomes.map((o) => o.kind).sort();
  assert.deepEqual(kinds, ['adapter-exception', 'timeout', 'unresolved-branch']);
  assert.deepEqual(reconcileLanguageLedger(run.ledger, files), { ok: true, errors: [] });

  // The finding carries producer + capability + language and validates.
  assert.equal(run.findings.length, 1);
  assert.equal(run.findings[0].producer, 'language:haskell-sast');
  assert.equal(run.findings[0].capability, 'sast');
  assert.equal(run.findings[0].language, 'haskell');
  assert.equal(validateLanguageFinding(run.findings[0]).valid, true);

  // Upstream of reports: the outcomes turn the scan-health status to partial with named conditions.
  const health = computeScanHealth({ scanMeta: { filesScanned: 5 }, languageCoverage: languageHealth(run) });
  assert.equal(health.status, 'partial');
  assert.ok(health.conditions.some((c) => /exception/.test(c)));
  assert.ok(health.conditions.some((c) => /timed out/.test(c)));
  assert.ok(health.conditions.some((c) => /unresolved/.test(c)));
  assert.equal(health.languageCoverage.byKind.timeout, 1);
  const grammarHealth = computeScanHealth({ languageCoverage: languageHealth(noGrammar) });
  assert.equal(grammarHealth.status, 'partial');
  assert.ok(grammarHealth.conditions.some((c) => /grammar/.test(c)));
  // A clean run stays complete.
  const clean = await runLanguageAnalysis({ files: { 'e/Fine.hs': 'x' }, adapters: [{ id: 'language:haskell-sast', language: 'haskell', analyze: () => ({ findings: [] }) }] });
  assert.equal(computeScanHealth({ languageCoverage: languageHealth(clean) }).status, 'complete');

  // Producers are registered with the shared pipeline registry too.
  assert.equal(isRegisteredProducer('language:haskell-sast'), true);
  assert.equal(isRegisteredLanguageProducer('language:ghost'), false);

  // No unregistered producer can silently affect the verdict: its findings are discarded
  // and its files are reported unresolved, which makes scan health partial.
  const ghost = await runLanguageAnalysis({
    files: { 'e/Fine.hs': 'x' },
    adapters: [{ id: 'language:ghost', language: 'haskell', analyze: () => ({ findings: [{ ...finding, severity: 'critical' }] }) }],
  });
  assert.equal(ghost.findings.length, 0);
  assert.equal(ghost.ledger.byFile['e/Fine.hs']['language:ghost'], 'unresolved');
  assert.deepEqual(ghost.outcomes.map((o) => o.kind), ['unregistered-producer']);
  assert.equal(computeScanHealth({ languageCoverage: languageHealth(ghost) }).status, 'partial');
  // A finding naming an unregistered producer fails validation outright.
  assert.equal(validateLanguageFinding({ ...legacyFinding, producer: 'language:ghost' }).valid, false);
});
