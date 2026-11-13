// Contract test for the Haskell and Nix/NixOS analysis (docs/reference/language-depth-contract.md): the language finding and component
// metadata, the producer registry, the per-file coverage outcomes and the shape of the generated support registry. Every table on the
// page is held against the code in both directions, and every rule is exercised on small inline inputs through the real functions
// (the real Haskell and Nix adapters for the missing-grammar case). No network, no compiler, no nix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { REPO, readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import {
  LANGUAGE_CONTRACT_VERSION, LANGUAGES, CAPABILITIES, EVIDENCE_KINDS, FILE_STATUSES, OUTCOME_KINDS, UNCERTAINTY_KINDS,
  registerLanguageProducer, isRegisteredLanguageProducer, validateLanguageFinding, validateLanguageComponent, withLanguageMetadata,
  runLanguageAnalysis, reconcileLanguageLedger, languageHealth,
} from '../../src/language/contracts.js';
import { isRegisteredProducer } from '../../src/pipeline/producer-registry.js';
import { createHaskellAdapter } from '../../src/language/haskell-adapter.js';
import { createNixAdapter } from '../../src/language/nix-adapter.js';
import {
  SUPPORT_REGISTRY_VERSION, REQUIRED_CAPABILITIES, REQUIRES_TOOL, NON_PROMOTING_EVIDENCE, evaluateSupport, checkPromotion,
} from '../../src/language/support-registry.js';

const PAGE = readPage('docs/reference/language-depth-contract.md');
const CONTRACTS_SRC = fs.readFileSync(path.join(REPO, 'scanner/src/language/contracts.js'), 'utf8');
const REGISTRY_SRC = fs.readFileSync(path.join(REPO, 'scanner/src/language/support-registry.js'), 'utf8');
const BUILD_SRC = fs.readFileSync(path.join(REPO, 'bench/language-support/registry-build.mjs'), 'utf8');
const REGISTRY = JSON.parse(fs.readFileSync(path.join(REPO, 'docs/language-support.json'), 'utf8'));

const sorted = (xs) => [...xs].sort();
const sameSet = (a, b, label) => assert.deepEqual(sorted(new Set(a)), sorted(new Set(b)), `${label}: the code and the page disagree`);
/** The table row line for `name` under the bold heading `heading`. */
function rowLine(heading, name) {
  const lines = PAGE.split('\n');
  const at = lines.findIndex((l) => l.startsWith(`**${heading}`));
  for (let i = at + 1; i < lines.length && !lines[i].startsWith('**') && !lines[i].startsWith('#'); i++) {
    if (lines[i].startsWith(`| \`${name}\` |`)) return lines[i];
  }
  assert.fail(`no "${name}" row under "${heading}"`);
}
const LEGACY = { id: 'L-1', severity: 'high', file: 'src/A.hs', line: 3, vuln: 'x', cwe: 'CWE-78', description: 'd', remediation: 'r', parser: 'IR', family: 'command-injection' };

const PRODUCER = 'language:contract-test-sast';
const producerDef = registerLanguageProducer({ id: PRODUCER, language: 'haskell', capability: 'sast', evidenceKinds: ['source', 'manifest'], version: '2' });

// ---- metadata ----

test('vocabularies: languages, capabilities, evidence kinds and uncertainty kinds equal the page tables', () => {
  sameSet(LANGUAGES, fieldsUnder(PAGE, 'Languages'), 'languages');
  sameSet(CAPABILITIES, fieldsUnder(PAGE, 'Capabilities'), 'capabilities');
  sameSet(EVIDENCE_KINDS, fieldsUnder(PAGE, 'Evidence kinds'), 'evidence kinds');
  sameSet(UNCERTAINTY_KINDS, fieldsUnder(PAGE, 'Uncertainty kinds'), 'uncertainty kinds');
  assert.equal(LANGUAGE_CONTRACT_VERSION, 1);
});

test('finding metadata: the fields withLanguageMetadata carries equal the page, and each one is validated', () => {
  const documented = fieldsUnder(PAGE, 'Finding metadata');
  // code side, read from the implementation: `language` plus the keys it copies from metadata
  const m = /for \(const k of \[([^\]]+)\]\) \{\s*\n\s*if \(out\[k\] === undefined && meta\[k\] !== undefined\)/.exec(CONTRACTS_SRC);
  assert.ok(m, 'withLanguageMetadata copy list not found');
  const copied = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
  sameSet(['language', ...copied], documented, 'finding metadata (source)');
  // runtime side: a finding given every documented field carries exactly those on top of the legacy ones
  const meta = { language: 'haskell', capability: 'sast', evidenceKind: 'source', scope: { target: 'lib:a', configuration: null, component: 'a' }, uncertainty: [{ kind: 'unresolved-import' }], originalLocation: { line: 2, column: 0, file: 'src/A.lhs' }, producer: PRODUCER };
  const out = withLanguageMetadata(LEGACY, { ...meta, notAField: 1 });
  const added = Object.fromEntries(Object.entries(out).filter(([k]) => !(k in LEGACY)));
  sameFields(added, documented, 'finding metadata (runtime)');
  assert.deepEqual(validateLanguageFinding(out), { valid: true, errors: [] });
  assert.deepEqual(validateLanguageFinding(LEGACY), { valid: true, errors: [] }, 'a legacy finding with no language field still validates');
  // a detector-set value wins; `language` falls back to the extension
  assert.equal(withLanguageMetadata({ ...LEGACY, capability: 'taint' }, meta).capability, 'taint');
  assert.equal(withLanguageMetadata({ ...LEGACY, file: 'hosts/web.nix' }, {}).language, 'nix');
  // every documented field is checked when present
  const bad = { language: 'cobol', capability: 'magic', evidenceKind: 'vibes', scope: 'x', uncertainty: [{ kind: 'nope' }], originalLocation: { line: 0 }, producer: 'language:not-registered' };
  sameSet(Object.keys(bad), documented, 'every documented field has a rejection case');
  for (const [k, v] of Object.entries(bad)) assert.equal(validateLanguageFinding({ ...LEGACY, [k]: v }).valid, false, `bad ${k}`);
  // legacy required fields stay required
  const { family, ...noFamily } = LEGACY;
  assert.equal(validateLanguageFinding(noFamily).valid, false);
});

test('scope and original location: the checked keys equal the page tables', () => {
  const s = /for \(const k of \[([^\]]+)\]\) \{\s*\n\s*if \(s\[k\]/.exec(CONTRACTS_SRC);
  assert.ok(s, 'scope key list not found');
  sameSet([...s[1].matchAll(/'([^']+)'/g)].map((x) => x[1]), fieldsUnder(PAGE, 'Scope'), 'scope');
  for (const k of fieldsUnder(PAGE, 'Scope')) {
    assert.equal(validateLanguageFinding({ ...LEGACY, scope: { [k]: 1 } }).valid, false, `scope.${k} must be a string or null`);
    assert.equal(validateLanguageFinding({ ...LEGACY, scope: { [k]: null } }).valid, true);
  }
  const vl = /function validLocation\(loc\) \{([\s\S]*?)\n\}/.exec(CONTRACTS_SRC);
  assert.ok(vl, 'validLocation not found');
  sameSet([...vl[1].matchAll(/loc\.(\w+)/g)].map((x) => x[1]), fieldsUnder(PAGE, 'Original location'), 'original location');
  const ok = { line: 1 };
  assert.equal(validateLanguageFinding({ ...LEGACY, originalLocation: ok }).valid, true, 'line alone is enough');
  for (const bad of [{ line: 0 }, { line: 1.5 }, { line: 1, column: -1 }, { line: 1, file: 3 }]) {
    assert.equal(validateLanguageFinding({ ...LEGACY, originalLocation: bad }).valid, false, JSON.stringify(bad));
  }
});

test('component: name required, version string or null, language fields checked when present', () => {
  assert.equal(validateLanguageComponent({ name: 'text', version: '2.0' }).valid, true);
  assert.equal(validateLanguageComponent({ name: 'text', version: null, language: 'haskell', evidenceKind: 'lock' }).valid, true);
  assert.equal(validateLanguageComponent({ version: '1' }).valid, false);
  assert.equal(validateLanguageComponent({ name: 'text', version: 2 }).valid, false);
  assert.equal(validateLanguageComponent({ name: 'text', evidenceKind: 'vibes' }).valid, false);
});

// ---- producers ----

test('producer registry: the definition carries exactly the documented fields, is mirrored, and refuses bad definitions', () => {
  sameFields(producerDef, fieldsUnder(PAGE, 'Producer definition'), 'producer definition');
  assert.ok(isRegisteredLanguageProducer(PRODUCER));
  assert.ok(isRegisteredProducer(PRODUCER), 'mirrored into the shared pipeline registry');
  const base = { id: 'language:contract-test-x', language: 'nix', capability: 'config' };
  assert.throws(() => registerLanguageProducer({ ...base, language: 'cobol' }));
  assert.throws(() => registerLanguageProducer({ ...base, capability: 'magic' }));
  assert.throws(() => registerLanguageProducer({ ...base, evidenceKinds: ['vibes'] }));
  assert.throws(() => registerLanguageProducer({ ...base, id: '' }));
  assert.throws(() => registerLanguageProducer({ id: PRODUCER, language: 'haskell', capability: 'sast' }), /duplicate/);
  const d = registerLanguageProducer(base);
  assert.deepEqual([...d.evidenceKinds], ['source']);
  assert.equal(d.version, '1');
});

// ---- coverage outcomes ----

test('coverage: every status and outcome is produced for real, shapes equal the page, the ledger reconciles', async () => {
  const files = {
    'src/Ok.hs': 'module Ok where\nf x = x\n',
    'src/Branchy.hs': 'module Branchy where\ng = 1\n',
    'src/Boom.hs': 'module Boom where\n',
    'src/Slow.hs': 'module Slow where\n',
    'dist-newstyle/build/Gen.hs': 'module Gen where\n',
    'hosts/web.nix': '{ }\n',
    'README.md': 'not a language source',
  };
  const unregistered = { id: 'language:contract-test-unregistered', language: 'haskell', analyze: () => { throw new Error('an unregistered adapter must never be called'); } };
  assert.equal(isRegisteredLanguageProducer(unregistered.id), false);
  const ours = {
    id: PRODUCER, language: 'haskell', hasGrammar: () => true,
    analyze: (file) => {
      if (file === 'src/Boom.hs') throw new Error('adapter broke');
      if (file === 'src/Slow.hs') return new Promise(() => {});
      if (file === 'src/Branchy.hs') return { findings: [], unresolved: [{ line: 2, reason: 'undecided branch' }] };
      return { findings: [{ ...LEGACY, file }] };
    },
  };
  const noGrammar = createHaskellAdapter({ grammarSource: () => null });
  const run = await runLanguageAnalysis({ files, adapters: [ours, unregistered, noGrammar], timeoutMs: 50 });

  sameFields(run, fieldsUnder(PAGE, 'Run result'), 'run result');
  sameFields(run.ledger, fieldsUnder(PAGE, 'Ledger'), 'ledger');
  for (const counts of Object.values(run.ledger.byAnalyzer)) sameFields(counts, fieldsUnder(PAGE, 'Analyzer counts'), 'analyzer counts');

  // per-file statuses
  const row = run.ledger.byFile;
  assert.equal(row['src/Ok.hs'][PRODUCER], 'analyzed');
  assert.equal(row['src/Branchy.hs'][PRODUCER], 'unresolved');
  assert.equal(row['src/Boom.hs'][PRODUCER], 'failed');
  assert.equal(row['src/Slow.hs'][PRODUCER], 'timed_out');
  assert.equal(row['src/Ok.hs'][noGrammar.id], 'missing_grammar', 'a missing grammar is a status, not a throw');
  assert.equal(row['src/Ok.hs'][unregistered.id], 'unresolved', 'an unregistered producer leaves the file unresolved, never clean');

  // the vocabulary: FILE_STATUSES equals the page; every status but the reserved `excluded` is produced; `excluded` never is
  sameSet(FILE_STATUSES, fieldsUnder(PAGE, 'File statuses'), 'file statuses');
  const seen = new Set(Object.values(row).flatMap((r) => Object.values(r)));
  sameSet(seen, FILE_STATUSES.filter((s) => s !== 'excluded'), 'statuses produced');
  assert.ok(!/setStatus\('excluded'\)/.test(CONTRACTS_SRC), 'runLanguageAnalysis assigns no excluded status (the page says it is reserved)');
  for (const c of Object.values(run.ledger.byAnalyzer)) assert.equal(c.excluded, 0);
  assert.equal(row['dist-newstyle/build/Gen.hs'], undefined);
  assert.deepEqual(run.ledger.excludedFiles, ['dist-newstyle/build/Gen.hs']);
  assert.ok(!('README.md' in row), 'a non-language file is not an analyzer input');

  // outcome kinds: all seven produced, equal to OUTCOME_KINDS and the page
  sameSet(OUTCOME_KINDS, fieldsUnder(PAGE, 'Outcome kinds'), 'outcome kinds');
  sameSet(run.outcomes.map((o) => o.kind), OUTCOME_KINDS, 'outcome kinds produced');
  for (const o of run.outcomes) for (const k of ['kind', 'file', 'language']) assert.ok(k in o, `${o.kind} outcome lacks ${k}`);

  // unregistered producer: its results are discarded and reported
  assert.ok(run.outcomes.some((o) => o.kind === 'unregistered-producer' && o.analyzer === unregistered.id));
  assert.ok(run.findings.every((f) => f.producer === PRODUCER), 'only registered producers contribute findings');
  assert.equal(run.findings.length, 1);
  const f = run.findings[0];
  assert.equal(f.language, 'haskell'); assert.equal(f.capability, 'sast'); assert.equal(f.producer, PRODUCER);
  assert.equal(validateLanguageFinding(f).valid, true);

  // reconciliation holds, and fails when a file is dropped or a status is invented
  assert.deepEqual(reconcileLanguageLedger(run.ledger, files), { ok: true, errors: [] });
  const dropped = JSON.parse(JSON.stringify(run.ledger)); dropped.discoveredFiles = dropped.discoveredFiles.filter((x) => x !== 'src/Ok.hs');
  assert.equal(reconcileLanguageLedger(dropped, files).ok, false);
  const invented = JSON.parse(JSON.stringify(run.ledger)); invented.byFile['src/Ok.hs'][PRODUCER] = 'fine';
  assert.equal(reconcileLanguageLedger(invented, files).ok, false);

  // health: documented fields, version, excluded paths in totals, a condition for every gap
  const health = languageHealth(run);
  sameFields(health, fieldsUnder(PAGE, 'Language health'), 'language health');
  assert.equal(health.schemaVersion, LANGUAGE_CONTRACT_VERSION);
  assert.equal(health.totals.excluded, 1);
  for (const re of [/grammar unavailable/, /adapter exception/, /timed out/, /unresolved language branch/, /unregistered language producer were discarded/]) {
    assert.ok(health.conditions.some((c) => re.test(c)), `no condition matching ${re}`);
  }
});

test('missing grammar: the real Haskell and Nix adapters report missing_grammar for an absent or tampered grammar, never a throw', async () => {
  const files = { 'src/A.hs': 'module A where\nf x = x\n', 'web.nix': '{ a = 1; }\n' };
  const run = await runLanguageAnalysis({ files, adapters: [createHaskellAdapter({ grammarSource: () => ({ tampered: true }) }), createNixAdapter({ grammarSource: () => null })] });
  assert.equal(Object.values(run.ledger.byFile['src/A.hs'])[0], 'missing_grammar');
  assert.equal(Object.values(run.ledger.byFile['web.nix'])[0], 'missing_grammar');
  assert.equal(run.outcomes.filter((o) => o.kind === 'missing-grammar').length, 2);
  // with the shipped grammar the same files are analyzed
  const good = await runLanguageAnalysis({ files, adapters: [createHaskellAdapter(), createNixAdapter()] });
  assert.equal(Object.values(good.ledger.byFile['src/A.hs'])[0], 'analyzed');
  assert.equal(Object.values(good.ledger.byFile['web.nix'])[0], 'analyzed');
  assert.deepEqual(reconcileLanguageLedger(good.ledger, files).ok, true);
});

// ---- support registry ----

test('registry: the committed docs/language-support.json carries exactly the documented envelope, entries, rows and tools', () => {
  sameFields(REGISTRY, fieldsUnder(PAGE, 'Registry envelope'), 'registry envelope');
  assert.equal(REGISTRY.schema, 'agentic-security/language-support@1');
  assert.equal(REGISTRY.version, SUPPORT_REGISTRY_VERSION);
  sameFields(REGISTRY.tools, fieldsUnder(PAGE, 'Tools'), 'tools');
  sameFields(REGISTRY.verified, ['ok', 'stale'], 'verified');
  sameSet(Object.keys(REGISTRY.languages), LANGUAGES, 'registry languages');
  const statuses = fieldsUnder(PAGE, 'Row statuses');
  for (const [lang, entry] of Object.entries(REGISTRY.languages)) {
    sameFields(entry, fieldsUnder(PAGE, 'Language entry'), `${lang} entry`);
    for (const r of Object.values(entry.rows)) {
      sameFields(r, fieldsUnder(PAGE, 'Capability row'), `${lang}/${r.capability} row`, ['generalization']);
      assert.ok(statuses.includes(r.status), `${lang}/${r.capability}: status "${r.status}" is not on the page`);
    }
  }
});

test('registry: required capabilities and their metric kinds equal the page, the code and the committed rows', () => {
  for (const lang of LANGUAGES) {
    const heading = `Required capabilities: ${lang}`;
    const names = fieldsUnder(PAGE, heading);
    sameSet(Object.keys(REQUIRED_CAPABILITIES[lang]), names, `${lang} required capabilities`);
    sameSet(Object.keys(REGISTRY.languages[lang].rows), names, `${lang} committed rows`);
    for (const cap of names) {
      const line = rowLine(heading, cap);
      const kind = /^\| `[^`]+` \| `([^`]+)`/.exec(line)[1];
      assert.equal(kind, REQUIRED_CAPABILITIES[lang][cap], `${lang}/${cap} metric kind`);
    }
    // the rows the page marks "blocked without" are exactly the ones that need a tool
    sameSet(names.filter((c) => /blocked without/.test(rowLine(heading, c))), Object.keys(REQUIRES_TOOL[lang] || {}), `${lang} tool-gated rows`);
  }
});

test('registry: the row status vocabulary equals the statuses the code can assign (no "partial")', () => {
  const code = (REGISTRY_SRC + '\n' + BUILD_SRC).split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  const found = new Set();
  for (const re of [/status:\s*'([a-z_-]+)'/g, /\.status\s*=\s*'([a-z_-]+)'/g, /row\(cap,\s*'([a-z_-]+)'/g, /status[^\n]*?\?\s*(?:\([^)]*\?\s*)?'([a-z_-]+)'\s*:\s*'([a-z_-]+)'/g, /row\(cap,[^\n]*?\?\s*'([a-z_-]+)'\s*:\s*'([a-z_-]+)'/g]) {
    for (const m of code.matchAll(re)) for (const g of m.slice(1)) if (g) found.add(g);
  }
  // the generalization sub-status shares the `status` key; its values are documented in the row's `generalization` cell
  const genCell = rowLine('Capability row', 'generalization');
  const genStatuses = [...genCell.split('|')[2].matchAll(/`([^`]+)`/g)].map((x) => x[1]);
  sameSet(found, [...fieldsUnder(PAGE, 'Row statuses'), ...genStatuses], 'row and generalization statuses');
  assert.ok(!found.has('partial'), 'no code path assigns "partial"');
});

test('registry rules: an absent tool blocks its rows, and evidence of another or a non-promoting kind never promotes', () => {
  for (const lang of LANGUAGES) {
    const none = evaluateSupport(lang, { measurement: {}, tools: {} });
    const all = evaluateSupport(lang, { measurement: {}, tools: { ghc: true, ghcMatchesRecorded: true, nix: true, nixos: true } });
    for (const cap of Object.keys(REQUIRED_CAPABILITIES[lang])) {
      if (REQUIRES_TOOL[lang] && REQUIRES_TOOL[lang][cap]) {
        assert.equal(none.rows[cap].status, 'blocked', `${lang}/${cap} without its tool`);
        assert.equal(all.rows[cap].status, 'not-measured', `${lang}/${cap} with its tool but no evidence`);
      } else if (cap === 'sca') {
        // stated on the page as a limit: an absent supply measurement is `failed`, not `not-measured`
        assert.equal(none.rows[cap].status, 'failed', `${lang}/sca with no evidence`);
        assert.match(none.rows[cap].reasons[0], /no manifest-resolution measurement/);
      } else {
        assert.equal(none.rows[cap].status, 'not-measured', `${lang}/${cap} with no evidence`);
      }
    }
  }
  const rule = PAGE.split('\n').find((l) => l.startsWith('- **Evidence of another kind never promotes.**'));
  assert.ok(rule, 'the promotion rule is on the page');
  sameSet([...rule.split(';')[1].matchAll(/`([^`]+)`/g)].map((x) => x[1]), NON_PROMOTING_EVIDENCE, 'non-promoting evidence');
  const evaluated = { rows: { sast: { status: 'supported', reasons: [] } } };
  assert.equal(checkPromotion('haskell', 'sast', 'supported', { metric: 'sast-holdout' }, evaluated).ok, true);
  assert.equal(checkPromotion('haskell', 'sast', 'supported', { metric: 'test-suite' }, evaluated).ok, false, 'another kind');
  for (const k of NON_PROMOTING_EVIDENCE) assert.equal(checkPromotion('haskell', 'sast', 'supported', { metric: k }, evaluated).ok, false, k);
});

test('page: the limits section is present and dated, and the page uses no em-dash', () => {
  assert.match(PAGE, /\n## What this does not do\n\n<!-- limits-verified: \d{4}-\d{2}-\d{2} -->\n/);
  assert.ok(!PAGE.includes('\u2014'), 'no em-dash on the page');
});
