// Tests for the v0.59 remaining-features additions:
//   - Python catalog entries (just validate they're loaded)
//   - Receiver-context wired into the summary-cache key
//   - P3.4 Exception flow
//   - P4.2 Sanitizer-validity proofs
//   - P4.4 String-value abstract domain
//   - P4.6 Source-side context labels (provenance)
//   - P4.5 RTA dispatch resolution

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CATALOG } from '../src/dataflow/catalog.js';
import { SummaryCache } from '../src/dataflow/summaries.js';
import {
  exceptionTaintFlow, applyExceptionTaintAtCatchEntry, joinFinally, describeTryCatchFinally,
} from '../src/dataflow/exception-flow.js';
import { isValidSanitizerFor, verifyProjectSanitizers } from '../src/dataflow/sanitizer-proof.js';
import {
  makeConst, makeConcat, join, abstract, render, isProvablyToHost, isSafeRedirectTarget, hashAbstract, TOP, BOTTOM,
} from '../src/dataflow/string-domain.js';
import {
  collectInstantiatedClasses, resolveMethodRTA, annotateRTA,
} from '../src/ir/class-hierarchy.js';

// ── Python catalog entries ────────────────────────────────────────────────
test('catalog: Python sources loaded for flask/django/fastapi/std', () => {
  const pySources = CATALOG.filter(e => e.kind === 'source' && e.language === 'py');
  assert.ok(pySources.length >= 20, `expected ≥20 Python sources, got ${pySources.length}`);
  // Spot-check key ones.
  assert.ok(pySources.some(e => e.id === 'py-flask-form'));
  assert.ok(pySources.some(e => e.id === 'py-django-post'));
  assert.ok(pySources.some(e => e.id === 'py-fastapi-query'));
});

test('catalog: Python sinks present for SQL/cmd/eval/pickle/yaml', () => {
  const pySinks = CATALOG.filter(e => e.kind === 'sink' && e.language === 'py');
  assert.ok(pySinks.some(e => e.id === 'py-cursor-execute'));
  assert.ok(pySinks.some(e => e.id === 'py-os-system'));
  assert.ok(pySinks.some(e => e.id === 'py-eval'));
  assert.ok(pySinks.some(e => e.id === 'py-pickle-loads'));
  assert.ok(pySinks.some(e => e.id === 'py-yaml-load'));
});

test('catalog: Python sanitizers present', () => {
  const pySan = CATALOG.filter(e => e.kind === 'sanitizer' && e.language === 'py');
  assert.ok(pySan.some(e => e.id === 'py-shlex-quote'));
  assert.ok(pySan.some(e => e.id === 'py-html-escape'));
  assert.ok(pySan.some(e => e.id === 'py-ast-literal-eval'));
});

// ── P4.6 source-side context labels ───────────────────────────────────────
test('catalog: every JS source has a provenance label', () => {
  const jsSources = CATALOG.filter(e => e.kind === 'source' && e.language === 'js');
  const labelsPresent = jsSources.filter(e => typeof e.provenance === 'string');
  assert.equal(labelsPresent.length, jsSources.length, `${jsSources.length - labelsPresent.length} JS sources missing provenance`);
});

test('catalog: provenance values come from a known set', () => {
  const KNOWN = new Set(['http-body', 'url-param', 'path-param', 'header', 'cookie', 'env', 'cli', 'file-read', 'stdin', 'url-fragment', 'network']);
  for (const e of CATALOG) {
    if (e.kind !== 'source' || !e.provenance) continue;
    assert.ok(KNOWN.has(e.provenance), `unknown provenance '${e.provenance}' on ${e.id}`);
  }
});

// ── Receiver-context wiring in SummaryCache ───────────────────────────────
test('summary-cache: receiver-type extends the cache key', () => {
  const cache = new SummaryCache();
  const t = new Set(['x']);
  const sum1 = { returnTainted: true,  mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] };
  const sum2 = { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] };
  cache.set('qid::save', t, sum1, 'UserRepo');
  cache.set('qid::save', t, sum2, 'Logger');
  assert.equal(cache.get('qid::save', t, 'UserRepo').returnTainted, true);
  assert.equal(cache.get('qid::save', t, 'Logger').returnTainted, false);
});

test('summary-cache: omitting receiver-type preserves backward-compat', () => {
  const cache = new SummaryCache();
  const t = new Set(['x']);
  const sum = { returnTainted: true, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [] };
  cache.set('qid::f', t, sum);
  assert.equal(cache.get('qid::f', t).returnTainted, true);
  // With a receiver type, it's a different cache slot.
  assert.equal(cache.get('qid::f', t, 'SomeRecv'), undefined);
});

// ── P3.4 Exception flow ───────────────────────────────────────────────────
test('exception-flow: throw of tainted value taints catchVar', () => {
  const throwNode = { kind: 'throw', value: { kind: 'ident', name: 'data' } };
  const isExprTainted = (e) => e && e.kind === 'ident' && e.name === 'data';
  const flows = exceptionTaintFlow(throwNode, 'e', isExprTainted);
  assert.ok(flows.includes('e'));
});

test('exception-flow: throw new Error(tainted) taints e + e.message + e.stack', () => {
  const throwNode = { kind: 'throw', value: { kind: 'call', callee: 'Error', args: [{ kind: 'ident', name: 'data' }] } };
  const isExprTainted = (e) => e && e.kind === 'ident' && e.name === 'data';
  const flows = exceptionTaintFlow(throwNode, 'e', isExprTainted);
  assert.ok(flows.includes('e'));
  assert.ok(flows.includes('e.message'));
  assert.ok(flows.includes('e.stack'));
});

test('exception-flow: applyExceptionTaintAtCatchEntry adds the paths', async () => {
  const { isCoveredBy } = await import('../src/dataflow/access-paths.js');
  const s = applyExceptionTaintAtCatchEntry(new Set(['preExisting']), ['e', 'e.message']);
  assert.ok(s.has('preExisting'));
  // Lattice semantics: when 'e' is tainted, 'e.message' is implicitly
  // tainted via prefix-coverage. Use isCoveredBy to check, not Set.has.
  assert.ok(isCoveredBy(s, 'e'));
  assert.ok(isCoveredBy(s, 'e.message'));
  assert.ok(isCoveredBy(s, 'e.stack'));     // any sub-path of `e` is covered
});

test('exception-flow: joinFinally is the conservative union', () => {
  const a = new Set(['x']);
  const b = new Set(['y']);
  const joined = joinFinally(a, b);
  assert.ok(joined.has('x'));
  assert.ok(joined.has('y'));
});

test('exception-flow: describeTryCatchFinally recovers catchVar', () => {
  const ast = {
    type: 'TryStatement',
    handler: { param: { name: 'e' } },
    finalizer: { type: 'BlockStatement' },
  };
  const d = describeTryCatchFinally(ast);
  assert.equal(d.catchVar, 'e');
  assert.equal(d.hasCatch, true);
  assert.equal(d.hasFinally, true);
});

// ── P4.2 Sanitizer-validity proofs ────────────────────────────────────────
test('sanitizer-proof: xss family — accepts DOMPurify call, rejects trim-only', () => {
  const ok = isValidSanitizerFor('return DOMPurify.sanitize(s)', 'xss');
  assert.equal(ok.trusted, true);
  const notOk = isValidSanitizerFor('return s.trim()', 'xss');
  assert.equal(notOk.trusted, false);
});

test('sanitizer-proof: sql family — accepts .prepare', () => {
  const ok = isValidSanitizerFor('const stmt = db.prepare("SELECT * FROM u")', 'sql');
  assert.equal(ok.trusted, true);
});

test('sanitizer-proof: CWE-89 maps to sql family', () => {
  const ok = isValidSanitizerFor('db.prepare("...")', 'CWE-89');
  assert.equal(ok.trusted, true);
});

test('sanitizer-proof: unknown family returns trusted=false', () => {
  const r = isValidSanitizerFor('return s', 'made-up-family');
  assert.equal(r.trusted, false);
});

test('sanitizer-proof: verifyProjectSanitizers walks IR + flags untrusted', () => {
  const perFileIR = {
    'a.js': { file: 'a.js', functions: [
      { qid: 'a.js::module::sanitize', name: 'sanitize', cfg: { nodes: {
        n1: { kind: 'return', value: { kind: 'ident', name: 'input' } },
      } } },
    ]},
  };
  const catalog = [
    { kind: 'sanitizer', match: { type: 'call', callee: 'sanitize' }, appliesTo: ['xss'] },
  ];
  const verdicts = verifyProjectSanitizers(perFileIR, catalog);
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].trusted, false);  // bare `return input` is not real XSS sanitization
});

// ── P4.4 String-value abstract domain ─────────────────────────────────────
test('string-domain: makeConst + render round-trip', () => {
  assert.equal(render(makeConst('hello')), 'hello');
});

test('string-domain: abstract on template + binary', () => {
  const tpl = abstract({ kind: 'tpl', parts: [{ kind: 'literal', value: 'a' }, { kind: 'ident', name: 'x' }] });
  // Mixed const+ident → Unknown (because ident is not abstracted to Const).
  assert.equal(tpl.kind, 'Unknown');
  const concat = abstract({ kind: 'binary', op: '+', left: { kind: 'literal', value: 'a' }, right: { kind: 'literal', value: 'b' } });
  assert.equal(concat.kind, 'Const');
  assert.equal(concat.value, 'ab');
});

test('string-domain: join — same const survives; different consts → Unknown', () => {
  assert.equal(join(makeConst('x'), makeConst('x')).value, 'x');
  assert.equal(join(makeConst('x'), makeConst('y')).kind, 'Unknown');
});

test('string-domain: isProvablyToHost — safe iff host matches allow-list', () => {
  const v = makeConst('https://internal.example.com/health');
  assert.equal(isProvablyToHost(v, ['internal.example.com']), true);
  assert.equal(isProvablyToHost(v, ['other.example.com']), false);
  assert.equal(isProvablyToHost(TOP, ['internal.example.com']), false);
});

test('string-domain: isSafeRedirectTarget — relative path safe; const allow-list safe', () => {
  assert.equal(isSafeRedirectTarget(makeConst('/dashboard'), []), true);
  assert.equal(isSafeRedirectTarget(makeConst('//evil.example.com'), []), false);
  assert.equal(isSafeRedirectTarget(makeConst('https://app.example.com/x'), ['app.example.com']), true);
});

test('string-domain: BOTTOM + hashAbstract', () => {
  assert.equal(BOTTOM.kind, 'Const');
  assert.equal(hashAbstract(makeConst('h')), 'h');
});

// ── P4.5 RTA dispatch resolution ──────────────────────────────────────────
test('rta: collectInstantiatedClasses finds `new Foo` patterns', () => {
  const perFileIR = {
    'a.js': { file: 'a.js', functions: [
      { qid: 'a.js::main', cfg: { nodes: {
        n1: { kind: 'assign', target: 'r', source: { kind: 'call', callee: { kind: 'ident', name: 'UserRepo' }, isNew: true } },
      } } },
    ]},
    'b.js': { file: 'b.js', functions: [
      { qid: 'b.js::main', cfg: { nodes: {
        n1: { kind: 'call', callee: 'Logger', isNew: true },
      } } },
    ]},
  };
  const live = collectInstantiatedClasses(perFileIR);
  assert.ok(live.has('UserRepo'));
  assert.ok(live.has('Logger'));
  assert.equal(live.has('NeverInstantiated'), false);
});

test('rta: resolveMethodRTA narrows by liveClasses', () => {
  const cha = {
    classes: new Map([
      ['Base', { name: 'Base', methods: new Set(['save']) }],
      ['SubA', { name: 'SubA', methods: new Set(['save']), extends: 'Base' }],
      ['SubB', { name: 'SubB', methods: new Set(['save']), extends: 'Base' }],
    ]),
  };
  const live = new Set(['SubA']);  // SubB exists in hierarchy but is never instantiated
  const resolved = resolveMethodRTA(cha, 'save', live, 'Base');
  assert.equal(resolved.length, 1);
  assert.equal(resolved[0].className, 'SubA');
});

test('rta: annotateRTA stamps liveClasses on cha', () => {
  const cha = { classes: new Map() };
  const perFileIR = {
    'a.js': { file: 'a.js', functions: [{ qid: 'f', cfg: { nodes: { n1: { kind: 'call', callee: 'Foo', isNew: true } } } }] },
  };
  annotateRTA(cha, perFileIR);
  assert.ok(cha.liveClasses);
  assert.ok(cha.liveClasses.has('Foo'));
});
