import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDispositionView, parseExcludeKinds, viewLine, languageOf } from '../src/report/disposition-view.js';
import { toSARIF } from '../src/report/index.js';

const scan = () => ({
  findings: [
    { id: '1', file: 'a/Main.hs', line: 1, vuln: 'x', severity: 'high', disposition: 'confirmed', confidence: 0.9 },
    { id: '2', file: 'a/B.hs', line: 1, vuln: 'x', severity: 'high', disposition: 'needs-review', confidence: 0.5 },
    { id: '3', file: 'web/c.js', line: 1, vuln: 'x', severity: 'low', disposition: 'hardening' },
    { id: '4', file: 'dist/gen.js', line: 1, vuln: 'x', severity: 'low', disposition: 'unvalidated' },
  ],
  secrets: [{ id: 's', file: 'k.env', line: 1, vuln: 'secret', disposition: 'unvalidated' }],
  supplyChain: [{ id: 'd1', file: 'package.json', name: 'lodash' }, { id: 'd2', file: 'package.json', name: 'minimist' }],
  suppressions: [{ vuln: 'x', file: 'z.hs', disposition: 'refuted' }],
});

test('groups separate by disposition and raw reconciles with shown plus hidden', () => {
  const v = buildDispositionView(scan());
  assert.deepEqual([v.counts.confirmed, v.counts.needsReview, v.counts.hardening, v.counts.history], [1, 1, 1, 1]);
  assert.equal(v.raw, 7); assert.equal(v.reconciles, true);
  assert.equal(v.actionable, 2);
});

test('hiding SCA does not mutate the scan and is reported as hidden, not assessed', () => {
  const s = scan();
  const v = buildDispositionView(s, { excludeKinds: ['sca'] });
  assert.equal(s.supplyChain.length, 2);
  assert.equal(v.hidden.byKind.sca, 2);
  assert.equal(v.reconciles, true);
  assert.match(v.note, /still stored/);
  assert.match(viewLine(v), /hidden from this view \(still stored, not assessed\)/);
});

test('generated files hide only when asked, and filters reconcile', () => {
  assert.equal(buildDispositionView(scan(), { excludeKinds: ['generated'] }).hidden.byKind.generated, 1);
  const v = buildDispositionView(scan(), { filters: { language: 'haskell' } });
  assert.equal(v.counts.confirmed + v.counts.needsReview, 2);
  assert.equal(v.reconciles, true);
  const c = buildDispositionView(scan(), { filters: { minConfidence: 0.8 } });
  assert.equal(c.counts.needsReview, 0); assert.equal(c.reconciles, true);
});

test('unknown kinds are rejected and languages resolve', () => {
  assert.equal(parseExcludeKinds('sca,nope').errors.length, 1);
  assert.deepEqual(parseExcludeKinds('sca,generated').kinds, ['sca', 'generated']);
  assert.equal(languageOf('x/Y.hs'), 'haskell');
});

test('SARIF carries the view', () => {
  const s = scan(); s.reportView = buildDispositionView(s, { excludeKinds: ['sca'] });
  const sarif = toSARIF(s, {});
  assert.equal(sarif.runs[0].invocations[0].properties.reportView.excludeKinds[0], 'sca');
});
