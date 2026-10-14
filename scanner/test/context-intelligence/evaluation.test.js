import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluateSuite, leakageAudit, renderMarkdown, renderCsv, DEFAULT_SUITE_DIR } from '../../src/context-intelligence/evaluation/index.js';
import { copyTree, cleanup } from './helpers.js';

test('the scorecard labels itself synthetic and makes no accuracy claim', async () => {
  const r = await evaluateSuite({ split: 'dev', systems: ['deterministic', 'dci'] });
  assert.equal(r.ok, true);
  const c = r.card;
  assert.equal(c.synthetic, true);
  assert.match(c.claim, /no accuracy claim/);
  assert.match(renderMarkdown(c), /SYNTHETIC SUITE, SCRIPTED READER/);
  assert.match(renderCsv(c), /^system,case,variant,vulnerable,flagged,outcome/);
  assert.match(c.hashes.suite, /^[0-9a-f]{64}$/);
  assert.equal(c.leakage.length, 0);
});

test('measurement is honest: dev has too few independent groups for an interval, the full suite has enough', async () => {
  const dev = await evaluateSuite({ split: 'dev', systems: ['dci'] });
  const m = dev.card.systems[0];
  assert.equal(m.status, 'measured');
  assert.equal(m.metrics.f1Interval.status, 'unmeasured');
  assert.ok(m.metrics.counts.tp >= 1, 'the machinery finds at least one planted defect');
  assert.equal(m.metrics.counts.tp + m.metrics.counts.fn + m.metrics.counts.fp + m.metrics.counts.tn, m.metrics.units);
  const all = await evaluateSuite({ split: 'all', systems: ['dci'] });
  assert.equal(all.card.systems[0].metrics.f1Interval.status, 'measured');
  assert.ok(all.card.systems[0].metrics.f1Interval.low <= all.card.systems[0].metrics.f1Interval.high);
});

test('the deterministic baseline spends no model calls; the model-backed systems report their cost', async () => {
  const r = await evaluateSuite({ split: 'dev', systems: ['deterministic', 'hunt', 'dci'] });
  const by = Object.fromEntries(r.card.systems.map(s => [s.system, s]));
  assert.equal(by.deterministic.calls, 0);
  assert.ok(by.hunt.calls > 0 && by.dci.calls > 0);
  assert.ok(by.dci.promptChars > 0);
});

test('the same inputs give the same scorecard hash', async () => {
  const a = await evaluateSuite({ split: 'dev', systems: ['deterministic', 'dci'] });
  const b = await evaluateSuite({ split: 'dev', systems: ['deterministic', 'dci'] });
  assert.equal(a.card.hashes.scorecard, b.card.hashes.scorecard);
  const stable = (card) => JSON.stringify(card.systems.map(x => ({ ...x, economics: { ...x.economics, wallMs: null } })));
  assert.equal(stable(a.card), stable(b.card), 'everything except wall time is identical');
});

test('compiler-enriched comparison is blocked, not faked, when no export is shipped', async () => {
  const r = await evaluateSuite({ split: 'dev', systems: ['dci-compiler'] });
  assert.equal(r.card.systems[0].status, 'blocked');
  assert.match(r.card.systems[0].reason, /compiler metadata/);
});

test('holdout discipline: a non-frozen variant is refused on the holdout unless declared final, and every holdout use is counted', async () => {
  const refused = await evaluateSuite({ split: 'holdout', variant: 'dci-all-packs', systems: ['dci'] });
  assert.equal(refused.ok, false);
  assert.match(refused.reason, /frozen/);
  const unknown = await evaluateSuite({ split: 'nope', systems: ['dci'] });
  assert.equal(unknown.ok, false);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-ledger-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    const one = await evaluateSuite({ split: 'holdout', systems: ['dci'], root });
    assert.equal(one.card.ledger.holdoutScoredRuns, 1);
    const two = await evaluateSuite({ split: 'holdout', systems: ['dci'], root });
    assert.equal(two.card.ledger.holdoutScoredRuns, 2);
    const dev = await evaluateSuite({ split: 'dev', systems: ['dci'], root });
    assert.equal(dev.card.ledger.holdoutScoredRuns, 2);
    assert.equal(dev.card.ledger.devScoredRuns, 1);
    const fin = await evaluateSuite({ split: 'holdout', variant: 'dci-all-packs', systems: ['dci'], root, final: true });
    assert.equal(fin.ok, true);
  } finally { cleanup(root); }
});

test('the label-leakage audit passes on the shipped corpus and catches a planted label', () => {
  assert.deepEqual(leakageAudit(DEFAULT_SUITE_DIR, { dci: ['a prompt with only source'] }), []);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-leak-'));
  try {
    copyTree(DEFAULT_SUITE_DIR, tmp);
    const f = path.join(tmp, 'corpus', 'c01', 'a', 'src', 'app.js');
    fs.appendFileSync(f, '\n// this route is vulnerable to IDOR\n');
    const hits = leakageAudit(tmp, {});
    assert.ok(hits.some(h => h.where === 'corpus' && /app\.js$/.test(h.file)));
    const p = leakageAudit(DEFAULT_SUITE_DIR, { hunt: ['... case c03 expected ...'] });
    assert.ok(p.some(h => h.where === 'prompt:hunt'));
  } finally { cleanup(tmp); }
});

test('economics: context-token percentiles, calls per true positive and wall time are reported without an invented price', async () => {
  const { percentile } = await import('../../src/context-intelligence/evaluation/index.js');
  assert.equal(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.5), 5);
  assert.equal(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95), 10);
  assert.equal(percentile([], 0.5), null);
  const r = await evaluateSuite({ split: 'dev', systems: ['hunt', 'dci'] });
  for (const s of r.card.systems) {
    const e = s.economics;
    assert.ok(e.contextTokens.median > 0 && e.contextTokens.p95 >= e.contextTokens.median && e.contextTokens.p99 >= e.contextTokens.p95);
    assert.equal(e.cost.usd, null);
    assert.ok(e.wallMs >= 0);
  }
  assert.match(renderMarkdown(r.card), /Economics \(estimated; no price supplied\)/);
});
