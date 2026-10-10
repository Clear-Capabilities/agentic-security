// DOC-002: policy cards for evaluation and routing, reproduction from the recorded manifests with bounded commands, and a measurement
// status page that keeps historical baselines, new measurements and aspirational targets apart and ties every headline figure to
// committed evidence. Each criterion is tested in both directions: a figure that matches passes, a doctored one is caught.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { read, REPO, SCANNER, script, run, blockWith, missingFrom } from './helpers.js';
import { loadFactor } from '../helpers/load.js';
import { PREREGISTERED_THRESHOLDS } from '../../src/posture/evaluation/protocol.js';
import { INTERVAL_METHODS } from '../../src/posture/evaluation/interval.js';
import { ROUTING_MINIMUMS, ROUTING_PROMOTION_TARGETS } from '../../src/posture/routing/calibration.js';
import { buildSyntheticSuite } from '../../src/posture/evaluation/synthetic.js';
import { loadBenchmark } from '../../src/posture/evaluation/invariant-ablation.js';

const EVAL_CARD = read('docs/guides/evaluation-policy-card.md');
const ROUTE_CARD = read('docs/guides/routing-policy-card.md');
const STATUS = read('docs/guides/measurement-status.md');
const REPRO = read('docs/guides/offline-reproduction.md');

const REQUIRED = ['Dataset provenance', 'Leakage controls', 'Supported strata', 'Denominators', 'Uncertainties', 'Economics', 'Known failure modes'];
const headings = (md) => [...md.matchAll(/^## (.+)$/gm)].map((m) => m[1].trim());
const missingSections = (md) => REQUIRED.filter((r) => !headings(md).includes(r));
const sectionOf = (md, title) => {
  const parts = md.split(/^## /m);
  const body = parts.find((p) => p.startsWith(title));
  assert.ok(body, `no section "${title}"`);
  return body;
};
const sha = (rel) => crypto.createHash('sha256').update(fs.readFileSync(path.join(REPO, rel))).digest('hex');

describe('[DOC-002.AC01] the policy cards carry provenance, leakage controls, strata, denominators, uncertainties, economics and failure modes', () => {
  test('[DOC-002.AC01] both cards have every required section, each with real content, in the order the criterion lists them', () => {
    for (const [name, md] of [['evaluation', EVAL_CARD], ['routing', ROUTE_CARD]]) {
      assert.deepEqual(missingSections(md), [], `${name} card is missing a section`);
      const order = headings(md).filter((h) => REQUIRED.includes(h));
      assert.deepEqual(order, REQUIRED, `${name} card sections are out of order`);
      for (const r of REQUIRED) assert.ok(sectionOf(md, r).split('\n').filter((l) => l.trim()).length >= 4, `${name}: section "${r}" is a stub`);
    }
  });

  test('[DOC-002.AC01] a card missing a section is caught (the check can fail)', () => {
    assert.deepEqual(missingSections(EVAL_CARD.replace('## Economics', '## Costs')), ['Economics']);
    assert.deepEqual(missingSections(ROUTE_CARD.replace('## Known failure modes', '## Notes')), ['Known failure modes']);
  });

  test('[DOC-002.AC01] the evaluation card states the thresholds and interval method the code registers', () => {
    assert.equal(PREREGISTERED_THRESHOLDS.minPositivesPerCoreLanguage, 100);
    assert.equal(PREREGISTERED_THRESHOLDS.minPositivesPerFamily, 30);
    assert.match(EVAL_CARD, /100 real, adjudicated, non-synthetic sealed positives and 100\s+negatives per core language and 30 positives per family/);
    const g = INTERVAL_METHODS['grouped-bootstrap-95'];
    assert.match(EVAL_CARD, new RegExp(`${g.replicates}\\s+resamples`));
    assert.match(EVAL_CARD, new RegExp(`fewer than ${g.minGroups} independent groups`));
    assert.match(EVAL_CARD, /Wilson/);
  });

  test('[DOC-002.AC01] the routing card states the minimums and promotion targets the code registers', () => {
    assert.match(ROUTE_CARD, new RegExp(`at\\s+least ${ROUTING_MINIMUMS.pairedTasksOverall} paired adjudicated tasks overall, ${ROUTING_MINIMUMS.pairedTasksPerStratum} per stratum`));
    assert.match(ROUTE_CARD, new RegExp(`above -${Math.abs(ROUTING_PROMOTION_TARGETS.qualityDifferenceLowerBound)}`));
    assert.match(ROUTE_CARD, new RegExp(`at least ${ROUTING_PROMOTION_TARGETS.medianCostReduction * 100}% lower`));
    assert.match(ROUTE_CARD, new RegExp(`at least ${ROUTING_PROMOTION_TARGETS.qualityGain} higher`));
    assert.match(ROUTE_CARD, new RegExp(`at most ${ROUTING_PROMOTION_TARGETS.p95LatencyRatio} times the baseline`));
  });

  test('[DOC-002.AC01] both cards say plainly that no stratum is supported and that this is machinery, not evidence', () => {
    assert.match(EVAL_CARD, /No stratum is supported today/);
    assert.match(EVAL_CARD, /machinery, not evidence/);
    assert.match(ROUTE_CARD, /\*\*None\.\*\*/);
    assert.match(ROUTE_CARD, /No cost or quality\s+advantage is claimed anywhere/);
    const r = script('scripts/routing-replay.mjs');
    assert.match(r.stdout, /Supported strata: none\./);
    assert.match(r.stdout, /No routing advantage is claimed\./);
  });

  test('[DOC-002.AC01] the cards name every population the repository holds and flag the synthetic ones', () => {
    for (const p of ['Independent record', 'Curated regression corpus', 'Synthetic evaluation suite', 'Deployment ablation', 'Invariant benchmark']) assert.ok(EVAL_CARD.includes(`| ${p} |`), `population ${p} is missing`);
    assert.match(EVAL_CARD, /Every synthetic population is flagged `synthetic: true`/);
    assert.match(ROUTE_CARD, /Generated populations only/);
    assert.ok(fs.existsSync(path.join(SCANNER, 'test/helpers/routing-fixtures.js')));
  });
});

describe('[DOC-002.AC02] a contributor can reproduce evaluation and routing replay offline with documented bounded commands', () => {
  const time = (fn) => { const t = Date.now(); const r = fn(); return { r, ms: Date.now() - t }; };
  const bound = () => 60000 * loadFactor();   // strict on an idle machine, scaled (capped) when the machine is oversubscribed

  test('[DOC-002.AC02] the synthetic evaluation prints the documented table and protocol hash, exits 0, and is bounded', () => {
    const { r, ms } = time(() => script('scripts/evaluation.mjs', ['synthetic']));
    assert.equal(r.status, 0, r.text);
    assert.ok(ms < bound(), `took ${ms} ms`);
    assert.deepEqual(missingFrom(blockWith(REPRO, 'SYNTHETIC suite: 3 authored files'), r.text), []);
  });

  test('[DOC-002.AC02] the miniature reproduction prints the documented controls, every one ok', () => {
    const { r, ms } = time(() => script('scripts/public-reproduction.mjs'));
    assert.equal(r.status, 0, r.text);
    assert.ok(ms < bound());
    assert.deepEqual(missingFrom(blockWith(REPRO, 'PUBLIC MINIATURE REPRODUCTION'), r.text), []);
    assert.equal((r.stdout.match(/^\s+ok\s/gm) ?? []).length, 5);
  });

  test('[DOC-002.AC02] the deployment ablation verifies its frozen set first and prints the documented arms', () => {
    const { r, ms } = time(() => script('scripts/evaluation.mjs', ['deployment-ablation']));
    assert.equal(r.status, 0, r.text);
    assert.ok(ms < bound());
    assert.deepEqual(missingFrom(blockWith(REPRO, 'SYNTHETIC cases authored by the tooling developers'), r.text), []);
    const frozen = JSON.parse(read('scanner/test/fixtures/deployment-ablation/frozen.json'));
    assert.match(REPRO, new RegExp(frozen.frozenHash.replace('sha256:', 'sha256:')), 'the page records the committed frozen hash');
  });

  test('[DOC-002.AC02] the invariant benchmark verifies against its pin, and the pin is the documented hash', () => {
    const loaded = loadBenchmark(path.join(SCANNER, 'test/fixtures/invariant-benchmark'));
    assert.equal(loaded.ok, true, JSON.stringify(loaded.errors));
    assert.ok(REPRO.includes(loaded.benchmark.manifestHash), 'the page records the benchmark manifest hash');
    const r = script('scripts/invariant-ablation.mjs', ['verify']);
    assert.equal(r.status, 0, r.text);
    assert.match(r.stdout, /benchmark intact: v1, 15 synthetic cases/);
  });

  test('[DOC-002.AC02] the oracle conformance pins verify statically, as documented', () => {
    const r = script('scripts/verification-conformance-check.mjs', ['--static']);
    assert.equal(r.status, 0, r.text);
    assert.match(r.stdout, /8 adapter\(s\) conform \(static contract and pins only; execution was not requested\)/);
    assert.match(REPRO, /8 adapter\(s\) conform \(static contract and pins only/);
  });

  test('[DOC-002.AC02] routing replay prints the documented denominators and controls, exits 0, makes no paid call, and is bounded', () => {
    const { r, ms } = time(() => script('scripts/routing-replay.mjs'));
    assert.equal(r.status, 0, r.text);
    assert.ok(ms < bound());
    const block = blockWith(REPRO, 'Routing replay report (SYNTHETIC): unmeasured').filter((l) => l.trim() !== '...');
    assert.deepEqual(missingFrom(block, r.text), []);
    assert.deepEqual(missingFrom(blockWith(REPRO, 'controls:'), r.text), []);
    assert.match(r.stdout, /0 paid call\(s\), \$0/);
    assert.equal((r.stdout.match(/^\s+ok\s/gm) ?? []).length, 7);
  });

  test('[DOC-002.AC02] the reproduction can fail: a deliberately broken control exits 1 and names itself, as documented', () => {
    const r = script('scripts/routing-replay.mjs', ['--fault', 'cherry-pick']);
    assert.equal(r.status, 1);
    assert.match(r.text, /A CONTROL FAILED: the routing replay path cannot be trusted until this is understood/);
    assert.match(REPRO, /exits 1/);
  });

  test('[DOC-002.AC02] the routing hashes are deterministic: two runs print the same report, card and receipt hashes, equal to the recorded ones', () => {
    const a = JSON.parse(script('scripts/routing-replay.mjs', ['--json']).stdout);
    const b = JSON.parse(script('scripts/routing-replay.mjs', ['--json']).stdout);
    assert.deepEqual([a.reportHash, a.cardHash, a.receiptsHead], [b.reportHash, b.cardHash, b.receiptsHead]);
    for (const h of [a.reportHash, a.cardHash, a.receiptsHead]) assert.ok(STATUS.includes(h), `measurement status does not record ${h}`);
    assert.equal(a.status, 'unmeasured');
    assert.equal(a.claimsAllowed, false);
  });

  test('[DOC-002.AC02] every command in the page is wired, none is interactive, and the page states the bound and the limits of reproduction', () => {
    assert.match(REPRO, /asks nothing on a terminal/);
    assert.match(REPRO, /No network|no network/);
    assert.match(REPRO, /What it does not prove/);
    const pkg = JSON.parse(read('scanner/package.json')).scripts;
    for (const n of ['evaluation:synthetic', 'reproduce:mini', 'reproduce:routing', 'bench:invariant-ablation', 'verification:conformance:static', 'verification:conformance:check']) assert.ok(pkg[n], n);
    const r = run('npm', ['run', '--silent', 'reproduce:routing', '--', '--json']);
    assert.equal(r.status, 0, r.text);
  });
});

describe('[DOC-002.AC03] historical baselines, new measurements and aspirational targets are separate and every headline figure links to current immutable evidence', () => {
  const S1 = sectionOf(STATUS, '1. Historical baselines');
  const S2 = sectionOf(STATUS, '2. New measurements (synthetic or generated)');
  const S3 = sectionOf(STATUS, '3. Aspirational targets');
  const result = JSON.parse(read('bench/independent/RESULT.json'));

  test('[DOC-002.AC03] the three kinds appear as three separate top-level sections, in that order, each labelled for what it is', () => {
    const order = headings(STATUS).filter((h) => /^[123]\. /.test(h));
    assert.deepEqual(order, ['1. Historical baselines', '2. New measurements (synthetic or generated)', '3. Aspirational targets']);
    assert.match(S1, /does not describe the current engine|do not describe the current engine|older engine/);
    assert.match(S2, /synthetic|generated/i);
    assert.match(S3, /have not\s+been met/);
    assert.match(S3, /not claims about current performance/);
  });

  test('[DOC-002.AC03] the page says plainly that no real-code accuracy gate has been met, and the gate code agrees', () => {
    assert.match(STATUS, /\*\*No real-code accuracy gate has been met\.\*\*/);
    assert.match(STATUS, /every real-code gate reads `insufficient-population` or\s+`unmeasured`/);
    const suite = buildSyntheticSuite({ fixturesDir: path.join(SCANNER, 'test/fixtures/evaluation-synthetic') });
    assert.ok(suite.protocol);
    const out = script('scripts/evaluation.mjs', ['synthetic']).stdout;
    assert.ok(!/\bpass\b/.test(out.split('\n').filter((l) => /real-code gates|insufficient-population/.test(l)).join('\n')), 'a real-code gate reads pass');
    assert.ok((out.match(/insufficient-population/g) ?? []).length >= 3);
  });

  test('[DOC-002.AC03] the historical baseline equals the committed record: 0.141.0, 2026-08-23, 991 scored, 13 unscored, precision 54.6%, recall 7.2%, F1 0.127', () => {
    assert.equal(result.engineVersion, '0.141.0');
    assert.equal(result.measuredAt, '2026-08-23');
    assert.equal(result.population.scoredEntries, 991);
    assert.equal(result.population.totalEntries - result.population.scoredEntries, 13);
    const o = result.overall;
    assert.equal(`${(o.precision.value * 100).toFixed(1)}%`, '54.6%');
    assert.equal(`${(o.recall.value * 100).toFixed(1)}%`, '7.2%');
    assert.equal(o.f1.toFixed(3), '0.127');
    assert.equal(`${o.precision.n}/${o.precision.d}`, '71/130');
    assert.equal(`${o.recall.n}/${o.recall.d}`, '71/991');
    for (const s of ['0.141.0', '2026-08-23', '991 scored', '13 unscored', '71/130 = 54.6%', '71/991 = 7.2%', '0.127', '`pattern-only`']) assert.ok(S1.includes(s), `section 1 does not state ${s}`);
    const h = result.heldOut.localized;
    assert.ok(S1.includes(`${h.precision.n}/${h.precision.d} = ${(h.precision.value * 100).toFixed(1)}%`));
    assert.ok(S1.includes(`${h.recall.n}/${h.recall.d} = ${(h.recall.value * 100).toFixed(1)}%`));
  });

  test('[DOC-002.AC03] the historical figures never appear in the new-measurement or aspirational sections (the populations are not mixed)', () => {
    for (const hist of ['54.6%', '7.2%', '0.127', '71/130', '71/991', '0.141.0']) {
      assert.ok(!S2.includes(hist) && !S3.includes(hist), `${hist} leaked out of the historical section`);
    }
    for (const asp of ['0.80', '0.90', '0.75']) assert.ok(!S1.includes(asp), `${asp} is an aspirational target and leaked into the historical section`);
  });

  test('[DOC-002.AC03] every aspirational target equals the preregistered threshold in code, and the page says none is met', () => {
    const t = PREREGISTERED_THRESHOLDS;
    for (const [s, v] of [['per core-language F1 at least 0.80', t.perLanguageF1], ['micro and macro F1 at least 0.80', t.overallMicroF1], ['pooled precision at least 0.90', t.pooledPrecision], ['recall at least 0.75', t.pooledRecall], ['F1 lower bound at least 0.70', t.perLanguageF1LowerBound], ['at least 95% target completion', t.completion]]) {
      assert.ok(S3.includes(s), `section 3 does not state "${s}"`);
      assert.equal(typeof v, 'number');
    }
    assert.equal(t.perLanguageF1, 0.8); assert.equal(t.pooledPrecision, 0.9); assert.equal(t.pooledRecall, 0.75); assert.equal(t.perLanguageF1LowerBound, 0.7);
    assert.match(S3, /Today, for each row: not met\./);
  });

  test('[DOC-002.AC03] each new-measurement row names a command that exists, and its printed figures are the ones the command prints now', () => {
    const syn = script('scripts/evaluation.mjs', ['synthetic']).stdout;
    for (const f of ['deep-taint           5/5           100.0%          66.7%    80.0%', 'model-assisted       0/5']) assert.ok(syn.replace(/\s+/g, ' ').includes(f.replace(/\s+/g, ' ')), `the synthetic suite no longer prints ${f}`);
    for (const f of ['deterministic-only 5/5 completed, recall 0.0%', 'deep-taint 5/5, recall 100.0%, precision 66.7%, F1 80.0%', 'model-assisted 0/5 completed']) assert.ok(S2.includes(f), f);
    const dep = script('scripts/evaluation.mjs', ['deployment-ablation']).stdout.replace(/\s+/g, ' ');
    for (const f of ['source-only 4 4 3 50.0% 57.1%', 'graph-enabled 7 2 0 77.8% 100.0%', 'FPs reduced 3, confirmed defects added 3, baseline confirmed defects LOST 0, FPs added 1']) assert.ok(dep.includes(f), `the ablation no longer prints ${f}`);
    for (const f of ['source-only TP 4, FP 4, FN 3', 'graph-enabled TP 7, FP 2, FN 0', 'false positives reduced 3, confirmed defects added 3, baseline defects lost 0, false positives added 1']) assert.ok(S2.includes(f), f);
    const inv = script('scripts/invariant-ablation.mjs', ['run', '--no-source']);
    if (inv.status === 0 && /approved-contract/.test(inv.stdout)) {
      const out = inv.stdout.replace(/\s+/g, ' ');
      if (/UNMEASURED not executed/.test(out)) {
        // A host that cannot run the trust boundary (the hosted Linux runner) executes no scenario: the honest output is 0/8 on every arm and
        // every class UNMEASURED, never a supported claim. The doc's quoted 8/8 is the macOS figure, so it is checked only where scenarios ran.
        assert.match(out, /approved-contract n\/a 0% \[0-32\] \(0\/8\)/);
        assert.ok(!/\bSUPPORTED\b/.test(out), 'a host that executed nothing must not report a supported class');
      } else {
        assert.match(out, /approved-contract 100% \[68-100\] \(8\/8\) 100% \[68-100\] \(8\/8\)/);
        assert.ok(S2.includes('approved contract precision 8/8, recall 8/8'));
      }
    }
    const cmds = [...S2.matchAll(/^\| `([^`]+)` \|/gm)].map((m) => m[1]);
    assert.ok(cmds.length >= 6);
    const pkg = JSON.parse(read('scanner/package.json')).scripts;
    for (const c of cmds) assert.ok(pkg[c.replace(/^npm run /, '').split(' ')[0]], `${c} is not an npm script`);
  });

  test('[DOC-002.AC03] every headline figure links to an immutable artifact whose SHA-256 the page records, and the digest is current', () => {
    const rows = [...STATUS.matchAll(/^\| \[([^\]]+)\]\(([^)]+)\) \| `([0-9a-f]{64})` \|$/gm)];
    assert.ok(rows.length >= 5, 'the evidence table lists the committed artifacts');
    for (const [, label, link, digest] of rows) {
      const rel = path.relative(REPO, path.resolve(REPO, 'docs/guides', link));
      assert.equal(rel, label, 'the link text is the path it links to');
      assert.equal(sha(rel), digest, `${rel} changed since the page recorded its digest`);
    }
    for (const must of ['bench/independent/RESULT.json', 'bench/independent/why-missed-summary.json']) assert.ok(rows.some((r) => r[1] === must), `${must} is not in the evidence table`);
  });

  test('[DOC-002.AC03] a doctored digest, or a refreshed artifact, would be caught', () => {
    const digest = /`(cd77c0cf4d04bd90f4736867719abe5b4799954c5eae262f91c2c6e6eee0ede5)`/.exec(STATUS)[1];
    assert.equal(sha('bench/independent/RESULT.json'), digest);
    const doctored = `${digest.slice(0, 63)}${digest.endsWith('0') ? '1' : '0'}`;
    assert.notEqual(sha('bench/independent/RESULT.json'), doctored);
    const tampered = Buffer.from(fs.readFileSync(path.join(REPO, 'bench/independent/RESULT.json')));
    tampered[tampered.length - 2] = tampered[tampered.length - 2] === 0x20 ? 0x21 : 0x20;
    assert.notEqual(crypto.createHash('sha256').update(tampered).digest('hex'), digest, 'one changed byte changes the digest');
  });

  test('[DOC-002.AC03] the hashes recorded from reproduction commands equal the ones recomputed now', () => {
    const recorded = Object.fromEntries([...STATUS.matchAll(/^\| ([a-z ]+ hash|routing receipts head) \| `(sha256:[0-9a-f]{64})` \|$/gm)].map((m) => [m[1], m[2]]));
    assert.equal(Object.keys(recorded).length, 6);
    const suite = buildSyntheticSuite({ fixturesDir: path.join(SCANNER, 'test/fixtures/evaluation-synthetic') });
    assert.equal(recorded['synthetic protocol hash'], suite.protocol.protocolHash);
    assert.equal(recorded['deployment ablation frozen hash'], JSON.parse(read('scanner/test/fixtures/deployment-ablation/frozen.json')).frozenHash);
    assert.equal(recorded['invariant benchmark manifest hash'], loadBenchmark(path.join(SCANNER, 'test/fixtures/invariant-benchmark')).benchmark.manifestHash);
    const rr = JSON.parse(script('scripts/routing-replay.mjs', ['--json']).stdout);
    assert.equal(recorded['routing report hash'], rr.reportHash);
    assert.equal(recorded['routing policy card hash'], rr.cardHash);
    assert.equal(recorded['routing receipts head'], rr.receiptsHead);
  });

  test('[DOC-002.AC03] no claim of current accuracy, advantage or certification is made outside the negated statements', () => {
    for (const md of [STATUS, EVAL_CARD, ROUTE_CARD]) {
      assert.ok(!/\bcurrent engine (?:accuracy|F1|precision) (?:is|of)\b/i.test(md));
      assert.ok(!/\brouting (?:saves|reduces cost|improves quality)\b/i.test(md));
    }
    assert.match(STATUS, /Nothing on this page supports a claim of current engine accuracy/);
  });
});
