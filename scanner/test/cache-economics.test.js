import { test } from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeTranscript, formatCacheReport, _internal } from '../src/posture/cache-economics.js';
const { parseTranscriptUsage, computeCacheEconomics, detectInvalidators, rateFor } = _internal;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, 'fixtures', 'cache-economics', 'session.jsonl');

test('rateFor — maps families, skips synthetic/unknown', () => {
  assert.equal(rateFor('claude-opus-4-8').in, 5);
  assert.equal(rateFor('claude-sonnet-4-6').in, 3);
  assert.equal(rateFor('claude-haiku-4-5-20251001').in, 1);
  assert.equal(rateFor('<synthetic>'), null);
  assert.equal(rateFor(null), null);
});

test('parseTranscriptUsage — only priceable assistant turns', () => {
  const recs = parseTranscriptUsage(FIXTURE);
  // 7 assistant lines, but the <synthetic> one is dropped, and the user line too.
  assert.equal(recs.length, 6);
  assert.ok(recs.every(r => rateFor(r.model)));
  assert.equal(recs[0].cacheCreate, 8000);
  assert.equal(recs[1].cacheRead, 10000);
});

test('computeCacheEconomics — caching saved money; hit ratio in range', () => {
  const m = computeCacheEconomics(parseTranscriptUsage(FIXTURE));
  assert.equal(m.turns, 6);
  assert.ok(m.savedUsd > 0, `expected positive savings, got ${m.savedUsd}`);
  assert.ok(m.actualUsd < m.uncachedUsd);
  assert.ok(m.cacheHitRatio > 0 && m.cacheHitRatio < 1);
  assert.ok(m.costPerTurnUsd > 0);
  // Opus turn 2: 10000 cached-read tokens at 0.1×$5/M = $0.005, vs $0.05 uncached.
  // Net savings across the session (~$0.09) — sanity-check the magnitude.
  assert.ok(m.savedUsd > 0.05, `savings should be material, got ${m.savedUsd}`);
  assert.deepEqual(Object.keys(m.perModel).sort(), ['Opus 4.8', 'Sonnet 4.6']);
});

test('detectInvalidators — flags the model switch and the TTL gap', () => {
  const leaks = detectInvalidators(parseTranscriptUsage(FIXTURE));
  assert.equal(leaks.length, 2);
  const causes = leaks.map(l => l.cause).sort();
  assert.deepEqual(causes, ['cache-expired', 'model-switch']);
  assert.ok(leaks.every(l => l.wastedUsd > 0));
});

test('analyzeTranscript + formatCacheReport — end to end on the fixture', () => {
  const result = analyzeTranscript({ transcriptPath: FIXTURE });
  assert.equal(result.ok, true);
  const report = formatCacheReport(result);
  assert.match(report, /cache hit ratio/);
  assert.match(report, /saved by caching/);
  assert.match(report, /cache leaks \(2/);
  assert.match(report, /model switch/);
});

test('analyzeTranscript — graceful when no transcript', () => {
  const result = analyzeTranscript({ transcriptPath: '/nope/missing.jsonl', projectDir: '/tmp/definitely-no-claude-project-xyz' });
  assert.equal(result.ok, false);
  assert.match(formatCacheReport(result), /no Claude Code transcript/);
});

// Parity: the CJS hook twin agrees with the ESM parser on the shared fixture.
test('hooks/lib/transcript.js — CJS twin agrees with ESM parser', () => {
  const require = createRequire(import.meta.url);
  const cjs = require('../../hooks/lib/transcript.js');
  const cjsRecs = cjs.parse(FIXTURE);
  const esmRecs = parseTranscriptUsage(FIXTURE);
  assert.equal(cjsRecs.length, esmRecs.length);
  // latestCacheTokens = last warm turn's input-side size (last sonnet turn).
  const last = esmRecs[esmRecs.length - 1];
  assert.equal(cjs.latestCacheTokens({ transcriptPath: FIXTURE }), last.cacheRead + last.cacheCreate + last.input);
});
