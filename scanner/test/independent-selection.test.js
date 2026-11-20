// Population selection of the independent measurement driver (scripts/engineering-excellence/independent-baseline.mjs).
//
// What these pin: `--splits` is parsed (it was documented in the usage comment but never read, so a "development only" plan
// silently selected validation too); a development-only paired comparison can reuse the baseline's exact development population
// instead of a fresh per-language sample, which over a smaller pool picks different entries; sealed can never be selected; and
// the scan-affecting environment is part of the run id, so a run with a threat-model knob set can never resume chunks measured
// without it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planRun, parseSplitNames, scanKnobs, assertKnobsMatch, RUNS_DIR } from '../../scripts/engineering-excellence/independent-baseline.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REAL_SPLITS = path.resolve(HERE, '..', '..', 'bench', 'independent', 'splits.mjs');

/** A throwaway root: a manifest of 3 languages, each with entries in all three splits, and a re-export of the real splits module. */
function fakeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-ind-sel-'));
  fs.mkdirSync(path.join(root, 'bench', 'independent'), { recursive: true });
  fs.writeFileSync(path.join(root, 'bench', 'independent', 'splits.mjs'), `export * from ${JSON.stringify(REAL_SPLITS)};\n`);
  const entries = []; const assignment = {};
  for (const language of ['go', 'python', 'ruby']) {
    for (let i = 0; i < 12; i++) {
      const id = `${language}-${String(i).padStart(2, '0')}`;
      entries.push({ id, language, repo: `r/${language}${i % 4}` });
      assignment[id] = i % 3 === 0 ? 'validation' : i % 5 === 0 ? 'sealed' : 'dev';
    }
  }
  fs.writeFileSync(path.join(root, 'bench', 'independent', 'manifest.json'), JSON.stringify({ entries }));
  fs.writeFileSync(path.join(root, 'bench', 'independent', 'splits.json'), JSON.stringify({ protocolHash: 'test', assignment }));
  return { root, assignment };
}

test('parseSplitNames: default both, named subset, sealed and unknown refused', () => {
  assert.deepEqual(parseSplitNames(null), ['dev', 'validation']);
  assert.deepEqual(parseSplitNames('dev'), ['dev']);
  assert.deepEqual(parseSplitNames('dev, dev'), ['dev']);
  assert.throws(() => parseSplitNames('dev,sealed'), /not sealed/);
  assert.throws(() => parseSplitNames('train'), /not train/);
  assert.throws(() => parseSplitNames(''), /at least one/);
});

test('planRun with splitNames [dev] selects development entries only', async () => {
  const { root, assignment } = fakeRoot();
  const p = await planRun(root, { perLanguage: 3, splitNames: ['dev'], env: {} });
  assert.ok(p.selection.ids.length > 0);
  for (const id of p.selection.ids) assert.equal(assignment[id], 'dev');
  assert.deepEqual(p.plan.selection.splitNames, ['dev']);
});

test('populationOf reuses the baseline development population; a fresh dev-only sample differs', async () => {
  const { root, assignment } = fakeRoot();
  const base = await planRun(root, { perLanguage: 3, splitNames: ['dev', 'validation'], env: {} });
  const baseDev = base.selection.ids.filter((id) => assignment[id] === 'dev').sort();
  const fresh = await planRun(root, { perLanguage: 3, splitNames: ['dev'], env: {} });
  const paired = await planRun(root, { perLanguage: 3, splitNames: ['dev'], populationOf: base.runId, env: {} });
  assert.deepEqual(paired.selection.ids, baseDev);
  assert.equal(paired.plan.selection.populationOf.source, base.runId);
  assert.notDeepEqual(fresh.selection.ids, baseDev, 'the fixture must exhibit the resampling difference this option exists for');
  for (const id of paired.selection.ids) assert.notEqual(assignment[id], 'validation');
  await assert.rejects(planRun(root, { splitNames: ['dev'], populationOf: 'no-such-run', env: {} }), /no selection.json/);
  assert.ok(fs.existsSync(path.join(RUNS_DIR(root), paired.runId, 'plan.json')));
});

test('scan knobs are part of the run id and a resume under different knobs is refused', async () => {
  const { root } = fakeRoot();
  const off = await planRun(root, { perLanguage: 3, splitNames: ['dev'], env: {} });
  const on = await planRun(root, { perLanguage: 3, splitNames: ['dev'], env: { AGENTIC_SECURITY_LIBRARY_SOURCES: '1' } });
  assert.notEqual(off.runId, on.runId);
  assert.deepEqual(on.plan.scanKnobs, { AGENTIC_SECURITY_LIBRARY_SOURCES: '1' });
  assert.doesNotThrow(() => assertKnobsMatch(on.plan, { AGENTIC_SECURITY_LIBRARY_SOURCES: '1', AGENTIC_SECURITY_BENCH_PROGRESS: '1' }));
  assert.throws(() => assertKnobsMatch(on.plan, {}), /planned with scan knobs/);
  assert.deepEqual(scanKnobs({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://x', AGENTIC_SECURITY_BENCH_PROGRESS: '1', HOME: '/h' }), { AGENTIC_SECURITY_LLM_ENDPOINT: '<set>' });
});
