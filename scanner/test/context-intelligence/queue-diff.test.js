import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempProject, cleanup, build, reviewWith } from './helpers.js';
import { scriptedReader } from '../../src/context-intelligence/evaluation/scripted-reader.js';
import { exportBatch, importBatch, planJobs, resourceKeyOf } from '../../src/context-intelligence/queue.js';
import { buildReviewPrompt, redactPackageText, checkEgressForFiles, describeModel } from '../../src/context-intelligence/review.js';
import { packById } from '../../src/context-intelligence/prompts/packs.js';
import { diffManifestSets } from '../../src/context-intelligence/diff.js';
import { storeRoot, readStoreFile } from '../../src/context-intelligence/store.js';

test('a corrupted queue checkpoint is ignored and reported, never trusted', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const built = await build(dir);
    const first = await reviewWith(dir, scriptedReader(), { built });
    const qf = path.join(storeRoot(dir), 'queues', `${first.result.runId}.json`);
    assert.ok(fs.existsSync(qf), 'checkpoint written');
    const doc = JSON.parse(fs.readFileSync(qf, 'utf8'));
    doc.jobs[Object.keys(doc.jobs)[0]].state = 'succeeded-but-forged';
    fs.writeFileSync(qf, JSON.stringify(doc));
    const again = await reviewWith(dir, scriptedReader(), { built });
    assert.equal(again.result.coverage.queueStateCorrupt, true);
    assert.equal(again.result.coverage.missingCoverage, 0);
  } finally { cleanup(dir); }
});

test('offline batch: export is bound to job keys, import is idempotent and rejects strangers', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const built = await build(dir);
    const packs = [packById('authz-idor')];
    const model = describeModel();
    const { jobs } = planJobs({ bundles: built.bundles, packs, model });
    const run = await reviewWith(dir, async () => 'unused', { built, limits: { maxCalls: 1 } }); // gives us a loadJob
    const loadJob = run.loadJob;
    const e = exportBatch(built.root, jobs, loadJob, { model, review: { buildReviewPrompt, redactPackageText, checkEgressForFiles } });
    assert.equal(e.ok, true);
    assert.equal(e.requests, jobs.length);
    const reqs = fs.readFileSync(e.requestsFile, 'utf8').trim().split('\n').map(JSON.parse);
    const reader = scriptedReader();
    const results = [];
    for (const r of reqs) results.push(JSON.stringify({ custom_id: r.custom_id, response: await reader(r.prompt) }));
    results.push(JSON.stringify({ custom_id: 'not-a-job', response: '{}' }), 'garbage');
    const text = results.join('\n');
    const imp = importBatch(built.root, e.batchId, text, { jobs, loadJob, fileContents: built.fileContents });
    assert.equal(imp.ok, true);
    assert.equal(imp.accepted + imp.declined, jobs.length);
    assert.ok(imp.rejected.some(r => r.reason === 'unknown-job'));
    assert.ok(imp.rejected.some(r => r.reason === 'not-json'));
    const again = importBatch(built.root, e.batchId, text, { jobs, loadJob, fileContents: built.fileContents });
    assert.equal(again.accepted, 0);
    assert.ok(again.duplicates >= jobs.length);
  } finally { cleanup(dir); }
});

test('diff: removing the ownership filter changes the protection state and the context hash', async () => {
  const guarded = tempProject('eval/corpus/c01/b');
  const open = tempProject('eval/corpus/c01/a');
  try {
    const a = await build(guarded); const b = await build(open);
    const d = diffManifestSets(a.bundles.map(x => x.manifest), b.bundles.map(x => x.manifest));
    assert.equal(d.changed.length, 1);
    assert.notEqual(d.changed[0].contextHash.from, d.changed[0].contextHash.to);
    const same = diffManifestSets(a.bundles.map(x => x.manifest), a.bundles.map(x => x.manifest));
    assert.equal(same.changed.length + same.added.length + same.removed.length, 0);
    assert.equal(same.unchangedCount, a.bundles.length);
  } finally { cleanup(guarded); cleanup(open); }
});

test('resource grouping ignores parameter names so sibling routes group together', () => {
  assert.equal(resourceKeyOf('/orgs/:orgId/docs/:id'), resourceKeyOf('/orgs/:o/docs/:docId'));
  assert.notEqual(resourceKeyOf('/docs/:id'), resourceKeyOf('/notes/:id'));
});

test('the store index never contains an absolute host path', async () => {
  const dir = tempProject('js-app');
  try {
    const { persistBuild } = await import('../../src/context-intelligence/persist.js');
    const { loadConfig } = await import('../../src/context-intelligence/config.js');
    const built = await build(dir);
    persistBuild(dir, built, loadConfig(dir).config);
    const idx = readStoreFile(dir, 'index.json');
    assert.equal(idx.ok, true);
    assert.equal(idx.text.includes(fs.realpathSync(dir)), false);
  } finally { cleanup(dir); }
});
