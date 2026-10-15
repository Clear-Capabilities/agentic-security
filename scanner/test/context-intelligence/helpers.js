// Shared helpers for the context-intelligence tests (not itself a test file).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildContext } from '../../src/context-intelligence/build.js';
import { loadConfig } from '../../src/context-intelligence/config.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.resolve(HERE, '../fixtures/context-intelligence');

export function copyTree(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name); const d = path.join(dest, e.name);
    if (e.isDirectory()) copyTree(s, d); else if (e.isFile()) fs.copyFileSync(s, d);
  }
}

/** A throwaway project copy; a package.json marker is added if missing so state writes are allowed. */
export function tempProject(fixtureRel) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-test-'));
  copyTree(path.join(FIXTURES, fixtureRel), dir);
  if (!fs.existsSync(path.join(dir, 'package.json')) && !fs.existsSync(path.join(dir, 'pyproject.toml')) && !fs.existsSync(path.join(dir, 'app.cabal'))) fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fixture"}\n');
  return dir;
}

export function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }

export async function build(dir, configPatch = {}) {
  const { config } = loadConfig(dir);
  Object.assign(config, configPatch);
  return buildContext(dir, { config });
}

export const byLabel = (built, text) => built.bundles.find(b => b.entrypoint.label.includes(text));

import { planJobs, runQueue } from '../../src/context-intelligence/queue.js';
import { packById } from '../../src/context-intelligence/prompts/packs.js';
import { describeModel } from '../../src/context-intelligence/review.js';

/** Run the review queue over a built context with an injected invoker. Returns { built, jobs, result, loadJob }. */
export async function reviewWith(dir, invoke, { packIds = ['authz-idor'], limits = {}, ctx = {}, built = null } = {}) {
  built = built || await build(dir);
  const packs = packIds.map(packById);
  const model = describeModel();
  const { jobs } = planJobs({ bundles: built.bundles, packs, model });
  const byEp = new Map(built.bundles.map(b => [b.entrypoint.id, b]));
  const packMap = new Map(packs.map(p => [p.id, p]));
  const loadJob = (job) => {
    const bundles = job.entrypointIds.map(id => byEp.get(id));
    if (bundles.some(b => !b || !b.manifest)) return { error: 'no bundle' };
    return { pack: packMap.get(job.packId), entrypoints: bundles.map(b => b.entrypoint), manifests: bundles.map(b => b.manifest), packageTexts: bundles.map((b, i) => (b.pack.packages.find(p => p.index === job.packageIndexes[i]) || b.pack.packages[0]).text) };
  };
  const result = await runQueue(jobs, {
    root: built.root, fileContents: built.fileContents, model, invoker: { ok: true, invoke }, loadJob, retryFailed: false,
    sleep: async () => {}, random: () => 0,
    limits: { concurrency: 2, maxCalls: 200, maxWallSeconds: 60, maxTokensPerJob: 40000, maxRetries: 2, jobTimeoutMs: 5000, maxCostUsd: null, costPerCallUsd: null, ...limits }, ...ctx,
  });
  return { built, jobs, result, loadJob };
}
