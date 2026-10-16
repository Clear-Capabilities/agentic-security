// Runtime correlation that knows which build it is talking about (E5-02).
//
// `correlateObservations` (observation-correlation.js) is pinned, byte for byte, by its own tests: it answers "was this flow seen in the window" and
// nothing about WHICH build was seen. This wrapper adds that, without changing it. A caller that names the static snapshot's identity gets back the
// same correlation, computed over only the observations that could be about that code, plus a statement per flow of whether the evidence is tied to
// the snapshot's build:
//
//   corroborated   every contributing observation matched the snapshot's identity (deployment-identity.js: matched)
//   unattested     at least one contributing observation carried no comparable identity: seen at runtime, but not shown to be this code
//   none           no contributing observation
//
// Observations from a DIFFERENT build are excluded and listed under `buildMismatchedObservationIds`: they are not evidence about this code at all.
// A caller that names no snapshot identity gets the original result unchanged.
import { execFileSync } from 'node:child_process';
import { correlateObservations } from './observation-correlation.js';
import { canCorroborate, linkObservationToSnapshot, normalizeIdentity, observationIdentity } from './deployment-identity.js';

const LAYER_RUNTIME_OBSERVED = 'runtime_observed';

/** The identity of the source snapshot at `root`: the git HEAD, whether the work tree is dirty, and anything the caller adds (image digest, build hash, environment). */
export function snapshotIdentityOf(root, extra = {}) {
  let commit = null; let dirty = false;
  try {
    commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).trim();
    dirty = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000 }).trim().length > 0;
  } catch { commit = null; }
  return { ...normalizeIdentity({ commit, dirty, ...extra }) };
}

/**
 * @param {object} graph
 * @param {object[]|null|undefined} observations as for correlateObservations
 * @param {object} opts correlateObservations' options plus
 *   snapshotIdentity     {commit, buildHash, imageDigest, sbomRef, environment, dirty} of the static snapshot. Without it the original result is returned unchanged.
 *   observationBuilds    {[observationId]: {commit, buildHash, imageDigest, sbomRef}} identity the importer recorded for an observation
 */
export function correlateWithBuild(graph, observations, opts = {}) {
  const snapshot = opts.snapshotIdentity && typeof opts.snapshotIdentity === 'object' ? normalizeIdentity(opts.snapshotIdentity) : null;
  if (!snapshot || !Array.isArray(observations)) return correlateObservations(graph, observations, opts);
  const builds = opts.observationBuilds && typeof opts.observationBuilds === 'object' ? opts.observationBuilds : {};
  const links = new Map(); const kept = []; const mismatched = [];
  for (const obs of observations) {
    const id = obs && typeof obs.id === 'string' ? obs.id : null;
    const claimed = id && builds[id] ? { ...observationIdentity(obs), ...normalizeIdentity({ ...builds[id], environment: obs.environment }) } : observationIdentity(obs);
    const link = linkObservationToSnapshot(claimed, snapshot);
    if (id) links.set(id, link);
    if (link.state === 'mismatched') { if (id) mismatched.push(id); continue; }
    kept.push(obs);
  }
  const base = correlateObservations(graph, kept, opts);
  const byFlow = {};
  for (const [fid, entry] of Object.entries(base.byFlow || {})) {
    const ids = entry.observationIds || [];
    const corroboration = entry.layer !== LAYER_RUNTIME_OBSERVED || !ids.length ? 'none' : ids.every((i) => canCorroborate(links.get(i))) ? 'corroborated' : 'unattested';
    byFlow[fid] = { ...entry, corroboration };
  }
  return {
    ...base, byFlow,
    buildMismatchedObservationIds: [...new Set(mismatched)].sort(),
    buildLink: { requested: true, snapshot: { commit: snapshot.commit, buildHash: snapshot.buildHash, imageDigest: snapshot.imageDigest, environment: snapshot.environment, dirty: snapshot.dirty } },
    limitations: [...(base.limitations || []), 'Observations from a different build were excluded; observations with no comparable build identity are kept but marked unattested, never corroborated.'],
  };
}
