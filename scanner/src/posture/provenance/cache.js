// Content-addressed provenance cache.
//
// Paths and writes both go through posture/state-dir.js rather than joining
// the state directory name by hand. That seam is what enforces the two
// invariants this module would otherwise each have to remember: it refuses to
// create state outside a project root, and it honours the read-only scan
// switch (`--no-state` / AGENTIC_SECURITY_NO_STATE), so scanning somebody
// else's tree leaves it byte-identical. See test/no-stray-state.test.js — a
// cache that quietly writes during a read-only scan is exactly the litter that
// guard exists to prevent.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { statePath, safeWriteState } from '../state-dir.js';

function keyPath(scanRoot, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return statePath(scanRoot, 'provenance', 'cache', hash + '.json');
}

export function makeCacheKey({ repoHead, stableId, detectorVersion, historyBoundary, mode }) {
  return [repoHead || '', stableId || '', detectorVersion || '', historyBoundary || '', mode || ''].join('|');
}

export function cacheGet(scanRoot, key) {
  try {
    const p = keyPath(scanRoot, key);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

export function cacheSet(scanRoot, key, value) {
  try {
    // safeWriteState creates the directory, applies the project-root check and
    // returns false (never throws) when the read-only switch is on. A refused
    // write is a cache miss next time, which is correct behaviour, not an error.
    safeWriteState(keyPath(scanRoot, key), JSON.stringify(value));
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
