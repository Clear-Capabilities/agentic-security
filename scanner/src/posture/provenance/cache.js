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
import { FINDING_PROVENANCE_SCHEMA_VERSION } from './schema.js';

function keyPath(scanRoot, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return statePath(scanRoot, 'provenance', 'cache', hash + '.json');
}

/**
 * The schema version is part of the key, and is added HERE rather than by the
 * caller so that no caller can forget it.
 *
 * `validate.js` rejects a provenance object stamped with a version this build
 * does not understand — but a cache hit never reached that check: `cacheGet`
 * returns the parsed object as-is. With the version outside the key, entries
 * written by an older schema stayed live key hits after a version bump and
 * flowed straight through, defeating the exact scenario the version field was
 * added to guard. Including it means a bump silently misses every stale entry
 * instead, which is the correct outcome: they are recomputed, not trusted.
 */
export function makeCacheKey({ repoHead, stableId, detectorVersion, historyBoundary, mode }) {
  return [
    FINDING_PROVENANCE_SCHEMA_VERSION,
    repoHead || '', stableId || '', detectorVersion || '', historyBoundary || '', mode || '',
  ].join('|');
}

export function cacheGet(scanRoot, key) {
  // Read directly and let the catch handle "missing" — an explicit
  // existsSync() check first is a check-then-use race for no benefit, since
  // the catch already covers every failure mode a stale check would too.
  try {
    return JSON.parse(fs.readFileSync(keyPath(scanRoot, key), 'utf8'));
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
