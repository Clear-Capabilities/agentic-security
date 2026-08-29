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
//
// PRIVACY AT REST (second independent Finding Provenance PRD audit): this
// cache deliberately stores the FULL provenance record — including raw
// `authorEmail` — not a pre-redacted one. That is a considered choice, not an
// oversight: `redactFindingProvenance` is applied per output boundary
// (report/index.js, mcp/tools.js), and different callers in the SAME scan
// legitimately want different presentations of the SAME cached record — one
// reader wants the default-redacted view, another passes
// `--include-author-email`, a third wants `--pseudonymize-authors`. If the
// cache stored an already-redacted record, whichever policy was in effect at
// WRITE time would win for every reader forever, silently breaking that
// per-call flexibility. So redaction stays a read-time/output-time concern,
// exactly as documented in posture/CLAUDE.md's "Privacy" section, and this
// cache is accepted as an at-rest store of raw personal data.
//
// The mitigation applied here is a permissions floor, not encryption: every
// write tightens the `provenance-cache/` directory to 0700 and the entry file
// to 0600 (same posture this project already uses for the per-install HMAC
// key at integrity.js's `scan-key`, mode 0600 / 0700 parent). That defeats
// "any local user/process can read this," which is the realistic at-rest
// threat for a developer machine or CI runner; it does NOT defeat an attacker
// with root or the operating-system user's own privileges — no local file
// permission ever does. Encryption-at-rest with a per-install key (the same
// pattern as `scan-key`) was considered and rejected for this task's scope:
// unlike the HMAC key, which only ever needs to reproduce a symmetric digest,
// a cache that must serve back the exact original record on every read would
// need the plaintext decrypted on every `cacheGet`, which does not raise the
// bar much over a permissions floor while adding real complexity (key
// rotation, corrupt-ciphertext handling) for a cache that is disposable and
// content-addressed to begin with. If that tradeoff is revisited, encrypting
// only `findingOrigin.authorEmail` (not the whole record) would preserve this
// module's byte-identical round-trip property, which is asserted by this
// file's own tests.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { statePath, safeWriteState } from '../state-dir.js';
import { FINDING_PROVENANCE_SCHEMA_VERSION } from './schema.js';

// Permission floor for the cache directory and every entry inside it — see
// the module header. Applied on every write (not just directory creation) so
// an entry written before this floor existed, or a directory whose mode
// drifted looser some other way, is tightened back down the next time this
// key is touched.
const CACHE_DIR_MODE = 0o700;
const CACHE_FILE_MODE = 0o600;

// Its own top-level `.agentic-security/provenance-cache/` directory, NOT
// nested under `provenance/` (where it lived through M0-M4) — the artifact
// registry (posture/artifact-registry.js) can only apply retention per
// TOP-LEVEL directory name, and this cache (pure HEAD-keyed memo, safely
// regenerable) needs a TTL that the provenance/ lifecycle ledger (permanent
// history) must never get. See PRD Section 8 / artifact-registry.js's
// 'provenance-cache' entry. Single helper so the read and write paths can
// never drift apart.
function keyPath(scanRoot, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return statePath(scanRoot, 'provenance-cache', hash + '.json');
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
 *
 * `lineageKey` (M4 §4.2 final-review fix) covers the resolved
 * `.agentic-security/repo-lineage.json` cross-repo link the same way
 * `historyBoundary` already covers `--provenance-since`: a cross-repo
 * `partial` result IS cacheable, so without this the cache key had no field
 * reflecting which (if any) lineage link produced it. Adding, removing, or
 * repointing the declaration at the same HEAD would then keep serving a
 * stale pre-lineage or a stale cross-repo answer. Callers pass the resolved
 * link's own `${path}@${atCommit}`, or the literal `'none'` when
 * `loadRepoLineage` returns nothing — never omit it in a way that collapses
 * both cases to the same empty string the other fields default to.
 */
export function makeCacheKey({ repoHead, stableId, detectorVersion, historyBoundary, mode, lineageKey }) {
  return [
    FINDING_PROVENANCE_SCHEMA_VERSION,
    repoHead || '', stableId || '', detectorVersion || '', historyBoundary || '', mode || '', lineageKey || 'none',
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
    // category:'provenance-cache' lets lsp/server.js keep THIS write alive
    // while every other state write stays suppressed on every save — see
    // state-dir.js's withStateWritesDisabled.
    const fp = keyPath(scanRoot, key);
    const wrote = safeWriteState(fp, JSON.stringify(value), { category: 'provenance-cache' });
    if (wrote) {
      // Permission floor (see module header) — best-effort, applied AFTER a
      // successful write so a chmod failure (e.g. an unsupported filesystem)
      // never turns a real cache write into a reported failure.
      try {
        fs.chmodSync(path.dirname(fp), CACHE_DIR_MODE);
        fs.chmodSync(fp, CACHE_FILE_MODE);
      } catch { /* best-effort — see above */ }
    }
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
