// What a context bundle and a decision made from it depend on, beyond the code it packs (contract-driven verification, D-AC05).
//
// `contextHash` covers the packed source, the pack settings and the entry point's shape. It does not cover what sits outside the pack:
// the file that registers the route and its middleware chain, the files holding the controls the reachability pass recorded, the
// boundary calls it stopped at, the service contract a hunt read the bundle under, and the environment the operator declared. A change
// in any of those leaves the packed text identical while making a cached review or a qualification decision wrong.
//
// `dependencyKeyOf` digests those inputs. The build records it per entry point (`index.json`), the context supplier recomputes it from
// the hunt's own file snapshot and marks a bundle `stale` (reason `dependency-changed`) when it differs, and the review queue folds it,
// with the contract reference and the environment, into every job key so a cached review result misses instead of being reused.
// Files are hashed whole: a file the build saw and the snapshot lacks is recorded as `null`, so a deletion is a change, never a match.
import { hashOf, sha256 } from './canonical.js';

export const DEPENDENCY_KEY_ALGORITHM = 'context-dependencies/1';

const siteFile = (site) => { if (typeof site !== 'string') return null; const i = site.lastIndexOf(':'); return i > 0 ? site.slice(0, i) : null; };

/** The repository-relative files a bundle depends on outside its packed segments, sorted and de-duplicated. */
export function dependencyFilesOf(manifest) {
  const files = new Set();
  const reg = manifest?.entrypoint?.registrationSite;
  if (reg?.file) files.add(reg.file);
  for (const c of manifest?.controls || []) if (c.file) files.add(c.file);
  for (const b of manifest?.boundaries || []) { const f = siteFile(b.firstSite); if (f) files.add(f); }
  return [...files].sort();
}

// a boundary is recorded as `{ calleeName, reason, count, firstSite: 'file:line' }`
const boundaryView = (b) => ({ calleeName: b.calleeName ?? null, reason: b.reason ?? null, file: siteFile(b.firstSite) });

/**
 * The key. `fileContents` is a repository-relative path -> text map (the build's snapshot or the hunt's). `contractRef` and
 * `environment` are optional; when absent they are recorded as null, so declaring either later changes the key.
 */
export function dependencyKeyOf({ manifest, fileContents = {}, contractRef = null, environment = null }) {
  const files = {};
  for (const f of dependencyFilesOf(manifest)) files[f] = typeof fileContents[f] === 'string' ? sha256(fileContents[f]) : null;
  const middleware = Array.isArray(manifest?.entrypoint?.middleware) ? manifest.entrypoint.middleware.map((m) => (typeof m === 'string' ? m : (m?.name ?? JSON.stringify(m)))) : [];
  const parts = {
    algorithm: DEPENDENCY_KEY_ALGORITHM,
    middleware,
    files,
    boundaries: (manifest?.boundaries || []).map(boundaryView),
    contractRef: contractRef ?? null,
    environment: environment ?? null,
  };
  return { key: hashOf(parts), files, middleware, contractRef: parts.contractRef, environment: parts.environment };
}

/** Which inputs differ between two recorded keys' parts; empty when they match. */
export function dependencyChanges(before, after) {
  const changes = [];
  if (JSON.stringify(before.middleware) !== JSON.stringify(after.middleware)) changes.push('middleware');
  const fileNames = new Set([...Object.keys(before.files || {}), ...Object.keys(after.files || {})]);
  for (const f of [...fileNames].sort()) if ((before.files || {})[f] !== (after.files || {})[f]) changes.push(`file:${f}`);
  if ((before.contractRef ?? null) !== (after.contractRef ?? null)) changes.push('contract');
  if (JSON.stringify(before.environment ?? null) !== JSON.stringify(after.environment ?? null)) changes.push('environment');
  return changes;
}
