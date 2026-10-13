// PRD 5 P0 §3 — Layer Secret Analysis: a secret added in one layer and later
// deleted (via an overlay whiteout) is still sitting in that earlier layer's
// raw tar bytes inside the image archive — recoverable by anyone who has the
// archive, even though it is invisible in `docker run`'s final filesystem.
//
// The actual credential detection is INJECTED as `detectFn` (the exact
// `(filePath, rawText) -> Finding[]` shape `src/posture/secret-history.js`
// already uses for the git-history analog of this same idea), so this module
// never imports `engine.js` and stays a pure, independently-testable
// transform over the layer data `filesystem.js` already extracted. The
// injected detector (`scanCredentials`) already returns only redacted/masked
// values (`masked`, a redacted `snippet`) — this module never re-touches raw
// file content once a finding exists, so there is no second place a value
// could leak back in.
import { isWhiteoutName } from './safe-tar.js';

export const DEFAULT_SECRET_SCAN_LIMITS = Object.freeze({
  maxFileBytes: 512 * 1024,
});

/**
 * `readLayersResult` is `filesystem.js#readLayers`'s output (ordered,
 * per-layer, pre-merge entries — the only shape that preserves "this path
 * existed in layer 3" even after a later layer's whiteout removes it from
 * the merged view). `deletedPaths` is `mergeLayers`'s output.
 *
 * Returns `{ findings, deletedButRecoverable, materializationSkipped }`:
 *   - `findings`: every detector hit across every layer's added files, each
 *     tagged with `path`/`layerIndex` and the detector's own (already
 *     redacted) finding fields — this is the full history sweep, not just
 *     the deleted-but-recoverable subset.
 *   - `deletedButRecoverable`: the subset of `findings` whose `path` was
 *     later removed by a whiteout in a LATER layer — PRD 5's named scenario.
 *   - `materializationSkipped`: paths whose content was too large to scan
 *     (disclosed, never silently treated as "no secret found").
 */
export function analyzeLayerSecrets({ readLayersResult, deletedPaths, detectFn, limits = DEFAULT_SECRET_SCAN_LIMITS }) {
  if (typeof detectFn !== 'function') throw new TypeError('analyzeLayerSecrets requires a detectFn(filePath, rawText) -> Finding[]');
  if (!readLayersResult || !Array.isArray(readLayersResult.layers)) throw new TypeError('analyzeLayerSecrets requires filesystem.js#readLayers output');

  const deletedAtByPath = new Map(); // path -> earliest layer index that deleted it
  for (const d of deletedPaths || []) {
    if (d.opaque) continue; // opaque-directory deletions are reported separately below
    if (!deletedAtByPath.has(d.path) || d.deletedAtLayer < deletedAtByPath.get(d.path)) {
      deletedAtByPath.set(d.path, d.deletedAtLayer);
    }
  }
  const opaqueDirs = (deletedPaths || []).filter((d) => d.opaque);

  const findings = [];
  const materializationSkipped = [];

  for (const { layerIndex, entries } of readLayersResult.layers) {
    for (const e of entries) {
      if (isWhiteoutName(e.name)) continue;
      if (e.typeflag !== '0' && e.typeflag !== '') continue; // regular files only
      if (e.size > limits.maxFileBytes) {
        materializationSkipped.push({ path: e.name, layerIndex, sizeBytes: e.size });
        continue;
      }
      let text;
      try {
        text = e.data.toString('utf8');
      } catch {
        continue; // not decodable as text — not a candidate for a text-pattern secret scan
      }
      let hits;
      try {
        hits = detectFn(e.name, text) || [];
      } catch {
        hits = []; // a detector failure on hostile/malformed content must never abort the sweep
      }
      for (const hit of hits) {
        const deletedAtLayer = deletedAtByPath.has(e.name) && deletedAtByPath.get(e.name) > layerIndex
          ? deletedAtByPath.get(e.name)
          : null;
        const underOpaqueDir = opaqueDirs.some((d) => d.deletedAtLayer > layerIndex && (e.name === d.path || e.name.startsWith(`${d.path}/`)));
        findings.push({
          ...hit,
          path: e.name,
          addedAtLayer: layerIndex,
          deletedAtLayer: deletedAtLayer ?? (underOpaqueDir ? opaqueDirs.find((d) => d.deletedAtLayer > layerIndex && (e.name === d.path || e.name.startsWith(`${d.path}/`))).deletedAtLayer : null),
          recoverable: deletedAtLayer != null || underOpaqueDir,
        });
      }
    }
  }

  const deletedButRecoverable = findings.filter((f) => f.recoverable);

  return { findings, deletedButRecoverable, materializationSkipped };
}
