// Merges an image's layers (in order) into one virtual filesystem view,
// applying AUFS/overlay whiteout semantics (`.wh.<name>` deletes a file,
// `.wh..wh..opq` makes a directory opaque to everything below it in earlier
// layers). Nothing here ever writes to a real filesystem path — the merged
// view is an in-memory Map keyed by the tar entry's (already path-safety-
// checked) name, which is what makes this immune to zip-slip by construction
// rather than by convention.
import { readTarEntries, isWhiteoutName, whiteoutTarget, DEFAULT_LIMITS } from './safe-tar.js';

export const DEFAULT_FS_LIMITS = Object.freeze({
  maxFileBytes: 1 * 1024 * 1024, // per-file materialization cap
  maxMaterializedTotalBytes: 256 * 1024 * 1024, // total content kept in memory
});

/**
 * Reads every layer's tar into per-layer entry lists (bounded by the same
 * safe-tar limits as the outer archive) without merging — the raw, ordered
 * per-layer view that layer-secrets.js needs to see what a LATER layer
 * deleted while it was still present in an EARLIER one.
 */
export function readLayers(layers, tarLimits = DEFAULT_LIMITS) {
  const result = [];
  const unsafeEntries = [];
  for (const layer of layers) {
    const entries = [];
    for (const e of readTarEntries(layer.tar, tarLimits)) {
      if (e.unsafe) {
        unsafeEntries.push({ layerIndex: layer.index, name: e.name });
        continue;
      }
      entries.push(e);
    }
    result.push({ layerIndex: layer.index, entries });
  }
  return { layers: result, unsafeEntries };
}

/**
 * Merges the per-layer entry lists (from readLayers) into one final
 * filesystem view, applying whiteouts in layer order. Returns:
 *   - `files`: Map<path, { sizeBytes, sourceLayerIndex, typeflag }> — every
 *     surviving path, metadata only.
 *   - `fileContents`: { path: string } — decoded text content, capped per
 *     file and in total (see DEFAULT_FS_LIMITS); large/binary files are
 *     present in `files` but absent here.
 *   - `deletedPaths`: [{ path, deletedAtLayer, opaque }] — every whiteout
 *     seen, in order, regardless of whether the path ever existed.
 *   - `materializationTruncated`: true once the total content cap was hit —
 *     disclosed, not silent.
 */
export function mergeLayers(readLayersResult, fsLimits = DEFAULT_FS_LIMITS) {
  const files = new Map(); // path -> { sizeBytes, sourceLayerIndex, typeflag, data }
  const deletedPaths = [];
  let materializedTotal = 0;
  let materializationTruncated = false;

  for (const { layerIndex, entries } of readLayersResult.layers) {
    const opaqueDirs = [];
    for (const e of entries) {
      if (isWhiteoutName(e.name)) {
        const wh = whiteoutTarget(e.name);
        if (wh.opaque) {
          opaqueDirs.push(wh.dir);
          deletedPaths.push({ path: wh.dir, deletedAtLayer: layerIndex, opaque: true });
          for (const existing of [...files.keys()]) {
            if (existing === wh.dir || existing.startsWith(`${wh.dir}/`)) files.delete(existing);
          }
        } else {
          deletedPaths.push({ path: wh.path, deletedAtLayer: layerIndex, opaque: false });
          files.delete(wh.path);
        }
        continue;
      }
      // An opaque marker earlier in THIS layer hides any further entry in
      // this same layer that would resurrect something under that dir —
      // real overlay semantics scope opaque to "everything from layers
      // BELOW this one", so same-layer adds after the marker still apply.
      files.set(e.name, { sizeBytes: e.size, sourceLayerIndex: layerIndex, typeflag: e.typeflag, data: e.data });
    }
  }

  const fileContents = {};
  for (const [path, meta] of files) {
    if (meta.typeflag !== '0' && meta.typeflag !== '') continue; // only regular files get content
    if (meta.sizeBytes > fsLimits.maxFileBytes) continue;
    if (materializedTotal + meta.sizeBytes > fsLimits.maxMaterializedTotalBytes) {
      materializationTruncated = true;
      continue;
    }
    fileContents[path] = meta.data.toString('utf8');
    materializedTotal += meta.sizeBytes;
  }

  const fileMeta = new Map();
  for (const [path, meta] of files) {
    fileMeta.set(path, { sizeBytes: meta.sizeBytes, sourceLayerIndex: meta.sourceLayerIndex, typeflag: meta.typeflag });
  }

  return { files: fileMeta, fileContents, deletedPaths, materializationTruncated };
}
