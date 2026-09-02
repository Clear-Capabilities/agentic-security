// graph-snapshot.js — M4 deliverable #8 (FR-503 §14, DFG-022): the
// GraphSnapshot extension contract + persist/load history + a
// comparability check.
//
// Mirrors obligation-mapping.js/decision-story.js's own contract shape
// exactly: a record is explicitly NOT a DataFlowGraph v1 entity (§10.10
// — "associated with, but not required inside, the immutable base
// graph"), never added to dataflow-graph.schema.json, never routed
// through validate.js.
//
// Persistence mirrors posture/sbom-diff.js's own proven architecture —
// persist-by-git-commit, most-recent-by-mtime lookup — the one real,
// already-shipped precedent in this codebase for "compare two scans."
// Not reused code (sbom-diff.js operates on flat SBOM components, not
// graph entities) but the same architecture, deliberately.
//
// A real, load-bearing gap found during scoping: engine.js's own call
// site to buildLineageGraph never passes opts.commit, so every real
// graph's own graphId today embeds the literal string 'uncommitted'
// regardless of the repo's real git state. Snapshot keying CANNOT read
// graph.graphId for the commit — it resolves the real git HEAD
// independently, exactly like sbom-diff.js's own _gitHead helper.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { statePath, stateWritesEnabled } from '../posture/state-dir.js';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';
import { snapshotId } from './ids.js';

const SNAPSHOT_VERSION = '1.0.0';
const HISTORY_DIR = 'lineage-snapshots';

function _historyDir(scanRoot) {
  return statePath(scanRoot, HISTORY_DIR);
}

// scanRoot is the SCANNED project's repository, not this project's own
// checkout — hardened per the same FR-PROV-024 precedent sbom-diff.js's
// own _gitHead already established. rev-parse HEAD touches neither the
// working tree nor the index, so this is read-only.
function _gitHead(scanRoot) {
  try {
    return execFileSync('git', hardenGitArgs(['rev-parse', 'HEAD']), {
      cwd: scanRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv(),
    }).trim();
  } catch { return null; }
}

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

/**
 * Structural validation only — mirrors
 * obligation-mapping.js#validateObligationMapping's own {valid, errors}
 * shape and "never throws" contract.
 */
export function validateGraphSnapshot(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'GraphSnapshot record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('snapshot:')) {
    err('$.id', 'id is required and must start with "snapshot:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.schemaVersion)) err('$.schemaVersion', 'schemaVersion is required');
  if (!_isNonEmptyString(record.commit)) err('$.commit', 'commit is required');
  if (!_isNonEmptyString(record.capturedAt)) err('$.capturedAt', 'capturedAt is required');
  if (!_isPlainObject(record.coverage)) err('$.coverage', 'coverage is required and must be an object');
  if (!_isPlainObject(record.graph)) err('$.graph', 'graph is required and must be an object');
  return { valid: errors.length === 0, errors };
}

/**
 * Build `graph` as a GraphSnapshot record, keyed by the REAL current git
 * HEAD of `scanRoot` (never `graph.graphId`'s own commit component —
 * see this file's own header). Falls back to a content hash of the
 * graph when no git repo is present, matching sbom-diff.js's own
 * precedent. opts.capturedAt overrides wall-clock time (deterministic
 * test fixtures, mirroring every other M4 exporter's own opts.generatedAt
 * convention). Zero disk I/O — validates and returns the snapshot,
 * never writes it.
 */
export function buildGraphSnapshot(graph, scanRoot, opts = {}) {
  const commit = _gitHead(scanRoot) || crypto.createHash('sha256').update(JSON.stringify(graph)).digest('hex').slice(0, 12);
  const capturedAt = opts.capturedAt ?? new Date().toISOString();
  const snapshot = {
    id: snapshotId({ graphId: graph.graphId, commit, capturedAt }),
    version: SNAPSHOT_VERSION,
    graphId: graph.graphId,
    schemaVersion: graph.schemaVersion,
    commit,
    capturedAt,
    coverage: graph.coverage ?? {},
    graph,
  };
  const { valid, errors } = validateGraphSnapshot(snapshot);
  if (!valid) {
    throw new Error(`buildGraphSnapshot: internal error — produced an invalid GraphSnapshot: ${JSON.stringify(errors)}`);
  }
  return snapshot;
}

/**
 * Persist `graph` as a GraphSnapshot, keyed by the REAL current git
 * HEAD of `scanRoot` (never `graph.graphId`'s own commit component —
 * see this file's own header). Falls back to a content hash of the
 * graph when no git repo is present, matching sbom-diff.js's own
 * precedent. opts.capturedAt overrides wall-clock time (deterministic
 * test fixtures, mirroring every other M4 exporter's own opts.generatedAt
 * convention).
 */
export function persistGraphSnapshot(graph, scanRoot, opts = {}) {
  const snapshot = buildGraphSnapshot(graph, scanRoot, opts);
  if (stateWritesEnabled()) {
    const dir = _historyDir(scanRoot);
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}
    try { fs.writeFileSync(path.join(dir, `${snapshot.commit}.json`), JSON.stringify(snapshot, null, 2)); } catch {}
  }
  return snapshot;
}

/** All persisted snapshots for scanRoot, newest first by mtime. Never
 * throws — an empty/missing history directory returns []. */
export function loadSnapshots(scanRoot) {
  const dir = _historyDir(scanRoot);
  if (!fs.existsSync(dir)) return [];
  let files;
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { return []; }
  const withMtime = files.map((f) => {
    const full = path.join(dir, f);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(full).mtimeMs; } catch {}
    return { full, mtimeMs };
  });
  withMtime.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const out = [];
  for (const { full } of withMtime) {
    try { out.push(JSON.parse(fs.readFileSync(full, 'utf8'))); } catch {}
  }
  return out;
}

/** One snapshot by its commit key, or null. Never throws. */
export function loadSnapshot(scanRoot, commitKey) {
  const dir = _historyDir(scanRoot);
  const full = path.join(dir, `${commitKey}.json`);
  if (!fs.existsSync(full)) return null;
  try { return JSON.parse(fs.readFileSync(full, 'utf8')); } catch { return null; }
}

/** The newest persisted snapshot that is NOT excludeCommitKey — the
 * default "compare against" target. Null if none exists. */
export function mostRecentPriorSnapshot(scanRoot, excludeCommitKey) {
  const all = loadSnapshots(scanRoot);
  return all.find((s) => s.commit !== excludeCommitKey) ?? null;
}

/**
 * Are two snapshots validly diffable? Only ever reports true on a REAL,
 * checkable signal — today, schemaVersion equality. The graphId
 * configHash gap (see this sub-project's own scoping doc) is a real,
 * disclosed limitation: two snapshots with the same schemaVersion but a
 * genuinely different analyzer/config are reported comparable, since no
 * real signal exists yet to detect that difference — never silently
 * papered over, but not fabricated either.
 */
export function snapshotsComparable(a, b) {
  if (!a || !b) return { comparable: false, reasons: ['one or both snapshots are missing'] };
  const reasons = [];
  if (a.schemaVersion !== b.schemaVersion) {
    reasons.push(`schemaVersion differs (${a.schemaVersion} vs ${b.schemaVersion})`);
  }
  return { comparable: reasons.length === 0, reasons };
}
