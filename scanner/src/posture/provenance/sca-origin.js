import * as crypto from 'node:crypto';
import { candidateCommitsForFile, getFirstParent, getBlobAtCommit, commitMeta } from './git-evidence.js';
import { PROVENANCE_METHOD } from './schema.js';

function parseSemver(v) {
  const m = String(v || '').replace(/^[^\d]*/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

function cmpSemver(a, b) {
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}

export function versionInRange(version, range) {
  const v = parseSemver(version);
  if (!v) return false;
  if (range.introduced) {
    const lo = parseSemver(range.introduced);
    if (lo && cmpSemver(v, lo) < 0) return false;
  }
  if (range.fixed) {
    const hi = parseSemver(range.fixed);
    if (hi && cmpSemver(v, hi) >= 0) return false;
  }
  return true;
}

export function scaStableId(entry) {
  const material = `${entry.osvId || ''}|${entry.name || ''}|${entry.ecosystem || ''}|${(entry.filePath || '').split('/').slice(-2).join('/')}`;
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 16);
}

function extractDeclaredVersion(blobText, depName, filePath) {
  const base = filePath.split('/').pop();
  if (base === 'package.json') {
    try {
      const d = JSON.parse(blobText);
      return (d.dependencies && d.dependencies[depName]) || (d.devDependencies && d.devDependencies[depName]) || null;
    } catch {
      return null;
    }
  }
  if (/^requirements(?:[._-][\w.-]+)?\.txt$/i.test(base)) {
    for (const line of blobText.split('\n')) {
      const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*[=~<>!]+\s*([^\s;#,]*)/);
      if (m && m[1].toLowerCase() === depName.toLowerCase()) return m[2];
    }
    return null;
  }
  return null;
}

function originResult({ meta, commitsConsidered, absentInParents, parentBoundaryVerified }) {
  return {
    status: 'complete', method: PROVENANCE_METHOD.DEPENDENCY_GRAPH_DIFF, commitsConsidered,
    findingOrigin: { commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
      authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
      presentInCommit: true, absentInParents },
    parentBoundaryVerified,
  };
}

export async function resolveDirectSCAOrigin(scanRoot, scaEntry, { since, deadlineAt } = {}) {
  const file = scaEntry.filePath;
  if (!file) return { status: 'not_available', reason: 'no-manifest-path', commitsConsidered: 0 };

  const candidates = candidateCommitsForFile(scanRoot, file, { since });
  if (candidates.length === 0) return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };

  const range = { introduced: null, fixed: (scaEntry.fixedVersions || [])[0] || null };
  let commitsConsidered = 0;
  // With no `introduced` lower bound, `versionInRange` treats any version below
  // `fixed` as "in range" (by design — see the versionInRange unit test). That
  // means a repo-root commit can be trivially "in range" even when it holds a
  // genuinely older/safer version than a later bump — the comparator has no
  // way to tell the difference without a lower bound. A parent-less root is
  // therefore not proof of introduction the way it is for a boolean predicate
  // (origin-resolver.js): we defer it as a low-confidence fallback and keep
  // walking for a commit where the declared version actually CHANGED into the
  // in-range value — that's the real origin of the currently-observed state.
  let rootFallback = null;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    const blob = getBlobAtCommit(scanRoot, sha, file);
    if (blob == null) continue;
    const declaredVersion = extractDeclaredVersion(blob, scaEntry.name, file);
    if (!declaredVersion || !versionInRange(declaredVersion, range)) continue;

    const parent = getFirstParent(scanRoot, sha);
    if (!parent) {
      if (!rootFallback) {
        const meta = commitMeta(scanRoot, sha);
        if (meta) rootFallback = meta;
      }
      continue;
    }

    const parentBlob = getBlobAtCommit(scanRoot, parent, file);
    const parentVersion = parentBlob ? extractDeclaredVersion(parentBlob, scaEntry.name, file) : null;
    if (parentVersion === declaredVersion) continue; // unrelated edit — the dep's declared value didn't change here

    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;
    return originResult({ meta, commitsConsidered, absentInParents: [parent], parentBoundaryVerified: true });
  }

  if (rootFallback) {
    return originResult({ meta: rootFallback, commitsConsidered, absentInParents: [], parentBoundaryVerified: false });
  }

  return { status: 'partial', reason: 'version-never-confirmed-in-candidates', commitsConsidered };
}
