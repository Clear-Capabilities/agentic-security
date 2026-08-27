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
  // `fixed` as "in range" (by design — see the versionInRange unit test: a
  // fixed-only range means "vulnerable since inception"). That makes two
  // distinct real-world situations indistinguishable by pure range membership:
  // (1) a genuinely safer earlier version that nonetheless also falls below
  // `fixed`, later bumped into the actually-vulnerable value, vs. (2) a
  // routine patch-level bump (e.g. a dependabot PR) that moves the declared
  // version WITHIN an already-vulnerable window. Both look identical as
  // "parent in range, child in range, version string differs" — there is no
  // way to tell them apart without an introduced bound. So a parent whose
  // version is ALSO in-range is never treated as a confirmed transition (that
  // would misattribute case 2 to the bump commit — a Critical bug caught in
  // review: reporting `parentBoundaryVerified:true` at a routine patch bump
  // when the dependency was vulnerable from the very first commit). Instead
  // it's an unresolved ambiguity, and it downgrades even a root-commit
  // fallback claim to `partial` rather than asserting a possibly-wrong commit
  // with high confidence — the two situations render identically because they
  // ARE identical given only a `fixed` version and no lower bound.
  let rootFallback = null;
  let ambiguousBump = false;

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
    const parentOutOfRange = !parentVersion || !versionInRange(parentVersion, range);
    if (!parentOutOfRange) {
      // Parent was already in the vulnerable range too. If the declared value
      // actually changed here, this is the ambiguous "still-vulnerable bump"
      // case described above — never attribute origin to it, and don't trust
      // an earlier root fallback either, since it proves the history isn't as
      // clean as a single unchanging value since repo creation.
      if (parentVersion !== declaredVersion) ambiguousBump = true;
      continue;
    }

    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;
    return originResult({ meta, commitsConsidered, absentInParents: [parent], parentBoundaryVerified: true });
  }

  if (rootFallback && !ambiguousBump) {
    return originResult({ meta: rootFallback, commitsConsidered, absentInParents: [], parentBoundaryVerified: false });
  }

  return {
    status: 'partial',
    reason: ambiguousBump ? 'ambiguous-range-no-introduced-bound' : 'version-never-confirmed-in-candidates',
    commitsConsidered,
  };
}
