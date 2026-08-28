// Transitive dependency origin resolution (Finding Provenance PRD, M3 §3.2).
//
// A transitive vulnerable_dep finding's vulnerable version was never
// declared directly in this repo's manifest — some DIRECT dependency's
// version bump pulled it into the graph. This module answers "which commit
// changed the lockfile such that the vulnerable transitive version first
// appears," re-deriving the dependency's ancestry AT EACH HISTORICAL
// CANDIDATE COMMIT rather than trusting the CURRENT depChain (Task 5) —
// the graph's shape can itself change across commits, so the current
// ancestry is a hint for the fixture/test author, not evidence a resolver
// can rely on for a historical claim.
//
// Scope: package-lock.json only for M3 — see the plan's Task 6 scope note.

import { candidateCommitsForFile, getFirstParent, getBlobAtCommit, commitMeta } from './git-evidence.js';
import { versionInRange } from './sca-origin.js';
import { PROVENANCE_METHOD } from './schema.js';

const LOCKFILE_BASENAME = 'package-lock.json';

// Extract {version, depChain} for `depName` from a package-lock.json blob's
// text, using the same `packages` key structure engine.js's
// _parsePackageLockJson reads at scan time (lockfile v2/v3 shape: keys are
// paths like "node_modules/express/node_modules/qs"). Returns null if the
// package isn't present in this blob at all (e.g., an OLDER lockfile before
// it was ever pulled in).
function extractTransitiveVersion(blobText, depName) {
  let doc;
  try { doc = JSON.parse(blobText); } catch { return null; }
  const packages = doc.packages;
  if (!packages || typeof packages !== 'object') return null;
  // Prefer the SHORTEST matching path (closest to a direct dependency) when
  // multiple nested copies of the same package exist at different depths —
  // matches the ancestry a reader would consider "the" instance most of the
  // time. Ties resolve to whichever JSON.stringify/Object.keys ordering
  // returns first (lockfiles preserve insertion order; this is deterministic
  // for a given blob, which is what matters for a repeatable resolution).
  let best = null;
  for (const key of Object.keys(packages)) {
    if (!key.endsWith(`node_modules/${depName}`)) continue;
    const depChain = key.split('node_modules/').filter(Boolean).map((s) => s.replace(/\/$/, ''));
    const entry = packages[key];
    const version = entry && entry.version;
    if (!version) continue;
    if (!best || depChain.length < best.depChain.length) best = { version, depChain };
  }
  return best;
}

function originResult({ meta, commitsConsidered, depChain }) {
  return {
    status: 'complete', method: PROVENANCE_METHOD.DEPENDENCY_GRAPH_DIFF, commitsConsidered,
    findingOrigin: {
      commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
      authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
      presentInCommit: true, absentInParents: [], revertOf: null, cherryPickOf: null,
    },
    parentBoundaryVerified: true,
    depChain,
  };
}

export async function resolveTransitiveSCAOrigin(scanRoot, scaEntry, { since, deadlineAt } = {}) {
  const file = scaEntry.filePath || scaEntry.file;
  if (!file) return { status: 'not_available', reason: 'no-manifest-path', commitsConsidered: 0 };
  const basename = file.split('/').pop();
  if (basename !== LOCKFILE_BASENAME) {
    return { status: 'not_available', reason: 'unsupported-lockfile-format', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForFile(scanRoot, file, { since });
  if (candidates.length === 0) return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };

  const range = { introduced: null, fixed: (scaEntry.fixedVersions || [])[0] || null };
  let commitsConsidered = 0;
  let rootFallback = null;
  let rootFallbackChain = null;
  let ambiguousBump = false;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    const blob = getBlobAtCommit(scanRoot, sha, file);
    if (blob == null) continue;
    const declared = extractTransitiveVersion(blob, scaEntry.name);
    if (!declared || !versionInRange(declared.version, range)) continue;

    const parent = getFirstParent(scanRoot, sha);
    if (!parent) {
      if (!rootFallback) {
        const meta = commitMeta(scanRoot, sha);
        if (meta) { rootFallback = meta; rootFallbackChain = declared.depChain; }
      }
      continue;
    }

    const parentBlob = getBlobAtCommit(scanRoot, parent, file);
    const parentDeclared = parentBlob ? extractTransitiveVersion(parentBlob, scaEntry.name) : null;
    const parentOutOfRange = !parentDeclared || !versionInRange(parentDeclared.version, range);
    if (!parentOutOfRange) {
      // Same ambiguity sca-origin.js's resolveDirectSCAOrigin documents: a
      // fixed-only range with no lower bound can't distinguish "vulnerable
      // since inception, unrelated bump" from "just became vulnerable here."
      if (parentDeclared.version !== declared.version) ambiguousBump = true;
      continue;
    }

    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;
    return originResult({ meta, commitsConsidered, depChain: declared.depChain });
  }

  if (rootFallback && !ambiguousBump) {
    return originResult({ meta: rootFallback, commitsConsidered, depChain: rootFallbackChain });
  }

  return {
    status: 'partial',
    reason: ambiguousBump ? 'ambiguous-range-no-introduced-bound' : 'version-never-confirmed-in-candidates',
    commitsConsidered,
  };
}
