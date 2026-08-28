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

function _sameDepChain(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  return a.every((seg, i) => seg === b[i]);
}

// Extract {version, depChain} for `depName` from a package-lock.json blob's
// text, using the same `packages` key structure engine.js's
// _parsePackageLockJson reads at scan time (lockfile v2/v3 shape: keys are
// paths like "node_modules/express/node_modules/qs"). Returns null if the
// package isn't present in this blob at all (e.g., an OLDER lockfile before
// it was ever pulled in).
//
// `preferredDepChain` (M3 §3.2 follow-up, final whole-branch review item #7)
// is the finding's OWN depChain (Task 5, propagated from engine.js's
// _parsePackageLockJson) identifying which specific nested copy the finding
// is actually about, when a lockfile has multiple nested copies of the same
// package name at different depths. When a `packages` key at THIS historical
// blob computes to that exact chain, it wins outright — the shortest-path
// heuristic below is a heuristic guess about "the" instance, and an exact
// match is not a guess. It is only ever a hint, though, per this module's own
// header comment: the graph's shape can differ commit-to-commit, so a
// historical blob may simply have no key whose chain matches the CURRENT
// depChain at all — in that case fall back to the shortest-path heuristic
// exactly as before, since re-deriving ancestry per-commit rather than
// trusting a mismatched hint is the whole reason this module doesn't just
// trust the current depChain outright.
function extractTransitiveVersion(blobText, depName, preferredDepChain) {
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
  let exact = null;
  for (const key of Object.keys(packages)) {
    if (!key.endsWith(`node_modules/${depName}`)) continue;
    const depChain = key.split('node_modules/').filter(Boolean).map((s) => s.replace(/\/$/, ''));
    const entry = packages[key];
    const version = entry && entry.version;
    if (!version) continue;
    if (!exact && Array.isArray(preferredDepChain) && preferredDepChain.length > 0 && _sameDepChain(depChain, preferredDepChain)) {
      exact = { version, depChain };
    }
    if (!best || depChain.length < best.depChain.length) best = { version, depChain };
  }
  return exact || best;
}

function originResult({ meta, commitsConsidered, depChain, absentInParents, parentBoundaryVerified }) {
  return {
    status: 'complete', method: PROVENANCE_METHOD.DEPENDENCY_GRAPH_DIFF, commitsConsidered,
    findingOrigin: {
      commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
      authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
      presentInCommit: true, absentInParents, revertOf: null, cherryPickOf: null,
    },
    parentBoundaryVerified,
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
  const preferredDepChain = Array.isArray(scaEntry.depChain) ? scaEntry.depChain : null;
  let commitsConsidered = 0;
  let rootFallback = null;
  let rootFallbackChain = null;
  let ambiguousBump = false;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    const blob = getBlobAtCommit(scanRoot, sha, file);
    if (blob == null) continue;
    const declared = extractTransitiveVersion(blob, scaEntry.name, preferredDepChain);
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
    const parentDeclared = parentBlob ? extractTransitiveVersion(parentBlob, scaEntry.name, preferredDepChain) : null;
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
    return originResult({ meta, commitsConsidered, depChain: declared.depChain, absentInParents: [parent], parentBoundaryVerified: true });
  }

  if (rootFallback && !ambiguousBump) {
    return originResult({ meta: rootFallback, commitsConsidered, depChain: rootFallbackChain, absentInParents: [], parentBoundaryVerified: false });
  }

  return {
    status: 'partial',
    reason: ambiguousBump ? 'ambiguous-range-no-introduced-bound' : 'version-never-confirmed-in-candidates',
    commitsConsidered,
  };
}
