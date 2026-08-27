// Finding-provenance coordinator — the integration point where every other
// provenance module meets a real finding list.
//
// NAMING: `annotateGitProvenance`, not `annotateProvenance` or
// `annotateFindingProvenance` — both of those are already taken by unrelated
// features that `engine.js` imports today: `sca/sigstore-verify.js`'s
// `annotateProvenance` (build attestations) and `posture/provenance.js`'s
// `annotateFindingProvenance` (parser-corroboration signals). Either name here
// would be a duplicate binding — a SyntaxError — the moment engine.js imports
// this module, and the second is worse still because it takes a findings array
// as its first argument exactly like this one, so a wrong import would run
// rather than fail. The name states the mechanism that distinguishes this one:
// provenance derived from GIT HISTORY.
//
// Its single hard guarantee: after `annotateGitProvenance(findings, ctx)`
// returns, EVERY finding in the array carries a terminal `findingProvenance`
// object. There is no path — not a missing git binary, not a malformed
// finding, not a downstream module throwing — that leaves a finding with
// `findingProvenance === undefined`. A consumer that has to check for
// "annotated or not" before reading the status defeats the whole point of the
// status enum, so the enum carries the failure modes instead:
// `not_available` (nothing to look at), `uncommitted` (PRD Scenario G),
// `budget_exhausted` (we ran out of time), `error` (something below us threw).
//
// Two ordering decisions are load-bearing:
//
//  1. **Uncommitted is checked FIRST, via `blameLine`, before `resolveOrigin`.**
//     A finding on a line that exists only in the working tree has no commit
//     history to walk — running the candidate-replay walk for it would be pure
//     waste, and worse, a cached result keyed on HEAD would be stale the moment
//     the line was edited. One `git blame` call settles it (PRD Scenario G).
//
//  2. **`repoState` is the REAL `getRepoState()` output, resolved once and
//     threaded into every `resolveOrigin` call.** This is not a convenience —
//     `origin-resolver.js` disambiguates "true repository root" from "shallow
//     clone boundary" purely on `repoState.shallow`. Handing it a stub or a
//     default would let a shallow repo reach `status:'complete'`, which is
//     exactly the false certainty the PRD forbids. Resolve it once (it is
//     four `git` calls) and pass it down; never reconstruct it per finding.

import * as crypto from 'node:crypto';
import { getRepoState, isGitRepo, blameLine } from './git-evidence.js';
import { resolveOrigin } from './origin-resolver.js';
import { resolveBranchEntry } from './branch-entry.js';
import { attributeEvidence } from './evidence-attribution.js';
import { assessConfidence } from './confidence.js';
import { cacheGet, cacheSet, makeCacheKey } from './cache.js';
import { emptyProvenance, PROVENANCE_STATUS } from './schema.js';

const DEFAULT_TIMEOUT_MS = 60000;
const MAX_CONCURRENCY = 4;

function computeDigest(finding, provenance) {
  const material = JSON.stringify({
    stableId: finding.stableId,
    origin: provenance.findingOrigin?.commit || null,
    branchEntry: provenance.branchIntroduction?.commit || null,
    evidence: (provenance.evidenceAttribution || []).map((n) => `${n.role}:${n.path}:${n.line}:${n.commit}`),
    method: provenance.method,
    reasons: provenance.confidence?.reasons || [],
    limitations: provenance.limitations,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}

async function resolveOne(finding, ctx) {
  const { scanRoot, repoState, deadlineAt } = ctx;

  // Cheap, correct short-circuit (PRD Scenario G). One blame call, before any
  // history walk: a working-tree-only line has no origin commit to find.
  if (finding.file && finding.line) {
    const blame = blameLine(scanRoot, finding.file, finding.line);
    if (blame && blame.uncommitted) {
      return emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED, {
        limitations: ['finding exists only in working tree/index'],
      });
    }
  }

  if (!finding.stableId) {
    return emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['finding has no stableId'] });
  }

  // The scan-wide budget. `resolveOrigin` honours `deadlineAt` internally, but
  // a finding whose turn comes up after the deadline has already passed should
  // not pay for a candidate walk at all.
  if (deadlineAt && Date.now() > deadlineAt) {
    return emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: 0 },
      limitations: ['analysis budget expired before this finding was reached'],
    });
  }

  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;

  const originResult = await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt, repoState });

  let provenance;
  if (originResult.status === 'complete') {
    const branchIntroduction = resolveBranchEntry(scanRoot, originResult.findingOrigin.commit, repoState.branch || 'HEAD');
    const evidenceAttribution = attributeEvidence(scanRoot, finding);
    const confidence = assessConfidence({
      parentBoundaryVerified: originResult.parentBoundaryVerified,
      historyComplete: !repoState.shallow,
      detectorCompatible: true,
      renameAmbiguous: false,
      shallow: repoState.shallow,
    });
    provenance = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: originResult.findingOrigin,
      branchIntroduction,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      evidenceAttribution,
      method: originResult.method,
      confidence,
      historyCoverage: { complete: !repoState.shallow, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: finding.parser || null, dirty: repoState.dirty },
    });
  } else if (originResult.status === 'partial') {
    provenance = emptyProvenance(PROVENANCE_STATUS.PARTIAL, {
      findingOrigin: originResult.findingOrigin || null,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: finding.parser || null, dirty: repoState.dirty },
      limitations: ['earliest observable — history could not confirm a verified parent boundary'],
      confidence: { level: 'low', score: 0.2, reasons: ['shallow_or_unverified_boundary'] },
    });
  } else if (originResult.status === 'budget_exhausted') {
    provenance = emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      limitations: ['analysis budget expired before origin could be resolved'],
    });
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  cacheSet(scanRoot, cacheKey, provenance);
  return provenance;
}

export async function annotateGitProvenance(findings, ctx) {
  if (!Array.isArray(findings) || findings.length === 0) return;
  const options = ctx || {};
  const scanRoot = options.scanRoot;

  const stampAll = (status, limitation) => {
    for (const f of findings) {
      if (!f || typeof f !== 'object') continue;
      f.findingProvenance = emptyProvenance(status, { limitations: [limitation] });
    }
  };

  if (options.disabled) {
    stampAll(PROVENANCE_STATUS.NOT_AVAILABLE, 'provenance disabled via --no-provenance');
    return;
  }
  if (!scanRoot || !isGitRepo(scanRoot)) {
    stampAll(PROVENANCE_STATUS.NOT_AVAILABLE, 'not a Git repository');
    return;
  }

  const repoState = getRepoState(scanRoot);
  if (!repoState) {
    // isGitRepo said yes and getRepoState said no — the repo moved out from
    // under us mid-scan. Every downstream module reads repoState, so there is
    // nothing to resolve against; say so rather than throwing on `.head`.
    stampAll(PROVENANCE_STATUS.NOT_AVAILABLE, 'repository state unavailable');
    return;
  }

  const deadlineAt = Date.now() + (options.timeoutMs || DEFAULT_TIMEOUT_MS);
  const fullCtx = { ...options, repoState, deadlineAt, scanRoot };

  let active = 0;
  let idx = 0;
  await new Promise((resolve) => {
    const next = () => {
      if (idx >= findings.length && active === 0) { resolve(); return; }
      while (active < MAX_CONCURRENCY && idx < findings.length) {
        const f = findings[idx++];
        if (!f || typeof f !== 'object') continue;
        active++;
        resolveOne(f, fullCtx)
          .then((prov) => {
            // A downstream module returning nothing must not leave a hole —
            // the terminal-status guarantee has no exceptions.
            f.findingProvenance = prov || emptyProvenance(PROVENANCE_STATUS.ERROR, {
              limitations: ['provenance resolution returned no result'],
            });
          })
          .catch((e) => {
            f.findingProvenance = emptyProvenance(PROVENANCE_STATUS.ERROR, { limitations: [String((e && e.message) || e)] });
          })
          .finally(() => { active--; next(); });
      }
      // Every finding was dispatched (or skipped as a non-object) and nothing
      // is in flight — the loop above cannot re-enter, so settle here.
      if (idx >= findings.length && active === 0) resolve();
    };
    next();
  });
}
