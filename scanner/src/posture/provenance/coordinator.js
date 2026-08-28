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
//
//  3. **`ctx.findingType === 'sca'` selects a whole different strategy, not a
//     flag on one.** A direct-dependency entry is a different SHAPE
//     (`filePath`/`name`/`ecosystem`, no `ruleId`) answering a different
//     QUESTION (which commit moved the declared version into the advisory's
//     vulnerable range) than a SAST finding. Four things change with it, and
//     each is commented at its site: the uncommitted blame short-circuit is
//     skipped, `stableId` is backfilled from `scaStableId`, `resolveOrigin` is
//     replaced by `resolveDirectSCAOrigin`, and `attributeEvidence` is replaced
//     by a single `manifest` node. Everything else — the budget check, the
//     cache, the terminal-status guarantee, the digest — is shared verbatim,
//     because those are properties of the coordinator, not of the finding type.

import * as crypto from 'node:crypto';
import { getRepoState, isGitRepo, blameLine } from './git-evidence.js';
import { resolveOrigin } from './origin-resolver.js';
import { resolveDirectSCAOrigin, scaStableId } from './sca-origin.js';
import { resolveTransitiveSCAOrigin } from './transitive-sca.js';
import { resolveBranchEntry } from './branch-entry.js';
import { attributeEvidence } from './evidence-attribution.js';
import { assessConfidence } from './confidence.js';
import { cacheGet, cacheSet, makeCacheKey } from './cache.js';
import { emptyProvenance, PROVENANCE_STATUS, PROVENANCE_METHOD, EVIDENCE_ROLE, CONFIDENCE_LEVEL } from './schema.js';

// Detector label recorded in `analysisBasis.detector` for SCA entries. A
// dependency finding has no `parser` (no file was parsed by a SAST detector),
// so the honest answer to "what produced this" is the manifest-diff walk.
const SCA_DETECTOR = 'sca-manifest-diff';
const TRANSITIVE_SCA_DETECTOR = 'sca-lockfile-history-diff';

// Exported so `engine.js` can establish ONE deadline across both of the calls
// it makes (SAST findings, then direct SCA deps) using the same default this
// module would have used. Without a shared deadline the scan-level budget was
// silently 2× the operator's --provenance-timeout.
export const PROVENANCE_DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_TIMEOUT_MS = PROVENANCE_DEFAULT_TIMEOUT_MS;
const MAX_CONCURRENCY = 4;

// Per-finding floor from the spec's sub-budget formula
// (`max(2s, global/estimatedFindingCount)`). The floor matters more than the
// quotient: a 200-finding scan under a 60s global budget divides to 300ms,
// which is less than a single `git blame`'s own 2s timeout and would starve
// every finding equally instead of a few. 2s is one blame's worth of work.
const MIN_PER_FINDING_BUDGET_MS = 2000;

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

// The two `partial` producers answer two different questions, so they must not
// share one sentence. origin-resolver's partial means "we could not see far
// enough back to verify the parent boundary of a code change"; sca-origin's
// means "the manifest history never let us pin which commit made this
// dependency vulnerable" — most often because the advisory carries a `fixed`
// bound and no `introduced` bound, which makes a still-vulnerable patch bump
// literally indistinguishable from a bump INTO the vulnerable window. Reusing
// the SAST wording for the SCA case would describe a boundary nobody was
// looking for, and reusing `shallow_or_unverified_boundary` as the confidence
// reason would blame the clone depth for an ambiguity in the advisory data.
function describePartial(isSca, reason) {
  if (!isSca) {
    return {
      limitation: reason
        ? `earliest observable — history could not confirm a verified parent boundary (${reason})`
        : 'earliest observable — history could not confirm a verified parent boundary',
      reasons: ['shallow_or_unverified_boundary'],
    };
  }
  const base = 'manifest history could not confirm which commit introduced the vulnerable version';
  return {
    limitation: reason ? `${base} (${reason})` : base,
    reasons: [reason === 'ambiguous-range-no-introduced-bound'
      ? 'ambiguous_version_range'
      : 'version_never_confirmed_in_manifest_history'],
  };
}

async function resolveOne(finding, ctx) {
  const { scanRoot, repoState, deadlineAt } = ctx;
  // Direct-dependency (SCA) entries are a different shape AND a different
  // question from a SAST finding: they carry `filePath`/`name`/`ecosystem`
  // rather than `file`/`line`/`ruleId`, and their origin is a version
  // transition in a committed manifest blob rather than a line of code.
  const isSca = ctx.findingType === 'sca';
  const isTransitiveSca = ctx.findingType === 'sca-transitive';
  // Both direct and transitive SCA entries share the same non-SAST shape —
  // no file+line to blame, stableId backfilled the same way. Only WHICH
  // resolver runs (Task 6 vs sca-origin.js) and what evidence/detector
  // label gets attached differ between them.
  const isScaLike = isSca || isTransitiveSca;

  // THE BUDGET CHECK COMES FIRST — before the blame call, not after it.
  //
  // `blameLine` is a synchronous execFileSync with a 2s timeout, and the
  // scheduler runs these four at a time. Checking the deadline below the blame
  // call meant every finding still queued when the budget expired paid for its
  // blame before being told the budget was gone: N post-deadline findings could
  // serialise into ~2N seconds PAST the configured timeout, which is precisely
  // what this check exists to prevent. A deadline that is only consulted after
  // the expensive call does not bound anything.
  //
  // A post-deadline finding therefore reports `budget_exhausted` rather than
  // `uncommitted`. Both are terminal and honest; the budget is simply the
  // question we can answer without spending anything.
  if (deadlineAt && Date.now() > deadlineAt) {
    return emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: 0 },
      limitations: ['analysis budget expired before this finding was reached'],
    });
  }

  // Cheap, correct short-circuit (PRD Scenario G). One blame call, before any
  // history walk: a working-tree-only line has no origin commit to find.
  //
  // Deliberately SAST-only. For a dependency the blame-able line is the
  // manifest line that declares it, and "is that line uncommitted" is not the
  // same question as "is this dependency uncommitted": reformatting or
  // re-sorting package.json dirties every declaration line without changing a
  // single declared version, which would turn every dependency in the project
  // into a false `uncommitted`. resolveDirectSCAOrigin reads committed blobs
  // and answers the real question directly, reporting `partial` when it cannot.
  if (!isScaLike && finding.file && finding.line) {
    const blame = blameLine(scanRoot, finding.file, finding.line);
    if (blame && blame.uncommitted) {
      return emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED, {
        limitations: ['finding exists only in working tree/index'],
      });
    }
  }

  // SCA entries reach this coordinator straight off the dependency parsers,
  // which never run through `stable-id.js` (it keys on file+line+ruleId, none
  // of which a dependency finding has). Backfill the SCA-shaped id here so the
  // cache key — and every consumer downstream of it — has something stable to
  // hold. An id the caller already set always wins.
  if (isScaLike && !finding.stableId) {
    finding.stableId = scaStableId(finding);
  }

  if (!finding.stableId) {
    return emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['finding has no stableId'] });
  }

  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });

  // IN-SCAN MEMOIZATION (M2 §2.4 performance fix): the disk cache alone
  // still pays a fresh cacheGet() read (and, on a miss, a fresh resolution
  // walk) for every finding sharing this cacheKey WITHIN one scan. Two
  // findings with the same stableId and history boundary are uncommon but
  // real (duplicate array entries, the same finding reappearing across a
  // dedupe boundary) — memoizing the PROMISE (not just the eventual value)
  // means a second caller that arrives while the first is still resolving
  // awaits the same in-flight work instead of starting its own.
  if (ctx.memo && ctx.memo.has(cacheKey)) return ctx.memo.get(cacheKey);

  const promise = resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca);
  if (ctx.memo) ctx.memo.set(cacheKey, promise);
  return promise;
}

async function resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca) {
  const { scanRoot, repoState, deadlineAt } = ctx;
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;
  // resolveOne computes isScaLike in its own scope; resolveAndCache does not
  // share it, so it is recomputed here from the two flags passed through.
  const isScaLike = isSca || isTransitiveSca;

  // PER-FINDING SUB-BUDGET (spec: `max(2s, global/estimatedFindingCount)`).
  //
  // The global deadline alone bounds the PASS but not the DISTRIBUTION inside
  // it: one finding whose candidate-commit list is long — a hot file touched by
  // a thousand commits — can walk it until the global deadline expires, and
  // every finding queued behind it then reports `budget_exhausted` without a
  // single git call spent on it. The sub-budget caps what any one finding may
  // consume, so the walk is truncated for the expensive finding instead of for
  // everyone after it. It never EXTENDS anything: the effective deadline is the
  // earlier of the two, so the global deadline still hard-bounds the pass.
  const perFindingDeadlineAt = ctx.perFindingBudgetMs
    ? Math.min(deadlineAt || Infinity, Date.now() + ctx.perFindingBudgetMs)
    : deadlineAt;

  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    : isTransitiveSca
    ? await resolveTransitiveSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
    // M3 §3.1: `ctx.mode` was already threaded into the CACHE KEY
    // (makeCacheKey's `mode` field, present since M0+M1) but never actually
    // reached resolveOrigin itself — `--provenance deep` was accepted and
    // cached distinctly from `standard`, but both modes ran identical code.
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt, repoState, mode: ctx.mode });

  const detector = isSca ? SCA_DETECTOR : isTransitiveSca ? TRANSITIVE_SCA_DETECTOR : (finding.parser || null);

  let provenance;
  let cacheable = true;
  if (originResult.status === 'complete') {
    const branchIntroduction = resolveBranchEntry(scanRoot, originResult.findingOrigin.commit, repoState.branch || 'HEAD');
    // attributeEvidence walks `source`/`sink`/`pathSteps` — a taint-flow shape
    // an SCA entry simply does not have, so calling it here would return an
    // empty list at best and mis-attribute `finding.file`/`finding.line` at
    // worst. A dependency's evidence is one node: the manifest that declares it,
    // as of the commit that introduced the vulnerable version. `line` comes from
    // the dependency parsers (Task 12 added it to package.json/requirements.txt
    // components) and stays `null` rather than 0 when a parser did not supply
    // one — 0 would read as a real line number.
    const evidenceAttribution = isScaLike
      ? [{
          role: EVIDENCE_ROLE.MANIFEST,
          path: finding.filePath || null,
          line: Number.isInteger(finding.line) ? finding.line : null,
          commit: originResult.findingOrigin.commit,
          depChain: isTransitiveSca && Array.isArray(originResult.depChain) ? originResult.depChain : null,
        }]
      : attributeEvidence(scanRoot, finding);
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
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
    });
  } else if (originResult.status === 'partial') {
    // isScaLike, not isSca: transitive-sca.js reuses sca-origin.js's exact
    // reason strings ('ambiguous-range-no-introduced-bound' /
    // 'version-never-confirmed-in-candidates'), so a transitive partial must
    // get the same "manifest history" wording a direct one does — the bare
    // isSca check here would silently route it to the SAST branch instead
    // ("verified parent boundary"), which describes a question the lockfile
    // walk never asked.
    const partial = describePartial(isScaLike, originResult.reason);
    provenance = emptyProvenance(PROVENANCE_STATUS.PARTIAL, {
      findingOrigin: originResult.findingOrigin || null,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      // `method` must be carried through. origin-resolver's shallow-boundary
      // case returns status:'partial' WITH a populated findingOrigin AND
      // method:'semantic-history-replay'. Letting emptyProvenance's 'none'
      // default stand emitted a self-contradictory record — "here is the origin
      // commit, found by no method" — which also fed computeDigest.
      method: originResult.method || PROVENANCE_METHOD.NONE,
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
      // The partial reasons mean materially different things — for SAST,
      // 'shallow-boundary-reached' ("we could not see far enough") vs
      // 'predicate-never-confirmed-in-candidates' ("we looked and never saw it
      // hold"); for SCA, 'ambiguous-range-no-introduced-bound' vs
      // 'version-never-confirmed-in-candidates'. Collapsing any of them into one
      // hardcoded string made them indistinguishable downstream, while the
      // not_available branch below has always propagated its reason. See
      // describePartial for why the SAST and SCA wordings are not shared.
      limitations: [partial.limitation],
      confidence: { level: CONFIDENCE_LEVEL.LOW, score: 0.2, reasons: partial.reasons },
    });
  } else if (originResult.status === 'budget_exhausted') {
    // Which budget ran out is a materially different fact for the operator:
    // the global one means "raise --provenance-timeout"; the per-finding one
    // means "this ONE finding's history is unusually deep" and raising the
    // global timeout will not help it unless the finding count drops too.
    const globalExpired = !!deadlineAt && Date.now() > deadlineAt;
    provenance = emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      limitations: [globalExpired
        ? 'analysis budget expired before origin could be resolved'
        : "this finding's per-finding share of the analysis budget expired before origin could be resolved"],
    });
    // NOT CACHED — see the cacheSet guard below.
    cacheable = false;
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  // A budget_exhausted result is the ONE outcome that is not a property of the
  // repository. complete/partial/not_available are all deterministic given
  // (HEAD, stableId, ruleset, boundary, mode) — the cache key — so caching them
  // is sound. "We ran out of time" is a property of the RUN: it depends on the
  // machine, the load, and the operator's --timeout. The key has no time
  // component and the cache has no TTL (both deliberate), so caching it would
  // pin the timeout in place until HEAD moved — including across a re-run with
  // a larger --timeout, silently defeating the operator's only remedy.
  if (cacheable) cacheSet(scanRoot, cacheKey, provenance);
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

  // A caller-supplied `deadlineAt` WINS over the locally-computed one. That is
  // what makes a scan-level global budget possible at all: engine.js runs this
  // annotator twice (SAST findings, then direct SCA deps) and each call
  // computing its own fresh window made the effective budget 2× the configured
  // timeout. Falling back to a computed one keeps every standalone caller (and
  // every test) working unchanged.
  const deadlineAt = options.deadlineAt || (Date.now() + (options.timeoutMs || DEFAULT_TIMEOUT_MS));
  // Sub-budget, from the REMAINING global budget rather than the configured
  // timeout: on the second of engine.js's two calls, most of the window may
  // already be spent, and dividing the original figure would hand each SCA
  // entry a share of time that no longer exists.
  // A caller-supplied value wins, on the same principle as `deadlineAt` above:
  // the caller is the only party that can see across multiple annotator passes.
  const remainingMs = Math.max(0, deadlineAt - Date.now());
  const perFindingBudgetMs = options.perFindingBudgetMs || Math.max(
    MIN_PER_FINDING_BUDGET_MS,
    Math.floor(remainingMs / Math.max(1, findings.length)),
  );
  // M2 §2.4: one memo per annotateGitProvenance call, not a module-level
  // cache — scoped to THIS scan's findings so a memo entry never survives
  // past the run that created it (the disk cache, keyed on repoHead already,
  // is what persists ACROSS scans).
  const memo = new Map();
  const fullCtx = { ...options, repoState, deadlineAt, perFindingBudgetMs, scanRoot, memo };

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
