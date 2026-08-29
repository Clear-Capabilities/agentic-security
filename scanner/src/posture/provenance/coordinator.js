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
import { getRepoState, isGitRepo, blameLine, getBlobAtCommit, getRemoteUrl } from './git-evidence.js';
import { resolveOrigin } from './origin-resolver.js';
import { resolveDirectSCAOrigin, scaStableId } from './sca-origin.js';
import { resolveTransitiveSCAOrigin } from './transitive-sca.js';
import { resolveMissingControl } from './missing-control-resolver.js';
import { resolveBranchEntry } from './branch-entry.js';
import { attributeEvidence } from './evidence-attribution.js';
import { assessConfidence } from './confidence.js';
import { cacheGet, cacheSet, makeCacheKey } from './cache.js';
import { loadRepoLineage } from './repo-lineage.js';
import { emptyProvenance, PROVENANCE_STATUS, PROVENANCE_METHOD, EVIDENCE_ROLE, CONFIDENCE_LEVEL } from './schema.js';
// FR-PROV-022: `resolveProviderConfig` is genuinely shared (both
// providers/github.js and providers/gitlab.js re-export the SAME function
// from config.js — importing it directly here avoids picking one module's
// re-export arbitrarily). `fetchPRMetadata`/`fetchCodeowners`, by contrast,
// are two DIFFERENT functions that happen to share a name across two
// DIFFERENT modules — aliased on import so both are reachable without a
// naming collision.
import { resolveProviderConfig } from './providers/config.js';
import { fetchPRMetadata as fetchPRMetadataGithub, fetchCodeowners as fetchCodeownersGithub } from './providers/github.js';
import { fetchPRMetadata as fetchPRMetadataGitlab, fetchCodeowners as fetchCodeownersGitlab } from './providers/gitlab.js';
// FR-PROV-017: the missing-control-candidate branch reuses rate-limit.js's
// OWN presence predicate rather than re-deriving one, so a historical blob is
// judged by the exact same regexes the live detector uses on HEAD. Imported
// statically (not via a dynamic import() inside the predicate) per this
// module's own convention for git-evidence.js's functions above — only
// `getBlobAtCommit` needed care about import placement, and it is already
// imported statically alongside the rest of git-evidence.js's exports.
import { hasRateLimit } from '../../sast/rate-limit.js';

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

// FR-PROV-022: an 8s-timeout-capped network call per finding is not
// automatically bounded by the scan's own deadlineAt -- N findings x up to
// 8s each could dwarf any reasonable scan budget. Capping the COUNT, not the
// per-call timeout, keeps the existing AbortSignal.timeout(8000) in
// providers/github.js and providers/gitlab.js untouched while bounding the
// aggregate. Per this codebase's "no silent caps" convention, this cap is
// disclosed in findingProvenance.limitations for every finding that would
// have qualified for enrichment but didn't get it because the cap was
// already spent.
//
// This is a per-SCAN cap, not a per-CALL one -- engine.js invokes
// `annotateGitProvenance` FIVE times per scan (SAST findings, direct SCA,
// transitive SCA, secrets, blameable logicVulns), sharing one
// `provenanceCtx`. The intent was always a single scan-wide budget of 20
// (fix-round item 2): see the `providerEnrichments` counter below, threaded
// through `ctx` the same way `deadlineAt` already is, so all five calls draw
// from ONE real budget instead of each getting a fresh 20 (a silent 5x
// looser cap than this constant and its disclosure string claimed).
export const MAX_PROVIDER_ENRICHMENTS_PER_SCAN = 20;

// PRD Data Contract, "Evidence integrity": the digest must bind the stable
// finding ID, repository identity, analysis HEAD, origin commit,
// branch-introduction commit, evidence-node locations and blob IDs,
// detector/ruleset version, history boundary, method, confidence reasons,
// and limitations. This binds ten of those eleven.
//
// `repoIdentity` is deliberately just `scanRoot` (the absolute path) for now,
// not a remote-URL-derived identity — no helper computes one yet. A future
// `getRemoteUrl`-style signal is a stronger repository-identity value once it
// exists; `scanRoot` is today's honest best effort, and swapping it in later
// is itself a value-breaking digest change like this one.
//
// Evidence-node BLOB IDs (the PRD's eleventh input) are deliberately NOT
// bound here. No primitive anywhere upstream computes a `git hash-object`
// -style content hash per evidence node today — `getBlobAtCommit` returns raw
// text, never an OID — and adding one would mean a new git-evidence.js
// primitive plus touching every evidence-node construction site
// (origin-resolver.js, sca-origin.js, transitive-sca.js,
// evidence-attribution.js). That is real, separate follow-up work, not an
// oversight: path:line:commit locations are bound below and already make two
// evidence sets with different content at the same location produce
// different digests only insofar as `commit` differs.
function computeDigest(finding, provenance, repoIdentity) {
  const material = JSON.stringify({
    stableId: finding.stableId,
    repoIdentity: repoIdentity || null,
    analysisHead: provenance.analysisBasis?.head || null,
    origin: provenance.findingOrigin?.commit || null,
    branchEntry: provenance.branchIntroduction?.commit || null,
    evidence: (provenance.evidenceAttribution || []).map((n) => `${n.role}:${n.path}:${n.line}:${n.commit}`),
    detectorVersion: provenance.analysisBasis?.detector || null,
    rulesetVersion: provenance.analysisBasis?.ruleset || null,
    historyBoundary: provenance.historyCoverage?.boundaryCommit || null,
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
function describePartial(isScaLike, reason) {
  if (!isScaLike) {
    // M4 §4.2: a cross-repo lineage result is a materially different kind of
    // "partial" from the shallow/unverified-boundary case above — the origin
    // was found, just in a DIFFERENT repository the operator declared a link
    // to, verified only by content presence rather than this repo's own
    // predicate-replay machinery. Reusing the generic "could not confirm a
    // verified parent boundary" wording here would bury that fact behind the
    // machine-readable `crossRepoLineage` flag, leaving an operator reading
    // only the limitations text with no way to know the answer crossed a
    // repository boundary at all.
    if (reason === 'cross-repo-lineage-best-effort') {
      return {
        limitation: 'origin resolved via a DIFFERENT, operator-linked repository (.agentic-security/repo-lineage.json) — a cross-repo content-presence match, not this repository\'s own verified history',
        reasons: ['cross_repo_lineage_best_effort'],
      };
    }
    // Second independent Finding Provenance PRD audit: a rename-shaped miss
    // (origin-resolver.js's `renameShapedMiss` — a git-selected candidate's
    // content lived at a path other than the finding's current one) is a
    // materially different fact from the generic "we looked and it was never
    // true" case the fallback wording below describes. This resolver still
    // does NOT follow the rename to the true origin commit — that is the
    // separately-scoped, honestly-disclosed engine gap
    // (`bench/provenance-accuracy/fixtures/rename.mjs`'s header) — so this is
    // still a `partial`/LOW-confidence result, just with an accurate reason
    // for WHY it stayed partial instead of the misattributing generic string.
    if (reason === 'rename-detected-not-followed') {
      return {
        limitation: 'a candidate commit was found for this line but its content could not be located at the finding\'s current file path — consistent with the file having been renamed after that commit; this resolver does not re-check candidates under a prior name, so the true origin could not be confirmed',
        reasons: ['rename_detected_not_followed'],
      };
    }
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

// FR-PROV-017: adapts resolveMissingControl's own status vocabulary
// (complete / unknown / budget_exhausted) onto the originResult shape the
// rest of resolveAndCache already branches on (status:'complete' / 'partial'
// / 'budget_exhausted' / anything else -> not_available), instead of adding a
// parallel branching structure below. `unknown` deliberately falls through to
// the shared `else` (not_available) branch — see missing-control-resolver.js's
// own header on why "control never present" and "genuine regression" must
// never be conflated, and Step 5's own mapping in this task's brief.
async function resolveMissingControlOrigin(scanRoot, finding, { since, deadlineAt } = {}) {
  const result = await resolveMissingControl(scanRoot, {
    file: finding.file,
    predicate: async (root, sha, f) => {
      const blob = getBlobAtCommit(root, sha, f);
      return blob != null && hasRateLimit(blob);
    },
    since,
    deadlineAt,
  });

  if (result.status === 'complete') {
    const removedAt = result.removedAt;
    return {
      status: 'complete',
      method: PROVENANCE_METHOD.MISSING_CONTROL_REGRESSION,
      commitsConsidered: result.commitsConsidered,
      // Standard findingOrigin shape, populated from removedAt's four fields
      // (commit/authorName/authorDate/summary) per the brief — everything
      // else the shape carries elsewhere (authorEmail, committerDate,
      // revert/cherry-pick detection, AI-authorship) has no analogue in what
      // resolveMissingControl itself observes, so it stays at its honest
      // default rather than being fabricated.
      findingOrigin: {
        commit: removedAt.commit,
        authorName: removedAt.authorName,
        authorEmail: null,
        authorDate: removedAt.authorDate,
        committerDate: null,
        summary: removedAt.summary,
        presentInCommit: false,
        absentInParents: [],
        revertOf: null,
        cherryPickOf: null,
        aiAuthorship: { status: 'unknown', verifier: null },
      },
    };
  }
  if (result.status === 'budget_exhausted') {
    return { status: 'budget_exhausted', commitsConsidered: result.commitsConsidered };
  }
  // 'unknown': the control was never observed present in reachable history.
  // This is the ORDINARY case for a rate-limit finding on genuinely new
  // code, not a regression — never attributed to the root commit as if a
  // disappearance had been proven.
  return {
    status: 'unknown',
    reason: 'no prior version of this control was observed in reachable history — this may be new code rather than a regression',
    commitsConsidered: result.commitsConsidered,
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
  // FR-PROV-017: an explicit boolean marker set at finding-construction time
  // (rate-limit.js), not a string-match on finding.id/finding.vuln here —
  // string-matching would couple this module's branching to another
  // module's id/vuln string format, which is exactly the fragility the
  // isDirect/isTransitiveSca-style markers already avoid elsewhere in this
  // pipeline.
  const isMissingControlCandidate = !isScaLike && !!finding.missingControlCandidate;

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
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: 0, crossRepoLineage: false },
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
    lineageKey: ctx.lineageKey,
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

  const promise = resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca, isMissingControlCandidate);
  if (ctx.memo) ctx.memo.set(cacheKey, promise);
  return promise;
}

async function resolveAndCache(finding, ctx, cacheKey, isSca, isTransitiveSca, isMissingControlCandidate = false) {
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
    // FR-PROV-017: "control absent" findings (rate-limit.js today) answer a
    // fundamentally different question from every other SAST finding — "when
    // did a previously-present safeguard disappear," not "when did this bad
    // pattern first appear" — so they route to resolveMissingControl instead
    // of resolveOrigin, same precedent as the isSca/isTransitiveSca branches
    // above routing to their own question-specific resolvers.
    : isMissingControlCandidate
    ? await resolveMissingControlOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: perFindingDeadlineAt })
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
    // Second independent Finding Provenance PRD audit: this call site used to
    // pass `renameAmbiguous: false` as a hardcoded literal — never computed
    // from any signal, so `confidence.js`'s `rename_ambiguous` reason was
    // permanently dead code. Investigated rather than just deleted: this
    // branch only runs when `originResult.status === 'complete'`, and under
    // this resolver's current architecture a genuine rename-ambiguous case
    // can never reach `complete` in the first place — `replayAt` looks up
    // every candidate's blob at the finding's CURRENT path only, so a
    // candidate whose content actually lived at a DIFFERENT (pre-rename)
    // path always fails with `no-files-at-commit` and the walk falls through
    // to `status:'partial'` (see origin-resolver.js's `renameShapedMiss` /
    // reason `rename-detected-not-followed`), never `complete`. So there is
    // no cheap real signal to wire here without doing the separately-scoped
    // rename-follow work (`bench/provenance-accuracy/fixtures/rename.mjs`'s
    // header) — the parameter is simply omitted rather than passing a
    // literal that looked computed but never was; `assessConfidence`'s own
    // default (`renameAmbiguous = false`) still applies, which is accurate
    // here precisely because this path is unreachable with it true.
    const confidence = assessConfidence({
      parentBoundaryVerified: originResult.parentBoundaryVerified,
      historyComplete: !repoState.shallow,
      detectorCompatible: true,
      shallow: repoState.shallow,
    });
    provenance = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: originResult.findingOrigin,
      branchIntroduction,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      evidenceAttribution,
      method: originResult.method,
      confidence,
      historyCoverage: { complete: !repoState.shallow, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered, crossRepoLineage: false },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
      // FR-PROV-017: a missing-control-regression `findingOrigin` names the
      // commit that REMOVED the safeguard, not the commit that introduced the
      // finding's line — every other `complete` result in this file means the
      // opposite. Said explicitly so a reader of `findingOrigin` alone (which
      // looks identical in shape to an ordinary origin) isn't misled by the
      // field name.
      limitations: isMissingControlCandidate
        ? ['this is a control-removal event (the safeguard was present in an earlier commit and absent as of this one) — not an ordinary code-introduction event; findingOrigin names the commit that REMOVED the control']
        : [],
    });

    // FR-PROV-022: provider (GitHub/GitLab) enrichment — strictly additive,
    // never affects `status`/`method`/`confidence` above. Guarded on all
    // three: a provider must actually be configured, the per-scan cap must
    // not be spent, and the global deadline must not have already passed
    // (the per-call 8s AbortSignal.timeout in providers/*.js is real but
    // isn't itself deadline-aware, hence the cap — see its declaration).
    if (ctx.providerConfig && ctx.providerEnrichments && ctx.providerEnrichments.remaining > 0 && !(deadlineAt && Date.now() > deadlineAt)) {
      ctx.providerEnrichments.remaining--;
      const fetchPRFn = ctx.providerName === 'github' ? fetchPRMetadataGithub : fetchPRMetadataGitlab;
      const fetchCodeownersFn = ctx.providerName === 'github' ? fetchCodeownersGithub : fetchCodeownersGitlab;
      const pr = await fetchPRFn(scanRoot, originResult.findingOrigin.commit, ctx.remoteUrl, ctx.providerConfig);
      if (pr) {
        const codeowners = await fetchCodeownersFn(scanRoot, ctx.remoteUrl, ctx.providerConfig);
        provenance.providerEnrichment = {
          provider: ctx.providerName,
          prNumber: pr.prNumber,
          reviewers: pr.reviewers,
          approvals: pr.approvals,
          mergedAt: pr.mergedAt,
          codeowners: codeowners || [],
        };
      }
    } else if (ctx.providerConfig && ctx.providerEnrichments && ctx.providerEnrichments.remaining === 0) {
      provenance.limitations.push(`provider enrichment cap (${MAX_PROVIDER_ENRICHMENTS_PER_SCAN}/scan, shared across the whole scan's annotateGitProvenance calls) reached; not attempted for this finding`);
    }
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
      historyCoverage: {
        complete: false, shallow: repoState.shallow, boundaryCommit: null,
        commitsConsidered: originResult.commitsConsidered || 0,
        // M4 §4.2: origin-resolver's cross-repo lineage continuation is the
        // only producer of this flag — every other 'partial' path (shallow
        // boundary, predicate-never-confirmed, SCA's ambiguous-range /
        // never-confirmed) leaves it at the schema default (false).
        crossRepoLineage: !!originResult.crossRepoLineage,
      },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector, dirty: repoState.dirty },
      // The partial reasons mean materially different things — for SAST,
      // 'shallow-boundary-reached' ("we could not see far enough") vs
      // 'predicate-never-confirmed-in-candidates' ("we looked at the right
      // path and it was never true there") vs 'rename-detected-not-followed'
      // ("we found a candidate but its content lived at a different path");
      // for SCA, 'ambiguous-range-no-introduced-bound' vs
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
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0, crossRepoLineage: false },
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

  provenance.evidenceDigest = computeDigest(finding, provenance, scanRoot);
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
  // annotator five times (SAST findings, direct SCA deps, transitive SCA deps
  // per Task 7, then secrets and blameable logicVulns per Task 11) and each
  // call computing its own fresh window made the effective budget a multiple
  // of the configured timeout. Falling back to a computed one keeps every
  // standalone caller (and every test) working unchanged.
  const deadlineAt = options.deadlineAt || (Date.now() + (options.timeoutMs || DEFAULT_TIMEOUT_MS));
  // Sub-budget, from the REMAINING global budget rather than the configured
  // timeout: on a LATER one of engine.js's five calls, most of the window may
  // already be spent, and dividing the original figure would hand each entry
  // a share of time that no longer exists.
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
  // Resolved ONCE per scan, not per finding: `loadRepoLineage` is a fast
  // local file read plus two git calls against the (small, local) lineage
  // config — cheap to redo per finding (`origin-resolver.js`'s
  // `tryCrossRepoLineage` already does, scoped to its own concern), but
  // there is no reason to pay it again here when every finding in this scan
  // shares the same answer. Feeds the cache key (see cache.js's
  // `makeCacheKey` doc) so adding, removing, or repointing the declared link
  // at the same HEAD invalidates stale cached results instead of serving
  // them past the change.
  const lineage = loadRepoLineage(scanRoot);
  const lineageKey = lineage ? `${lineage.path}@${lineage.atCommit}` : 'none';

  // FR-PROV-022: resolved ONCE per scan, same precedent as `lineageKey`
  // above. `resolveProviderConfig` is a config-file/env-var read, not a
  // network call, so this stays cheap even when nothing is configured — but
  // `getRemoteUrl` (a git subprocess) is only ever invoked when a provider
  // actually is, which is what makes "zero network calls when unconfigured"
  // structural rather than merely tested. At most one provider is active at
  // a time; if both a GitHub and a GitLab config are somehow present (e.g. a
  // fork mirrored across both), GitHub wins — an arbitrary but documented
  // tie-break, since a finding's origin commit can only ever live on one of
  // the two remotes' PR/MR history in practice.
  const githubConfig = resolveProviderConfig(scanRoot, 'github');
  const gitlabConfig = resolveProviderConfig(scanRoot, 'gitlab');
  const providerConfig = githubConfig || gitlabConfig;
  const providerName = githubConfig ? 'github' : gitlabConfig ? 'gitlab' : null;
  const remoteUrl = providerConfig ? getRemoteUrl(scanRoot) : null;

  // Fix-round item 2: a caller-supplied counter WINS, same precedent as
  // `deadlineAt` above -- this is what makes the cap a real per-SCAN budget
  // across engine.js's five `annotateGitProvenance` calls rather than five
  // independent fresh-20 budgets. It MUST be a mutable object, not a bare
  // number: engine.js reuses one `provenanceCtx` but spreads it into a NEW
  // object literal for four of its five calls
  // (`{ ...provenanceCtx, findingType: 'sca' }`) -- a bare number would be
  // copied by value into each spread, so a decrement in one call would be
  // invisible to the next. A nested object's IDENTITY survives a shallow
  // spread, so every call decrements the SAME counter. A standalone caller
  // that never supplies one (every direct test, every non-engine.js caller)
  // gets a fresh `{ remaining: 20 }`, unchanged from before this fix.
  const providerEnrichments = (options.providerEnrichments && typeof options.providerEnrichments.remaining === 'number')
    ? options.providerEnrichments
    : { remaining: MAX_PROVIDER_ENRICHMENTS_PER_SCAN };

  const fullCtx = {
    ...options, repoState, deadlineAt, perFindingBudgetMs, scanRoot, memo, lineageKey,
    providerConfig, providerName, remoteUrl,
    providerEnrichments,
  };

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
