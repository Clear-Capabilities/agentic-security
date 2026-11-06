# Finding provenance: contract

The frozen shape and behaviour of the `findingProvenance` record a scan attaches to every finding: the record and its parts, the six terminal states, the confidence reasons, the eligibility definition behind the coverage figure, the identity rules, the default behaviour per command, the shared scan-level timeout and the absolute latency budget. The test `scanner/test/contracts/finding-provenance.contract.test.js` holds the implementation to every table and every rule on this page, in both directions: a field that disappears fails, and so does a field this page does not list.

This capability is Preview. Freezing the contract does not promote it: eligible coverage on this project is below the 95% target (the figure and the causes are in the [guide](../guides/finding-provenance.md)), and no independent real-code population has measured known-origin accuracy (GA-02). What a record does NOT establish is stated beside what it does.

## The record

Every finding a scan produces (SAST, secrets, direct and transitive dependencies, business-logic findings with a real source line) carries `findingProvenance`. There is no path that leaves it absent: a missing git binary, a malformed finding or a thrown resolver lands in one of the terminal states below.

**Record** (`schemaVersion` `1.0`)

| Field | Meaning |
|---|---|
| `schemaVersion` | The record version, `1.0`. |
| `status` | One of the six terminal states below. |
| `findingOrigin` | The introducing commit (the origin table), or `null` when none was resolved. |
| `branchIntroduction` | The branch or merge the origin entered the scanned branch through, or `null`. |
| `providerEnrichment` | Pull request and code owner metadata from a configured forge, or `null`. |
| `firstObserved` | When this scanner first saw the finding, or `null`. |
| `evidenceAttribution` | Evidence nodes (the evidence node table); empty when nothing was resolved. |
| `method` | How the origin was found: `semantic-history-replay`, `dependency-graph-diff`, `line-attribution`, `scan-history`, `missing-control-regression`, or `none`. |
| `confidence` | The confidence table. |
| `historyCoverage` | The history coverage table. |
| `analysisBasis` | The analysis basis table. |
| `limitations` | Sentences stating what this record could not establish and why. |
| `evidenceDigest` | A digest over the record's evidence, or `null`. |

**Origin** (`findingOrigin`)

| Field | Meaning |
|---|---|
| `commit` | The full SHA of the introducing commit. |
| `authorName` | The commit's recorded author name (pseudonymised on request, never inferred). |
| `authorEmail` | The author email; withheld (`null`) from every output unless asked for. |
| `authorDate` | The author date. |
| `committerDate` | The committer date. |
| `summary` | The commit subject. |
| `presentInCommit` | Always `true`: the predicate was replayed and held at this commit. |
| `absentInParents` | The parents in which the predicate was replayed and did not hold; empty for a root commit. |
| `revertOf` | In deep mode, the commit this origin reverts (decided by diff inversion, not by message alone), else `null`. |
| `cherryPickOf` | In deep mode, the commit a `cherry-pick -x` trailer names, else `null`. |
| `aiAuthorship` | `{status, verifier}`; `unknown` with no verifier registered, which is the shipped state. |

**Branch introduction** (`branchIntroduction`)

| Field | Meaning |
|---|---|
| `commit` | The commit through which the origin entered the scanned branch. |
| `ref` | The ref that commit was reached from. |
| `relationship` | `direct` (the origin is on the branch's own line) or `merge`. |

**First observed** (`firstObserved`)

| Field | Meaning |
|---|---|
| `scanId` | The scan that first recorded the finding, or `null`. |
| `observedAt` | When; a fixed epoch under `--deterministic`. |

**Evidence node** (each entry of `evidenceAttribution`)

| Field | Meaning |
|---|---|
| `role` | `source`, `sink`, `transformation`, `removed_guard`, `secret` or `manifest`. |
| `path` | The file. |
| `line` | The line, or `null` when the producer gave none. |
| `commit` | The commit the evidence is attributed to. |
| `depChain` | Dependency findings only: the chain from the declared dependency to the vulnerable one, re-derived from the lockfile at the origin commit. |

**Confidence** (`confidence`)

| Field | Meaning |
|---|---|
| `level` | `high`, `medium`, `low` or `unknown`. |
| `score` | A number in `[0, 1]` paired with the level. |
| `reasons` | Codes from the confidence reasons table, never empty for a resolved origin. |

**History coverage** (`historyCoverage`)

| Field | Meaning |
|---|---|
| `complete` | Whether the whole relevant history was visible. |
| `shallow` | Whether the repository is a shallow clone. |
| `boundaryCommit` | The `--provenance-since` or shallow boundary the walk stopped at, or `null`. |
| `commitsConsidered` | How many candidate commits were replayed. |
| `crossRepoLineage` | Whether the answer crossed into a declared linked repository. |

**Analysis basis** (`analysisBasis`)

| Field | Meaning |
|---|---|
| `head` | The repository head the scan ran at. |
| `ruleset` | The ruleset version the predicate came from. |
| `detector` | The producer of the finding. |
| `dirty` | Whether the working tree had uncommitted changes. |

**Provider enrichment** (`providerEnrichment`, when a forge provider is configured and answered)

| Field | Meaning |
|---|---|
| `provider` | `github` or `gitlab`. |
| `prNumber` | The pull or merge request number. |
| `reviewers` | Reviewer logins (pseudonymised on request). |
| `approvals` | An approval count, or `null` when the endpoint does not report one. |
| `mergedAt` | When it merged, or `null`. |
| `codeowners` | The code owner lines, or empty. |

## Terminal states

**Terminal states** (`status`)

| State | Meaning |
|---|---|
| `complete` | The introducing commit was found and its parent boundary was inspected: the predicate did not hold in a parent, or the file did not exist there. A root commit with no parent is `complete` with a `medium` cap, never `high`. |
| `partial` | Something is known but the boundary was not verified: a shallow clone, a parent whose replay failed, a rename not followed, a dependency advisory with no introduced bound, a predicate never confirmed in the visible history. |
| `uncommitted` | The vulnerable line exists only in the working tree or index. A dirty file whose vulnerable line is committed is NOT this: it resolves to its commit, and `analysisBasis.dirty` records the edit. |
| `not_available` | Provenance was not attempted: `--no-provenance`, a finding kind it does not cover, or a finding with no stable id. |
| `budget_exhausted` | The scan-level or per-finding budget ran out before this finding was resolved. Never cached. |
| `error` | Resolution was attempted and failed. |

Rules:

- **Terminal, always.** After annotation every finding carries one of the six states; a thrown resolver is `error`, not an absent field.
- **Never false certainty.** A shallow clone cannot reach `complete`. A parent that could not be inspected proves nothing about absence, so the result is `partial` with reason `parent-not-inspectable`. The oldest candidate wins: a flaw that is fixed and reintroduced resolves to its first introduction (the lifecycle ledger, not the origin, records the reintroduction).
- **Parent boundary.** `complete` requires a replayed parent (or a true root). The corpus `bench/provenance-accuracy` holds this over 23 labelled histories, including a revert of a fix, a cherry-pick with `-x`, a squash merge, an amended commit, a `git mv`, a dirty file, a merge whose first parent carries the flaw, a conflict resolution that introduces the flaw, a transitive lockfile bump and an unreachable forge provider.
- **Budget results are not cached.** `budget_exhausted` describes the run, not the repository; the next scan resolves the finding afresh.
- **Forge metadata that cannot be fetched is recorded.** A configured provider that errs or does not answer leaves `providerEnrichment` `null` and adds a limitation naming the provider and the reason; the origin, status and confidence are unchanged.

## Confidence reasons

**Confidence reasons** (`confidence.reasons`)

| Code | Meaning |
|---|---|
| `parent_absence_verified` | The predicate was replayed in a parent and did not hold. |
| `complete_history` | No shallow boundary and no `--provenance-since` boundary cut the walk. |
| `partial_history` | The walk was bounded. |
| `no_parent_to_test` | The origin is a root commit. |
| `shallow_history` | The repository is a shallow clone. |
| `rename_ambiguous` | Declared but unreachable in this resolver: a rename-shaped miss cannot reach a resolved origin. |
| `detector_incompatible` | The ruleset at the origin commit cannot be compared with the current one. |
| `no_defensible_origin` | No origin could be defended. |
| `cross_repo_lineage_best_effort` | The origin was found in a declared linked repository by content match. |
| `rename_detected_not_followed` | A candidate's content lived under another path and was not followed. |
| `parent_not_inspectable` | The parent's replay failed. |
| `shallow_or_unverified_boundary` | The boundary could not be verified. |
| `ambiguous_version_range` | Dependency findings: the advisory has no introduced bound, so no commit can be named as the one that entered the range. |
| `version_never_confirmed_in_manifest_history` | Dependency findings: no candidate commit's manifest or lockfile carried a version in the range. |
| `budget_exhausted` | The budget ran out before a confidence could be formed. |

A `high` level needs `parent_absence_verified` and `complete_history`. A root commit caps at `medium`. Every `partial` record is `low`.

## Eligibility and coverage

The coverage figure (`provenance coverage`, in the scorecard and the engineering-excellence report) is two rates over frozen categories: `overallRate` is attributed over every finding; `eligibleRate` is attributed over attributed plus eligible-but-unattributed. Shrinking eligibility cannot raise `overallRate`, and every ineligible finding is listed with its reason, so the two cannot be traded against each other.

**Eligibility categories** (`attributionCoverage().categories`)

| Category | Meaning |
|---|---|
| `attributed` | `complete`. |
| `uncommitted` | `uncommitted`; counted as attributed. |
| `ineligible:ignored` | Git ignores the file. |
| `ineligible:generated` | The path or header marks generated code. |
| `ineligible:untracked` | Git does not track the file. |
| `ineligible:history-unavailable` | Not a work tree, no commits, or a shallow clone cut the history. |
| `eligible:budget_exhausted` | The budget ran out. |
| `eligible:project-wide` | A whole-project analysis that replaying one file cannot reproduce. |
| `eligible:unconfirmed` | `partial` for any other reason. |
| `eligible:not_available` | No provenance recorded for an eligible finding. |
| `eligible:error` | Resolution failed. |

Rules:

- The target is `0.95` on `eligibleRate`; with fewer than `30` eligible findings the status is `insufficient_eligible`, never `met`.
- The categories are a frozen list: a new reason for not attributing a finding is a new category on this page, not a quiet move into `ineligible`.

## Identity

- Author email is withheld (`null`) from every output by default; `--include-author-email` (`AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL=1`) includes it. The MCP server never includes it regardless.
- `--pseudonymize-authors` (`AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS=1`) replaces `authorName`, reviewer logins and code owner handles with a stable `Contributor-xxxxxxxx` derived from the recorded identity: the same person gets the same pseudonym across runs, and nothing else about them is kept.
- Identity comes only from the commit's own recorded author. Usernames, local git configuration and commit-message mentions are never used.
- The provenance cache stores the unredacted record under `0600` so one cached record can serve every redaction policy; redaction happens at every output boundary.

## Default behaviour and the shared timeout

**Defaults and limits**

| Setting | Value |
|---|---|
| `scan` | Provenance off unless a provenance flag is given (`--provenance`, `--provenance-since`, `--provenance-timeout`, `--require-provenance`, `--include-author-email`, `--pseudonymize-authors`). |
| `ci` | Provenance on; `--assurance strict` fails the build on any status outside `complete` and `uncommitted`. |
| `AGENTIC_SECURITY_NO_PROVENANCE=1` | Every finding is `not_available`. |
| `AGENTIC_SECURITY_PROVENANCE_MODE` | `standard` (first-parent boundary) or `deep` (every parent, plus revert and cherry-pick annotation). |
| `AGENTIC_SECURITY_PROVENANCE_SINCE` | A ref the walk does not pass; recorded as `historyCoverage.boundaryCommit`. |
| `AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS` | The one budget for the whole scan's provenance work, default `60000`; `300000` under `--deterministic`. |
| per-finding share | `max(2000, remaining / findings)` milliseconds, so one deep history cannot starve the rest. |
| provider enrichments | At most `20` per scan, shared across every annotation call; each call has an `8000` millisecond timeout. |

## Performance budget

The overhead bench (`bench/provenance`, `npm run bench:provenance:check`) measures, over 60 iterations of a 15-finding, 45-commit fixture, the wall time provenance adds to the same iteration's provenance-disabled scan. The budget is absolute, frozen in the runner with its derivation, and checked beside the ratio gates; a re-baseline cannot loosen it.

**Latency budget** (p95 of added milliseconds)

| Arm | Budget |
|---|---|
| `cold` | `2000` ms with an empty provenance cache. |
| `warm` | `250` ms on a cache hit. |

The per-finding figure is what to carry to a larger project: the cold cost is about 77 ms per finding with findings on the maintainer host, from the git processes and the two historical replays each finding costs, and the ratio against a 44 ms base scan is not a useful number. The 1.3x ratio target of the earlier plan is withdrawn in favour of this budget; it was never met on a cold cache and could not be.

## Limits

<!-- limits-verified: 2026-11-05 -->

- The corpus is 23 synthetic histories written by this project; known-origin accuracy on independent real repositories is unmeasured.
- Eligible coverage on this project's own source is below the 95% target; whole-project analyses are the largest cause and need a project-scoped replay that does not exist.
- A cherry-pick without `-x` leaves no trailer and is reported as an ordinary commit. A revert is recognised by diff inversion against an earlier candidate, so a hand-written revert that differs by a line is not.
- Rename following uses git's own rename detection; a file rewritten so heavily that git does not pair it is not followed.
- Deep mode costs extra git processes per finding; the budget above is measured in standard mode.
- The provider endpoint is reached with a plain request and an 8 second timeout; a slow endpoint spends budget from the per-scan cap, never from the scan's own deadline.
- The record is repository history, not organisational evidence: it does not prove developer intent, control operation outside code, organisational compliance or certification.
