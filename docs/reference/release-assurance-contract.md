# Release assurance: package and verdict contract

<!-- seo: title="Release assurance contract: the signed package, the verdict and the offline verifier" description="The frozen fields of a signed release package, the three verdicts and their reason codes, the verifier's rejection codes and the commands that build and check a package." -->

**Maturity:** Preview

A release package is one signed file holding the evidence for one build. This page freezes its shape, the verdict computed from it, and the commands that build and check it. A compatibility test (`scanner/test/contracts/release-assurance.contract.test.js`) builds a package from a real scan and holds it to the tables below in both directions, so a field cannot be added or removed without changing this page and the package's `schemaVersion` in the same commit. The meaning and an end-to-end example are in the [release assurance guide](../guides/release-assurance.md).

## Commands

```bash
agentic-security release-package build [path] --private-key <pem> [--output <file>] [--fix-records <file>] [--public-key-out <file>]
agentic-security release-package verify <package.json> --public-key <pem> [--require kind,kind]
node scripts/verify-release-package.mjs <package.json> --public-key <pem> [--require kind,kind]
agentic-security release-view <package.json> [--view developer|ciso|auditor|all] [--format text|json|html] [--previous <older.json>] [--public-key <pem>]
```

`build` reads the last scan, refuses one whose signature is missing or does not verify, and records the scan's health and one record per finding (and, with `--fix-records`, one verification record per fix claimed). The proof tier of a finding is what the scan recorded; with none recorded it is `taint-proven` when the taint engine found the path and `unproven` otherwise. An executed counterexample is never inferred. The verdict is computed from the package's own contents and recorded as the `release-verdict` policy decision.

`scripts/verify-release-package.mjs` is the independent verifier. It imports only Node built-ins and the verifier module, nothing from the code that builds a package, so a defect in the producer cannot make it agree with the producer.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Built, or verified: every check passed and the stated verdict matches the recomputed one |
| `1` | The scan state failed its integrity check, or a package was rejected (every failure is listed) |
| `2` | A usage problem or an unreadable input |

## The package

`agentic-security/release-package`, `schemaVersion` `1.0.0`.

**Package**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/release-package` |
| `schemaVersion` | `1.0.0` |
| `snapshot` | The build the evidence is about (below) |
| `evidence` | Every record, in dependency order (below) |
| `lineageOrder` | The record digests in that order |
| `requiredKinds` | Kinds the package declares it must contain. `scan-health` and `finding` are always included |
| `findings` | One summary per finding (below) |
| `completeness` | Whether the scan finished (below) |
| `policy` | `decisions`: decisions already taken, recorded as given and never evaluated by the package |
| `assertions` | Statements with the evidence that supports each and a status of `supported`, `unsupported` or `unknown` |
| `proves` | What a valid signature establishes |
| `doesNotProve` | What it does not |
| `issuance` | Who signed and on what basis (below) |
| `signature` | The Ed25519 signature (below) |

**Snapshot**

| Field | Meaning |
|---|---|
| `schema` | The snapshot schema |
| `commit` | The commit, or `null` |
| `treeDigest` | A digest of the tree, or `null` |
| `dirty` | Whether the working tree had uncommitted changes |
| `engineVersion` | The scanner version that produced the scan |
| `bundleSha` | The scanner bundle's digest, or `null` |
| `configDigest` | A digest of the configuration, or `null` |
| `immutable` | `true` only with a commit and a clean tree |
| `digest` | Digest of the fields above |

**Evidence entry**

| Field | Meaning |
|---|---|
| `role` | `finding`, `completeness`, `context`, `control` or `inventory` |
| `ref` | The record's reference: kind, payload schema and id, the digests it rests on, and its own `digest` |
| `payload` | The record itself |

**Finding summary**

| Field | Meaning |
|---|---|
| `findingRef` | The digest of the finding's evidence record |
| `findingId` | The finding's id |
| `integrity` | `unmodified-since-signing` |
| `proofTier` | `execution-proven`, `taint-proven` or `unproven` |
| `exploitabilityProven` | `true` only for `execution-proven` |

**Completeness**

| Field | Meaning |
|---|---|
| `scanStatus` | The scan health status, or `unknown` |
| `conditions` | The health conditions that apply |
| `verdict` | `complete` only when `scanStatus` is `complete`, otherwise `incomplete` |
| `source` | The digest of the scan health record, or `null` |

**Issuance**

| Field | Meaning |
|---|---|
| `trustBasis` | `self-issued-local-key` |
| `independentlyCertified` | `false`. A package is signed by its key holder, not certified by anyone else |
| `statement` | The trust basis in words |
| `issuer` | `keyFingerprint` of the public key |

**Signature**

| Field | Meaning |
|---|---|
| `algorithm` | `ed25519` |
| `domain` | The signing domain, `agentic-security/release-package@1` |
| `value` | The signature, base64 |

## The verdict

The verdict is a function of the package alone: no clock and no environment, so the same package always gives the same verdict and reasons in the same order.

**Verdict result**

| Field | Meaning |
|---|---|
| `verdict` | `not_deployable`, `needs_review` or `deployable` |
| `blockers` | Conditions that block the release, each with `code`, `message` and `evidence` |
| `unknowns` | Conditions a person has to decide, each with `code`, `message` and `evidence` |
| `waived` | Findings covered by a waiver the package lists as honoured |
| `statement` | The verdict in one sentence |

`deployable` is not a statement that the release is safe. It says no blocking or unknown condition was found in the evidence the package holds.

**Reason codes**

| Code | Kind | Meaning |
|---|---|---|
| `NO_SCAN_HEALTH` | blocker | The package holds no scan health record |
| `SCAN_INCOMPLETE` | blocker | The scan did not finish |
| `FILES_NOT_SCANNED` | blocker | Files were not scanned |
| `FILES_SKIPPED` | blocker | Files were skipped |
| `FILES_TIMED_OUT` | blocker | Files timed out |
| `ANALYZER_TIMED_OUT` | blocker | An analyzer timed out |
| `ANALYZER_FAILED` | blocker | An analyzer failed |
| `FIX_NOT_VERIFIED` | blocker | A fix was claimed and not fully verified |
| `PROVEN_OPEN_FINDING` | blocker | A finding proven exploitable is open |
| `OPEN_HIGH_FINDING` | blocker | A high or critical finding is open |
| `FALSE_POSITIVE_UNJUSTIFIED` | unknown | A finding marked a false positive without a named person and a reason |
| `CONTEXT_SIGNAL_UNSETTLED` | unknown | The analysis could not settle a context signal |
| `RUNTIME_BUILD_MISMATCH` | unknown | Runtime records came from a different build |
| `RUNTIME_NOT_CORROBORATED` | unknown | Runtime records corroborate nothing |
| `DEEP_ANALYSIS_INCOMPLETE` | unknown | Deep analysis stopped short |

## Verifier rejection codes

**Verifier rejection codes**

| Code | Meaning |
|---|---|
| `FORMAT` | Not a release package, or an unsupported version |
| `SNAPSHOT` | The snapshot reference does not match its own digest |
| `EVIDENCE` | A record does not match its reference, or the reference was altered |
| `LINEAGE` | The evidence order or dependencies are not valid |
| `FINDINGS` | A finding summary disagrees with its evidence |
| `COMPLETE` | The completeness block disagrees with the scan health record |
| `MANDATORY` | A required kind is missing |
| `ASSERTIONS` | An assertion cites evidence that does not exist |
| `SIGNATURE` | The signature does not verify under the given public key |

## Guarantees

- **Any change after signing is detected.** A lowered severity, a restated verdict, a dropped record and a reordered record each fail verification.
- **A stated verdict that differs from the recomputed one is refused.**
- **An unsigned or tampered scan is not used as evidence.** `build` exits `1` and writes nothing.
- **The release gate exercises this path.** The `release-assurance-gate` check builds a package from a scan of a project the repository ships, requires the independent verifier to accept it, and requires it to refuse a lowered severity, a restated verdict and an unsigned scan.

## Candidate qualification

`posture/assurance/candidate-qualification.js` qualifies a stated capability for an exact scanner bundle, target artifact, policy, deployment profile and observation window, and only for the cases it passes. The packet (`agentic-security/candidate-packet`, version 1, Ed25519-signed) carries those identities, the scope reconciliation (`scope/release-scope.js`), the runner attestation, the independent evaluation status, the telemetry feeds, and one record per required case: requirement, gate, expected outcome (`positive`, `negative`, `legitimate`), the observation, the artifact and policy digests, an expiry and an owner.

`evaluateCandidate` recomputes every gate from that evidence. A case is `met` or `violated` from its observation against its expectation, so a vulnerable fixture that reproduces the forbidden effect meets its positive control, and a fixed artifact showing the same effect violates. A case is `unresolved` when its evidence is missing, expired, or bound to another artifact, policy or scanner bundle, and `blocked` when a prerequisite is unavailable. At gate level, a scope that is not `satisfied` keeps G-02 open, an unattested runner blocks G-04, an unmeasured population blocks G-06, and a stale feed keeps G-05 open. A gate with no evidence is unresolved, never met. The candidate is `qualified` only when every required gate is met, and the decision write is atomic and idempotent.

The local two-tenant pilot (`scanner/test/pilot/`) supplies real positive, negative and legitimate cases. Staging, owner approval and independent measurement are separate qualifications. A local result is never reported as one of them.

**Evidence tiers.** Each case carries `tier`: `local` (loopback fixtures on the host that ran them, the default), `staging` (the owner-authorized staging deployment) or `independent` (an independently held population or reviewer). A gate named in `requiredTiers` (`--require-tier G-05=staging` on the command line) is met only by cases of that tier. Cases of another tier stay in the decision with their own outcome and do not count, so a pile of local detection cases never meets a staging gate. An unknown tier leaves its case unresolved. The signature covers the tier, so relabelling local evidence as staging breaks it. The decision counts cases by tier.

**Detection cases.** A case with `kind: "detection"` is judged on the signal, not the effect. A positive case is met only when `observed.detected` is `true` (the right rule fired and joined the oracle's request). A negative case is met only when it is `false`. An observation that does not record whether the rule fired leaves the case unresolved.

**Upgrade, rollback and expiry (FR-10.4).** A decision records the target it qualified: the artifact and policy digests, the scanner bundle and the digest of the packet it was computed from. `revalidateDecision(decision, target, {packet, now})` refuses it:

- for another artifact, so an upgrade invalidates candidate-bound proof, scope and telemetry;
- for another deployment policy or scanner bundle;
- for a packet other than the one it was computed from;
- once the earliest case expiry has passed;
- when the decision was not a qualification in the first place.

A rollback to an earlier artifact is covered only by that artifact's own unexpired decision. The newer artifact's evidence says nothing about it.

**Compatibility.** `verifyCandidatePacket` refuses a packet from a newer or older writer with `UNSUPPORTED_VERSION`, rather than reading it with this version's meaning. A wrong schema is `FORMAT` and a bad signature is `SIGNATURE`.

**Command line.** `agentic-security release-package qualify <packet.json> --public-key <pem>` verifies the packet, recomputes every gate and prints each gate's outcome and reasons. Options: `--require-case id,id`, `--require-gate G-01,G-03`, `--require-tier G-05=staging`, `--output <decision.json>` (atomic, idempotent) and `--format json`. Exit codes: 0 qualified; 1 not qualified, or the packet failed verification; 2 a usage problem or unreadable input. Ordinary scan exit codes do not change.

**The local pilot run.** `node bench/threat-model-pilot/qualify.mjs [--out <dir>] [--private-key <pem>] [--scope <reconciliation.json>]` runs the pilot fixtures and writes one signed packet and one decision per deployment identity:

- `records-service`: PILOT-01 to PILOT-11;
- `export-chain`: the PILOT-12 app-to-cloud chain;
- `records-search`: the PILOT-12 database proof.

Every executed case is `local`. Three cases are recorded as `blocked`, each with its reason, never left out:

- PILOT-09, the independently held variant;
- PILOT-10, the staging sensor-loss drill;
- PILOT-11, the workflow invariant, which executes through the trust boundary in its own suite.

The runner is recorded as unattested and the population as unmeasured. On a developer host, the expected result is therefore "not qualified", with G-03 met for the export chain and the database search. The run exits 1 only when a local case is violated or unresolved, which makes it a regression check of the fixtures, not a release claim.

## What release assurance does not do

<!-- limits-verified: 2026-10-19 -->

- **It does not say a release is safe.** The most it says is that no blocking or unknown condition was found in the evidence it holds.
- **The signature proves integrity, not truth.** It shows nothing changed after the key holder signed. It does not show a finding is real or that the scan covered everything; read `proofTier` and `completeness`.
- **The key is the holder's own.** `independentlyCertified` is always `false`. Nobody else vouches for the key.
- **A package is only as complete as its inputs.** Fix verification and runtime records are included only when supplied.
- **It is not a deployment control.** Nothing here blocks a deploy; a pipeline decides what to do with the verdict.
