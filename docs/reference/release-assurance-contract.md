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

## What release assurance does not do

<!-- limits-verified: 2026-10-19 -->

- **It does not say a release is safe.** The most it says is that no blocking or unknown condition was found in the evidence it holds.
- **The signature proves integrity, not truth.** It shows nothing changed after the key holder signed. It does not show a finding is real or that the scan covered everything; read `proofTier` and `completeness`.
- **The key is the holder's own.** `independentlyCertified` is always `false`. Nobody else vouches for the key.
- **A package is only as complete as its inputs.** Fix verification and runtime records are included only when supplied.
- **It is not a deployment control.** Nothing here blocks a deploy; a pipeline decides what to do with the verdict.
