# Source-to-artifact provenance: contract

<!-- seo: title="Artifact provenance contract: image scan, verify, trace and VEX output, and what each input and signature state means" description="The frozen fields of image scan, image verify, provenance trace and supply vex, the three image inputs, the four signature states and the mismatch detector, with the measured hosted run and its limits." -->

**Maturity:** see the [capability registry](../capabilities.yaml). The behavior and a walkthrough are in the [artifact provenance guide](../guides/artifact-provenance.md).

A compatibility test (`scanner/test/contracts/artifact-provenance.contract.test.js`) runs the real commands on an archive and holds each output to the tables below in both directions, so a field cannot be added or removed without changing this page. The hosted `artifact-real` job runs the same commands against a real container engine, a real registry and a real signing tool; its measured result is below.

## Commands

```bash
agentic-security image scan <archive.tar> [--format json|cli] [--attest]
agentic-security image scan <name> --engine docker|podman
agentic-security image scan --registry <ref> [--platform linux/amd64] [--allow-http-loopback]
agentic-security image verify <archive.tar|digest> [--signature <file>] [--public-key <pem>] [--attestation <file>] [--cosign --repository <repo>] [--ignore-tlog]
agentic-security provenance trace <archive.tar|digest> [--source <project>] [--deployment-id <id> --deployment-environment <env> --deployment-digest <digest>] [--format json|cli]
agentic-security supply vex <archive.tar|digest>
```

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Reported. For `image verify`, no signature or attestation was found to be invalid |
| `1` | The input could not be read, the registry or engine refused, a `--source` scan carries no dependency data, or `image verify` found a signature or attestation invalid |
| `2` | A usage problem: no target given, or an unknown `--format` |

## The three inputs

| Input | What it is |
|---|---|
| Archive | A `docker save` or OCI-layout tar file, read by a hardened reader: entry names are checked, sizes and counts are capped, and nothing is written to disk |
| Engine | `<name> --engine docker` or `--engine podman`: the engine exports the image (`save`) and the result goes through the same reader. Nothing is run |
| Registry | `--registry <ref>`: one explicitly named image over HTTPS (plain HTTP only to a loopback registry you allow), every blob digest-verified, credentials only from the environment or the container config for that registry |

All three give the same inventory and the same advisories for the same image. The registry input is bound to the registry's manifest digest; the archive and engine inputs report the image configuration digest.

## `image scan`

**Scan output**

| Field | Meaning |
|---|---|
| `inventory` | What is in the image (below) |
| `vulnerabilities` | Dependency findings correlated with the advisory database |
| `secrets` | Secrets found in any layer (below) |
| `scannedAt` | When |
| `source` | `kind`: `archive`, `engine` or `registry`, with the engine or registry details |

**Inventory**

| Field | Meaning |
|---|---|
| `digest` | The image digest |
| `digestKind` | `config` or `manifest` |
| `repoTags` | Tags the image carries |
| `os` | Operating system |
| `architecture` | CPU architecture |
| `baseImage` | Read only from the base-image labels, or `null`. Never guessed |
| `osPackages` | Operating-system packages |
| `appPackages` | Application packages, from manifests inside the image |
| `layers` | Each layer's index, size and diff id |
| `entrypoint` | The image entrypoint |
| `cmd` | The image command |
| `buildLabels` | The image's build labels |
| `history` | The image history |
| `unsafeEntries` | Archive entries that were refused (a hostile path) |
| `materializationTruncated` | Whether a size cap stopped the read |

**Secrets**

| Field | Meaning |
|---|---|
| `deletedButRecoverable` | Secrets present in a layer and removed by a later one, which remain recoverable from the earlier layer. Values are masked |
| `totalFindings` | All secret findings |

A vulnerability entry is a dependency finding: `type`, `name`, `version`, `ecosystem`, `purl`, `osvId`, `cveAliases`, `description`, `fixedVersions`, `severity`, `cvssVector`, `osvVulnFunctions`, `scope`, `file`, `line`, `depChain`, `advisory`, `range` and, when the advisory links a public exploit reference, `hasKnownAttackRef`.

## `image verify`

**Verify output**

| Field | Meaning |
|---|---|
| `digest` | The image checked |
| `signature` | The signature result (below) |
| `attestation` | The provenance attestation result |

Each result has `state` and `reason`.

**Signature and attestation states**

| State | Meaning |
|---|---|
| `verified` | A signature or attestation was checked against the key and names this exact digest |
| `invalid` | One exists and does not verify: a wrong key, a changed image, or a subject digest that is not this image's |
| `missing` | None exists for this digest, or a signature was supplied without the key to check it (the reason says which) |
| `unavailable` | The check could not run: no digest to check against, or cosign is not installed or could not reach what it needed. It is not a verdict |

Signature results delegated to cosign (`--cosign`) also carry `via`, `mode` (`key` or `keyless`), `signatures` and `identity`. A key-signed image from a registry with no transparency log can be verified only with `--ignore-tlog`, which is an explicit opt-in; a verified result that skipped the log says `transparencyLog: not-checked`. Keyless verification always needs the log.

## `provenance trace`

**Trace output**

| Field | Meaning |
|---|---|
| `artifactProvenanceGraph` | `nodes` and `edges` from the git commit through the build to the image digest, its components, its findings and any deployment you declared |
| `trace` | `found`, `root` and `reached`: what is reachable from the commit |
| `mismatch` | `null` without `--source`; otherwise the comparison below |

Node kinds: `gitCommit`, `build`, `ociDigest`, `sbomComponent`, `finding`, `deployment`. The commit node's only source is the image's `org.opencontainers.image.revision` label; without it the node says `known: false` and nothing is inferred from git history. A deployment node exists only when you declare one.

**Mismatch**

| Field | Meaning |
|---|---|
| `scenarioA` | Advisories that affect the image and not the source: fixed in source, still vulnerable in the artifact |
| `scenarioB` | Advisories the source has whose package is absent from the image |
| `hasMismatch` | `true` when either is non-empty |

Advisories are matched by advisory id alone, never by package URL, because the source and the artifact usually run different versions of the same package. A `--source` scan with no dependency data is refused rather than read as clean.

## `supply vex`

**VEX output**

| Field | Meaning |
|---|---|
| `digest` | The image |
| `statements` | One per advisory and component: `purl`, `name`, `ecosystem`, `osvId`, `status`, `justification` and `evidence` |

Status is `not_affected`, `affected`, `fixed` or `under_investigation`. `not_affected` needs positive evidence (the component is absent, or confirmed unreachable); `affected` needs confirmed reachability, not only a listed version; absent that, the status is `under_investigation`.

## Measured results

<!-- measured-results -->
From the hosted `artifact-real` job (`bench/artifact-real/RESULT.json`), run against docker 28.0.4, a registry container and cosign v2.4.1:

| Check | Result |
|---|---|
| Archive, engine and registry inputs report the same advisories for one image | 10 advisories on all three |
| The clean image reports strictly fewer | 3 advisories |
| Signed image, its own key | `verified` |
| Same image, another key | `invalid` |
| Unsigned image | `missing` |
| Source patched, image still vulnerable | 7 advisories reported as fixed in source and vulnerable in the artifact |
| Source equal to the image | 0 reported |

All 14 checks passed. The first hosted run found three defects, all fixed before this result: a source scan limited to SCA was read as having no advisories (so a source on the same version looked fixed), cosign's wrong-key message was classified as `missing`, and a key-signed image from a registry with no transparency log could not be verified without an explicit opt-in (`--ignore-tlog`).
<!-- /measured-results -->

## Guarantees

- **Nothing is run.** An image is read, never executed.
- **An absent signature is `missing`, not `verified`, and a check that could not run is `unavailable`, not a verdict.**
- **The commit is the image's own label.** It is never inferred.
- **A comparison with nothing to compare is refused.** A source with no dependency data is not "fixed".

## What this does not do

<!-- limits-verified: 2026-10-19 -->

- **Keyless verification needs cosign and the public transparency log.** This tool delegates it to cosign and does not query the log itself. Without cosign, a keyed check against a file you supply still works.
- **Nothing discovers which digest is running where.** A deployment node exists only when you declare one.
- **The registry client fetches one named image.** It does not browse a registry, and it reads credentials only for the registry you named.
- **Advisory data is the OSV database.** A package the database does not know is not reported, and a registry or archive that cannot be read says so rather than reporting an empty image.
- **Platform selection is one platform per scan.** A multi-platform index is resolved to the platform you ask for (`linux/amd64` by default).
