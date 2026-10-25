# Source-to-Artifact Security & Provenance

**Maturity:** GA. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

**Status: new.** A finding in Git tells you a dependency is vulnerable. It does not tell you whether the
container image actually running in production was built before or after the fix — or whether the
vulnerable package even shipped in that image at all. This closes that gap: source code → commit → build →
container image → artifact → deployment → finding, as one traceable chain.

## What this reuses, and what is new

Everything here operates on a **built artifact** (a container image archive), never on source. A new
`scanner/src/artifact/` package feeds an image's extracted filesystem through the engine's *existing* SCA
pipeline (`sca/index.js`'s `parseManifests`/`queryOSV`, `sca/image-packages.js`'s `extractImagePackages`) —
there is no parallel vulnerability pipeline, no second CVE source, no second OS-package parser.

What's genuinely new:

- A hand-rolled, hardened tar/gzip reader (`safe-tar.js`) — hard caps on entry count/size/total archive
  size, a real decompression-bomb guard (`gunzipSync({maxOutputLength})`), and content kept only in memory,
  never written to a real filesystem path, which makes zip-slip structurally impossible rather than merely
  checked for.
- Layer-merge filesystem reconstruction with AUFS/overlay whiteout semantics (`.wh.<name>` deletes,
  `.wh..wh..opq` opaque-directory markers).
- Layer secret analysis that catches a secret **added in one layer and deleted in a later one** —
  recoverable from the earlier layer's raw bytes even though it's gone from the final image — reported
  under `secrets.deletedButRecoverable`, value never printed.
- Real signature/attestation verification: a detached signature over the image digest (Ed25519/ECDSA/RSA,
  auto-detected), and real DSSE (Dead Simple Signing Envelope) Pre-Authentication Encoding verification for
  in-toto/SLSA attestations — a genuine cosign-keyed attestation bundle verifies here given the matching
  public key. States are exactly `verified`/`invalid`/`missing`/`unavailable` — absent material is never
  silently treated as verified.
- The artifact provenance graph: Git Commit → Build → OCI Digest → SBOM Component → Finding → Deployment,
  built only from evidence (the Git-Commit edge needs an `org.opencontainers.image.revision` build label —
  absent that, it's honestly `(not declared)`, never inferred from local git history).
- Source-vs-artifact mismatch detection, keyed on the OSV **advisory id**, not the package+version — source
  and a deployed artifact are expected to run different versions of the same package, so keying on version
  would make every ordinary drift look like a false mismatch.
- VEX status derivation (`affected`/`not_affected`/`fixed`/`under_investigation`) on positive evidence only:
  `not_affected` requires the component to be absent or confirmed unreachable; `affected` requires confirmed
  reachability, not merely "OSV lists this version as vulnerable" (otherwise `under_investigation`).

## Quickstart

```bash
agentic-security image scan ./build/image.tar
```

```json
{
  "digest": "sha256:9a51ce2f...",
  "os": "debian", "architecture": "amd64",
  "baseImage": { "name": "node", "digest": "sha256:1b2c..." },
  "osPackages": 142, "appPackages": 38,
  "vulnerabilities": { "critical": 0, "high": 1, "medium": 3 },
  "secrets": { "found": 0, "deletedButRecoverable": 1 }
}
```

```bash
agentic-security image verify sha256:9a51ce2f... \
  --attestation provenance.json --public-key cosign.pub
```

```bash
agentic-security provenance trace sha256:9a51ce2f... --source . --format cli
```

```text
SOURCE: FIXED
DEPLOYED ARTIFACT: STILL VULNERABLE
PRODUCTION EXPOSURE: PRESENT
```

That third command is the PRD's own named "Killer Demonstration": the source tree's own last scan is clean
(the developer already fixed the advisory), but the archive you scanned with `image scan` still has it —
meaning the fix never reached what's actually running. The reverse case is also reported honestly: an
advisory source flags against a package that never actually shipped in the built artifact at all (e.g. a
dev-only dependency) is reported as **built artifact: affected component absent**, not a false alarm.

```bash
agentic-security supply vex sha256:9a51ce2f...
```

Returns a VEX statement per advisory affecting the artifact, each backed by the positive-evidence rule
above — never "probably fine" and never "probably vulnerable" without a reason attached.

## The required-fixture killer scenario

`scanner/test/fixtures/artifact-provenance/` proves all 7 of the PRD's named fixture properties plus the
Killer Demonstration end to end against the real built CLI
(`scanner/test/cli/artifact-provenance-cli.test.js`), using real cached OSV advisory data (lodash 4.17.4 vs.
4.17.21) and real Ed25519/DSSE cryptography — not mocked:

1. A vulnerable base package vs. a clean equivalent — same shape, different digest, fewer advisories.
2. A secret added in one layer and deleted by a later layer's whiteout — recoverable, never printed.
3. A valid detached signature verifies; the same signature over a different digest is reported `invalid`.
4. A validly-signed attestation whose `subject` digest names a different artifact is reported `invalid`
   ("incorrect provenance" — the subject doesn't match what you scanned).
5. The Killer Demonstration itself: `SOURCE: FIXED` / `DEPLOYED ARTIFACT: STILL VULNERABLE` / `PRODUCTION
   EXPOSURE: PRESENT`, printed verbatim in the PRD's own words.

See that fixture's own `README.md` for the full property-by-property mapping, including two extra tests
(`supply vex` against the real CLI, and a hostile path-traversal tar entry that's surfaced, never silently
dropped or crashed on).

## Output schema

`image scan IMAGE` prints (and stores under `.agentic-security/artifact-scans/<sha256>.json`) one record: `inventory` (`digest`,
`digestKind` of `manifest` or `config`, `repoTags`, `os`, `architecture`, `baseImage`, `osPackages`, `appPackages`, `layers` with sizes and diff
ids, `entrypoint`, `cmd`, `buildLabels`, `history`, `unsafeEntries`, `materializationTruncated`), `vulnerabilities` (OSV matches with the package,
`osvId`, `cveAliases`, `fixedVersions`, `severity`, `cvssVector`, `range`), `secrets` (`deletedButRecoverable`, listed by layer, path and kind,
never by value, and `totalFindings`), `scannedAt`, and `source` (`archive`, `registry` with host, repository, reference, platform and bytes
fetched, or `engine` with the runtime and reference). `image verify` prints `{digest, signature: {state, via, reason}, attestation: {state,
reason}}` where `state` is exactly one of `verified`, `invalid`, `missing`, `unavailable`.

`image scan --attest` writes `.agentic-security/attestations/artifact-<id>.json`, schema `agentic-security/artifact-evidence@1`: `artifact`,
`scan` (vulnerabilities and secret locations, each capped and with `truncated` totals so a cut-off list is visible, and
`vulnerabilityLookup`), `signature` (the image's own signature state, or `not-checked`), `engine`, `proves`, `doesNotProve`, and an Ed25519
`attestation`. `verify-attestation <bundle> --public-key <pem>` exits 0 if valid and 1 if the bundle was edited, carries a key the
signature does not cover, or was signed by another key. The bundle proves the record is unmodified since signing; it does not prove the image
is free of vulnerabilities.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `... (bad_reference)` | The registry reference was not a plain `[host/]repo[:tag]` or `repo@sha256:...`: a scheme, spaces, `..`, userinfo or a leading `-` are refused. |
| `refusing a non-HTTPS target (insecure_transport)` | Registries are reached over HTTPS only. A loopback registry over plain HTTP needs `--allow-http-loopback`. A redirect to a plain-HTTP host is refused. |
| `the registry refused access (unauthorized)` | Set `AGENTIC_SECURITY_REGISTRY_TOKEN`, or `AGENTIC_SECURITY_REGISTRY_USER` and `AGENTIC_SECURITY_REGISTRY_PASSWORD`, or log in with Docker (its config is read for that registry only). The credential is never printed and is not sent to a host the registry redirects to. |
| `the image has no linux/arm64 variant (platform_not_found)` | The error lists what exists; choose with `--platform os/arch`. |
| `a downloaded blob does not match its digest (digest_mismatch)` | The registry served bytes that are not what its manifest promised. Nothing is scanned. Treat the source as untrustworthy. |
| `... is not installed or not on PATH; nothing was read (engine_unavailable)` | `--engine docker|podman` needs that tool. The image is exported with `save`, never run. |
| `image scan --engine` hangs, then `timeout` | The export has a time and size limit (`engine_error` / `too_large` for the size). A very large image needs a tar file you scan directly. |
| `signature: unavailable` after `--cosign` | cosign is not installed, could not reach what it needed, or `--repository` was not given. `unavailable` is never read as verified. `missing` means no signature exists for this digest; `invalid` means one exists and does not verify (or names a different digest). |
| `--attest could not write the signed bundle` | State writes are disabled, or the directory has no project marker (`.git`, `package.json`, ...). Nothing was signed to disk. |
| `NOTE: some layer content exceeded the scan size cap` | Large files in layers are skipped, not scanned. The scan says so rather than reporting the layer clean. |

## What this does not do

<!-- limits-verified: 2026-10-19 -->

Disclosed, not silently dropped. The reference page [lists every field and exit code](../reference/artifact-provenance-contract.md); these are the limits.

- **Keyless signature verification needs cosign and the public transparency log.** `image verify --cosign` delegates it to cosign; this tool does not query the log itself. A key-signed image from a registry with no transparency log verifies only with the explicit `--ignore-tlog` opt-in, and the result says the log was not checked.
- **Nothing discovers which digest is running where.** A deployment node in the provenance graph only appears when you declare one with `--deployment-id` and `--deployment-digest`; nothing polls a running cluster or registry.
- **The registry client fetches one named image.** It does not browse a registry or discover tags, it needs HTTPS (plain HTTP only to a loopback registry you allow), and it reads credentials only for the registry you named.
- **One platform per scan.** A multi-platform index resolves to the platform you ask for (`linux/amd64` by default).
- **Advisory data is the OSV database.** A package it does not know is not reported.
- **The commit is the image's own label.** An image built without `org.opencontainers.image.revision` has an unknown commit, and nothing is inferred from git history.

See `docs/implementation-status/source-to-artifact-provenance.md` for the full, itemized status.
