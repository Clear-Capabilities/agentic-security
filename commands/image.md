---
description: Scan a built container image archive (OCI/Docker tar) for its real inventory, vulnerabilities, and signature/attestation state.
argument-hint: "scan|verify <archive-or-digest> [flags]"
---

## Image

PRD "Source-to-Artifact Security & Provenance" — the literal CLI shape that
PRD names. Operates on the **built artifact** (a container image archive),
not source code: closes the gap between "this dependency has a CVE" and
"this specific image digest actually ships it."

**Reuses the existing SCA pipeline, never a parallel one.** Inventory
extraction feeds the same manifest parsers and OS-package-DB parser every
other SCA finding in this codebase uses, then the same OSV/KEV/EPSS query
path (`sca/index.js`'s `queryOSV`) every other vulnerability in this
codebase goes through.

**Two input shapes, by design — never two others.** A `docker save`-shaped
tar (`manifest.json` + a config blob + per-layer tars) or an OCI-layout tar
(`oci-layout` + `index.json` + `blobs/sha256/*`), as a local file path.
**Not implemented, disclosed, not silently dropped:** a local Docker daemon
image reference (`docker save <name>` piped in) and an explicit remote OCI
registry reference — see
`docs/implementation-status/source-to-artifact-provenance.md`.

**Never executes the image.** A hand-rolled, hardened tar/gzip reader
(`src/artifact/safe-tar.js`) with hard caps on entry count, entry size,
total archive size, and the decompression-bomb guard — no `docker run`, no
daemon. Every tar entry's path is safety-checked (no `..`/absolute paths);
nothing is ever written to a real filesystem path, only to in-memory maps,
so zip-slip is structurally impossible rather than merely guarded against.

### `scan`

Parses the archive, builds the inventory (digest, OS, OS packages,
application packages, architecture, base image if declared, layers,
entrypoint, build labels), correlates every package against real OSV/KEV/EPSS
data, and sweeps every layer for a secret that was added and later deleted
by an overlay whiteout but remains recoverable from an earlier layer's raw
tar bytes — **the secret's value is never printed**, only the same
masked/redacted form the ordinary secrets scanner already returns. The
result persists to `.agentic-security/artifact-scans/<digest-hex>.json` so
`provenance trace`/`supply vex` can reference it by digest without
re-parsing the archive.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `<archive>` | Yes | Path to a docker-archive or oci-archive tar file. |
| `--format json\|cli` | No | Defaults to `json`. |

Exit codes: `0` success; `1` the archive could not be read or parsed (not a
recognized format, a missing referenced blob, a decompression-bomb guard
trip); `2` a usage error (no archive given).

### `verify`

Checks signature/attestation material only — never re-runs vulnerability
correlation. States are exactly `verified`/`invalid`/`missing`/`unavailable`
— **absent material is `missing`, never silently treated as `verified`**.

A plain detached signature (`verifyImageSignature`) is this tool's own local
convention over the image digest string — not cosign's "simple signing"
format. An attestation (`verifyProvenanceAttestation`) is REAL DSSE
(Pre-Authentication Encoding) verification for an in-toto/SLSA provenance
statement — the actual encoding cosign/Sigstore attestations use, so a real
cosign-keyed attestation bundle verifies here given the matching public key.
Keyless/Rekor-transparency-log verification is **not implemented**.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `<archive-or-digest>` | Yes | A path to the archive, or a `sha256:<hex>` digest from a prior `scan`. |
| `--signature <file>` | No | A detached signature over the image digest. |
| `--public-key <file>` | No | PEM public key (Ed25519, ECDSA, or RSA) to verify against. |
| `--attestation <file>` | No | A DSSE envelope JSON (`{payloadType, payload, signatures}`) carrying an in-toto/SLSA statement. |

Exit codes: `0` every supplied check is `verified`, `missing`, or
`unavailable` (nothing cryptographically failed); `1` a supplied signature
or attestation is `invalid`; `2` a usage error.

### Examples

```
/image scan ./build/image.tar
/image scan ./build/image.tar --format cli
/image verify ./build/image.tar --signature image.sig --public-key cosign.pub
/image verify sha256:abc123... --attestation provenance.json --public-key cosign.pub
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs image "$@"
exit $?
```
