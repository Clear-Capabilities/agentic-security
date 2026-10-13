# Source-to-Artifact Security & Provenance

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

## What this does not do

Disclosed, not silently dropped:

- **No local Docker-daemon image input.** `image scan` takes a local docker-archive/oci-archive tar file
  path only — not `docker save <name>` piped in. Shelling out to `docker` would be this codebase's first
  external-process invocation in the CLI entrypoint and needs its own timeout/cancellation discipline; not
  attempted in this increment.
- **No remote OCI registry reference.** `image scan registry.example.com/app:tag` needs an OCI Distribution
  API v2 client (manifest/blob GET, bearer-token auth) — genuinely new network capability, out of scope.
- **No keyless/Rekor-transparency-log signature verification.** `image verify` checks a real signature given
  an explicit public key; it does not query Rekor to discover one, the way `sca/sigstore-verify.js` already
  does for ordinary dependency packages.
- **No "which digest is running where" discovery.** A deployment node in the provenance graph only ever
  appears when you declare one yourself via `--deployment-id`/`--deployment-digest` — nothing here polls a
  running cluster or registry on its own.

See `docs/implementation-status/source-to-artifact-provenance.md` for the full, itemized status.
