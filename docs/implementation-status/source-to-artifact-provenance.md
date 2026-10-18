# PRD 5 — Source-to-Artifact Security & Provenance

**Status as of 2026-10-12: P0 scope complete, honestly bounded (see "Deliberately NOT done" below).**

## Objective (from the PRD)

Connect source code → commit → build → container/image → artifact → deployment → finding. Understand
whether a vulnerability found in Git is actually present in what was built and deployed, and whether a
fix in Git has actually reached what's running.

## What already existed (reused, not rebuilt)

| PRD 5 concept | Existing module | Reuse |
|---|---|---|
| Container vulnerability correlation | `src/sca/index.js` (`parseManifests`, `queryOSV`) + `src/sca/image-packages.js` (`extractImagePackages`) | `vuln-correlate.js` hands an image's merged-filesystem components straight to these — no parallel vuln pipeline. |
| OS-package inventory | `src/sca/image-packages.js` | Reused as-is against the merged layer view. |
| Ed25519 signing primitives | `src/posture/evidence-bundle.js`'s precedent (not imported — a new sibling bundle was scoped but not built; see below) | The signature.js module hand-rolls its own `node:crypto` verification rather than reusing a signing module, since PRD 5 only asks for *verification*, never *issuing* a signed bundle. |
| Finding git-commit origin | `src/posture/provenance/` (`annotateGitProvenance`, field `findingProvenance`) | The artifact provenance graph's Git-Commit node reads a build label, never this module directly — but the naming discipline below is modeled on its own documented collision-avoidance rule. |

## Naming discipline (this repo already has 5 unrelated uses of "provenance")

Per `root CLAUDE.md` and `src/posture/CLAUDE.md`, "provenance" already means: (1) git-commit finding origin
(`findingProvenance`), (2) multi-parser corroboration (`posture/provenance.js`'s `annotateFindingProvenance`),
(3) Sigstore package-build verification (`sca/sigstore-verify.js`'s `annotateProvenance`), (4) a pre-existing
bare `finding.provenance` field, (5) Nix build provenance as purl properties. "Artifact" is taken by
`posture/artifact-registry.js` (internal `.agentic-security/*` state classification, unrelated to container
images). "Lineage" is taken wholesale by `src/lineage/`.

This PRD's new concept — binding a finding to the built/deployed artifact that ships it — lives under a new
**`src/artifact/`** directory (its own `CLAUDE.md` restates this rule), with a naming rule: never a bare
`.provenance`/`*Provenance` field; this PRD's graph field is `artifactProvenanceGraph`, built by
`buildArtifactProvenanceGraph`. The PRD's own literal CLI surface (`agentic-security provenance trace`) is
honored as user-facing text — the discipline is about internal module/field/function names, not the CLI
vocabulary the PRD mandates.

## What shipped

1. **`src/artifact/safe-tar.js`** — hand-rolled, hardened POSIX/GNU tar reader. Hard caps on entry count
   (200k), per-entry size (512MB), total archive size (4GB); Node's native `gunzipSync({maxOutputLength})`
   for a real decompression-bomb guard (no custom streaming counter needed); `isSafeEntryName` flags (never
   silently normalizes) a `..`/absolute/NUL-containing path. Nothing is ever written to a real filesystem
   path — every caller keeps content in an in-memory Map, which is what makes zip-slip structurally
   impossible here. 16 tests.
2. **`src/artifact/image-archive.js`** — parses a `docker save`-shaped archive (`manifest.json` + config
   blob + per-layer tars) or an OCI-layout archive (`oci-layout` + `index.json` + `blobs/sha256/*`) into one
   normalized shape. Rejects a multi-image archive, a missing referenced blob, or malformed JSON — never
   guesses. 10 tests.
3. **`src/artifact/filesystem.js`** — merges layers in order with AUFS/overlay whiteout semantics
   (`.wh.<name>` deletes, `.wh..wh..opq` makes a directory opaque to earlier layers), bounded per-file and
   total content-materialization caps. `readLayers` keeps the raw, pre-merge per-layer view that
   `layer-secrets.js` needs. 7 tests.
4. **`src/artifact/inventory.js`** — PRD P0 §1-2. Produces digest/OS/architecture/baseImage/osPackages/
   appPackages/layers/entrypoint/buildLabels by feeding the merged filesystem through
   `extractImagePackages` + an injected `parseManifests`. `baseImage` is read only from
   `org.opencontainers.image.base.name`/`.digest` labels — `null`, never a heuristic guess, when absent.
   7 tests.
5. **`src/artifact/vuln-correlate.js`** — PRD P0 §4. A thin wrapper handing the inventory's components to
   an injected `queryOSVFn` (the engine's own `queryOSV`) — literal "reuse current SCA semantics." 5 tests.
6. **`src/artifact/layer-secrets.js`** — PRD P0 §3. `detectFn` is injected (mirroring
   `posture/secret-history.js`'s own detector-injection shape), so this package never imports `engine.js`
   directly. `deletedButRecoverable` is the subset of findings whose path (or an ancestor opaque-marked
   directory) was removed by a LATER layer's whiteout. The injected detector already returns
   masked/redacted values; this module never re-touches raw content once a finding exists. 7 tests.
7. **`src/artifact/signature.js`** — PRD P0 §5. States are exactly `verified`/`invalid`/`missing`/
   `unavailable` (deliberately different words from `sigstore-verify.js`'s own vocabulary).
   `verifyImageSignature` is a real `node:crypto` detached-signature check (Ed25519/ECDSA/RSA, auto-detected)
   over the image digest string. `verifyProvenanceAttestation` implements REAL DSSE PAE (Pre-Authentication
   Encoding) verification for in-toto/SLSA attestations — a genuine cosign-keyed DSSE envelope verifies here
   given the matching public key, proven against hand-built real signatures (Ed25519 and ECDSA P-256) in
   17 tests, not mocked crypto.
8. **`src/artifact/provenance-graph.js`** — PRD P0 §6. `buildArtifactProvenanceGraph` assembles Git Commit →
   Build → OCI Digest → SBOM Component → Finding → Deployment purely from evidence the modules above already
   computed. The Git-Commit edge's only evidence is the `org.opencontainers.image.revision` label; absent
   that, `known: false`, never inferred from local git history. `deployment` is always operator-declared.
   `traceArtifactProvenanceGraph` walks the graph (the `provenance trace` CLI command's query surface).
   11 tests.
9. **`src/artifact/mismatch.js`** — PRD P0 §7, the PRD's own "Killer Demonstration". Compares by **OSV
   advisory id alone**, never by purl (which bakes in the version) — purl-keying was tried first and found
   wrong (see the module header and `src/artifact/CLAUDE.md` for the full reasoning: source and artifact
   are, by this comparison's entire premise, usually running different versions of the same package).
   Scenario A = an advisory affecting the artifact's installed version, absent from source's. Scenario B =
   an advisory source flags whose PACKAGE (name+ecosystem) never appears in the artifact's inventory at
   all. 9 tests.
10. **`src/artifact/vex.js`** — PRD P0 §8. `not_affected` is reachable from exactly two evidence paths
    (component absent; confirmed-unreachable reachability evidence) — never from absence of information.
    `affected` symmetrically requires CONFIRMED reachability, not merely "OSV lists this version
    vulnerable"; absent that, `under_investigation`. `fixed` requires a clean dotted-numeric version
    comparison against a real `fixedVersions` entry. 9 tests.
11. **CLI** (`bin/agentic-security.js`): `image scan`/`image verify`, `provenance trace`, `supply vex` — the
    PRD's own literal CLI shape (NOT a mode of the pre-existing `/supply` slash command, which is a
    different layer — see the naming note in `src/artifact/CLAUDE.md`). A scanned artifact persists to
    `.agentic-security/artifact-scans/<digest-hex>.json` (registered in `posture/artifact-registry.js`,
    'generated'/'scan' retention) so `provenance trace <digest>`/`supply vex <digest>` can re-reference it
    without re-parsing the archive.
12. **Required fixture + killer scenario**: `test/fixtures/artifact-provenance/README.md` +
    `test/cli/artifact-provenance-cli.test.js` (8 tests) — all 7 PRD-named fixture properties (vulnerable
    base package, clean equivalent, deleted-but-recoverable secret, valid signature, invalid signature,
    incorrect provenance, stale vulnerable deployment) plus the Killer Demonstration itself, proven against
    the REAL BUILT CLI, using REAL OSV advisory data (via this repo's own disk cache — lodash 4.17.4 vs.
    4.17.21) and REAL cryptographic signatures (Ed25519).
13. **Documentation**: `commands/image.md`, `commands/provenance.md` (new), `commands/supply.md` (new
    `--vex` mode), `src/artifact/CLAUDE.md` (new), root `CLAUDE.md` (dispatcher table, repository layout,
    version), `docs/capability-ledger.json`, `CHANGELOG.md`, README version badge.

## Deliberately NOT done (disclosed, not silently dropped)

- **Keyless/Rekor verification is delegated, not implemented.** `cosign.js` runs cosign and reads its answer; this repository
  does not itself verify certificate chains or transparency-log proofs. Tested only against a stand-in cosign
  (`test/fixtures/artifact/fake-cosign/cosign`), so how a real cosign behaves is not proven here.
- **Local engine input is proven only against a stand-in `docker`** (`test/fixtures/proof-fabric/fake-engine/docker`), not a real
  daemon. Podman is accepted by name and untested.
- **The registry client is proven only against a local mock registry.** Not exercised against Docker Hub, GHCR, ECR or any real
  registry; foreign layers, schema-1 manifests and non-sha256 digests are refused rather than handled.
- **Closed in this increment (PRD gap closure):** local Docker/Podman input (`engine-source.js`), explicit remote OCI references
  (`registry.js`, `oci-layout.js`), cosign delegation (`cosign.js`), and the signed evidence bundle (`artifact-evidence.js`,
  verified by `verify-attestation`). Tests: `test/artifact/registry.test.js`, `test/artifact/sources-cosign-evidence.test.js`,
  `test/cli/artifact-sources-cli.test.js`.
- **A pre-existing, unrelated observation**, found while building the Killer Demonstration fixture: a plain
  `agentic-security scan`/`scan --only sca` run against a small test project declaring an exact, pinned
  vulnerable npm dependency (e.g. `lodash@4.17.4`) does not populate `scan.supplyChain` with the
  `vulnerable_dep` entries that calling `queryOSV` directly (the same function, same component shape)
  demonstrably returns. This is **not** PRD 5 code — `src/artifact/vuln-correlate.js` calls `queryOSV`
  exactly the way this investigation confirmed works correctly — and was not investigated further (out of
  scope here); the killer-scenario CLI test's "source" side writes its `last-scan.json` input directly
  rather than depending on a live `cmdScan` SCA run, which is also this codebase's own existing convention
  (see `test/sca-batch.test.js`'s injected `vulnerable_dep` fixtures). Worth a dedicated look in a future
  session.

## Verification

- `node --test test/artifact/*.test.js test/cli/artifact-provenance-cli.test.js` — 95 + 8 = 103 tests, all
  passing, including real Ed25519/ECDSA signature generation+verification and real DSSE PAE attestation
  verification (not mocked crypto), and the full Killer Demonstration against the real built CLI with real
  cached OSV advisory data for lodash 4.17.4 (10 advisories) vs. 4.17.21 (3 advisories, a real subset).
- `npm run test:lifecycle` — 338 tests passing; no dead-module/wiring warnings for the new `src/artifact/`
  package; `test-registry-completeness` confirms `artifact-scans` is registered.
- Full verification (build, `npm test`, self-scan baseline review, doc-drift/lint, pre-push gate,
  `test:language-slow`) to be run and recorded before ship.
