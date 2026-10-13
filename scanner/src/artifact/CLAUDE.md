# src/artifact/

PRD 5 — Source-to-Artifact Security & Provenance. Binds a finding to the actual **built artifact** (a
container image, today) that ships it, closing the gap between "this source file has a vulnerability" and
"this specific image digest contains it." Isolated from every other subsystem this package already uses the
word "provenance" for — see the naming section below before adding a new field or function name here.

## Naming discipline (read this before adding a field)

This repo already has 5 unrelated uses of "provenance"/"artifact": `posture/provenance/`'s `findingProvenance`
(git-commit origin), `posture/provenance.js`'s `annotateFindingProvenance` (parser corroboration),
`sca/sigstore-verify.js`'s `annotateProvenance` (package-build Sigstore verification), a pre-existing bare
`finding.provenance` field, and `posture/artifact-registry.js` (internal `.agentic-security/*` state
classification — nothing to do with container images). **Never** introduce a bare `.provenance`/`*Provenance`
field or a module/field literally named `artifact-registry` here. This package's own graph field is
`artifactProvenanceGraph`, built by `buildArtifactProvenanceGraph` — the compound name is deliberate. The
PRD's own literal CLI surface (`agentic-security provenance trace`) is honored as user-facing text regardless;
the discipline is about internal names, not the CLI vocabulary the PRD mandates.

## Module map (read in this order — each builds on the last)

- `safe-tar.js` — hardened POSIX/GNU tar reader. Every byte any other module in this package reads passes
  through here first. Hard caps on entry count/size/archive size (`DEFAULT_LIMITS`), gzip decompression with
  Node's native `maxOutputLength` guard (no custom streaming counter needed — see the file header), and an
  entry-name safety check (`isSafeEntryName`) that flags `..`/absolute/NUL paths rather than normalizing
  them. No caller ever writes extracted content to a real filesystem path — every result is an in-memory
  `Map`/object keyed by the (safety-checked) tar entry name, which is what makes zip-slip structurally
  impossible here rather than merely guarded against.
- `image-archive.js` — parses a `docker save`-shaped archive (`manifest.json` + a config blob + per-layer
  tars) or an OCI-layout archive (`oci-layout` + `index.json` + `blobs/sha256/*`) into one normalized shape.
  Rejects (never guesses) a multi-image archive, a missing referenced blob, or malformed JSON.
- `filesystem.js` — merges an image's layers in order, applying AUFS/overlay whiteout semantics
  (`.wh.<name>` deletes, `.wh..wh..opq` makes a directory opaque to earlier layers). `readLayers` keeps the
  RAW per-layer, pre-merge view (what `layer-secrets.js` needs to see "this existed in layer 3" even after a
  later layer's whiteout hides it); `mergeLayers` produces the final filesystem view, bounded by
  `DEFAULT_FS_LIMITS` (per-file and total materialization caps — large/binary files are tracked in `files`
  metadata but never fully read into memory).
- `inventory.js` — PRD P0 §1-2 (OCI image scanning + inventory). Ties the above together and feeds the merged
  filesystem's text content through the EXISTING SCA pipeline: `sca/image-packages.js#extractImagePackages`
  for OS packages, and an injected `manifestParser` (the engine's own `parseManifests`, from `sca/index.js`)
  for application packages — no parallel manifest-parsing logic. `baseImage` is read ONLY from the
  `org.opencontainers.image.base.name`/`.digest` labels when present; absent that, it is `null`, never a
  guess from layer-content heuristics (no base-image fingerprint table exists in this codebase, and inventing
  one would produce a confident-looking wrong answer).
- `vuln-correlate.js` — PRD P0 §4. A thin wrapper handing `inventory`'s components to an injected
  `queryOSVFn` (the engine's own `queryOSV`) — "reuse current SCA semantics" literally, not a reimplementation.
- `layer-secrets.js` — PRD P0 §3 (layer secret analysis). `detectFn` is injected, mirroring
  `posture/secret-history.js`'s own `(filePath, rawText) -> Finding[]` detector-injection shape for the exact
  same reason: this package never imports `engine.js` directly, and the real `scanCredentials` detector
  already returns redacted/masked values — this module never re-touches raw content once a finding exists,
  so there's no second place a secret value could leak back in. `deletedButRecoverable` is the subset of
  findings whose path (or an ancestor opaque-marked directory) was removed by a LATER layer's whiteout — the
  PRD's named scenario ("added in layer 3, deleted in layer 5, but remains recoverable").
- `signature.js` — PRD P0 §5. States are exactly the PRD's own four (`verified`/`invalid`/`missing`/
  `unavailable`) — deliberately different words from `sigstore-verify.js`'s own vocabulary so the two are
  never confused. `verifyImageSignature` is this tool's own local detached-signature convention (NOT cosign's
  "simple signing" format). `verifyProvenanceAttestation` implements the REAL DSSE PAE (Pre-Authentication
  Encoding) cosign/Sigstore attestations actually use — a real cosign-keyed attestation bundle verifies here
  given the matching public key. Keyless/Rekor-transparency-log verification is NOT implemented (disclosed
  gap; `sigstore-verify.js`'s Rekor-query pattern is the template a future increment could extend this with).
- `provenance-graph.js` — PRD P0 §6. Assembles Git Commit → Build → OCI Digest → SBOM Component → Finding →
  Deployment from evidence the modules above already computed — no new detection. The Git-Commit edge's only
  evidence source is the `org.opencontainers.image.revision` label; absent that, the commit node is
  `known: false`, never inferred from local git history by heuristic. `deployment` is always
  OPERATOR-DECLARED (`{id, environment, digest}`) — nothing in this codebase discovers "which digest is
  running where" on its own (`lineage/deployment/` models topology, not running digests), so a missing
  `deployment` argument means the graph simply stops short, never a fabricated edge.
- `mismatch.js` — PRD P0 §7, the PRD's own "Killer Demonstration". Compares a source-tree SCA scan against
  one artifact's correlation by **OSV advisory id alone** — never by purl (which bakes in the version). Keying
  by purl was tried first and is wrong: source and artifact are usually running different versions of the
  same package by the entire premise of this comparison, so a purl-keyed match would report every version
  difference as a double mismatch instead of asking "does this specific advisory affect each side's own
  installed version." Scenario A ("Git: fixed / Production: still vulnerable") = an advisory present against
  the artifact's version, absent against source's. Scenario B ("Git: vulnerable / Built artifact: absent") =
  an advisory source flags whose PACKAGE (ecosystem+name, not version) never appears in the artifact's
  inventory at all.
- `vex.js` — PRD P0 §8. `not_affected` is reachable from exactly two evidence paths (component absent from
  the artifact; confirmed-unreachable per existing dataflow/reachability evidence) — never from the absence
  of information, per the PRD's own "`not affected` requires positive evidence" rule. Symmetrically,
  `affected` requires CONFIRMED reachability, not merely "OSV lists this version as vulnerable"; absent that
  confirmation the honest status is `under_investigation`, never a confident `affected` the evidence doesn't
  support. `fixed` requires a clean dotted-numeric version comparison against a real `fixedVersions` entry —
  an unparseable version pair skips that check rather than guessing.

## CLI (`bin/agentic-security.js`)

`image scan`/`image verify`/`provenance trace`/`supply vex` — the PRD's own literal CLI shape (NOT a mode of
the `/supply` SLASH COMMAND, which is a different layer: Claude Code UI sugar that shells out to `scan --only
sca`/`cve-watch`). A scanned artifact persists to `.agentic-security/artifact-scans/<digest-hex>.json`
(registered in `posture/artifact-registry.js`) so `provenance trace <digest>`/`supply vex <digest>` can
re-reference it without re-parsing the archive. Local-daemon image input (`docker save`) and a remote OCI
registry reference are **NOT implemented** — only `docker save`/OCI-layout TAR FILE input — disclosed in
`docs/implementation-status/source-to-artifact-provenance.md`, not silently dropped.

## Test scope

`test/artifact/*.test.js` + `test/cli/artifact-provenance-cli.test.js`, wired into `npm run test:posture`
(same precedent as `fleet/`, `rule-compiler/`, `proof-fabric/` — not large enough for its own scoped script).
`test/helpers/build-tar-fixture.js` is a test-only tar/OCI-archive WRITER (production code only ever reads
tar, via `safe-tar.js`) — mirrors `build-git-fixture.js`'s role for the lineage/deployment suites.
