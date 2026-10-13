---
description: Trace a scanned image artifact's provenance graph and detect drift between source and what's deployed.
argument-hint: "trace <archive-or-digest> [--source <dir>] [flags]"
---

## Provenance

PRD "Source-to-Artifact Security & Provenance" — the literal CLI shape that
PRD names. **Not** `posture/provenance/`'s git-commit finding provenance,
and **not** `sca/sigstore-verify.js`'s package-build provenance — this is
the artifact's own provenance graph: Git Commit → Build → OCI Digest → SBOM
Component → Finding → Deployment. See
`docs/implementation-status/source-to-artifact-provenance.md`'s
naming-discipline section for why this repo keeps those three apart.

### `trace`

Builds the graph for one scanned artifact (from `image scan`) and, when
`--source` is given, runs the PRD's own "Killer Demonstration" comparison
against that source tree's last scan:

- **`SOURCE: FIXED` / `DEPLOYED ARTIFACT: STILL VULNERABLE` / `PRODUCTION
  EXPOSURE: PRESENT`** — an OSV advisory affects the artifact's installed
  version but not source's — the developer fixed it, but production is
  still running the old image.
- **Built artifact: affected component absent** — source flags an advisory
  against a package that never actually shipped in this artifact at all
  (an optional/dev-only dependency).

The Git-Commit node's only evidence is the `org.opencontainers.image.revision`
build label; without it the commit is honestly `(not declared)`, never
inferred from local git history by heuristic.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `<archive-or-digest>` | Yes | A path to the archive, or a `sha256:<hex>` digest from a prior `image scan`. |
| `--source <dir>` | No | A source tree with a `.agentic-security/last-scan.json` (run `scan` there first) — enables the stale-deployment comparison. |
| `--deployment-id <id>` | No | Declare an operator-known deployment record. This codebase has no mechanism that discovers "which digest is running where" on its own — a deployment node only ever appears when you supply one. |
| `--deployment-environment <name>` | No | Paired with `--deployment-id`. |
| `--deployment-digest <digest>` | No | Paired with `--deployment-id` — compared against the scanned artifact's own digest (`digestMatches` in the JSON output). |
| `--format json\|cli` | No | Defaults to `json`. |

Exit codes: `0` success (a mismatch is a REPORTED finding, not a CLI
failure); `1` the archive/digest could not be resolved, or `--source` has
no `last-scan.json`; `2` a usage error.

### Examples

```
/provenance trace ./build/image.tar
/provenance trace sha256:abc123... --source . --format cli
/provenance trace ./build/image.tar --deployment-id prod-east-1 --deployment-environment production --deployment-digest sha256:def456...
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs provenance "$@"
exit $?
```
