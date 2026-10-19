# Provenance

<!-- seo: title="Provenance: which commit introduced a finding and which artifact ships it" description="Finding provenance from Git history and source-to-artifact provenance for container image archives, including what each does not claim." -->

**Maturity:** Preview

Provenance connects a finding to where it came from and where it ships. Two features exist, and they are separate on purpose.

## Finding provenance (Git)

Which commit introduced a finding, when, by whom, and how confident that answer is, resolved from Git history (not `git blame`, which answers a different question).

- `scan` leaves it off by default because it costs real time; any provenance flag turns it on. `ci` turns it on.
- A finding with no resolvable origin says so (`status: not_available`) instead of guessing. The demo app, which is not a Git repository, reports exactly that.
- Only a complete scan can close a finding.

See [Finding provenance](../guides/finding-provenance.md).

## Source-to-artifact provenance (images)

Whether a finding is present in a built container image and whether a fix in source reached it. The chain it models:

`Git commit → build → OCI digest → SBOM component → finding → deployment`

```bash
agentic-security image scan <image-archive>
agentic-security provenance trace sha256:<digest> --source <dir>
```

`provenance trace` reads the record a previous `image scan` stored, addressed by digest. It catches the case a CVE scanner alone cannot: source is fixed but the deployed image still contains the old code (`SOURCE: FIXED`, `DEPLOYED ARTIFACT: STILL VULNERABLE`).

Images can also come from a local Docker or Podman engine (`--engine`) or one explicitly named registry reference (`--registry`, HTTPS, digest-verified), and signatures can be checked through cosign (`image verify --cosign`). Those paths were tested against stand-ins and a mock registry, not a real daemon or registry. Not implemented: keyless transparency-log signature discovery, and discovery of which digest is running where (a deployment appears only when you declare one). See [Source-to-artifact provenance](../guides/artifact-provenance.md).

## What provenance does not establish

- Git provenance is an attribution of introduction, not of intent or fault.
- A clean image scan is not a statement about the running deployment unless you declared that deployment.
