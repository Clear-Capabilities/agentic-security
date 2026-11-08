# Evidence record

Additive fields on a scan and on each finding. They extend the existing JSON, add nothing that replaces a field, and are produced from data the scan already holds plus read-only Git queries on the scan root.

## Scan record (`scanRecord`, schema `scan-record/1`)

| Field | Meaning |
|---|---|
| `tool` | Name and version of the scanner |
| `source` | `vcs`, the commit, whether the tree is dirty, and for up to 200 changed files the path, status and SHA-256 of the current content |
| `invocation` | The flags that shaped the run. A flag whose name contains key, token, secret or password is recorded as `<redacted>` |
| `ignorePolicy` | Scope mode, the digest of the effective ignore rules and whether tracked-file semantics applied |
| `rules` | The ruleset version and where it came from |
| `model` | Provider, model, egress and per-stage status when a model was used, otherwise `configured: false` |
| `capability` | The scan health status and the number of recorded conditions |
| `fileCounts` | Files scanned, included and skipped |
| `elapsedMs` | Wall-clock time |

## Finding record (`record`, schema `finding-record/1`)

| Field | Meaning |
|---|---|
| `stableId` | The finding's stable identity, unchanged by a harmless line shift |
| `path`, `sourceHash`, `span` | The file, the SHA-256 of the content that was scanned, and the line range from source to sink |
| `ruleFamily`, `ruleVersion` | The rule family and the scanner version that produced it |
| `originalSeverity`, `confidence` | Kept separate from disposition |
| `disposition` | `confirmed`, `needs-review`, `refuted`, `hardening` or `unvalidated` |
| `evidence` | Source-to-sink, guards found, and the missing evidence the disposition names |
| `reviewerVerdicts`, `modelOpinion` | Reviewer verdicts and the model's opinion, each kept apart from the disposition |
| `remediation` | The suggested fix text |

## What it does not claim

- A clean tree with a recorded commit says which code was scanned. It does not say the scan was complete; read `capability` and the coverage record for that.
- `sourceHash` is the hash of the content the scanner read. It is not a signature. Use an attestation bundle for a signed record.
- `reconcileFindings` in `src/pipeline/evidence-record.js` checks that raw and displayed counts differ only by named reasons.
