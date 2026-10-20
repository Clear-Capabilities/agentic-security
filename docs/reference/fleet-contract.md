# Fleet: manifest and result contract

<!-- seo: title="Fleet contract: the manifest keys, the run output and the enterprise graph" description="The frozen manifest keys, the fleet scan and status output fields, the assurance values and the enterprise graph record, with the limits of a declared-package-name fleet." -->

**Maturity:** Preview

This page freezes the shapes a fleet run reads and writes: the manifest you declare, the output of `fleet scan --json` and `fleet status --json`, and the enterprise graph file. A compatibility test (`scanner/test/contracts/fleet.contract.test.js`) runs a real fleet scan over two fixture repositories and holds each shape to the tables below in both directions, so a key cannot be added or removed without changing this page. How to use fleet is in the [Fleet guide](../guides/fleet.md).

## The manifest

The manifest is validated closed-world: any key not listed here refuses the whole manifest.

**Manifest keys**

| Key | Meaning |
|---|---|
| `organization` | Required. The organization name |
| `repositories` | Required, non-empty. The repositories to scan |
| `resources` | Things that are not repositories: queues, databases, gateways, external providers |
| `workers` | Parallel scans, 1 to 32 (default 4) |
| `retries` | Extra attempts for a failed or timed-out repository, 0 to 5 (default 1) |
| `perRepoTimeout` | A duration such as `20m` (default 20 minutes) |

**Repository keys**

| Key | Meaning |
|---|---|
| `id` | Required. Lower-case kebab-case, unique across repositories and resources |
| `path` | Required. A directory |
| `required` | `false` means its problems do not turn the organization red (default `true`) |
| `kind` | `service`, `library`, `frontend`, `worker` or `gateway` |
| `internetFacing` | A boolean you declare |
| `environment` | `production`, `staging` or `development` |
| `dataClasses` | Data class names such as `pci` |
| `trustZone` | A name |
| `calls` | Repositories or gateways this one calls |
| `produces` | Queues it writes to |
| `consumes` | Queues it reads from |
| `reads` | Databases it reads |
| `writes` | Databases it writes |
| `providers` | External providers it uses |
| `aliases` | Up to 16 host or code names so the code search can recognise it |

**Resource keys**

| Key | Meaning |
|---|---|
| `id` | Required, unique |
| `kind` | Required: `queue`, `database`, `external-provider` or `gateway` |
| `dataClasses` | Data class names |
| `trustZone` | A name |
| `internetFacing` | A boolean you declare |
| `environment` | `production`, `staging` or `development` |
| `aliases` | Up to 16 names |

## Run output

`fleet scan --json` prints the first table; `fleet status --json` prints the `runId`, `health` and `jobs`.

**Scan output**

| Field | Meaning |
|---|---|
| `runId` | The run |
| `health` | Whether the organization can be trusted (below) |
| `rollup` | Totals across repositories (below) |

**Health**

| Field | Meaning |
|---|---|
| `counts` | `requested`, `complete`, `partial`, `failed`, `timedOut`, `cancelled`, `notRun` |
| `assurance` | `green`, `degraded` or `red` |
| `reasons` | The sentences that explain anything other than `green` |
| `repositories` | One entry per repository (below) |

`green`: every required repository is complete and nothing else is wrong. `degraded`: every required repository has a result, but a result is partial or an optional repository has a problem. `red`: a required repository has no result.

**Health repository**

| Field | Meaning |
|---|---|
| `id` | The repository |
| `required` | From the manifest |
| `state` | `complete`, `partial`, `failed`, `timed-out`, `cancelled` or `not-run` |
| `attempts` | Attempts made |
| `error` | The last error, or `null` |
| `cached` | Whether an unchanged repository's earlier result was reused |
| `findings` | The finding count, or `null` with no result |
| `jobStatus` | The job's own status |
| `finished` | Whether the job reached a final state |

**Rollup**

| Field | Meaning |
|---|---|
| `repos` | Repositories in the manifest |
| `scanned` | Repositories with a result |
| `failed` | Repositories with none |
| `failures` | Who failed and why |
| `total` | Findings across the fleet |
| `proven` | Findings proven by execution |
| `bySeverity` | Counts by severity |
| `reposWithPartialScanHealth` | Repositories whose scan did not cover everything |
| `reposWithPolicyDrift` | Repositories whose policy changed since the last run |
| `provenance` | Time-to-fix figures from Git history |

**Job**

| Field | Meaning |
|---|---|
| `jobId` | `<runId>:<repo>` |
| `repo` | The repository |
| `status` | `queued`, `leased`, `succeeded`, `partial`, `failed`, `timed_out` or `cancelled` |
| `attempts` | Attempts made |
| `worker` | Which worker held it |
| `leaseExpiresAt` | When the lease ends, or `null` |
| `error` | The last error, or `null` |

## The enterprise graph

Written to `.agentic-security/fleet/enterprise-graph.json`, `agentic-security/enterprise-graph` version 1.

**Graph**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/enterprise-graph` |
| `version` | `1` |
| `organization` | From the manifest |
| `nodes` | Repositories, resources and the `internet` node |
| `edges` | Relationships, each with its evidence |
| `digest` | Digest of the nodes and edges |
| `runId` | The run that built it |
| `manifestFile` | The manifest it was built from |
| `findingsByRepo` | Finding locations and counts per repository |
| `codeBoundaries` | What `--lineage` added, or a note that it was not requested |
| `discovery` | What the code search found, or a note that it did not run |
| `builtAt` | When it was built |

**Node**

| Field | Meaning |
|---|---|
| `id` | The repository or resource id |
| `type` | `internet`, `repository`, `queue`, `database`, `external-provider` or `gateway` |
| `kind` | The declared kind |
| `internetFacing` | As declared |
| `environment` | As declared, or `null` |
| `dataClasses` | Declared classes, plus any Code Boundaries found |
| `trustZone` | As declared, or `null` |
| `required` | From the manifest |

A node also carries `discoveredDataClasses` when Code Boundaries added any.

**Edge**

| Field | Meaning |
|---|---|
| `id` | Stable id from type and endpoints |
| `type` | `exposes`, `calls`, `produces`, `consumes`, `reads`, `writes`, `uses-provider`, `connects-to` or `depends-on` |
| `from` | The source node |
| `to` | The target node |
| `reach` | `true` for data or request reach, `false` for a package dependency |
| `evidence` | At least one `{ source, ... }`: `fleet-manifest`, `package-manifest`, `discovered-code-literal` or `code-boundaries` |
| `discovered` | `true` when every piece of evidence is found in code and none is declared |

## Guarantees

- **Every edge has evidence.** A graph with an edge that lacks it is rejected.
- **A relationship is declared, then checked.** An edge found only in code says so (`discovered: true`); it never replaces a declared one.
- **A crashed repository is never folded into "0 findings".** It is `failed` or `not-run` in `health`, and the organization is `red` if it was required.
- **An artifact is checked against the hash the job store recorded** before it is used.

## What fleet does not do

<!-- limits-verified: 2026-10-19 -->

- **It runs on one machine.** There is no remote worker or distributed queue. A lease held by another host is recovered by expiry only.
- **Packages match by declared name.** Two repositories that share a name under different ecosystems are not told apart, and a version pin is matched as text, not resolved.
- **Edge discovery is literal matching** plus a summary of each repository's data flow graph; it cannot follow one data element across a repository boundary.
- **Scan results are summaries.** The store keeps finding locations and counts, not source.
- **Scaling is measured on a small workload.** See the guide for the figures and what they do not say.
