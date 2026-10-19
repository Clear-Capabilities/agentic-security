# Fleet: scan an organization, resume it, and ask what a flaw can reach

**Maturity:** Labs. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

**Status: new.** The unit of analysis is a declared set of repositories. One manifest, one command, one honest account of what
was and was not scanned, and answers to the questions an organization actually asks about a shared flaw. Everything runs on your
own machine from a local database; there is no server and no account.

## What it is made of

* **A job store** (SQLite, `.agentic-security/fleet/fleet.db`). One idempotent job per repository, with a lease, a heartbeat, a retry
  count, a timeout, and the hash of its result. The store sits behind a small interface; the conformance tests run the same
  assertions against an in-memory implementation and the SQLite one, which is what shows a PostgreSQL or queue-backed store could
  take its place. None is built.
* **A controller** that plans the run, leases jobs to bounded workers, and runs each repository's scan in its own supervised child
  process under a hard timeout. One hung repository costs one worker one timeout and nothing else.
* **A content-addressed cache.** A repository's result is reused only when its commit (and any uncommitted change), its lockfiles,
  the scan configuration and the scanner build are all unchanged. Anything that cannot be determined means no caching.
* **An enterprise graph** that joins package dependencies, declared service calls, queues, databases and external providers, with
  the evidence for every edge.
* **Organization health** that cannot be green while a required repository has no result.

## The manifest

```yaml
# fleet.yaml
organization: acme
workers: 3          # parallel scans (1 to 32)
retries: 1          # extra attempts for a failed or timed-out repository (0 to 5)
perRepoTimeout: 20m
resources:          # things that are not repositories
  - { id: edge-gateway, kind: gateway, internetFacing: true, environment: production }
  - { id: payments-queue, kind: queue, environment: production }
  - { id: card-db, kind: database, dataClasses: [pci], environment: production, trustZone: cardholder }
repositories:
  - { id: frontend, path: ./org/frontend, kind: frontend, internetFacing: true, environment: production, calls: [edge-gateway, payments-api] }
  - { id: payments-api, path: ./org/payments-api, kind: service, environment: production, dataClasses: [pci], produces: [payments-queue] }
  - { id: shared-auth-lib, path: ./org/shared-auth-lib, kind: library }
  - { id: payments-worker, path: ./org/payments-worker, kind: worker, environment: production, dataClasses: [pci], consumes: [payments-queue], writes: [card-db] }
  - { id: ledger-db-client, path: ./org/ledger-db-client, kind: library, required: false }
```

The manifest is validated closed-world: an unknown key, a duplicate id, a path that is not a directory, or a reference to something
that does not exist (or is the wrong kind: you cannot `produces` into a database) refuses the whole manifest. `required: false`
marks a repository whose problems should not turn the organization red.

**These relationships are declared, and then checked against the code.** `calls`, `produces`, `consumes`, `reads`, `writes`,
`providers` and `internetFacing` come from you, and every edge built from them says `source: fleet-manifest`. Dependency edges come
from each repository's own package manifest and say so. After a scan, the code is searched for a few exact patterns that name
another node (see "Edges found in code" below); anything it finds is a separate kind of edge, marked as found only in code unless
you also declared it. Give a node `aliases:` (hostnames or names its code uses) so the search can recognise it.

## Scan

```
$ agentic-security fleet scan fleet.yaml
[fleet] planning 5 repository(ies) for acme (3 worker(s), 1 retry, 1200s per repository)...
[fleet] done: ledger-db-client
[fleet] done: payments-api
[fleet] done: frontend
[fleet] done: payments-worker
[fleet] done: shared-auth-lib
5 repo(s) scanned, 7 finding(s) (1 critical, 2 high, 4 low), 0 execution-proven. PROVENANCE: no proven-origin findings across the fleet; 5 repo(s) with no complete-status provenance.

Run: frun-7e95015368025c8a
Repositories requested: 5
Complete: 5
Partial: 0
Failed: 0
Timed out: 0

Assurance: GREEN
```

Progress lines go to stderr; the report goes to stdout. The exit code is `0` only when the organization is GREEN. `fleet scan`
accepts `--workers N`, `--retries N`, `--timeout-seconds N` (or `--timeout-ms N`) and `--no-cache`.

## Organization health

| Assurance | Meaning |
|---|---|
| GREEN | every required repository has a complete result, and no optional repository has a problem |
| DEGRADED | every required repository has a result, but some result is partial or an optional repository has a problem |
| RED | at least one required repository has no result: failed, timed out, cancelled, still queued, or never planned |

Every requested repository is counted under exactly one heading, so a repository that fails cannot shrink the denominator. A
`partial` result means the scan finished but the engine itself reported a degraded scan; that is not evidence of a clean repository.

## When something goes wrong, and resume

```
$ agentic-security fleet scan fleet.yaml --timeout-ms 100 --retries 0 --no-cache   # a limit no real scan can meet
Run: frun-22fa9195e66d8b9c
Repositories requested: 5
Complete: 0
Partial: 0
Failed: 0
Timed out: 5

Assurance: RED
  4 required repositories have no result: frontend (timed-out), payments-api (timed-out), shared-auth-lib (timed-out), payments-worker (timed-out)
  1 optional repository has a problem: ledger-db-client (timed-out)

Retry the failed and timed-out repositories with: agentic-security fleet resume frun-22fa9195e66d8b9c --retry-failed
```

```
$ agentic-security fleet resume frun-22fa9195e66d8b9c --retry-failed --timeout-seconds 120
[fleet] resuming frun-22fa9195e66d8b9c: 5 unfinished, 0 lease(s) recovered, 5 failed repository(ies) re-queued; finished results are reused.
5 repo(s) scanned, 7 finding(s) (1 critical, 2 high, 4 low), 0 execution-proven. PROVENANCE: no proven-origin findings across the fleet; 5 repo(s) with no complete-status provenance.

Run: frun-22fa9195e66d8b9c
Repositories requested: 5
Complete: 5
Partial: 0
Failed: 0
Timed out: 0

Assurance: GREEN
```

`fleet resume <run-id>` continues a run. It recovers jobs held by a worker process on this machine that no longer exists, lets
other leases expire on their own, runs what is still queued, and reuses every finished result. Failed and timed-out repositories
are re-queued only with `--retry-failed`. A limit given on the resume command applies to the work still to do. A manifest that has
changed since the run was planned is refused: a resumed run must scan what it planned.

The guarantees underneath are tested with two real processes racing on the database, a controller killed with SIGKILL mid-run, and
a worker whose lease expired while it was still scanning:

* a job is handed to one worker at a time;
* a worker that lost its lease is fenced out (its late result is refused and its scan is told to stop), so a retry never produces a
  second set of findings for one repository;
* results are written per attempt and the job points at the winning one, and every result is checked against its recorded hash
  before it is used.

## Questions about a flaw

Blast radius of a shared component, with counts:

```
$ agentic-security fleet query --blast-radius shared-auth-lib
shared-auth-lib

Used by:
3 repositories
1 Internet-facing service
3 production apps
2 PCI-scoped services
```

Pinned to a version, repositories that pin something else are excluded, and a repository reached only through an excluded one is
not counted:

```
$ agentic-security fleet query --blast-radius shared-auth-lib --version abc123
shared-auth-lib@abc123

Used by:
1 repository
1 Internet-facing service
1 production app

Excluded, their pinned version does not match: payments-api
```

Internet-facing paths to regulated data, hop by hop. The query below is the one sentence shape the command recognises; it is mapped
to `--internet-to pci --involving-vulnerable auth`, which you can also type directly. "Vulnerable authentication code" means the
repositories whose scan produced an authentication finding, plus everything that depends on them:

```
$ agentic-security fleet query "Show every Internet-facing path to PCI data involving vulnerable authentication code"
Internet -> frontend -> payments-api
    involves vulnerable code: frontend (depends on shared-auth-lib), payments-api (depends on shared-auth-lib)
Internet -> frontend -> payments-api -> payments-queue -> payments-worker
    involves vulnerable code: frontend (depends on shared-auth-lib), payments-api (depends on shared-auth-lib), payments-worker (depends on payments-api)
Internet -> frontend -> payments-api -> payments-queue -> payments-worker -> card-db
    involves vulnerable code: frontend (depends on shared-auth-lib), payments-api (depends on shared-auth-lib), payments-worker (depends on payments-api)

3 path(s). Reach edges are as declared in the fleet manifest.
```

`--involving-vulnerable` also takes a repository id. Anything that is not that sentence is refused with the flags to use; this is
not a natural-language engine. Path searches are bounded (depth 8, 200 paths) and say so when a bound is reached.

The older dependency query still works:

```
$ agentic-security fleet query --depends-on shared-auth-lib
Repositories depending on shared-auth-lib (directly or transitively):
  frontend  (depth 1, via frontend)
  payments-api  (depth 1, via payments-api)
  payments-worker  (depth 2, via payments-api -> payments-worker)
```

`fleet explore --out graph.html` writes a single static page listing every node and every edge with its evidence. It has no script
and needs no server.

## Edges found in code

`fleet scan` reads each repository's source and configuration text for: a URL literal whose host is a node's id or alias (or whose
first label is, so `payments-api` matches `payments-api.svc.cluster.local`); a queue's name on a line that publishes to it or on one
that consumes from it; a database's name on a line that opens a connection. Each hit is an edge with the file and line, tagged
`source: discovered-code-literal`. It sits beside a declared edge of the same shape rather than replacing it. `fleet edges
--undeclared` lists the ones you did not declare, and an attack path that depends on one says so:

```
agentic-security fleet edges --undeclared
agentic-security fleet query --internet-to pci
```

The search matches whole tokens (`orders` never matches `reorders`), skips comment lines, `node_modules`, build output and symlinks,
keeps no credential from a connection string, and is bounded in files and bytes (a truncated repository says so). It sees literals
only: a URL built at run time, read from the environment or routed by a service mesh is not found, and the direction of a database
use is unknown, so those are `connects-to` edges. A discovered edge is a lead with evidence, not a confirmed call. `--no-discover`
turns the search off.

## Code Boundaries, from the code itself

`fleet scan --lineage` runs each repository's scan with the Data Flow Explorer's own data flow graph (Code Boundaries) and folds a
bounded summary of it into the enterprise graph: the data classes the code handles, the hosts it sends data to, the queue topics it
publishes or consumes, and the stores it connects to. The whole graph is not copied. It adds to what the manifest says and never replaces
it; every edge it contributes carries `source: code-boundaries` evidence, and an edge that both the code literals and Code Boundaries
agree on has both. In this three-repository example the manifest never said the API handles payment data or calls the ledger:

```
agentic-security fleet scan fleet.yaml --lineage
...

Assurance: GREEN

Code Boundaries: 3 repositories contributed a data flow graph. Data classes found in code but not declared: api (pci).

Edges found in code: 1 not in the manifest, 0 matching a declared edge. List them with: agentic-security fleet edges --undeclared
```

```
agentic-security fleet query --internet-to pci
Internet -> web -> api
    reaches pci data only because the code shows it, not the manifest: api

1 path(s). Reach edges are as declared in the fleet manifest, plus any marked above as found only in code.
```

```
agentic-security fleet edges --undeclared
api -[calls]-> ledger  FOUND ONLY IN CODE  (index.js:5, code boundaries: ledger.internal)
```

A path that exists only because of a data class the code shows (not the manifest) says so, so a reader can tell a declared exposure
from an inferred one. Slower than a plain scan (it builds the graph for every repository), so it is opt-in; the choice is remembered on the
run, so `fleet resume` does the same thing. A destination, topic or database is joined to a node only when its name is that node's id or a
declared `aliases:` entry.

`fleet status` and `fleet resume` accept either a run id or the id of one of its jobs (`fleet status frun-1234abcd:payments-api`): a job
id resolves to the run it belongs to.

## Commands

```bash
agentic-security fleet init
agentic-security fleet scan fleet.yaml [--workers N] [--retries N] [--timeout-seconds N] [--no-cache] [--no-discover] [--lineage]
agentic-security fleet status [run-id]
agentic-security fleet resume <run-id|manifest.yaml> [--retry-failed]
agentic-security fleet query --blast-radius <component> [--version <pin>]
agentic-security fleet query --internet-to <data-class> [--involving-vulnerable auth|<repo-id>]
agentic-security fleet query --depends-on <repo-id>
agentic-security fleet query "Show every Internet-facing path to PCI data involving vulnerable authentication code"
agentic-security fleet edges [--undeclared] [--json]
agentic-security fleet explore [--out graph.html]
```

## Output schema

`fleet scan --json` and `fleet status <run-id|job-id> --json` print the run and its jobs. The health block is the same one the text report
shows:

```json
{
  "runId": "frun-f382cd7e8f719609",
  "health": {
    "counts": { "requested": 3, "complete": 3, "partial": 0, "failed": 0, "timedOut": 0, "cancelled": 0, "notRun": 0 },
    "assurance": "green",
    "reasons": [],
    "repositories": [ { "id": "web", "state": "complete", "required": true } ]
  },
  "jobs": [ { "jobId": "frun-f382cd7e8f719609:web", "repo": "web", "status": "succeeded", "attempts": 1, "worker": "host:4242:0", "leaseExpiresAt": null, "error": null } ]
}
```

`assurance` is `green` (every required repository complete, nothing else wrong), `degraded` (every required repository has a result, but
some result is partial or an optional repository has a problem) or `red` (a required repository has no result). The enterprise graph is
written to `.agentic-security/fleet/enterprise-graph.json` (`agentic-security/enterprise-graph` version 1): `nodes` (`id`, `type`, `kind`,
`internetFacing`, `environment`, `dataClasses`, `trustZone`, `required`, and `discoveredDataClasses` when Code Boundaries added any), `edges`
(`id`, `type`, `from`, `to`, `reach`, `discovered`, and an `evidence` list of `{source, ...}` where `source` is `fleet-manifest`,
`package-manifest`, `discovered-code-literal` or `code-boundaries`), `discovery`, `codeBoundaries`, `runId` and a `digest`. Every edge has at
least one evidence entry; a graph without that is rejected. Per-repository results are artifacts under `.agentic-security/fleet/artifacts/<run-id>/`,
each checked against the hash the job store recorded before it is used.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `Assurance: RED` though the code looks fine | A required repository has no result: failed, timed out, cancelled or never ran. `Reasons` names them. `fleet resume <run-id> --retry-failed` re-runs only those. Mark a repository `required: false` only if its absence really should not turn the organization red. |
| `Invalid fleet manifest: ...` | The manifest is validated closed-world: an unknown key, a duplicate id, a path that is not a directory, or a reference to a missing or wrong-kind node refuses the whole file. The message names the line to fix. |
| `Nothing to resume for that manifest` | No run of that manifest has unfinished work. Resume by run id (or job id) with `--retry-failed` to retry failures. |
| `The manifest ... has changed since run ... was planned` | A resumed run must scan what it planned. Start a new run with `fleet scan`. |
| `No Internet-facing path to X data` but you expect one | Reach edges are what the manifest declares, plus what the code literals and (with `--lineage`) Code Boundaries show. Declare the call, or give the target node an `aliases:` entry so the code's hostname can be joined to it, then `fleet scan` again. |
| `No node in the fleet manifest is marked as holding X data` | Nothing declares that class. Add `dataClasses:` to the node, or scan with `--lineage` so the code can show it. |
| A repository shows a result that is not from today | It was served from the content-addressed cache because its commit, lockfiles, configuration and the scanner build are unchanged. `--no-cache` forces a fresh scan. |
| The run died when the controller was killed | Leases expire and `fleet resume` recovers jobs held by a dead worker on this host. Another host's leases are recovered only by expiry. |
| `fleet` fails to start with a SQLite error | The job store uses `node:sqlite` (this project requires Node 24 or newer). |

## What is not built

* **No PostgreSQL or remote-worker store, and no distributed queue.** The interface allows them; one machine's SQLite file is what
  exists. Leases on another host are recovered by expiry only.
* **Edge discovery is literal matching, plus a summary of each repository's data flow graph.** The literal search reads string and URL
  literals (see "Edges found in code"). With `--lineage` the Data Flow Explorer's per-repository graph contributes data classes and
  destinations; it is summarized, not joined node for node, so the enterprise graph cannot follow a single data element across a
  repository boundary.
* **Dependency matching is by declared package name.** Two repositories that share a name under different ecosystems are not
  disambiguated, and a version pin is matched as text (a commit id or version string appearing in the pinned spec), not resolved.
* **`fleet explore` is a static listing, not the Data Flow Explorer.** No graph drawing, no filtering.
* **Scan results are summaries.** The store keeps each repository's finding locations and counts, not source code.
* **Scaling is measured once, on one machine, on a toy workload.** `node bench/fleet-scale/run.mjs` scans 24 synthetic repositories
  (6 small files each, cache off) with 1, 2, 4 and 8 workers. Captured on an 8-logical-core Apple M2: 14.6 s, 8.14 s, 4.9 s and
  4.56 s, a 1.00x, 1.79x, 2.98x and 3.20x speedup, which is 100%, 90%, 74% and 40% parallel efficiency. So it is close to linear
  at 2 workers, clearly sub-linear at 4, and past that the extra workers buy little on this hardware (an M2 has 4 performance and 4
  efficiency cores, and each scan spawns its own Node process). That is the job fabric on tiny repositories; it says nothing about
  real repositories, where scan time dominates and "near-linear scaling" is not a claim this repository can make.
