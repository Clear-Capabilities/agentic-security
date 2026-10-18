# Implementation status: Organization-Wide Security Graph + Distributed Scan Fabric (PRD 4)

**Percent complete:** all nine P0 requirements are implemented and tested, bounded as described under "Honest limits". The PRD's
storage abstraction is delivered as an interface with two implementations (SQLite and in-memory), not with PostgreSQL or remote
workers, which the PRD names as future work.

**Current phase:** G (completion): unit, integration, adversarial, multi-process and end-to-end tests pass.

**Branch:** `feature/moat-prd6-eval-lab` (carries PRDs 4 gap-closure, 6 and 7).

## Requirement to evidence

| Requirement | Where | Evidence |
|---|---|---|
| 1. Fleet manifest (organization, repositories, workers, perRepoTimeout) plus the metadata the graph needs | `fleet/fleet-manifest.js` | `test/fleet/enterprise-graph.test.js` (closed-world validation, references must resolve and fit) |
| 2. Distributed job model (job id, repo, commit, status, worker, lease, heartbeat, retry count, timeout, artifacts, hashes), idempotent | `fleet/job-store.js` | one conformance suite run against both stores; idempotent enqueue; a two-process claim race on the SQLite file |
| 3. Resumability: `fleet resume`, finished valid results reused | `fleet/job-runner.js`, `fleet/cli.js` | a controller killed with SIGKILL mid-run is resumed to GREEN with one job per repository; dead-worker recovery; manifest-changed refusal |
| 4. Bounded parallelism; one hung repository must not stop the fleet | `fleet/job-runner.js`, `fleet/scan-child.js` | peak concurrency asserted; a hung scan times out in its own child and the rest finish; `--timeout-ms 100` makes every real scan time out and the org RED |
| 5. Content-addressed cache; scanner changes invalidate | `fleet/scan-cache.js` | commit, dirty tree, untracked file, lockfile, configuration, scanner build and unknown inputs each invalidate; an edited record is a miss |
| 6. Enterprise graph federating repositories, APIs, queues, databases, dependencies, data, providers and trust zones; every edge keeps its evidence | `fleet/enterprise-graph.js` | `validateEnterpriseGraph` (no edge without evidence), checked on every query |
| 7. Cross-repository attack paths (Internet -> gateway -> API -> queue -> worker -> card database) | `attackPaths` | the PRD chain, hop by hop with each edge's evidence; a service nothing exposes is on no path |
| 8. Shared-component blast radius with counts (repositories, Internet-facing, production, PCI-scoped), version aware | `componentBlastRadius` | counts asserted; a pin that does not name the version is excluded and anything reached only through it is not counted |
| 9. Organization scan health; cannot be green while required repositories are missing | `fleet/org-health.js` | every requested repository is counted under one heading (1,250 example); queued, cancelled, failed, timed out and never-planned repositories all make it RED |
| Definition of done: one command answers which Internet-facing applications reach regulated data through code depending on a vulnerable shared component | `fleet query "Show every Internet-facing path to PCI data involving vulnerable authentication code"` | five-repository organization with a real command-injection finding in the shared library; captured in the guide |

## Honest limits

* **Reach edges are declared in the manifest.** Calls between services, queue producers and consumers, database access and
  Internet exposure come from the operator, and every such edge says `source: fleet-manifest`. Dependency edges come from package
  manifests. Edges implied by code but not declared are not found; the per-repository Data Flow Explorer graph has them and is not
  joined in.
* **"Vulnerable authentication code" is a selection, not an analysis.** It is the repositories whose scan produced an authentication
  finding (an authentication-class CWE or family) plus everything that depends on them.
* **One question shape.** The documented sentence is recognised and mapped to the structured query; nothing else is parsed.
* **Storage is SQLite on one machine.** No PostgreSQL store, no distributed queue, no remote workers. A lease held on another host is
  recovered by expiry only.
* **Dependency matching is by declared package name**, and a version pin is matched as text.
* **`fleet explore` writes a static listing**, not the interactive Data Flow Explorer.
* **Scaling is not benchmarked.** "Near-linear worker scaling within the supported range" is a PRD metric this change does not
  measure; the protocol's correctness under concurrency is what is tested.
* **A source checkout never reuses a cached result** (no built bundle, no scanner identity); an installed or built scanner does.

## Also changed

* Dependency edges now carry the pinned spec and the manifest file they came from. Existing queries are unchanged.
* `fleet scan` no longer writes into a scanned repository (the scan child runs with state writes disabled).

## Blockers

None.

## Last verified commands

* `cd scanner && node --test test/fleet/*.test.js`
