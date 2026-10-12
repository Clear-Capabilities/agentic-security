# Fleet: organization-wide scanning and blast radius

**Status: new.** Turns the unit of analysis from one repository into a declared set of them: one manifest, one
invocation, one rolled-up result — and a real, grounded answer to "if this shared library had a flaw, which other
repositories in my organization would be affected, and how?"

## What this reuses, and what is new

The scanning half is entirely the EXISTING `posture/fleet.js` (`runFleet`): bounded concurrency, a resumable
on-disk checkpoint, per-repository isolation (one repo exploding never takes the run down), and an honest rollup
(a failed repo is reported failed, never folded into "0 findings"). What was missing was a declarative manifest to
drive it and a way to reason across repositories rather than within one. Those two things are new:

- `fleet.yaml` — repository list, in a plain YAML format, validated closed-world.
- A cross-repository **dependency graph**, built purely from each repository's own package manifest
  (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `pyproject.toml`) — no deployment configuration
  (Kubernetes manifests, Terraform, compose files) is required, so a fleet of plain application repositories works
  immediately. This is intentionally lighter-weight than, and does not touch, the existing deployment-boundary
  graph (`lineage/deployment/`), which models network/identity/tenant trust zones from actual deployment config
  and remains the right tool when that config exists.

## Quickstart

```yaml
# fleet.yaml
organization: acme
repositories:
  - id: frontend
    path: ../frontend
  - id: payments-api
    path: ../payments-api
  - id: shared-auth-lib
    path: ../shared-auth-lib
  - id: payments-worker
    path: ../payments-worker
workers: 4
perRepoTimeout: 20m
```

```bash
agentic-security fleet init          # writes a starter fleet.yaml
agentic-security fleet scan fleet.yaml
```

```
[fleet] scanning 4 repository(ies) for acme (2 worker(s))...
[fleet] done: payments-api (1 finding(s))
[fleet] done: frontend (1 finding(s))
[fleet] done: shared-auth-lib (3 finding(s))
[fleet] done: payments-worker (1 finding(s))
4 repo(s) scanned, 6 finding(s) (1 critical, 1 high, 4 low), 0 execution-proven. PROVENANCE: no proven-origin findings across the fleet; 4 repo(s) with no complete-status provenance.

Repositories requested: 4
Complete: 4
Failed: 0
```

A second invocation resumes rather than re-scanning repositories the checkpoint already marked complete
(`fleet resume fleet.yaml` makes that explicit; `fleet scan` already resumes by default).

## Blast radius: "which repositories depend on this one"

```bash
agentic-security fleet query --depends-on shared-auth-lib
```

```
Repositories depending on shared-auth-lib (directly or transitively):
  frontend  (depth 1, via frontend)
  payments-api  (depth 1, via payments-api)
  payments-worker  (depth 2, via payments-api -> payments-worker)
```

This is a real captured run: `shared-auth-lib` has a command-injection vulnerability the deterministic engine
actually finds (not asserted away in a fixture), `frontend` and `payments-api` declare it as a direct dependency,
and `payments-worker` reaches it only transitively, through `payments-api` — the query correctly reports it at
depth 2 with the full path. `--json` gives the same answer machine-readably:

```bash
agentic-security fleet query --depends-on shared-auth-lib --json
```

```json
{
  "target": "shared-auth-lib",
  "blastRadius": [
    { "id": "frontend", "depth": 1, "path": ["shared-auth-lib", "frontend"] },
    { "id": "payments-api", "depth": 1, "path": ["shared-auth-lib", "payments-api"] },
    { "id": "payments-worker", "depth": 2, "path": ["shared-auth-lib", "payments-api", "payments-worker"] }
  ]
}
```

## Status

```bash
agentic-security fleet status
```

```
4 repo(s) scanned, 6 finding(s) (1 critical, 1 high, 4 low), 0 execution-proven. PROVENANCE: no proven-origin findings across the fleet; 4 repo(s) with no complete-status provenance.
```

`fleet status` reads the last rollup without re-scanning. `Complete`/`Failed` in `fleet scan`'s own output states the
organization-level completeness the PRD asks for directly: a repository that failed to scan is counted as failed,
never silently dropped from the denominator.

## What this does not do (yet)

- **Matching is by declared package name only.** Two repositories that happen to declare the same name under
  different ecosystems are not disambiguated — a disclosed limit, not a guess. `fleet-graph.js`'s own tests pin
  this.
- **No "Internet-facing" or "reaches regulated data" overlay.** The PRD's fuller example query ("show every
  Internet-facing application that can reach regulated data through this vulnerable shared component") needs the
  deployment-boundary graph's trust-zone model (`lineage/deployment/`) layered on top of this dependency graph —
  genuinely more work, not done here. `fleet query` today answers the dependency-reachability half only.
- **No natural-language query parser.** `--depends-on <repo-id>` is the one supported query shape; there is no
  general NLU layer translating arbitrary questions into graph queries.
- **No SQLite-backed job store.** The PRD asks for one as the initial storage with an abstraction allowing
  Postgres/remote workers later; this reuses the existing flat-JSON checkpoint (`posture/fleet.js`) instead. The
  existing `posture/portfolio/backend.js` abstraction (probe/lease/local-or-shared backend) is the natural place to
  add a SQLite implementation later, but that integration is not done.
- **Concurrency is in-process** (bounded `Promise.all` workers over `runFleet`), not a persisted, independently
  resumable job queue with lease/retry semantics — `posture/portfolio/work-units.js`/`scheduler.js` already have
  that machinery for a different, heavier surface; this feature deliberately uses the lighter-weight tool.

## Reference

- Module: `scanner/src/posture/fleet/` (`fleet-manifest.js`, `fleet-graph.js`, `cli.js`), reusing
  `scanner/src/posture/fleet.js`.
- Tests: `scanner/test/fleet/{fleet-graph,fleet-manifest,fleet-cli}.test.js` (`npm run test:posture`); the CLI test
  is the killer scenario, against a real spawned CLI and a real deterministic finding.
- Implementation status: [`docs/implementation-status/fleet.md`](../implementation-status/fleet.md)
