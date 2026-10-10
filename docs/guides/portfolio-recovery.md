# Portfolio recovery

How a multi-repository audit survives a crashed worker, a duplicated message, a changed policy and a missing shared backend,
and how to read its progress without mistaking activity for coverage. Everything runs locally, with no network and no hosted
service. The portfolio store is one JSON file written atomically; there is no server.

**Status: machinery, not evidence.** No real portfolio exists in this repository. Every example uses two synthetic repositories
and a virtual clock.

## The model in one paragraph

A plan splits the **authorized** repositories into work units, one per repository, exact commit and task type, with a stable id
that is a hash of those fields and the unit's required inputs. A repository that is not on the authorization list is excluded and
disclosed, never planned. A unit is `pending`, `leased`, `running`, `verified`, `blocked`, `failed` or `canceled`. A lease has an
expiry. **Only a `verified` unit with a recorded result is progress.** Leased, running, blocked and failed units, an expired
lease and a repeated delivery all leave the count where it was.

## Run the walk-through

```
npm run example:portfolio-recovery
```

About a second, no terminal input, exit 0 when every step behaved as described. The clock is a number the script passes in, so
nothing sleeps. The steps and what it printed:

```text
1. a worker leases a unit and crashes
  t=10ms, worker-1 running and silent: verified 0/2, leased 0, running 1, pending 1, blocked 0, stale results 0

2. the lease expires; another worker takes the unit; the late result of the first is refused
  ok   worker-2 holds wu:56f4602d04cfb86f#0.2 (worker-1 held wu:56f4602d04cfb86f#0.1)
  ok   late result from the expired attempt: stale-attempt

3. a result delivered twice is counted once
  ok   first delivery counted true, duplicate counted false
  after both deliveries: verified 1/2, leased 0, running 0, pending 1, blocked 0, stale results 0

4. a blocked unit is not progress
  blocked: verified 1/2, leased 0, running 0, pending 0, blocked 1, stale results 0
  ok   the blocked unit is reported as blocked, not verified

5. dependency invalidation: the policy digest changes
  resume plan: reuse 0, invalidate 2 (changed: policy)
  after invalidation: verified 0/2, leased 0, running 0, pending 2, blocked 0, stale results 2
  ok   the old results are kept as inspectable stale records
  re-verified under the new policy: verified 2/2, leased 0, running 0, pending 0, blocked 0, stale results 2

6. convergence with a fresh run
  ok   the recovered run and a fresh run have identical scoped results
```

## Recovery cases

| Situation | What happens |
|---|---|
| A worker dies holding a unit | Its lease expires. The next lease request recovers the unit to `pending` (or `failed` once retries are spent), records an `expired` event and issues a new attempt id. Time is an argument, so recovery is tested without sleeping. |
| The dead worker reports late (a zombie) | Refused as `stale-attempt`: the result is discarded, because a stale worker must not displace its successor's. |
| The same completion arrives twice | Acknowledged and counted once. Operations are idempotent by attempt id. |
| The same lease request arrives twice | The same lease comes back; no second unit is leased. |
| A unit cannot proceed (missing input) | It is parked as `blocked` with a reason, is not progress, and independent units still run. Unblocking returns it to `pending`. |
| A cancellation | A scope (a unit, a repository, or all) is recorded in the ledger so a process that did not receive the call still honours it, in-process attempts are aborted, and a lease is released only when the attempt settled with no surviving child process. Verified units and receipts are untouched, and the report says it is incomplete. An empty scope is refused, never read as cancel-all. |
| A shared backend is unavailable | A typed `blocked` state. There is deliberately no fallback to a local write, so two workers can never silently write concurrently. |
| The store file is damaged | It fails verification and is an error. It is never silently reset to empty. |

## Dependency invalidation

Every verified result records one digest for each of six dimensions: code, policy, graph, invariant, oracle and toolchain. On
resume the current digests are compared dimension by dimension. A match keeps the unit verified. Any difference invalidates it:
the old result moves to a `stale` list (still inspectable, with the changed dimensions), the unit returns to `pending` in a new
generation, and every claim that depends on the unit is marked stale. A stale result never counts toward completion. A change
only to the graph can be narrowed with the boundary drift plan: a unit is kept only when the plan is complete and every
hypothesis the unit covers is shown untouched by the change; an incomplete plan, an unbound hypothesis or a unit with no
hypotheses invalidates. The narrowing fails closed.

## Reading progress

```
agentic-security portfolio progress --store store.json
```

The command is off unless the `portfolio-assurance` feature is on; the walk-through enables it for its own child process with
`AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE=1`. The view it printed for the finished walk-through:

```text
Portfolio progress (SYNTHETIC; as of 1791583557916): 2/2 unit(s) verified; 2/2 repositories fully verified
  Not verified: 0 blocked, 0 failed, 0 canceled, 0 stale, 0 pending, 0 in flight
  Workers: 0 live, 0 stale or silent (stale after 15000 ms without a heartbeat)
  Budget: not declared to this view
  Pending human review: 0
  Every planned unit is verified (2 of 2) in 2 of 2 repositories. That means the planned checks completed; it does not mean every repository passed (findings were not supplied to this view).
  This does not mean the software is safe or free of vulnerabilities, and a signature on it is not independent certification.
```

The view keeps apart verified units (the only progress), blocked, failed, canceled and stale units with their reasons,
per-repository coverage, per-limit budget (used, reserved, remaining; an unenforced limit says so), pending human review, and every
worker with its age. A worker is `stale` after 15 seconds without a heartbeat. Findings are aggregated by stable identity only,
every occurrence is kept, and a finding with no stable id is listed apart, never merged. A finished controller is reported as
finished, never as passed. The same view is served read-only by the MCP tool `portfolio_progress`.

## Budgets and fairness

Scheduling is bounded at two levels (the portfolio and each repository) on wall time, provider spend, requests and storage, plus
concurrency. A unit with no estimate is not leased, because unknown is never zero. A unit that would exceed a limit is refused as
`at-capacity` (a wait) or `exhausted` (it will not recover), and a refusal changes nothing. Priority is a weight from 1 to 8, never
an order: the next lease goes to the admissible repository with the lowest leases-granted-per-weight, so a large repository cannot
starve a small one. A repository that is blocked is skipped with a reason and never waited on.

## Retention, legal hold and offline operation

```
agentic-security portfolio retention plan --records records.json --root ./evidence
agentic-security portfolio backend probe --mode local --dir ./store
agentic-security portfolio export --store store.json --out state.json
```

Retention works by class: replay evidence, metadata, model traces and secrets, with defaults and ceilings. A required current
receipt is never deleted (an expired one is reported as expired but required). A legal hold, by id, class or repository, blocks
deletion; a malformed hold refuses the whole plan. `plan` deletes nothing. `apply` needs a log and an actor, writes each deletion
to a hash-chained log before removing the file, and exits 1 if anything it should have removed could not be. The log holds digests
and sizes, never content. The local backend supports durable restart and offline export; a customer-operated shared backend
supports leases with a fenced token, tested with real processes. **Not claimed:** safety on a network file system (the backend
reports it `unverified` and you must verify atomic exclusive create on that mount), agreement between clocks of different hosts,
and race-free recovery of a stale lock in a narrow window. None of it needs a hosted service.

## Unsupported platforms for enforcement

Portfolio coordination does not depend on the enforcement backend, but a work unit that runs a task under capability
enforcement does: **Linux is partially verified (only what the hosted `sandbox-linux` job proved; mediated network and process-count caps remain unverified) and macOS is host-proved only.** The capability runner returns a typed `blocked` result
naming the missing control when the backend it needs is not available, and the target never executes. A unit parked as `blocked`
on that result is not progress, whatever else the portfolio completes. See the
[capability matrix](../reference/assurance-capability-matrix.md).

Next: [assurance review](assurance-review.md) for what to do with a finished portfolio's evidence.
