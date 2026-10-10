# Operating the background controller

How to start the supervised background controller for a finite run, watch it, pause it, cancel it, recover from a blocked run,
see what happens when a file it depends on changes, and finish with a final verification. This page is a walk-through you can
run; the full command reference and the profile fields are in the [loop runbook](loop-engineering.md).

**What this is.** `scripts/loop-engineering/run.mjs` is this repository's own development tool, not part of the shipped scanner.
It works through the requirements of a document one at a time, launches one worker per requirement, and counts only evidence
that it issued or that you ran yourself. It never pushes, publishes, deploys or merges, and it runs one editing worker at a time.

**It is finite.** Every run is bounded by the profile's limits and stops in a stated status when one is reached. A stop is a
truthful checkpoint, not a failure to be looped past. Nothing here promises unattended completion.

## Run the walk-through

```
npm run example:controller
```

It builds a disposable repository in the OS temp folder with two requirements and a scripted worker (the controller's own test
harness, so no model is called, no account is needed and nothing is spent), drives the real controller as an operator would, and
removes everything at the end. It takes about ten seconds, every step has a hard timeout, and nothing reads from a terminal. It
exits 0 when every step behaved as described. Its output, trimmed to the lines that matter:

```text
== finite background start, live status, pause, resume ==

$ node scripts/loop-engineering/run.mjs start --background --serve 127.0.0.1:0
    | run ID:        run-20261009T220439Z-6d3168
    | controller PID: 16213
    | dashboard:     http://127.0.0.1:58346
    | verified completion: 0%  (0/3 weight, 0/2 requirements, 0/2 criteria; manifest v1)
  exit 0 in 293 ms
  ok   start returned in 293 ms (limit 5000)

$ node scripts/loop-engineering/run.mjs status
    | run run-20261009T220439Z-6d3168: running
    | verified completion: 66.6%  (2/3 weight; 1/2 requirements; 1/2 criteria; manifest v1)
    | controller: live pid 16213; guardian: live; dashboard: http://127.0.0.1:58346
    | states: verified 1, running 1
    | current: HS-002 (worker attempt 1)
  exit 0 in 74 ms
  ok   status answered in 74 ms (limit 2000) while a worker was busy

$ node scripts/loop-engineering/run.mjs pause
    | pause: ok
  status after pause: paused

$ node scripts/loop-engineering/run.mjs resume
    | resume: ok

== cancellation ==

$ node scripts/loop-engineering/run.mjs stop --run run-20261009T220439Z-6d3168
    | stopped run run-20261009T220439Z-6d3168 in 2770ms; checkpoint preserved; verified completion 66.6%
    | resume: node scripts/loop-engineering/run.mjs resume
  unverified ids named: HS-002

== dependency invalidation ==
  after editing a file HS-001 watches: HS-001 stale (1 reason(s) recorded), verified 0%
  ok   the edited requirement is stale and its weight left the numerator

$ node scripts/loop-engineering/run.mjs resume
    | resumed run run-20261009T220439Z-6d3168 with a new controller process (restart #1); stale evidence will be re-verified before new work
  ok   completed, verified 100%

== blocked recovery (a worker that is not logged in) ==
  ok   run is blocked with blocker auth-missing; nothing prompted
  ok   after the cause was fixed and the run resumed: completed
```

The run ids, pids and ports change on every run. The ports above are the ones the operating system gave `--serve 127.0.0.1:0`.

## What each step shows

| Step | Command | What to expect |
|---|---|---|
| Finite background start | `start --background --serve 127.0.0.1:0` | Returns within 5 seconds with the run id, the controller pid, the dashboard address and the stop command. The controller and a guardian process are detached and owned by the operating system. The dashboard listens on loopback only; port `0` asks for any free port and a busy port never kills the process holding it. |
| Live status | `status` or `status --json` | Returns within 2 seconds even with a worker busy. A controller that has not written its heartbeat for 15 seconds is reported `stale`, never `running`. The percentage counts only fresh, fully passing, independently issued evidence and is capped at 99.9 until every requirement and the final verification have passed. |
| Pause | `pause` | Checkpoints and stops starting new work. `resume` continues the same run. |
| Cancellation | `stop --run <id>` | Stops only this run's own processes, checkpoints, and closes the dashboard. A worker's whole process tree is reclaimed. The final status names every requirement not yet verified. |
| Dependency invalidation | edit a watched file, then `status` or `resume` | Evidence is bound to a digest of the files a requirement watches. Edit one and the requirement becomes `stale` with its reason, its weight leaves the numerator, and the percentage drops. `resume` re-verifies before it starts new work. Nothing is promoted from the old evidence. |
| Blocked recovery | fix the cause, then `resume` | A missing login, a denied permission, a missing tool or an absent network is recorded as a blocker. The controller never prompts for any of them. A blocked requirement waits for you. Fix the cause and `resume`. `retry --requirement <id>` re-evaluates an external blocker on a live controller. |
| Final verification | `verify --all --final` | See below. |

## Final verification

For a profile that sets `finalVerification.required`, once every requirement is verified the controller builds, re-runs every
registered criterion, then runs the release gates, all against a single whole-tree digest. Completion needs the digest to be
identical before the phase, after every verification and after the last gate, with no skipped test, no unsupported or blocked
required backend, and evidence for every requirement and gate. The verdict is written to `final-evidence.json`, signed with the
checkout's key and bound to the acceptance hash, the PRD, the profile and the digest. If a bound input later changes, `status`
reports `final-stale` and the percentage falls below 100. A failing final phase returns the failed requirements to the workers
within their attempt caps, or ends the run `blocked` naming each unmet item.

`verify --all --final` is executed by a live controller. In the scripted walk-through the run has already completed and the controller
has exited, so the command exits 2 and says it needs a live controller (run `start` or `resume`); against a live controller on a
profile without the final requirement it instead prints that the controller owns the final phase and runs it automatically. The final
phase itself is described by the runbook and tested in the controller's suite; it is not exercised by this example.

The assurance-differentiation profile adds a `closure` block, which makes the final phase the protected closure of the last
requirement (REL-003, described in the [runbook](loop-engineering.md#protected-closure-rel-003)). It validates the other
requirements' receipts first, runs the closure requirement second, checks the requirement graph, evidence hashes, named gates,
controller limits and supported scope, and issues one record only at the expected counts (70 requirements, 210 criteria). A measured
gate that is synthetic or has no adjudicated population is listed as open and is never closure. The final phase starts only once every
other requirement is verified, so a run that cannot verify them stops earlier, `blocked`, naming what is unmet. The closure binds the
committed revision: commit the implementation first. The untracked requirements document does not count as dirty.

## Finish with a report

```
node scripts/loop-engineering/run.mjs report --json
```

The completion report lists every unmet criterion with its reason, every blocker, every budget stop, what is implemented and
verified, where the evidence lives, and the exact next commands, each with its bound. It says `verified-complete` only for a run
that finished with a passing final verification, and even then it is a finite statement about the criteria it lists.

## The assurance-differentiation profile

`scripts/loop-engineering/profiles/assurance-differentiation.json` registers the differentiation programme with the same
controller. Its limits are finite starting values: heartbeat every 5 seconds, stale after 15, worker idle stop at 180 seconds, no
progress stop at 600, subprocess wall 120 with a 10 second kill grace, 3 attempts per requirement, 2 repeats of an identical
failure, 150 attempts and 43200 seconds for the run. Its two money budgets (50 and 6 US dollars) are ceilings, not spending
authorization. Controls the controller cannot enforce are listed in the profile as `unenforced` with a reason and are not claimed;
two remain (`budgetsAreCapsNotAuthorization`, `linuxEnforcementBackend`).

What a hung or costly step does to a run, in operator terms:

- **A hung helper or test.** A helper subprocess is killed with its whole process tree at 120 seconds (10 second grace). A suite is
  killed at its class ceiling (120 / 900 / 7200 seconds), and inside a wrapper each test file has its own lease, so one hung file is
  killed and named (`<file> finished within its lease` fails in the TAP, `hungFiles` appears in the evidence) instead of silently
  spending the whole ceiling.
- **A network call** (hosted-CI verification) is cut at 15 seconds, retried at most twice with a capped backoff, and then reported.
- **A paid infrastructure step** (a gate that declares a cost) is run only when the separate provider envelope is enabled
  and preauthorized in the profile, is charged before it runs, and is not run once the $25 envelope cannot cover it. Read it from
  `report --json` under `budgets.providerEnvelope`; the model spend is a different figure.
- **A worker whose cost was not reported** is charged the $6 reserve, not zero, and the run stops with `paused-budget` (reason starting
  `unknown billing`) when the reserve no longer fits under the model cap. Raising any of these is a reviewed profile edit and a new `init`.

To launch it for real:

```
node scripts/loop-engineering/run.mjs preflight
node scripts/loop-engineering/run.mjs plan --next
```

`preflight` reports what is missing and never logs in. All eleven suites are runnable: the loop suite uses its own test files,
and each of the other ten has a protected wrapper under `scripts/assurance-differentiation/test/` that runs the real scoped test
files and re-emits every result under its own name, so a skipped or empty run stays a failed criterion. A wrapper is frozen at
`init`; a profile can still declare a suite `notYetRunnable`, and `preflight` and `start` then refuse to launch, naming the suite.
The programme document is an untracked file in the repository root. Read that before expecting a launch to succeed on a fresh
checkout.

## Explicit policy changes

Nothing in the controller changes its own rules, and a worker cannot loosen them.

- **Limits.** `attemptsPerRequirement` and `sameFailureRepeats` are never reset by `retry`, a restart or a re-`init`. Raising a
  limit or a budget is an edit to the profile by the supervising session, followed by a new `init`. A model budget that is reached
  stops the run in `paused-budget` the next time it needs a worker attempt.
- **Frozen inputs.** `init` freezes the requirements document, the canonical profile, the protected suite wrappers and a digest of
  the controller's own code. A change to any of them stops the run `blocked` with a reason that begins `drift:` and names the input.
  `resume` is refused until a supervising session reviews the change and runs `init` again, which makes the affected evidence stale.
- **Capability grants for a task.** A task that needs a capability it was not given is blocked, and the block carries a proposal
  of the narrowest change. The task cannot sign the grant; a change is a signed grant bound to the exact manifest digests before
  and after, short-lived and single-use, and it creates a new policy version. See [blocked capability example](assurance-examples.md#4-a-blocked-capability).

## Unsupported enforcement platforms

The controller runs on macOS and Linux; Windows is unsupported and disclosed as such in the profile. That is about the controller.
Enforcement of what a task may read, run and reach is a separate matter: **Linux is partially verified** (only the controls the hosted `sandbox-linux` job proved; mediated network and process-count caps remain unverified, so a task that needs either is blocked there); **macOS is host-proved for development only** and is not an advertised enforced backend; **Windows has no backend**. A
criterion that needs an unavailable backend ends `blocked`, naming it. It is never skipped into a pass, and raising a deadline
does not make a slow machine pass. The per-platform table is in the [capability matrix](../reference/assurance-capability-matrix.md).

## Where things are written

Controller state lives in `.loop-engineering/` (git-ignored, mode 0700): the manifest, one directory per run with its state,
events, evidence, attempt logs and reports, and a per-checkout evidence key. It is deliberately separate from `.agentic-security/`
so loop state is never mistaken for scan evidence. Delete a finished run's directory to reclaim space; leave an active run alone.
Next: [portfolio recovery](portfolio-recovery.md) and [assurance review](assurance-review.md).
