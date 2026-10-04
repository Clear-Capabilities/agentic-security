# Background implementation loop (operations runbook)

**What this is.** `scripts/loop-engineering/run.mjs` is a supervised, bounded background controller that works through the
requirements of a product requirements document one at a time, launches a worker per requirement, and records
**independently verified** evidence. It was built for the Haskell and Nix/NixOS programme
(`HASKELL_NIXOS_FULL_CAPABILITY_PRD.md`, execution profile `scripts/loop-engineering/profiles/haskell-nix.json`).

**What this is not.** It is a *new development tool*, not part of the scanner. Every `agentic-security ...` command in the
rest of the documentation is the shipped scanner CLI; every `node scripts/loop-engineering/run.mjs ...` command here is
this repository's own tooling and is not installed with the package. The loop never publishes, pushes, deploys, activates a
NixOS configuration, or runs a worker with more than one concurrent edit.

**It is finite.** It does not promise unattended completion. Every run is bounded by the budgets in the profile
(`limits`): wall clock (`runWallSeconds`), total attempts (`runMaxAttempts`), attempts per requirement
(`attemptsPerRequirement`), identical-failure repeats (`sameFailureRepeats`) and model spend (`claudeBudgetUsd`,
`perAttemptBudgetUsd`). When any one is reached the run stops in a stated terminal status and says what is left.

**Prerequisites:** Node.js >= 24, a git checkout, `git`. For real work: the `claude` command-line tool, already logged in.
macOS and Linux are supported; Windows is unsupported and disclosed as such in the profile.

---

## Commands

```bash
node scripts/loop-engineering/run.mjs init --prd HASKELL_NIXOS_FULL_CAPABILITY_PRD.md --profile scripts/loop-engineering/profiles/haskell-nix.json
node scripts/loop-engineering/run.mjs preflight
node scripts/loop-engineering/run.mjs plan --next
node scripts/loop-engineering/run.mjs start --background --serve 127.0.0.1:4317
node scripts/loop-engineering/run.mjs status
node scripts/loop-engineering/run.mjs status --json
node scripts/loop-engineering/run.mjs pause
node scripts/loop-engineering/run.mjs resume
node scripts/loop-engineering/run.mjs retry --requirement HS-001
node scripts/loop-engineering/run.mjs verify --requirement HS-001
node scripts/loop-engineering/run.mjs verify --all --final
node scripts/loop-engineering/run.mjs stop --run <run-id>
```

| Command | What it does | Bounded by |
|---|---|---|
| `init` | Parses the PRD, freezes the manifest (IDs, weights, dependencies, criteria text, suites) with an acceptance hash, captures the baseline, writes the run record. Editing the PRD afterwards without re-initialising is detected and the run stops with `prd-changed`. | returns immediately |
| `preflight` | Validates the runtime, the model tool and its authentication (**never logs in**), permissions, budgets, disk, the dashboard port and which tools are present. A missing authentication is reported, not prompted for. | seconds |
| `plan --next` | Prints the next dependency-ready requirement. Starts no worker. | immediate |
| `start --background` | Detaches an OS-owned controller (plus a guardian process) and returns within 5 s with the run id, controller pid, dashboard URL and the stop command. `--foreground` runs the same controller attached, for debugging. | the profile budgets |
| `status` | Liveness-checked status: a controller that is not heartbeating is reported `stale`, never `running`. Returns within 2 s even while a worker is busy. `--json` for scripts. | 2 s |
| `pause` / `resume` | `pause` checkpoints and stops starting new work. `resume` continues; if the controller is dead it **restarts** one. | n/a |
| `retry --requirement ID` | Skips a retry backoff, or re-evaluates an *external* blocker (missing tool, denied permission, network, authentication). A requirement that exhausted its attempt cap or repeated the same failure is refused: caps are never bypassed. It acts on a **live** controller; once a run has ended (`blocked`, `stopped`, ...) it answers "no live controller" and you use `resume`. | the caps |
| `verify --requirement ID` | Runs that requirement's registered suite as a bounded subprocess and issues signed evidence. | the suite's `timeoutSeconds` |
| `verify --all --final` | Re-verifies every criterion and every release gate against one stable tree. Used last. | `runWallSeconds` |
| `stop --run ID` | Stops only this run's owned processes, checkpoints, closes the dashboard. | grace period, then kill |
| `exec --deadline S -- CMD` | Runs a command under a registered, bounded lease so the controller can reclaim it. Used by workers and gates. | the deadline |

## The dashboard

`start --serve host:port` serves a local, read-only dashboard (default `127.0.0.1:4317`) with the same data as `status`:
overall verified percentage, per-category and per-requirement state, the criteria still unmet, blockers and the latest
bounded, redacted attempt log. It listens on loopback only and accepts only requests addressed to that host and port.
**Port conflict:** if the requested port is busy the dashboard binds a free port instead, records that it did so, and prints
the real URL; it never fails the run and never kills the process holding the port. Use `--serve 127.0.0.1:0` to ask for any
free port.

## How progress is calculated

The percentage is **verified completion**, and only fresh, fully passing, independently issued evidence counts.

- A requirement contributes its **weight** to the numerator only when its registered suite passed *all* of its criteria and
  the evidence is **fresh**: signed with the checkout's key and bound to a digest of the files the requirement watches.
- Anything else stays in the denominator: not started, running, failed, timed out, blocked on a tool, and implemented-but
  -**stale**. A worker's claim of "done" counts for nothing; the controller does not parse it as completion.
- The figure is floored to one decimal and capped at 99.9 until every requirement is verified. `100` appears only when the
  numerator equals the denominator.
- Editing a watched file makes earlier evidence **stale** (the requirement is still implemented, but no longer verified).
  That is why the final phase re-verifies everything against one stable tree.

A skipped test is a failure of its criterion here, and an unavailable compiler or Nix is a failed or **blocked** criterion,
not a pass.

## Finite retries and failures

| Situation | What happens |
|---|---|
| a worker attempt fails | retry with a bounded backoff, `retryBackoffMaxSeconds` apart at most, and at most `attemptsPerRequirement` times |
| the same failure repeats `sameFailureRepeats` times | the requirement is marked `failed` and the loop moves on; it does not loop on it |
| a worker is silent for `workerIdleSeconds`, or makes no progress for `noProgressSeconds`, or runs past `claudeAttemptSeconds` | the worker's whole process tree is killed after `killGraceSeconds` and the attempt counts as failed |
| a subprocess or suite exceeds its deadline | terminated (process group, with a grace period) and recorded as timed out |
| output grows past `maxOutputMiB`, a log past `maxLogMiB`, or memory past `maxRssMiB` | the process is stopped; logs are truncated to the cap, so retention is bounded |
| the model tool is not logged in | the run records an `auth-missing` blocker and does **not** prompt: a blocked requirement waits for you |
| a required tool (`nix`, `ghc`, `cabal`, `stack`) is absent | the requirement's criteria are `blocked` with the tool named, and `retry` re-checks it once you install it |
| permission is denied to the worker | a `permission-denied` blocker with the denied tool; the worker never receives a prompt (`permissionMode: dontAsk`) |
| the model budget is reached | the run stops in `paused-budget`; raising the budget is an explicit profile edit followed by a new `init` |

## Recovery

- **Controller killed or lost** (crash, `kill -9`, closed terminal, reboot): `status` reports `stale` after the heartbeat
  lease lapses (15 s). `resume` takes the run lock, restarts the controller from the checkpoint and re-assesses evidence.
  No attempt is repeated silently: completed requirements stay verified while their evidence stays fresh.
- **Machine sleep:** the lease lapses while asleep; on wake `status` shows `stale` until `resume`. Wall-clock budgets keep
  counting, so a long sleep can end a run in a stated budget status.
- **Reboot:** the same as a lost controller. The loop installs no launch agent or service of its own. If you want one,
  an operating-system job (`launchd` on macOS, a `systemd` user unit on Linux) that runs `resume` is a reasonable wrapper;
  none is shipped or tested here, and it would still be bounded by the profile budgets.
- **Stale evidence:** after you edit a watched file, `resume` (or `status`) shows the affected requirements as `stale` with
  the reason; the controller re-verifies them. Nothing is promoted from the old evidence.
- **Final status** (`final-report.json`) lists every unverified requirement id, its unmet criteria, its blockers and the exact
  command to continue.

## Where things are written

Everything the controller learns lives in `.loop-engineering/` (git-ignored, mode 0700): `manifest/`, `runs/<run-id>/`
(`state.json`, `events.jsonl`, `evidence/`, `attempts/`, `logs/`, `status.html`, `final-report.json`) and a per-checkout
evidence key. It is deliberately outside `.agentic-security/`, so loop state can never be mistaken for scan evidence.
Delete a finished run's directory to reclaim space; the manifest and evidence of an active run must be left alone.

## Haskell and Nix tools in the loop

| Tool | Used for | When absent | Troubleshooting |
|---|---|---|---|
| `ghc`, `cabal` | HS-006.AC01 (route fixtures compile), compile checks of fixes | the criterion is `blocked` naming the tool | install a GHC; `retry --requirement HS-006` re-checks; `compileOperationMaxSeconds` bounds one compile |
| `nix` | NIX-011 (isolated evaluation), NIX-012 (NixOS host and VM checks) | `blocked`, naming the tool | needs the sandbox probe to pass too; `vmOperationMaxSeconds` bounds a VM operation |
| `stack` | resolved Stack export checks | those checks report not-run | none needed for default scans |

An optional evaluator that is selected but cannot prove its isolation, or exceeds its deadline, is reported as
`unsupported`, `blocked` or `timed_out` in the scan health; it is never a silent pass, and the loop treats the dependent
criterion as unmet. Do not raise the evaluator's deadlines to make a slow machine pass: change the machine or leave the
criterion blocked.

## What is verified, and how

`scripts/loop-engineering/test/` holds the loop's own tests, run with `npm run test:loop` in `scanner/`. The runbook test
(`loop-runbook.test.js`) executes the commands in this page against a disposable repository with a scripted worker: a
clean-checkout dry run that creates the manifest and dashboard, a worker that completes a criterion, a stalled worker that is
terminated, a resume over stale evidence, a blocked authentication that never prompts, a stop that reclaims every process,
and a final status that lists the remaining ids.
