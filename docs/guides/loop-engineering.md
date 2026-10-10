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
node scripts/loop-engineering/run.mjs report --json
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
| `report [--json] [--write]` | The completion report (see "The completion report"): every unmet criterion, blocker and budget stop, what is implemented, evidence paths and the bounded next commands. Computed from the run directory, so it works with no live controller. | immediate |
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
| the model budget is reached | the run stops in `paused-budget` **when it next needs a worker attempt**; raising the budget is an explicit profile edit followed by a new `init`. Re-validating evidence and the final phase cost no model spend and still run, so a run that has finished its model work can still verify its result |

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
- **Final status** (`final-report.json`, plus `completion-report.json`) lists every unverified requirement id, its unmet criteria, its blockers and the exact
  command to continue.

## Where things are written

Everything the controller learns lives in `.loop-engineering/` (git-ignored, mode 0700): `manifest/`, `runs/<run-id>/`
(`state.json`, `events.jsonl`, `evidence/`, `attempts/`, `logs/`, `status.html`, `final-report.json`) and a per-checkout
evidence key. It is deliberately outside `.agentic-security/`, so loop state can never be mistaken for scan evidence.
Delete a finished run's directory to reclaim space; the manifest and evidence of an active run must be left alone.

## The assurance-differentiation profile

`profiles/assurance-differentiation.json` registers `AGENTIC_SECURITY_DIFFERENTIATION_PRD.md` (an untracked root PRD) with the
same controller and the same section-8 importer. It carries the PRD section 7 limits as finite caps. The two budgets
(`claudeBudgetUsd` 50, `perAttemptBudgetUsd` 6) are ceilings, not spending authorization.

Four optional profile fields were added; a profile without them (such as `haskell-nix`) behaves exactly as before.

| Field | Meaning |
|---|---|
| `workstreams` | Ordered prefix and number-range rules that put every requirement in exactly one of eleven workstreams (seven product workstreams plus foundation, loop, documentation and release), each with its own evidence watch set. A requirement matching no rule or two rules refuses `init`. The manifest records the grouping and `computeProgress` reports a per-workstream view. |
| `suites.<key>.protectedWrapper` / `notYetRunnable` | A supervisor-authored suite wrapper that must exist before launch, and an honest declaration that it does not exist yet. `preflight` and `start` refuse to launch while either is unmet, naming the suite and the reason. |
| `unenforced` | PRD-named controls this controller cannot enforce (for example `networkRequestSeconds` and the separate provider envelope). They are listed with a status and a reason, never claimed; a control leaves the list only when a test proves it (`heartbeatSeconds` did, see below). |
| `finalVerification` | `{ "required": true }` makes a stable-tree final verification part of completion for a profile with no release requirement of its own (see "Final verification"). An added `closure` block turns it into the protected closure of the last requirement (see "Protected closure (REL-003)"). |

Until the protected wrappers under `scripts/assurance-differentiation/test/` are authored, only the `loop` suite is runnable and
`preflight` reports the other ten as blockers. `profileVersion` must be 1; any other value is refused with the migration hint.

## Operating guarantees (assurance profile)

These are enforced by the controller and proven by `scripts/loop-engineering/test/loop-assurance-runtime.test.js`, each test tagged with its PRD criterion.

- **Heartbeat.** The controller writes its lease every `heartbeatSeconds` (5 in the assurance profile) from a dedicated thread, so a worker flooding stdout cannot delay it. A controller is judged `stale` by the reader after 15 s without a beat. A profile whose `heartbeatSeconds` is too slow to ever be judged live (more than 5) is refused at `init`. The lease also records when the main loop last ticked (`mainLoopAgeMs` in `status --json`), so a wedged main loop is visible behind a healthy beat.
- **Start and status.** `start --background` returns within 5 s and `status` within 2 s, with a worker busy or flooding. A launch that cannot proceed is refused promptly with the reason.
- **Worker limits.** A silent worker is stopped at `workerIdleSeconds`, a busy but non-progressing one at `noProgressSeconds`, any attempt at `claudeAttemptSeconds`, and one that floods output at `maxOutputMiB`. The attempt log is written line by line through the redactor and stops at `maxLogMiB`. A worker whose stream reports a running cost above `perAttemptBudgetUsd` is stopped (`attempt-budget`) and the spend is charged; this backs up the model tool's own ceiling and does not replace it. Descendants of a stopped worker are reclaimed; processes the controller does not own are never signalled.
- **Maximums.** `attemptsPerRequirement` and `sameFailureRepeats` are never reset by `retry`, a controller restart or a re-`init`. Only a reviewed profile edit followed by a new `init` changes a cap.
- **Completion evidence.** Only evidence the controller (or the operator's own `verify`) issued counts. A done flag, an evidence file or a completion claim written by a worker contributes nothing, and neither does a `verify` run launched by a worker (it is recorded and rejected). Changing a watched file, the PRD or the acceptance text makes the affected evidence stale.
- **Progress.** `verified_progress` is fresh verified weight over all required weight; blocked, stale and failed work stays in the denominator; the figure is floored to one decimal and capped at 99.9 until every requirement is verified **and** the final verification has passed on the current tree. The CLI, `status --json` and the dashboard print the same summary lines (`summary.lines`), including each workstream's count, the stale, blocked and failed requirements, the active criterion, spend, last heartbeat and the exact continuation command.
- **Checkpoints and logs.** `state.json` is replaced atomically and each controller checkpoint also refreshes `state.json.bak`; a torn primary is recovered from the backup, and with neither the controller refuses to start rather than reset attempt counters. Every event carries a sequence id that is unique across the controller, guardian and CLI and continues across restarts; `events.jsonl` and `jobs.jsonl` rotate at `maxLogMiB`. Events, status and attempt logs are redacted.
- **Recovery.** After SIGTERM, SIGKILL, a controller restart, a simulated sleep (wall clock jump) or a busy dashboard port, `resume` continues unfinished work and does not re-run requirements whose evidence is still fresh. A sleep interrupts the in-flight attempt without charging it. A port conflict never disturbs the port's owner.

### Drift

`init` freezes the PRD bytes, the canonical profile, every `protectedWrapper` suite file and a digest of the controller's own code. While the run is initialised the controller and `status` re-check them; any change stops the run as `blocked` with a reason beginning `drift:` and the input named. The attempt in flight is not charged. `resume` is refused until a supervising session reviews the change and runs `init` again, which re-freezes the inputs, clears the drift and (because evidence is bound to the PRD digest, the acceptance definition and the watched tree) makes the affected evidence stale. Worker-writable suites are not frozen.

### Final verification

For a profile with `finalVerification.required`, once every requirement is verified the controller runs one final phase: it builds, re-runs **every** registered criterion, then runs the release gates, all against a single whole-tree digest. Completion requires that the digest is identical before the phase, after every verification and after the last gate, and that no test was skipped, no required backend was unsupported or blocked, and every requirement and gate has evidence. The verdict is written to `final-evidence.json`, signed with the checkout key and bound to the acceptance hash, the PRD, the profile and the digest. If any bound input later changes, `status` reports `final-stale` and the percentage drops below 100. A failing final phase either returns the failed requirements to the workers (bounded by `attemptsPerRequirement`) or ends the run `blocked` naming each unmet item.

### Protected closure (REL-003)

A profile whose `finalVerification` carries a `closure` block gets a stricter final phase than the generic one above. It closes the document only when the **expected** counts are met (the assurance profile expects 70 requirements, 210 criteria and weight 269); "nothing failed" is not enough. The code is `lib/closure.mjs` (the decision and the fact gathering), `lib/closure-config.mjs` (profile validation, import-free so the profile validator can use it) and `lib/closure-bundle.mjs` (the release assurance bundle); `finalPhaseClosure` in `lib/controller.mjs` only gathers facts and calls `evaluateClosure`.

The order is the contract and is recorded in the issued record (`closure.order`):

1. Build, then freeze one whole-tree digest.
2. Verify every requirement **other than** the closure requirement in this phase. Their receipts are then validated: present, a valid signed envelope, fresh for the tree, issued by the controller (a worker-launched or operator verify never counts), issued in this final phase, no skipped test, every criterion a pass. A criterion that is failed, skipped, blocked, stale or waived keeps the receipt out; there is no waiver path.
3. Only then execute the closure requirement's own criteria on the same tree.
4. Run the final gates and the measured gates, gather the deliverables, re-hash every cited evidence file, and issue the single signed `final-evidence.json` with one atomic rename.

Beyond per-requirement tests the decision also checks DAG consistency (unique ids, known dependencies, no cycle, sequential criterion ids, expected totals, and no requirement passing while a dependency does not), evidence-file hashes (taken at validation and again at issuance, plus the recorded log hashes), the gates named under `closure.requiredGates.{quality,routing,release}` (each must also be one of the profile's `finalGates`, so a required gate always runs), controller limits (the live profile equals the frozen one, stays inside `closure.limits.max` and `.min`, no budget exhausted, no run-level blocker), the supported scope (the platform is in the profile's supported list; the scope documents exist) and a clean committed tree (`requireCleanTree`; the closure binds the committed revision, so commit first).

A **measured gate** (`closure.measuredGates`) runs a bounded command and reads its JSON status. Only a non-synthetic `pass` counts. `insufficient-population`, `unmeasured`, `fail` and anything marked `synthetic` are listed under `open` and prevent closure; they are never turned into completion. The six deliverables, written under the run directory's `final/` or cited from the repository, are the implementation diff since the revision the run was initialised at, the updated PRD ledger, the scorecards, the policy cards, the replayable fixtures and the release assurance bundle (an unsigned, offline-verifiable portable evidence bundle whose manifest lists every unmet check as incomplete or unsupported, so it is itself `open` until nothing is). A deliverable that exists but describes unfinished work is `open`.

`status` reports a closure record as complete only while it still says it closed at the expected counts with nothing open, its cited evidence files are unchanged, and the tree digest still matches. Tests: `scanner/test/release-closure/final-closure.test.js` (each guard, both directions) and `final-closure-controller.test.js` (the real controller on disposable repositories), both part of `npm run test:release-closure`.

### The completion report

`completion-report.json` (also `report --json`) is written at every terminal state by the controller, and by the guardian after a crash. It lists every unmet criterion with its reason, every blocker, every budget stop (run budget, `attemptsPerRequirement`, `sameFailureRepeats`), what is implemented and verified, where the release evidence lives, and the exact next commands, each with its bound. It says `verified-complete` only for a run that finished with a passing final verification, and even then states that this is a finite statement about the criteria it lists, not a promise of unattended completion.

## Haskell and Nix tools in the loop

| Tool | Used for | When absent | Troubleshooting |
|---|---|---|---|
| `ghc`, `cabal` | HS-006.AC01 (route fixtures compile), compile checks of fixes | the criterion is `blocked` naming the tool | install a GHC; `retry --requirement HS-006` re-checks; `compileOperationMaxSeconds` bounds one compile |
| `nix` | NIX-011 (isolated evaluation), NIX-012 (NixOS host and VM checks) | the suite is run on a GitHub-hosted runner (see "Hosted verification" below); if that is not possible it is `blocked`, naming the tool | needs the sandbox probe to pass too; `vmOperationMaxSeconds` bounds a VM operation |
| `stack` | resolved Stack export checks | those checks report not-run | none needed for default scans |

## Hosted verification

A suite whose profile entry has a `remote` block (NIX-011, NIX-012) is run on a GitHub-hosted runner when the tool it needs is missing
on the controller's machine. This exists because NIX-012 needs a booted NixOS and NIX-011 needs `nix`, and a developer's laptop
often has neither. The evidence it produces is labelled: `invoker: controller+hosted-ci`, a `remote` block (run id and URL, commit,
artifact digest, one entry per leg) and a limitation line saying the suite did not run on this host. It is never presented as a local run.

What the controller requires before it accepts a hosted run:

1. A **clean working tree** and a HEAD that is the tip of a **pushed branch**: the runner tests a commit, so what it tests is exactly what is on disk here.
2. The committed `.github/workflows/verify-remote.yml`, dispatched on that branch with the commit, the requirement, the watch globs and a
   **nonce**. The controller finds its own run by the nonce, not "the latest run", and requires the workflow that ran to be the one at that commit.
3. A `meta.json` from the runner whose **digest of the watched files equals the controller's own** (the runner computes it with
   `scripts/loop-engineering/digest.mjs`, the code the controller uses), so the two sides tested the same bytes.
4. A TAP file **per declared leg** whose hash matches the one recorded. NIX-011 has one leg; NIX-012 has two: an x86_64 NixOS guest on
   KVM and an aarch64 guest emulated in software (the criterion allows "actual tested emulation"; the arm runners have no KVM).
5. The TAP is judged exactly as a local run is (a tagged test per criterion; failed, skipped and untagged tests fail it), and **every leg must pass every criterion**.

Anything else (a failed run, a wrong commit, a different digest, a missing leg or file, a hash mismatch, a skipped test) fails closed.
If the preflight cannot be met (dirty tree, commit not pushed, `gh` missing or not logged in) the requirement is `blocked` with the
reason, not failed and not passed. `LOOP_REMOTE_VERIFY=0` turns the mode off. It trusts GitHub's account of what ran and the committed
workflow; it is not a substitute for a local run where a local run is possible.

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
