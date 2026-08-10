# State-Seam Completion PRD — finish the migration, and stop the benchmarks mutating themselves

**Status:** proposed · **Created:** 2026-08-10 · **Engine version:** 0.135.0
**Predecessor:** `docs/NON_MUTATING_SCAN_PRD.md` (S1/S2/S4 landed in 0.135.0; S3 did not)
**Severity:** medium for users, **high for measurement integrity**

---

## 1. What is actually left, measured rather than assumed

The 0.135.0 release note said *"55 modules remain on the migration ledger and
still build state paths by hand."* That framing is **misleading, and it was
mine**. Counting what those 55 modules actually do:

| | Count | Mutates a scanned tree? |
|---|---|---|
| Modules that **write or mkdir** a state path | **≥13** | yes — this is the real work |
| Modules that only **read** a state path | **~42** | no |
| **Total on the ledger** | **55** | |

Most of the ledger constructs a path in order to *read* it — `loadPolicy`,
`readLog`, `previouslyRefuted`. Those cannot mutate anything. They are a
**consistency** liability (if the state location ever moves they silently look in
the wrong place and degrade to "no state found", which every one of them treats
as a normal condition) — not a **correctness** one.

Treating all 55 as equally urgent would spend most of the effort on the ~42 that
cannot cause the bug this whole line of work exists to prevent.

**How firm is "13"?** Not very, and that is worth saying rather than rounding
away. Three static passes over the same 55 files returned **10, 12, and 13**
writers as the heuristic improved — a ±3-line window around the literal missed
writers that build a path in one function and write it in another; tracking the
tainted variable found them; a constant-prefix form (`mcp/tools.js`) slipped
past both until it was read by hand. Every module named below has been
**confirmed by inspection**, so 13 is a floor, not an estimate. Establishing the
exact set is the first task of M1, and it is done by reading the files, not by
running a better regex — this is precisely the kind of question where a
confident number from a heuristic is worse than a hand-checked list.

### The 13 confirmed writers, and which of them a scan can reach

| Module | Artifact | Guarded today? | Reachable from a plain `scan`? |
|---|---|---|---|
| `bin/agentic-security.js` | `findings.json`, `last-scan.json`, `.sig`, CI artifacts | **yes** — switch honoured at all 3 sites | yes |
| `posture/threat-model-auto.js` | `threat-model.{json,md}` | **yes** — early return | yes |
| `posture/custom-rules.js` | `shadow-findings.json` | **no** | yes, when a `shadow:` rule matches |
| `dataflow/ifds-precise.js` | `ifds-summaries.json` | **no** | yes, when summary caching is on |
| `posture/sca-policy.js` | policy artifacts | **no** | yes, on the SCA path |
| `posture/pr-augment.js` | `scan-baselines/<ref>.json` | **no** | yes, on the PR-augment path |
| `integrations/tickets.js` | `tickets.json` | **no** | no — ticket sync |
| `llm-validator/consistency.js` | `llm-cache/` | **no** | only with `AGENTIC_SECURITY_LLM_VALIDATE=1` |
| `posture/deterministic.js` | `rules.lock` | **no** | no — `rules lock` subcommand |
| `posture/fix-plan.js` | `fix-plans/` | **no** | no — fix path |
| `posture/corpus-enroll.js` | corpus entry dirs | **no** | no — enrolment script |
| `mcp/audit.js` | MCP audit log | **no** | no — MCP server |
| `mcp/tools.js` | `agent-scratchpad/` | **no** | no — MCP server |

Two are already correct and merely hand-build the path (ledger debt, no
behaviour bug). **Eleven are unguarded**, and **four of those sit on the scan
path**: `custom-rules.js`, `ifds-precise.js`, `sca-policy.js` and
`pr-augment.js`.

The last two were missed entirely by the first analysis pass. That is the
strongest argument for M1 beginning with a hand-read inventory: the modules a
regex misses are, by construction, the ones whose write is furthest from the
path construction — which is exactly the shape that is hardest to notice by eye
later.

**Honest limit on that claim.** The unguarded writes are established by
*inspection*. I attempted to reproduce the `shadow-findings.json` leak with a
`shadow: true` custom rule and **could not make the rule fire**, so its
exploitability is **unconfirmed**. The code path is plainly unguarded and must
be fixed regardless; but nobody should record "confirmed leak" for it until a
firing case exists. Producing that case is a task in M1.

---

## 2. The bigger problem: the gated corpus mutates itself, and grows without bound

S3 was deferred in the last PRD. Measured today, that deferral is the most
expensive item on this list.

**None of the 11 bench runners scan with `--no-state`.** Only 5 purge state at
all, and `bench/cve-replay/runner.mjs` — **the runner behind the gate that runs
on every single push, and behind the published scorecard** — purges nothing.

Measured in `bench/cve-replay/` right now:

| | |
|---|---|
| Corpus trees containing `.agentic-security/` | **420** (every `pre/` and `post/`) |
| State files | **5,231** |
| State files containing `CWE-` strings | **510** |
| Total state written into the corpus | **~20.8 MB** (corpus was 25 MB, 4.2 MB after cleanup) |
| Distinct `sbom-history/<commit>.json` snapshots per tree | **9** |

That last row is the one that matters. The snapshots are keyed by **git commit**,
so **every gate run adds one new file to each of 420 trees, forever.** Nine runs
have accreted 9 files per tree. Nothing ever removes them. This is unbounded
growth in a directory the gate depends on.

**Is the published 210/210 wrong?** No — and the reason is worth stating
precisely, because it is thinner than it looks. S4 put `.agentic-security` into
`IGNORE_DIRS`, so the engine skips those directories when walking. The
contamination is present but **unreadable**, so the measurement is sound.

It is sound because of exactly one control. Remove or regress that one line and
510 files carrying CWE identifiers become scannable input to the benchmark that
gates every push. The last PRD's own conclusion applies verbatim: *a control
nobody is forced through is not a control* — and here, a single control with no
second line of defence is one edit away from silently re-opening a defect that
went unnoticed for weeks.

The corpus state is **gitignored and uncommitted**, so it has never entered the
repository. That is the one piece of good news.

---

## 3. Goals

1. **No scan configuration writes to a tree under `--no-state`** — not just the
   default one.
2. **Every bench runner leaves its corpus byte-identical**, asserted rather than
   trusted.
3. **The seam is the only route** for state writes, so the ledger reaches zero
   and the guard covers everything.

## 4. Non-goals

- Removing persistent state. Scan history, fix history and threat models are
  real features; they need a *location*, not deletion.
- Changing default behaviour for a developer scanning their own project.
- Rewriting the ~42 read-only call sites for elegance. They migrate because the
  ledger should reach zero, not because they are dangerous.

---

## 5. Workstreams

### M1 — Inventory by hand, then guard the 11 unguarded writers · **P0**

**Begin by confirming the set by hand** — read all 55 ledger modules and record
write/read for each. Three regex passes disagreed (10/12/13); the list above is
a floor established by inspection, not a result to be trusted as complete.

Four of the confirmed eleven are on the scan path and are the only ones that can
affect a `--no-state` scan today; the rest are reachable from subcommands, the
MCP server, ticket sync, or enrolment, and should be consistent regardless.

- Route each through `statePath()` + `safeWriteState()`, or add
  `stateWritesEnabled()` to an existing refusal branch where the write is async
  (the pattern already used at `bin/agentic-security.js`'s three sites).
- **Each writer keeps returning what it returned before.** The switch changes
  what is *written*, never what is *reported*. `pqc-migration-plan.js` is the
  reference: it still returns the plan with writing off.
- **Produce the missing repro first.** Build a fixture where a `shadow: true`
  custom rule actually fires, and confirm `shadow-findings.json` appears with
  the switch on and not with it off. If the rule cannot be made to fire at all,
  that is a **separate bug worth its own finding** — a documented feature that
  does not work — and must be reported, not quietly dropped.

**Acceptance:** for each unguarded writer, a test asserting the artifact appears with
writes enabled and does not appear with them disabled, and that the return value
is unchanged. Both directions, per the project's standing rule.

### M2 — The acceptance test covers one configuration; make it cover the matrix · **P0**

`test/no-stray-state.test.js` proves zero new paths for a **default** scan of a
two-file fixture. That is exactly one point in a large space, and the two
scan-path writers in M1 are invisible to it — the fixture has no `rules.yml` and
does not enable summary caching.

- Extend to a matrix over the flags that change which writers execute: default,
  `--deep`, `--all`, a project carrying a `shadow:` custom rule, and summary
  caching enabled.
- Assert **zero new paths** for every cell, comparing full path listings, not
  `git status` — git does not track empty directories, and that gap already hid
  two directory-creating writers once.
- Keep the existing "findings are still produced" assertion in every cell. A
  read-only scan that silently reports nothing would pass a zero-paths check for
  entirely the wrong reason.

**Acceptance:** the matrix passes, and is proven to FAIL when the switch is
disabled — as the current single-cell test already is.

### M3 — Bench runners must leave their corpora byte-identical · **P0**

The highest-value item, because it protects the numbers this project publishes.

- Every bench runner scans with state writing **off**. `bench/independent/`'s
  pre-scan purge stays as defence in depth: two independent controls, because
  this failure was invisible for weeks.
- A **shared assertion helper**: hash the tree before the run, hash it after,
  fail on any difference. A benchmark that mutates its own corpus is measuring
  something other than the code.
- **Wire it into `bench/cve-replay/runner.mjs` first.** It gates every push and
  feeds the scorecard, and it is the one runner with no purge at all.
- One-time cleanup of the 420 existing trees, so the corpus starts from the
  upstream files and nothing this project produced.

**Acceptance:** a full corpus run leaves the tree byte-identical, asserted. The
assertion is proven to fail on a deliberately planted file. Re-running the gate
twice adds **zero** new `sbom-history/` snapshots — today it adds 420.

### M4 — Retire the remaining read-only path builders · **P2**

Mechanical, low risk, and deliberately last. Replace hand-built paths with
`statePath(scanRoot, …)`. No behaviour change is intended and none should occur;
each module already treats "no state found" as normal.

Batch it, keep the suite green between batches, and delete ledger entries as
they migrate — the stale-entry test enforces that, so a migrated module cannot
be left listed and silently unwatched.

**Acceptance:** ledger reaches **0 entries**; the guard then covers `src/` and
`bin/` in full and the ALLOWLIST can be reduced to the seam itself.

---

## 6. Sequencing

```
M3 (bench byte-identity) ──┐   ← do first: protects the published numbers
M1 (guard 11 writers) ─────┼──> M2 (matrix test proves M1) ──> M4 (~42 readers)
```

M3 leads because it is the only item with a live integrity cost that compounds
on every push. M1 and M2 are a pair — M1 without M2 is unverified, M2 without M1
just documents the holes. M4 is cleanup and can trail.

## 7. How we will know it worked

| Metric | Now | Target |
|---|---|---|
| Unguarded state writers | 11 of 13 confirmed | **0**, over a hand-verified inventory |
| Scan configurations proven to add zero paths | 1 | **6** (the matrix) |
| Bench runners asserting byte-identity | 0 of 11 | **11** |
| State files inside `bench/cve-replay/` | 5,231 (~20.8 MB) | **0** |
| New files added to the corpus per gate run | 420 | **0** |
| Ledger entries | 55 | **0** |
| Controls preventing benchmark self-contamination | 1 (`IGNORE_DIRS`) | **3** (ignore + no-state + byte-identity assert) |

## 8. Risks

| Risk | Mitigation |
|---|---|
| Migrating a writer breaks a feature that depends on its artifact | Each gets a both-directions test before the change; return values are asserted unchanged |
| Turning writes off in benches hides a bug that only appears with state on | Benches measure detection, not persistence; the fix-lifecycle tests continue to exercise state-on paths |
| The byte-identity assertion is slow on a 25 MB corpus | Hash file paths + sizes + mtimes first, full content only on mismatch |
| M4 is ~42 mechanical edits — attention lapses | Batch with the suite green between; the stale-entry test catches a half-migration |

## 9. What this episode should teach beyond the fix

The last PRD's lesson was *a control nobody is forced through is not a control*.
This one adds two.

**A count is not a measurement.** "55 modules remain" sounded like 55 units of
risk. Thirteen can write; four of those are on the scan path. The number was
accurate and the impression it created was wrong, which is the more dangerous
combination — nobody checks a figure they already believe.

**And the correction needed correcting.** The first pass at this PRD said ten
writers, two on the scan path. Improving the analysis moved it to thirteen and
four — `sca-policy.js` and `pr-augment.js` build the path in one function and
write it in another, which the first heuristic could not see. A number produced
by a heuristic and a number produced by reading the code are different kinds of
claim, and only the second belongs in a plan someone will execute.

**Deferring the verification step is how the original defect survived.** S3 was
the assertion that benchmarks do not mutate themselves, and it was the one part
of the last PRD that got postponed as lower priority. In the fortnight since,
the gated corpus accumulated 5,231 state files and grows by 420 more on every
push. The fix landed; the check that would have proven the fix held did not —
and it is the check, not the fix, that keeps a defect from coming back.


---

## Appendix A — corrections to this document's own figures

**"1.49 MB of state" was wrong; the real figure is ~20.8 MB.** It came from
`find … -exec wc -c {} + | tail -1`, which prints one `total` line *per exec
batch*; taking the last line reported only the final batch. Deleting the state
took `bench/cve-replay/` from 25 MB to 4.2 MB, which is the measurement that
settled it.

The error understated the problem by 14x and would not have changed a single
decision here — but it is recorded because the habit that produces it is the
same one that produced the withdrawn recall figure: trusting a number a command
printed without checking what the command actually counted.


## Appendix B — the writer/reader split was wrong, and the hand review is the reason we know

Section 1 claimed **≥13 writers / ~42 readers**, flagged as a floor needing
hand verification. M1's first task did that verification. The result:

| | Count | Basis |
|---|---|---|
| **Provably read-only** | **25** | the file contains **no write syscall at all** — provable by absence, not by heuristic |
| **Writers** | **~30** | confirmed by reading the write sites |

So the ledger is roughly **half writers, half readers** — not "mostly reads".
The reframing in section 1 was wrong, and wrong in the direction that made the
work look smaller.

Two things are worth keeping from the episode. The **floor** language was the
right hedge: 13 was labelled a floor precisely because the heuristics kept
moving, and it did not turn into a claim that 13 was the answer. And the
partition that finally settled it is not a better regex — it is a different
*kind* of argument: a module containing no write syscall **cannot** write,
which is checkable by absence and cannot be defeated by where the path happens
to be constructed. Every heuristic before it was trying to trace a path to a
write; this one asks whether a write exists at all.

Estimating scope with a heuristic and then planning against the estimate is
what produced both this error and the "1.49 MB" one in Appendix A. The plan
below is unchanged in substance — every writer still needs the same treatment —
but M1 and M4 are about twice and half the size respectively.
