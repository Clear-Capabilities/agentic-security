# Non-Mutating Scan PRD — a scan must not modify what it scans

**Status:** proposed · **Created:** 2026-08-09 · **Engine version:** 0.134.0
**Severity:** high — affects every user, and silently corrupted our own benchmark

---

## 1. The defect

**Scanning a directory writes `.agentic-security/` into it.** A scan is an
observation; this one leaves 7+ files behind, including `threat-model.json`,
`exploit-bundles.json` and `scan-history.json` — all of which contain the
engine's own conclusions, with **CWE identifiers in them**.

### How it was found

Auditing the independent evaluation population after an explicit challenge to
prove the numbers were not gamed. Measured:

- **220 polluted trees** — every `pre/` and `post/` of all 110 entries
- **544 state files containing `CWE-` strings**

The second scan of any tree therefore reads the first scan's *conclusions as if
they were source code*. On a benchmark that is self-grading: the engine scores
against its own prior output. It arrived by accident rather than intent, which
is the only way this ever shows up in practice.

Every measurement after the first run on a fresh cache had to be withdrawn.

### Why it is worse than a benchmark bug

For a user, `agentic-security scan .` **mutates their repository**. Consequences
already observed or plainly implied:

- CI that asserts a clean working tree fails after a scan.
- A scan of a third-party dependency, a customer's code, or a read-only mount
  either fails or leaves artefacts in someone else's tree.
- Anything that re-scans inherits the artefact, compounding per run.
- Scan output containing CWE strings becomes scannable input — a feedback loop
  the engine has no defence against.

This is not hypothetical history either. `posture/state-dir.js` opens with:

> *"one report: DB migration system saw the folder as a migration file. One user
> uninstalled the plugin entirely."*

That module was written to fix exactly this class of problem. It works. **It is
simply not used by most of the code.**

### The actual root cause, measured

| | Count |
|---|---|
| Modules under `posture/` that reference `.agentic-security` | **72** |
| Modules that route writes through `state-dir.js`'s guard | **5** |

`state-dir.js` exports `resolveProjectRoot`, `stateDir`, `statePath`,
`isSafeStateDir`, `ensureStateDir` and `safeWriteState`. The seam exists and is
correct. Sixty-seven modules build their own paths beside it.

**A guard that 7% of callers use is documentation, not a control** — the same
lesson the pre-push gate learned when `core.hooksPath` was unset in fresh clones.

---

## 2. Goals

1. **A scan never writes to the directory being scanned.** Default behaviour,
   not a flag.
2. **State writing has exactly one seam,** enforced mechanically rather than by
   convention.
3. **A benchmark cannot be self-contaminated by construction,** not by
   remembering to clean up.
4. No loss of the features that legitimately persist state.

## 3. Non-goals

- Removing persistent state. Scan history, threat models and fix history are
  real features; they need a *location*, not deletion.
- Changing where an interactive user's state lives by default. A developer
  scanning their own project should still get `.agentic-security/` at the
  project root — that is useful and expected.

---

## 4. Workstreams

### S1 — Read-only scan by default for foreign trees · **P0**

The scan path must distinguish *my project* from *a directory I was pointed at*.

- Add `--no-state` / `AGENTIC_SECURITY_NO_STATE=1`: perform the scan, emit the
  report, write nothing.
- **Make it the default when the scan root is not the project root** — i.e. when
  `resolveProjectRoot(scanRoot)` disagrees with `scanRoot`, or no project marker
  (`.git`, `package.json`) is found. Scanning something that is not your project
  should not write to it, and requiring a flag means the flag is missed.
- A read-only target must degrade to a successful scan with a warning, never an
  error. Failing to scan because state could not be written is the wrong
  trade in every direction.

**Acceptance:** scanning a fresh clone of an unrelated repository leaves
`git status` clean. Verified by test, on a real temp clone, asserting zero new
paths.

### S2 — One seam, enforced by a guard test · **P0**

- Migrate all 72 modules to `state-dir.js`'s helpers.
- Add `test/no-stray-state.test.js`, modelled on `no-dead-modules.test.js`
  (which has caught four real defects in this repo, including two of mine): fail
  the build if any file under `scanner/src/` constructs a `.agentic-security`
  path outside `state-dir.js`.
- Allowlist entries permitted only with a written reason, as the dead-module
  guard requires.

**Acceptance:** the guard fails on a deliberately reintroduced direct path
write, and passes on the migrated tree. **Both directions proven** — a guard
demonstrated in only the passing direction has not been demonstrated.

### S3 — Benchmarks cannot self-contaminate · **P1**

The harness fix already landed (`bench/independent/runner.mjs` purges state
before every scan and refuses to score any finding whose path contains
`.agentic-security`). Generalise it:

- Every bench runner scans with `--no-state`.
- A shared assertion: **the tree hash before a scan equals the tree hash after**.
  A benchmark that mutates its own corpus is measuring something other than the
  code.
- `bench/cve-replay`'s existing pre-run purge stays, as defence in depth. Two
  independent controls, because this failure was invisible for weeks.

**Acceptance:** a bench run over a corpus leaves it byte-identical, asserted
rather than assumed.

### S4 — Never score the engine's own output · **P1**

Defence in depth for the specific failure observed:

- Findings whose path lies inside a state directory are excluded from every
  benchmark denominator (**done** in the independent runner; extend to all).
- The engine itself should skip `.agentic-security/` when walking a tree.
  Scanning our own state is never useful and is how output becomes input.

**Acceptance:** a state directory deliberately planted inside a scanned tree
produces zero findings.

---

## 5. Sequencing

```
S1 (read-only default) ──┐
S2 (one seam + guard)  ──┴─> S4 (never scan state) ──> S3 (bench assertions)
```

S1 and S2 are independent and both P0. S1 stops the bleeding for users; S2 stops
it recurring. S4 is small and closes the feedback loop. S3 makes recurrence
detectable rather than trusted.

## 6. How we will know it worked

| Metric | At PRD time | Target | **Measured now** |
|---|---|---|---|
| Paths added by scanning a foreign repo | 10 | **0** | **0** — asserted by test, both directions |
| Modules writing state outside the seam | 67 of 72 | **0**, guard-enforced | **55** remain on the ledger; guard blocks any 56th |
| Benchmark trees mutated by a scoring run | 220 of 220 | **0**, asserted | 0 (runner purges pre-scan) — S3 byte-identity assertion still outstanding |
| Findings sourced from our own state files | possible | impossible | impossible — `.agentic-security` in `IGNORE_DIRS` **and** filtered at scoring |

### Status, honestly

**S4 done. S1 done. S2 mechanism done, migration ~14% complete. S3 outstanding.**

The `--no-state` acceptance criterion is met and pinned by
`test/no-stray-state.test.js`: a real CLI scan of a temp project adds zero paths
while still reporting findings, and the test was proven to FAIL when the switch
is off.

Three corrections found while implementing, each worth more than the line of
code that fixed it:

1. **`git status` is not a sufficient check.** Git does not track empty
   directories, so an earlier revision reported a clean tree while still
   creating `sbom-history/` and `fix-history/`. The acceptance test compares the
   full path listing instead. *Directory creation is mutation.*
2. **The guard was blind to `bin/`.** It walked only `src/`, and the three
   largest artifacts — `findings.json`, `last-scan.json`, `.sig` — are written by
   `bin/agentic-security.js`. A seam guard that cannot see the CLI entry point
   misses the primary writer. Now walks both; found 4 files immediately.
3. **The guard's detector counted prose as a violation, then over-corrected.**
   Comment-blind, it pinned 5 already-clean modules to the ledger permanently.
   Stripping block comments *before* line comments then let a glob in a doc
   comment (`.agentic-security/rules/*.yml`) open a block comment that consumed
   **12,198 characters** and hid a genuine violation. Order is now load-bearing
   and asserted in both directions.

The ledger is the honest measure of what is left: 55 modules still build state
paths by hand. Each needs the same three-line treatment. What has changed
permanently is that a 56th cannot be added.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Migrating 72 modules breaks a state path | Each module has tests; migrate in batches with the suite green between them |
| `--no-state` disables a feature a user relies on | It is default only for *foreign* trees; a user's own project is unchanged |
| The guard test becomes an allowlist dumping ground | Same rule as the dead-module guard: every entry carries a written reason and is reviewed |

## 8. What this episode should teach beyond the fix

The defect existed, was documented in `state-dir.js`'s own header, had a working
solution, and still affected 67 of 72 modules. The gap was never knowledge — it
was that nothing *enforced* the seam.

This project already knows the answer, from the pre-push gate: a control nobody
is forced through is not a control. Every fix in this PRD is therefore paired
with a mechanical check, and every check must be proven to fail on a bad input
before it is believed.
