# Verified remediation: requirement ledger

The implementation ledger for the verified-remediation work (the requirement document is an untracked working file at the repository root, by this repository's convention). One row per requirement. A row's status is one of:

- **implemented**: production code is wired and unit-tested.
- **integration-tested**: exercised end to end through a real route (CLI, MCP or the central verifier) against real files or processes.
- **measured**: an independent measurement exists and is named.
- **partial**: some acceptance criteria hold; the rest are listed.
- **open**: not started.
- **blocked**: needs a named prerequisite this repository does not have.

A passing unit test alone does not make a row integration-tested. Commands are run from `scanner/` unless they start with `node bench/` or `node scripts/` (repository root).

Baseline reproduced on 2026-11-15 at `e9fe5f71` (scanner 0.195.46), from the inspected `60c9cfbf` (0.195.44):

```
node bench/fix-verification/runner.mjs --check
patches 23 (safe 8, unsafe 15); unsafe accepted 1/15; safe rejected 3/8; degraded among accepted 0.0%; unscored 0
```

All four recorded gaps (GAP-01 to GAP-04) reproduced at that commit, as the requirement document described them.

## M0: reproduce and correct the existing verifier defects

| ID | Status | Changed paths | Verification | Evidence and limitation |
| --- | --- | --- | --- | --- |
| GAP-01 / FR-01 purpose-sensitive hashing | integration-tested | `src/posture/deterministic-fix.js`, `src/mcp/tools.js` (`autofixDecision`), `src/posture/fix-style-mirror.js`, `agents/security-fixer.md` | `npm run test:repair`, `node --test test/deterministic-fix.test.js test/mcp.test.js` | Purpose is read from the enclosing function. Password recipes exist for the single-statement Python and JavaScript shapes only; every other password shape is needs-review. Purpose classification is lexical, not a semantic proof. |
| AC-01.1 | integration-tested | as above | `test/repair/deterministic-purpose.test.js` | A CWE-916 finding never produces sha256; with no visible password it is needs-review. |
| AC-01.2 | integration-tested | as above | same | A password hash and a Content-MD5 digest in one file: only the password operation changes. |
| AC-01.3 | integration-tested | as above | same; MCP test "a weak hash with no visible purpose gets no autofix" | Missing facts are named in `autofixDecision.missingFacts`. |
| AC-01.4 | integration-tested | as above | same (both migrations are executed: Python 3 with `hashlib.scrypt`, Node) | Legacy login kept, new `scrypt$` format written, wrong passwords rejected, salted outputs differ. Callers in other files are not rewritten; the recipe names in-file comparisons only. |
| AC-01.5 | integration-tested | as above | `test/repair/tls-repair.test.js` (real handshakes, certificates minted with `openssl`) | Skips with a reason where `openssl` is missing. |
| AC-01.6 | implemented | `src/posture/fix-style-mirror.js` | `test/repair/deterministic-purpose.test.js` | Examples are labelled `candidate-pattern`, `establishesSafety: false`; no fast-hash examples for a password finding. |
| GAP-02 / FR-02 test deltas | integration-tested | `src/fix/test-results.js` (new), `src/fix/test-commands.js`, `src/fix/verify-patch.js`, `src/posture/fix-verify.js` | `npm run test:repair`, `node --test test/engineering-excellence/e3-05-functional-preservation.test.js` | Both trees run for Node's test runner; per-test identities from a verifier-owned reporter. Suites run under `sandbox/supervise.js` (process group ended, survivors reported). Not confined: the project's tests run with the user's environment and can write outside the copy; confinement is FR-05. |
| AC-02.1 | integration-tested | as above | `test/repair/test-results.test.js` | |
| AC-02.2 | integration-tested | as above | same | A changed failure signature is a failure, never pre-existing. |
| AC-02.3 | integration-tested | as above | same | A removed test (discovery changed by the patch) fails; an edited test file, runner config or test script is refused before running. |
| AC-02.4 / AC-02.6 | integration-tested | as above | same | Unchanged non-required baseline failure is recorded and excused; a required one makes the result inconclusive. With no passing test on the patched tree the result is inconclusive. |
| AC-02.5 | integration-tested | as above | same | Timeout, missing runner, zero tests, malformed report. |
| AC-02.7 | partial | as above | same | Node's runner: executed. jest and vitest: parsers unit-tested on captured report shapes; not executed against an installed runner in this repository. Python: later milestone. |
| GAP-03 / FR-03 patch scope | implemented | `src/fix/line-diff.js` (new), `src/fix/patch-scope.js` (new), `src/posture/fix-plan.js`, `src/mcp/tools.js` | `test/repair/patch-scope.test.js` | One computation for fix-plan and MCP synthesis. Material categories reuse `posture/material-change.js` plus equal-length authorization, credential, crypto and trust-boundary edits. |
| AC-03.1 | implemented | as above | same | 150-line rewrite measures 150 edited lines (300 added plus deleted). |
| AC-03.2 | implemented | as above | same | |
| AC-03.3 | implemented | as above | same | |
| AC-03.4 | partial | as above | MCP uses the shared function | The CLI reports patch scope only through the M1 `repair` command, not yet written. |
| AC-03.5 | open | | | Existing apply-service concurrency check; to be re-pinned with the M1 coordinator. |
| GAP-04 / M0-05 SQL indirection | integration-tested | `bench/fix-verification/cases.mjs` | `node bench/fix-verification/runner.mjs --check` | Closed by execution: the replay runs the handler on a real SQLite engine (`node:sqlite`) with a planted row; the indirection patch still leaks it and is rejected by `exploitProofAfter`. Real routes reach this only when a reproducer is supplied; automatic SQL reproducers for arbitrary findings are M1 work. |
| M0-06 safe refusals | integration-tested | `src/posture/fix-verify.js`, `src/sast/reflected-input.js` | `test/repair/preexisting-findings.test.js`, `test/repair/escaper-recognition.test.js`, the fix bench | Pre-existing findings (same stable id) are excused only when the baseline rescan reproduces the target finding. A local escape helper is recognised by its body (`&`, `<`, `>` to entities). Paired unsafe control: `xss-send/weak-escape-helper`. |
| M0-07 existing gates | integration-tested | | see the M0 gate results below | |

M0 gate results (2026-11-15, this checkout, macOS userspace sandbox):

```
node bench/fix-verification/runner.mjs --check
patches 24 (safe 8, unsafe 16); unsafe accepted 0/16; safe rejected 0/8; degraded among accepted 25.0%; unscored 0
node bench/fix-verification/proof-gate.mjs --check     -> matches baseline (0 of 16 unsafe applied, 2 of 8 safe applied, 6 refused for want of a reproducer)
npm run bench:cve-replay:check                         -> 229/229 baselined entries still pass
npm run bench:mutation:check                           -> 460/460 verdict-flip correctness
npm run bench:self-scan:check                          -> no drift after one reviewed baseline change (below)
npm run test:repair / test:mcp / test:sast / test:verification / test:invariants / test:evaluation -> all pass
```

The degraded share rose from 0 to 25 percent because the two corrected safe fixes are accepted as MITIGATION: their footprint leg is unobservable, and the record says so.

Reviewed self-scan baseline change: `fix/test-commands.js` 1 to 2, a TOCTOU finding on the pre-existing `has()` existence check, which the detector now pairs with new read-only reads of other paths. No path is checked and then used. A ReDoS finding in the new `patch-scope.js` was real and was fixed, not baselined.

Known effect elsewhere: `bench/sard/scripts/verify-fixes.mjs` (not a gate) will report fewer deterministic Java weak-hash fixes, because a digest with no visible purpose is no longer swapped.

## M1 and later

| ID | Status | Note |
| --- | --- | --- |
| FR-04 to FR-08, FR-17, FR-18 (P0 workflow) | open | |
| FR-09 to FR-12 (P1) | open | |
| FR-13 to FR-16 (P2) | open | |
| Section 8 comparison | blocked | Needs configured real model endpoints, an independent adjudicated task population and protected grading; none exists in this repository. No comparative claim is made. |
