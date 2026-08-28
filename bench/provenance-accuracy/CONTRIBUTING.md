# Adding a provenance-accuracy fixture

This corpus measures the Finding Provenance PRD's own launch target:
**"Known-origin accuracy >=98% exact commit accuracy on a labeled historical
fixture corpus."** Every fixture is a small, self-contained git history with a
documented TRUE answer — a commit SHA, or a documented non-commit outcome for
the two classes where a specific SHA is not the correct answer at all — and
the runner scores what the REAL `runScan` -> `annotateGitProvenance` pipeline
actually returns against it. This is not a mocked-resolver unit test; it is
the shipped code path, end to end.

## Layout

```
bench/provenance-accuracy/
  runner.mjs            # scores every fixture, both plain and --check/--update-baseline
  sca-scan-helper.mjs    # subprocess helper for kind:'sca' fixtures (HOME redirection)
  BASELINE.json          # committed per-fixture pass/fail verdicts + {matched, scoreable}
  fixtures/<id>.mjs      # one file per fixture, each exporting `manifest`
```

## manifest.js shape

```js
export const manifest = {
  id: 'direct-introduction',          // must match the filename (no .mjs)
  scenario: 'PRD Scenario A — direct introduction',  // free text, printed in the report
  description: 'one line describing the fixture',
  kind: 'sast',                       // 'sast' (default) | 'sca'
  expect: 'commit',                   // 'commit' (default) | 'partial' | 'uncommitted'

  build(fx) {
    // fx is a createGitFixture() instance (scanner/test/helpers/build-git-fixture.js) —
    // the same helper the provenance unit-test suite uses throughout.
    fx.writeFile('server.js', '...safe...');
    fx.commit('safe baseline');
    fx.writeFile('server.js', '...vulnerable...');
    return fx.commit('introduce vuln');   // the TRUE origin commit — see "Return shape" below
  },

  finding: { file: 'server.js', line: 3, vuln: /^SQL Injection$/ },  // locates the ONE finding to score
  // kind:'sca' fixtures also need:
  // sca: { ecosystem, name, version, id, description, fixedVersions, severity }
};
```

### Return shape from `build(fx)`

- **A bare string** — the commit SHA the fixture asserts is the true origin.
  This is the common case (see `direct-introduction.mjs`, `guard-removal.mjs`,
  most fixtures in this corpus).
- **An object** `{ commit, root, cleanup }` — for a fixture that needs a
  DIFFERENT directory scanned than `fx.root` (e.g. `shallow-clone-partial.mjs`
  scans a `git clone --depth 1` of the fixture, not the fixture itself) and/or
  extra teardown beyond `fx.cleanup()`. `commit` may be `null` when `expect`
  is `'partial'` or `'uncommitted'` — there is no specific SHA to assert for
  those classes.

### `expect` — what "correct" means for this fixture

- `'commit'` (default) — the located finding's `findingProvenance.status` must
  be exactly `'complete'` AND `findingProvenance.findingOrigin.commit` must
  exactly equal the SHA `build()` returned. A commit that merely happens to
  match under a `'partial'` status does **not** pass — see the PRD's "false
  certainty" success metric (0 cases where partial history is labeled
  definitive origin). This corpus enforces the same standard on itself.
- `'partial'` — correct behaviour is `findingProvenance.status === 'partial'`,
  regardless of what (if anything) `findingOrigin.commit` names. Used for
  PRD Scenario F (shallow clone): the correct answer is honestly declining to
  claim a verified origin, not naming a SHA.
- `'uncommitted'` — correct behaviour is
  `findingProvenance.status === 'uncommitted'`. Used for PRD Scenario G.

### `finding` — locating the one finding this fixture is about

For `kind:'sast'` (default), matched against every entry in
`scan.findings`/`scan.secrets`/`scan.logicVulns`:
`{ file, line?, vuln?, cwe? }` — `vuln` may be a string (exact match against
`finding.vuln`) or a `RegExp`. `line` matches against EITHER `finding.line`
OR `finding.sink?.line` (many detector families only set the latter — see
`uncommitted-change.mjs`'s header for why this matters for that one
`expect:'uncommitted'` case specifically, where only `finding.line` is
consulted by the engine's own short-circuit).

For `kind:'sca'`, matched against `scan.supplyChain`:
`{ name, isDirect }`.

**The runner requires the locator to match EXACTLY ONE finding.** Zero or
more than one is scored `env-error`, not a pass or a fail — an ambiguous
fixture is not evidence about the resolver.

## The discipline (same as `bench/cve-replay/CONTRIBUTING.md`)

**Never add a fixture without confirming, by actually running it, what it
scores.** Run:

```bash
cd scanner && node ../bench/provenance-accuracy/runner.mjs
```

and read the per-fixture row for your new `id`. Three outcomes:

1. **PASS, and you expected PASS** — good, proceed to update the baseline.
2. **FAIL, and you expected PASS** — this is either a bug in your fixture
   (wrong SHA returned, wrong locator, a `finding.line` your chosen detector
   family never sets) or a genuine gap in the engine. Investigate before
   committing either way — **do not** paper over a fixture bug by loosening
   `expect`, and do not silently accept an engine gap without at least
   documenting it in the fixture's own header (see `rename.mjs` for the
   worked example: a fixture kept and committed as a documented, expected
   miss, with the root cause traced to specific lines in
   `origin-resolver.js`/`predicate-replay.js`).
3. **ENV-ERROR** — your locator matched 0 or >1 findings, or `build()`
   threw. Fix the fixture; this is never a valid state to commit.

**Do not pad the corpus with easy fixtures to inflate the headline number.**
The PRD's 98% is an aspiration this corpus measures against, not a target to
engineer backward from. A fixture belongs here because it exercises a real
PRD scenario or a real edge in the resolver's algorithm, not because it is
guaranteed to pass. `rename.mjs` is deliberately committed as a MISS — see its
header for the traced root cause — because an honest 12/13 is worth more than
a padded 13/13 that quietly dropped the one scenario the resolver doesn't
actually handle yet.

Once you're satisfied:

```bash
node ../bench/provenance-accuracy/runner.mjs --update-baseline
git add bench/provenance-accuracy/
```

`--update-baseline` **refuses to write** if any fixture is currently
`env-error` (same rule as `bench/cve-replay/runner.mjs`) — a baseline can only
ever be written from a run where every fixture actually produced a verdict.

## The gate (`npm run bench:provenance-accuracy:check`, `scanner/package.json`)

Regression-only floor gate, mirroring `bench/cve-replay/runner.mjs`'s
`--check-baseline` classification exactly (not layer-recall's equality
gate — see `runner.mjs`'s own header comment for why the two benches want
different gating philosophies):

- **REGRESSED** — a fixture that was `pass` in the baseline is now `fail`.
- **NEW FIXTURE FAILING** — a fixture not in the baseline (i.e. just added)
  scored `fail` this run — the exact "added without confirming it scores
  correctly" mistake this discipline exists to prevent.
- **BASELINED FIXTURE MISSING** — a fixture the baseline expects no longer
  exists (renamed or deleted without updating the baseline).
- An **improvement** (baselined `fail` -> now `pass`) does not fail the gate,
  but is printed as a nudge to re-baseline and update the recorded number —
  see the task report for `rename.mjs`'s current status and what would need to
  change in `origin-resolver.js`/`predicate-replay.js` to fix it.

Exit codes: `0` clean, `1` drift (any of the three classes above), `2` usage
error (bad flags, or `--check` with no `BASELINE.json` on disk), `3`
environment error (any fixture is `env-error` this run — the gate refuses to
even compute drift from an incomplete run, exactly as `--update-baseline`
refuses to write one).
