# DAG improvements: implementation status

Base commit: `0bd6146a5122635e30bdd49e08561ef11e81fcd3` (changes uncommitted). Verified 1 of 67; in progress 6; pending 60.

## Current work
M1 (DAG-07 completeness) core is in place; remaining DAG-07 items below.

Evidence this turn: `npm run test:lineage` 1345 pass, 0 fail; PRD baseline suites plus scan-health 118 pass, 0 fail; `npm run test:smoke` 30 pass; `test/lineage-fault-injection.test.js` passes with `--experimental-test-module-mocks`.

## Remaining in M1
R07.1/R07.2 gaps (seeding and reverse-selection records, signed export, CLI, UI), R07.3 tainted-entry reuse in incremental cache, R07.5 typed ambiguous-summary relation, R07.7 timing measurement and watchdog, R07.8 diversity ranking review, R07.9 resumable queries (optional).

## Blockers
None.
