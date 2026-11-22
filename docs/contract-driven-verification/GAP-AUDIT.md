# Contract-driven hunting and verified remediation: Phase 0 gap audit

Recorded 2026-11-22 against `main` at `f3d61312` (0.221.1). The requirement document that this audit serves was written against
0.221.0 (`a3d902df`); nothing material to its integration map changed between the two (0.221.1 re-derived a performance gate's hosted
baseline). The audit read every module in the integration map and the tests that pin them; it ran nothing and changed nothing. Every
status below names the file and line that supports it. "Satisfied" means the mechanism exists and is pinned by a test; it says nothing
about effectiveness on real code, which stays unmeasured until the evaluation of Epic C runs on an independent population.

## 1. Baseline

| Item | Value |
| --- | --- |
| Commit audited | `f3d61312` (main, 0.221.1; PR #203) |
| Package version | `0.221.1` (`scanner/package.json`) |
| Working tree | clean on the agent worktree at audit time |
| Check commands | `cd scanner && npm test` (full); scoped `npm run test:discovery` (context intelligence and discovery), `test:invariants`, `test:evaluation`, `test:deployment`, `test:verification`, `test:repair`, `test:mcp`; gates `npm run bench:mutation:check`, `bench:self-scan:check`, `bench:cve-replay:check`, `bench:layer-recall:check`; `node scripts/check-doc-drift.mjs --gate`; `node scripts/ga-program/ledger.mjs --check` |

## 2. What exists, by subsystem (evidence in the four audit notes under `docs/contract-driven-verification/audit/`)

- **Context (DCI).** Deterministic, hash-bound per-entry-point bundles (`context-manifest/1`, `contextHash`, per-span `spanHash`);
  a citation check that refuses `range-invalid`, `file-not-in-snapshot`, `beyond-end-of-file`, `outside-provided-context`,
  `stale-context`, `claim-not-grounded-in-cited-lines`; controls of four kinds (`authentication`, `authorization-role`, `ownership`,
  `tenant-scope`) with `observed|inferred` evidence and `evaluated_and_ineffective` for a control after the sensitive operation; DCI
  invariants (`agentic-security/dci-invariants` 1.0.0, verdicts `satisfied|violated|unknown|not_applicable|public_by_policy|expired`).
  Gaps: a control has no id, revision or digest; a DCI invariant has no revision, digest or approval; `evaluateInvariants` and the
  deterministic findings path have no caller outside tests and no `context` subcommand.
- **Discovery (hunt).** Partition, seven lenses, hunter with citation discards, deterministic corroboration tiers
  (`taint-confirmed|sink-adjacent|unconfirmed`), a three-angle majority-vote refutation panel, judge, cross-run memory keyed
  `file:line:family`, budgets for calls and wall time, egress through the one guarded transport. Gaps: the hunt never receives a DCI
  bundle (raw files, 60k characters); the refutation vote is a Boolean plus a narrative with NO source text in the prompt; only a
  `taint-confirmed` candidate resists model-only removal; no per-candidate record of which stage dropped it; no result cache.
- **Executable invariants.** Content-addressed contracts (`inv…` over key, revision, class, scope, actors, tenants, resources,
  transitions, forbidden, oracle), a hash-chained HMAC-signed approval ledger with actions `propose|approve|reject|supersede`, human
  reviewers from a policy or registry, a project file claiming approval refused; bounded seeded scenarios, cooperative fixed-start-order
  concurrency, replay manifests, shrinking that preserves the failing assertion, coverage gaps, a scenario export and a regression
  artifact; repair verification with four legs and preservation of other approved contracts. Gaps: no `revoke` or `expire`; no CLI or
  MCP path records an approval; `verifyLedger` does not re-check the reviewer against the current policy; no virtual time or deterministic
  scheduler; no fault tests for ledger or artifact persistence.
- **Oracles and execution.** Verifier-side authority, closed request keys, harness digest tamper check, conformance controls (positive,
  negative, inconclusive, tamper, cancellation, replay); application adapters for Node (`node:sqlite`, in-memory duplex HTTP) and
  Python WSGI; platform declarations `darwin: supported`, `linux: unverified`. Gaps: no Express+PostgreSQL or FastAPI+PostgreSQL
  profile; the business-state oracle observes an in-memory store only; the Linux status statements contradict each other across docs.
- **Evaluation lab.** Datasets with enforced leakage policy and neutralization, four arm types including `hunt` (loopback-only, no
  memory, prompt-guarded), localized scoring with line tolerance 3, Student-t intervals over repeats, paired win/loss counts, reports in
  five formats, null-with-reason; a separate frozen protocol, grouped splits, adjudicated labels and signed release gates that the lab
  does not use. Gaps: no per-defect detection history across repeats, no union or stable recall, no stage attrition, no semantic
  secondary view; the lab run pins no prompt version or matcher version; `test/eval-lab/arm-hunt.test.js` is in no `test:*` script; the
  run record drops the hunt counters and caps findings at 200; the router consumes lab scoreboards with no synthetic check.
- **Deployment boundaries and runtime.** Exact-revision cross-repository resolution with distinct gap codes (`access-denied`,
  `repository-unavailable`, `version-mismatch`, `revision-unknown`, `unresolved-identity`), trust zones, boundary types, trace
  correlation (JSONL; the twin accepts `otel-json` and four more), sanitization by closed allowlists, `completeness` never `complete`,
  absence never blocks, drift categories, Ed25519 proof bindings. Gaps: no end-user principal, role or source-of-trust model, no queue
  relation, headers dropped; `resolveCrossRepoBoundaries`, drift and proof-binding promotion have no CLI caller; build identity cannot
  be imported (`deployment.*` keys not in `RUNTIME_ATTRIBUTE_KEYS`); no observation-to-regression workflow; no shadow comparison.
- **Routing.** Outcome labels only from independent adjudication or trusted execution; synthetic data yields `unmeasured`; shadow mode
  spends nothing. Gap: the lab-to-router path has no synthetic protection.

## 3. Requirement classification

Status vocabulary: `satisfied`, `partial`, `missing-integration` (the pieces exist, nothing connects them), `missing`, `blocked`
(needs infrastructure, data or authorization that is not present).

| Requirement | Status | Evidence and gap | Plan (phase) |
| --- | --- | --- | --- |
| A-01 contract schema + readable pack | missing | no `service-contract` anywhere; closest: DCI question packs (`prompts/packs.js`), executable invariant schema | `scanner/src/contracts/{schema,pack,identity}.js` (1) |
| A-02 approval and lifecycle | partial | invariant ledger has propose/approve/reject/supersede, HMAC, human reviewers; no revoke/expire, no CLI approval path, reviewer not re-checked at verify | adapter `contracts/approval.js` over `lifecycle.js`; add `revoke`; expiry from contract policy; `verifyLedger` reviewer re-check (1) |
| A-03 shared consumption, cache keys | missing-integration | `invariantId` only in DCI results and the posture ledger; hunt candidates carry none; DCI `jobKeyOf` `settings` always `{}` | `contractRef`/`invariantId` on DCI candidates, hunt candidates, proof, repair artifact; contract and pack digests in `jobKeyOf` (1) |
| A-04 contract-gap | missing | no such state | qualification decision `contract-gap`; baseline findings untouched (1) |
| B-01 context into hunt and refutation | missing | hunt reads raw files; refute prompt has no source | `contextSupplier` from the DCI store for hunter and panel, token-bounded (1) |
| B-02 structured qualification | missing | candidate fields are id, focusAreaId, lens, title, file, line, family, cwe, rationale, entryPoint, sink | additive `qualification` record validated by `resolveCitation` (1) |
| B-03 refutation as blocker, retention | partial | Boolean vote; `taint-confirmed` resists; refuted candidates listed in coverage only | versioned vote parser (v2 blocker with citations; v1 becomes `insufficient-evidence`); `contested`; every candidate kept with history (1) |
| B-04 stage attrition, memory hygiene | partial | aggregate coverage counters only; `citationsDiscarded` always 0 (bug); memory learns from any `refuted` | per-candidate `history[]`; memory records only evidence-grounded refutations (1); attrition into Eval Lab (2) |
| C-01 Eval Lab frozen full run | partial | lab pins dataset hash, arms, config, scanner commit; no prompt/matcher version; protocol exists separately | bind lab runs to `protocol.js`, pin prompt and matcher versions (2) |
| C-02 per-vulnerability stability | missing | per-repeat results only; hunt memory already off in `arm-hunt.js` | detection history, union/stable recall, completion with scheduled/started/unsupported (2) |
| C-03 semantic secondary view | missing | adjudication schemas exist (`labels.js`), unused by the lab | evaluator-only semantic report with source anchors and adjudication statuses (2) |
| C-04 real-code population | blocked (data) + partial (machinery) | importer exists; `spanApproximate` unused by scoring; gates registered | pilot import from the development split only; `insufficient-population` where absent (2) |
| C-05 paired arms and economics | partial | arms exist; `paired` not rendered; no retries; lab-to-router unprotected | contract arm; render paired; synthetic guard before routing (2) |
| D-01 explicit federation | missing-integration | `resolveCrossRepoBoundaries` complete, no caller | service scope from the contract's repositories (3) |
| D-02 identity propagation | missing | workload identities only; headers dropped | principal/source-of-trust transition records (3) |
| D-03 contradictions and controls | partial | drift categories; controls not environment-matched to candidates | contradiction records (3) |
| E-01..E-04 determinism, faults, harness faults | missing | cooperative order only; `faultPoint` only in fix journal | virtual-time adapter around supported points; fault plans; ledger/artifact fault tests (4) |
| F-01 repair standard | satisfied | `invariants/repair.js` four legs, preservation, `oracle-changed` | keep; add contract identity to artifact (3) |
| F-02 real framework/database profiles | missing | node:sqlite + WSGI only; PostgreSQL not executed | lifecycle once; Express+PostgreSQL and FastAPI+PostgreSQL behind the build sandbox; typed setup blocker when unavailable (3) |
| F-03 Linux oracle backend | blocked (host) + contradictory docs | probes implemented; oracle adapters declare linux `unverified` | audit the exact path on a Linux host (hosted job); until then keep `unverified` and reconcile the contradictory statements (3) |
| F-04 regression artifact | partial | artifact has invariant, approval, legs, manifests; no contract identity, environment manifest, fault plan | extend `invariants/repair.js` artifact (3) |
| G-01 telemetry import | satisfied | adapters, sanitization, environment binding, completeness never complete | keep; make `deployment.*` keys importable (5) |
| G-02 observation-to-regression | missing | `repair observe` records notes only | discrepancy record -> proposal -> approval -> replay -> regression (5) |
| G-03 shadow comparison | missing | none | isolated baseline/patched replay (5) |
| H-01 semantic mutations | missing | conformance covers oracle tamper, not application mutations | mutation population and kill-rate report (4) |
| H-02 oracle boundaries | satisfied | `oracle-changed`, harness digest, `__oracle_` reserved, candidates cannot change the judge | keep (4) |
| H-03 model checking | optional | none | only after P0/P1 |

## 4. Stale status statements found (to correct with evidence, not rewrite)

Listed per subsystem in the audit notes. The ones that matter to this programme: the eval-lab status page says the hunt adapter is not
built (`docs/implementation-status/eval-lab-and-model-router.md:5,18,50,59`); `test/eval-lab/arm-hunt.test.js` is cited as evidence
but no `test:*` script runs it; the Linux trust-boundary statements disagree between `capabilities/CLAUDE.md`, `probes.js`, the oracle
adapters, `repair-contract.md`, `capabilities.yaml` and `test/trust-boundary.test.js`; `scanner/CLAUDE.md` says Linux `unverified`
where the code says `partially-verified`; `mcp-server` says two write tools where six write; `commands/scan.md` omits four `hunt` flags.

## 5. Defects found by reading (fixed in Phase 1 where they touch the slice)

1. `discovery/index.js:404` `coverage.citationsDiscarded` is always 0: `runs.push` never copies the hunter's count.
2. `hunt --no-memory` sets `scanRoot` undefined, so egress and redaction policy are read from the current directory's project, not the
   scanned root (`bin/agentic-security.js:2801`, `hunter.js:161`, `lenses.js:89`, `disprove.js:72`).
3. `posture/evaluation/lab/run.js:173` keeps `findings.slice(0, 200)` and drops `output.hunt`.
4. `test/eval-lab/arm-hunt.test.js` is not in any `test:*` script and the orphan guard reads only `test/`.
5. `routing/policy-router.js` routes from a lab scoreboard with no split or synthetic check.
6. `invariants/lifecycle.js verifyLedger` does not re-check a recorded reviewer against the current policy or registry.
