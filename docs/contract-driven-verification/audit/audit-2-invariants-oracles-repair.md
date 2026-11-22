# Audit 2: invariants, oracles, replay, repair, proof fabric (2026-11-22, agent read-only)

Schema (posture/invariants/schema.js): fields schema, schemaVersion, id, key, revision, name, description, class, scope, actors, tenants,
resources, transitions, forbidden, oracle, author, review, supersedes; INVARIANT_CLASSES tenant-isolation, privilege-constraint,
value-conservation, workflow-order, idempotency; REVIEW_STATES proposed, approved, rejected, superseded; origins authored, inferred;
environments disposable-fixture, shared, production; id = content hash 'inv…' over ID_FIELDS (key, revision, class, scope, actors,
tenants, resources, transitions, forbidden, oracle); review/author not in id; oracle binding in id; LIMITS actors 8, tenants 4,
resources 16, transitions 24, forbidden 8; expressions.js closed ops cross-tenant-write, cross-tenant-read, unauthorized-role-change,
sum-not-conserved, transition-outside, duplicate-effect.
Lifecycle (lifecycle.js): ACTIONS propose, approve, reject, supersede; MACHINE; NO revoke/expire; ledger is caller-persisted
(--ledger <file>); hash-chained prev + HMAC over SIGNED_FIELDS with per-install key (no trust roots, no asymmetric keys; 'tamper-evidence
for the operator, not non-repudiation'); authorizeReviewer: kind 'human' in policy.reviewers or fix/approver-registry verifyApprover;
default 'no-authorized-policy'; verifyLedger codes sequence-broken, chain-broken, id-mismatch, bad-signature, illegal-transition,
not-a-human-reviewer; GAP verifyLedger does not re-check reviewer vs current policy; dropping last record undetectable. Project file
approved refused: proposal-must-be-proposed; classifyViolation/isAuthoritative use ledger only. NO CLI/MCP records approvals (callers:
evaluation/invariant-ablation.js, scripts/tenant-invariant-example.mjs). approver registry .agentic-security/authorized-approvers.json
(project-controlled; not loaded by invariants). project-input.js bounded readers only.
Scenarios (scenarios.js): SCENARIO_KINDS cross-tenant-access, privilege-change, reordered-workflow, duplicate-request,
concurrent-operations; HARD_BOUNDS actors 4, depth 12, requests 16, scenarios 6, timeBudgetMs 8000 (reject not clamp); mulberry32 seed;
id hashes invariant, kind, seed, inputs, fixtureDigest; disposable-fixture only; MAX_PARALLEL 4, Promise.allSettled single process, attack
played twice, differing replayDigest -> nondeterministic (no verdict); scheduling 'cooperative-fixed-start-order' | 'sequential'.
Replay manifest (replay/replay.js) ALLOWED: schema, schemaVersion, id, hypothesisId, repository{commit}, patch{digest}|null,
fixture{digest}, toolchain{runtime,version,platform,arch,containerDigest}, oracle{id,version,logicDigest}, entry, inputs, inputsDigest,
budgets{timeoutMs,graceMs,maxOutputBytes}, scope{executes,network:false,writes:'workspace-only'}, expected{outcome}?; runtime must be node;
containerDigest unsupported; awaiting-prerequisites resumable. Shrink: removes units only; preserves forbidden-outcome id+phase;
checkMinimization (actor-changed, assertion-changed); SHRINK_HARD_BUDGET maxRuns 40 / 120000 ms; uses Date.now(). Coverage GAP_CODES
absent-contract, unapproved-contract, not-executed, untested-transition, untested-actor, untested-state, bounded-depth,
unsupported-scenario, unsettled-scenario, unsupported-race, cooperative-scheduling.
Export: 'agentic-security/invariant-scenario-export' {invariant{id,key,revision,class,name}, approval{state,source,documentClaims},
fixture{digest,entry,included:false}, oracle{id:'business-state',version:'1'}, bounds, scenarios[], notBuilt, withheld,
secretsExported:false, claims{exhaustive:false}, reproduce, id 'sexp'}. Regression artifact (repair.js:268): schema, hypothesisId,
commit, patch{digest,files}, fixture{digest,files}, invariant{id,key,revision,class,document,approval{state,transitionId,reviewer,
authority,ledgerHead,ledgerDigest}}, scenario{id,digest,document,shrinkRecordId}, legs[{role,patched,expected,manifest}],
repair{diffDigest,ledger}, scope, id 'rart', artifactDigest.
Oracles (oracle.js): ORACLE_CLASSES five originals + replay-idempotency, functional-regression, business-state, application-security,
application-behaviour; platform statuses supported, unverified, unsupported (linux 'supported' rejected); closed REQUEST_KEYS; run:
feature gate -> requiresFeature -> prerequisites -> runInBoundary only -> harness digest check (tamper -> error) -> verifier interpret;
verdict without commit -> inconclusive; receipts WeakSet, deep-frozen, unsigned; oracleLogicDigest {id,class,version,budgets,harness}.
registry frozen. business-state: factory app with in-memory ctx.store/ctx.emit, state-assertions judge the log; durable state in a real
DB NOT observed. app-adapters application-security/behaviour v6: node (node:sqlite, in-memory duplex HTTP), python WSGI; NO Express+
PostgreSQL, NO FastAPI (ASGI). conformance.js static + execution checks (positive, negative, inconclusive, receipts, tamper-harness-rewrite,
tamper-verdict-text, tamper-caller-verdict, unavailable-prerequisite, cancellation, replay); not-run where boundary cannot run;
--require-execution. Trust boundary controls write-confinement, read-denial, env-scrub, tree-termination, file-size-limit, network; not
proved -> blocked. Oracle platform declarations darwin supported, linux unverified, win32 unsupported. capabilities.yaml: no entry for
invariants/business-state/X-201..208 oracles; contract-repair Labs 'trust boundary does not yet run on Linux'; capability-enforcement
Labs 'Linux partially verified'.
Repair (invariants/repair.js): legs approved contract in verifying ledger; verifyPatchNegative original confirmed -> patched refuted;
workflow baseline + patched refuted (business-state behaviour oracle); other APPROVED contracts on both revisions (proposed -> notRequired);
status verified-fix | not-verified-fix | disabled | rejected; REASON_CODES via CODE_OF (unknown -> setup-failed); artifact replay passed|
failed|invalid|prerequisite-unmet|disabled; preexisting vs invariant-regression vs workflow-baseline-invalid; verified-fix requires all
runs + promotion + preservation + artifact with no secrets. patch-negative.js FUNCTIONAL_ORACLES functional-regression, business-state;
promotePatch oracle-changed; harness digest; __oracle_ reserved. src/repair dispositions proposed, refuted-finding, needs-review,
verified-for-contract, mitigation, rejected, blocked, cancelled; quarantine, regression guards, test deltas newlyFailing/changedFailure/
preExisting/requiredBaselineFailing; candidates cannot change the judge.
Proof fabric states CANDIDATE -> STATICALLY_CORROBORATED -> REPRODUCER_GENERATED -> REPRODUCED -> EXPLOIT_CONFIRMED -> FIX_REPLAY_BLOCKED
-> FIX_VERIFIED; advance one rung; fromProofTier('execution-proven') -> REPRODUCED; orchestrator attempts 3/required 3/independentReplay;
model -> 'inference' only; hypothesis-promotion needs receipt + runtime-confirmed.
Fault injection: faultPoint in fix/batch-journal.js (AGENTIC_SECURITY_TEST_FAULTS=1, AGENTIC_SECURITY_FAULT_AT); scan checkpoint exit 137;
routing-replay --fault; injected clock only in portfolio work-units; replay/repair resume. MISSING: virtual clock/deterministic scheduler
in invariants/oracles; fault tests for invariant ledger/regression artifact/scenario export persistence.
Stale: Linux boundary statements contradict control-probes.js + capabilities/CLAUDE.md (namespace read-denial/tree probes implemented,
suites run in sandbox-linux); scanner/CLAUDE.md duplicate test rows; posture/CLAUDE.md misplaced bullets; test/trust-boundary.test.js
header vs :25.
