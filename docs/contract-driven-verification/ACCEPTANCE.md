# Acceptance matrix: contract-driven verification

Generated from `ledger.json`. `verified-synthetic` means a test executed the behaviour on a synthetic fixture on this host (macOS); it is not a measurement of effectiveness on real code or with a real model. `not-run` and `blocked` say why in the observation column.

| Criterion | Status | Test | Observed |
|---|---|---|---|
| A-AC01 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | the same contractRef on the report, the qualification record and (repair.js) the regression artifact |
| A-AC02 | verified-synthetic | `scanner/test/contracts-driven/contract-schema.test.js` | proposed, edited (wrong-scope), expired, revoked, forged, dropped reviewer and model approvals all fail |
| A-AC03 | verified-synthetic | `scanner/test/contracts-driven/contract-schema.test.js` | identical content gives identical ref; review claim excluded; cache invalidation of context jobs not yet implemented |
| A-AC04 | verified-synthetic | `scanner/test/contracts-driven/contract-schema.test.js` | pack-digest-mismatch, pack-names-undeclared-invariant, pack-omits-invariant with both sources |
| A-AC05 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | a candidate naming an undeclared invariant is contract-gap and still reported |
| A-AC06 | verified-synthetic | `scanner/test/contracts-driven/contract-schema.test.js` | bindingView: missing and unsupported bindings are gaps |
| B-AC01 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | every challenger prompt carries the VERIFIED CONTEXT span |
| B-AC02 | verified-synthetic | `scanner/test/contracts-driven/refutation-evidence.test.js` | stale, out-of-bundle and uncited blockers remove nothing |
| B-AC03 | verified-synthetic | `scanner/test/contracts-driven/refutation-evidence.test.js` | silence undecided; legacy votes insufficient-evidence; unavailable store needs-context |
| B-AC04 | verified-synthetic | `scanner/test/contracts-driven/refutation-evidence.test.js` | taint-confirmed survives a grounded majority as contested with votes kept |
| B-AC05 | verified-synthetic | `scanner/test/contracts-driven/refutation-evidence.test.js` | a grounded majority disqualifies; refutationBasis records it |
| B-AC06 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | a source comment asking for clearance, cited by a vote, changes nothing |
| B-AC07 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | history[] per candidate and attrition in the report |
| C-AC01 | verified-synthetic | `scanner/test/contracts-driven/evaluation-stability.test.js` | 1/10 not stable, 7/10 and 10/10 stable with distinct intervals |
| C-AC02 | verified-synthetic | `scanner/test/contracts-driven/evaluation-stability.test.js` | timeout, blocked and never-started repetitions are scheduled non-detections; valid-run view labelled |
| C-AC03 | verified-synthetic | `scanner/test/contracts-driven/evaluation-stability.test.js` | arm requests carry workspace and task only; hunt arm has no memory and builds context from its own workspace |
| C-AC04 | verified-synthetic | `scanner/test/contracts-driven/evaluation-stability.test.js` | semantic view needs anchor plus independent adjudication; localized recall unchanged; duplicates once |
| C-AC05 | not-run |  | frozen run replay not exercised; model and provider versions recorded where declared |
| C-AC06 | not-run |  | the registered no-regression gate exists in evaluation/gates.js; not wired to lab runs |
| C-AC07 | verified-synthetic | `scanner/test/contracts-driven/evaluation-stability.test.js` | run.measurement.population synthetic/real-code in JSON and Markdown; router refuses synthetic |
| C-AC08 | not-run |  | requires a local model; the hunt arm calls the product hunt path, but no real-model run was made |
| D-AC01 | verified-synthetic | `scanner/test/contracts-driven/service-scope.test.js` | three temp git repositories resolve at their pinned commits |
| D-AC02 | verified-synthetic | `scanner/test/contracts-driven/service-scope.test.js` | spoofable-forwarded-identity (api) and tenant-from-message-unverified (worker) candidates; untraced use unresolved |
| D-AC03 | verified-synthetic | `scanner/test/contracts-driven/refutation-evidence.test.js` | a blocker grounds only on a recorded control of the claimed kind on the reaching entry point |
| D-AC04 | verified-synthetic | `scanner/test/contracts-driven/service-scope.test.js` | access-denied (never located), repository-unavailable, revision-unknown, version-mismatch |
| D-AC05 | not-run |  | context job cache keys do not yet include the contract digest |
| D-AC06 | verified-synthetic | `scanner/test/contracts-driven/service-scope.test.js` | any unresolved repository makes the scope partial |
| E-AC01 | verified-synthetic | `scanner/test/contracts-driven/fault-plans.test.js` | duplicate delivery reproduces the double credit in two fresh boundary runs (confirmed, confirmed); the idempotent twin refuted twice |
| E-AC02 | verified-synthetic | `scanner/test/contracts-driven/fault-plans.test.js` | reorder versus duplicate delivery: diffFaultArtifacts names plan.kind and schedule |
| E-AC03 | implemented-not-executed | `scanner/test/invariants/scenario-shrinking.test.js` | existing shrinking preserves the failing assertion; not re-run against fault scenarios |
| E-AC04 | verified-synthetic | `scanner/test/contracts-driven/fault-plans.test.js` | unsupported faults refused with reasons; nondeterministic replays are reported by the oracle |
| E-AC05 | verified-synthetic | `scanner/test/contracts-driven/harness-faults.test.js` | interrupted write leaves the prior ledger; duplicate transition refused; corrupt file is corrupt |
| E-AC06 | not-run |  | fast and extended profiles not separated |
| F-AC01 | blocked |  | no real framework or database on this host |
| F-AC02 | verified-synthetic | `scanner/test/contracts-driven/contract-hunt.test.js` | deny-everyone patch: not-verified-fix (authorized-workflow-broken), slice script and mutation population |
| F-AC03 | verified-synthetic | `scanner/test/contracts-driven/application-profiles.test.js` | missing framework, database, runtime or fetch authorisation are typed blockers; available host still unsupported without a confined runner |
| F-AC04 | blocked |  | no Linux execution of the oracle path |
| F-AC05 | implemented-not-executed |  | runRegressionArtifact exists; a fresh-process replay of the slice artifact was not run in this work |
| F-AC06 | verified-synthetic | `scanner/test/contracts-driven/application-profiles.test.js` | Linux unverified; win32 unsupported |
| G-AC01 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | DELETE /invoices/:id observed, unmodeled -> discrepancy and proposal |
| G-AC02 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | modeled routes with no traffic are not-observed-in-window with the limitation |
| G-AC03 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | other environment rejected; unknown and mismatched builds and stale windows are limitations |
| G-AC04 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | baseline and patch replayed in separate boundary runs with their own stores |
| G-AC05 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | a deny-all patch fails with authorized-workflow-regression; both reports kept |
| G-AC06 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | proposal is proposed; regression record sealed-ineligible |
| H-AC01 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | 10 scheduled mutants, all classified; none dropped |
| H-AC02 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | authorization-after-write: killed by the business-state oracle, survived under the status-only judge |
| H-AC03 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | a patch writing __oracle_harness.mjs is refused |
| H-AC04 | verified-synthetic | `scanner/test/contracts-driven/verifier-and-feedback.test.js` | killed, survived, equivalent kept distinct; unsupported when the boundary cannot run |
| H-AC05 | not-run |  | optional bounded model checking not done |

## Requirements

| Requirement | Implementation | Evidence | Notes |
|---|---|---|---|
| A-01 Canonical contract and readable threat pack | implemented-not-executed | synthetic | contract schema, digest, ref, pack reconciliation, binding view; slice fixture contract validates |
| A-02 Approval and lifecycle adapters (revoke, expire, scope-bound approval) | implemented-not-executed | synthetic | service-contract subjects and revoke in the one ledger; reviewer re-check; expiry from the contract policy; wrong-scope on an edited contract |
| A-03 Shared consumption and cache invalidation (contractRef, invariantId across stages) | implemented-not-executed | synthetic | contractRef and invariantId on candidates, in the report and in the regression artifact; context cache keys not yet extended (jobKeyOf settings still empty) |
| A-04 Useful behaviour with missing intent (contract-gap) | implemented-not-executed | synthetic | contract-gap decision; uncovered candidates keep their evidence and reach the report |
| B-01 Context bundles supplied to hunter and refuters | implemented-not-executed | synthetic | verified bundles to the hunter (budgeted) and the exact span plus controls to every challenger |
| B-02 Structured qualification evidence | implemented-not-executed | synthetic | qualification record with citations validated against the bundle, controls with effectiveness, unresolved, decision and reasons |
| B-03 Refutation as a cited blocker; candidate retention | implemented-not-executed | synthetic | refutation-vote/2 blocker with citations and control kind; deterministic, model-only or insufficient-evidence grounding; contested; legacy votes parsed as insufficient evidence |
| B-04 Stage attrition and corrective feedback | implemented-not-executed | synthetic | per-candidate history in the hunt; the hunt arm carries contract attrition into the lab run; stageAttrition summed per arm |
| C-01 Eval Lab frozen full run | implemented-not-executed | synthetic | run config pins matcherVersion, stability policy, prompt versions; scanner records commit and dirty; frozen protocol binding of lab runs not yet enforced |
| C-02 Per-vulnerability stability | implemented-not-executed | synthetic | detection frequency, union and stable recall with Wilson intervals, completion by status over scheduled repetitions, valid-run diagnostic; cancelled attempts recorded |
| C-03 Localized scoring kept; semantic secondary view | implemented-not-executed | synthetic | evaluator-only semantic view (eval semantic); localized score unchanged; model proposals are ambiguous; duplicates count once |
| C-04 Real-code population and honest release gates | blocked | unmeasured | machinery exists (importer, gates); no independently adjudicated real-code pilot with semantic references; insufficient-population |
| C-05 Paired workflow arms and economics | in-progress | unmeasured | contract arm (hunt adapter with adapter.contract); paired comparison rendered; router refuses synthetic scores; no local model run performed, so the four-arm comparison is unmeasured |
| D-01 Explicit boundary federation reused | implemented-not-executed | synthetic | operator root map and authorised list; exact-revision check per repository; gap codes shared with the deployment boundary graph; no fetch, no credentials; resolveCrossRepoBoundaries (deployment exports) still has no CLI caller |
| D-02 Identity and authorization propagation | implemented-not-executed | synthetic | signed claim, forwarded header, caller-supplied header and message-field transitions; spoofable forwarded identity and tenant-from-message candidates; untraced uses unresolved; line-level static pattern, not a dataflow proof |
| D-03 Contradictions and controls | in-progress | synthetic | a control only grounds a blocker when the context layer recorded it present on the reaching entry point; environment-scoped control matching across repositories not implemented |
| E-01 Supported determinism boundary | verified-synthetic | synthetic | determinism boundary stated: seed, order, explicit group schedule, repeated delivery, durable store; virtual time not instrumented (unsupported) |
| E-02 Security fault plans | verified-synthetic | synthetic | duplicate delivery, reorder, revocation-between (needs the app's revoking step); dependency timeout/failure, process interruption, disk failure unsupported with reasons |
| E-03 Reference-model and metamorphic checks | not-started | none | no independent reference model in this work; the business-state assertions are the existing transition rules |
| E-04 Fault testing applied to the harness | implemented-not-executed | synthetic | atomic ledger persistence, interrupted write, corrupt file, duplicate transition |
| F-01 Repair standard preserved | implemented-not-executed | none |  |
| F-02 Representative application profiles | blocked | unmeasured | profile lifecycle declared for express-postgres and fastapi-postgres; this host: express not installed, fastapi not importable, no PostgreSQL binaries, container images not allowed without an operator fetch policy; no confined runner for a real database exists, so legs are unsupported |
| F-03 Linux oracle backend verified before advertised | blocked | unmeasured | Linux stays unverified for the oracle path; no Linux host or hosted job executed the confinement controls for it in this work |
| F-04 Durable regression artifact | implemented-not-executed | synthetic | regression artifact carries contract ref and invariant id; environment manifest helper pins lockfile, migrations, image digest or says why not |
| G-01 Telemetry import reused | implemented-not-executed | synthetic | reuses importTraceLines sanitization; build binding matched/mismatched/unknown supplied by the operator |
| G-02 Observation-to-regression workflow | implemented-not-executed | synthetic | discrepancy -> proposed contract revision -> regression record gated on approval and replay; sealed-ineligible |
| G-03 Isolated shadow patch comparison | verified-synthetic | synthetic | baseline and patched replayed in separate boundary runs; versioned thresholds; latency objectives not measured |
| H-01 Semantic mutations of the application | verified-synthetic | synthetic | six application and four verifier mutants on the slice; mechanical justifications, no independent review recorded |
| H-02 Independent oracle boundaries | verified-synthetic | synthetic | a patch writing into the oracle namespace is refused |
| H-03 Selective model checking (optional) | not-started | none |  |

## Defects found and fixed while implementing

- ir/parser-js.js: assignment-side calls were left out of fn.calls (cross-file call graph and DCI reachability never followed const r = helper(x))
- context-intelligence/graph-schema.js: two anonymous functions on one line collided in the symbol graph; the build was refused
- context-intelligence/{reachability,invariants}.js: an operation inside the middleware chain counted as the first sensitive operation at the chain position
- discovery/index.js: coverage.citationsDiscarded always 0; --no-memory cleared scanRoot (egress/redaction policy read from the wrong project)
- posture/invariants/lifecycle.js: verifyLedger did not re-check a recorded reviewer against the current policy (now does when a policy is supplied)
- posture/evaluation/lab/run.js: detect findings silently capped at 200 and hunt counters dropped; cancelled jobs had no attempt record
- test/eval-lab/arm-hunt.test.js was in no test scope; now in test:posture
- posture/routing/policy-router.js: routed on lab scores from synthetic datasets; now refused
