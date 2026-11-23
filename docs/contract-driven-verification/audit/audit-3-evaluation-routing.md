# Audit 3: evaluation lab + routing (2026-11-22, agent read-only)

Dataset: schema 'agentic-security/eval-dataset'; SPLITS dev, validation, sealed; kinds vulnerable, fixed, hard-negative; leakagePolicy.mode
'enforce' only; vulnerable needs cwe + expectedSpan{file,startLine,endLine}; hard-negative needs category, resemblesCwe, lookalikeSpan; git
rev must be a commit; datasetHash = digestOf({dataset, entries}). Arm request: {schema 'agentic-security/eval-request', task, language,
workspace} (+target/candidate for falsify/exploit/patch); labels never in request. neutralize.js stageNeutralized: removePaths, rename
/cwe[-_]?\d/ files -> caseNNNN, strip comments (line-preserving), auditWorkspace; leak kinds weakness-in-file-name, descriptive-comment,
weakness-id-in-content, protected-term, advisory-id; leak => quarantine. leakageAudit status clean | entries-excluded | no-entries-usable.
Importer scripts/eval-lab/import-independent.mjs refuses sealed; source.spanApproximate NOT used by scoring.
Arms: adapter.type builtin-scanner | command | ollama | hunt; TASKS detect, falsify, exploit, patch; attempt statuses completed | timeout |
error | blocked | unavailable (+ 'skipped-budget'). arm-hunt.js: detect-only, loopback-only, deterministic scan + runDiscovery, guardPrompt
on every hunter prompt (hit blocks attempt), NO scanRoot (no hunt memory), no focus area -> unavailable, budget exhausted -> error, findings
carry source deterministic|hunt + tier + contested, output.hunt counters.
BUGS: test/eval-lab/arm-hunt.test.js not in any test:* script (no-orphan-tests reads only top-level test/); run.js:173 keeps only
findings.slice(0,200) (hunt counters dropped; cap can turn a TP into a miss); cancellation leaves unstarted jobs with no attempt record;
routing policy-router routes from lab scoreboard with no synthetic/split check.
Run record: config {tasks, repeats, concurrency, timeoutMs, budgetUsd, lineTolerance: 3}; per arm model{id,provider,local,version??null} +
configDigest; dataset.hash+split; scanner{version, commit} (git rev-parse at run time, dirty tree not refused); runId from dataset hash +
arms + config + startedAt. NOT pinned: prompt/template version (ollama prompt hard-coded arm-ollama.js:58), matcher version, reference
digest, frozen protocol binding. Frozen protocol exists in evaluation/protocol.js (engine.version/bundleDigest, measurement.commit
cleanTree, tools, models[{provider,model,version}], limits{perTargetTimeoutMs, spendCeilingUsd, replicates}, matching;
PREREGISTERED_THRESHOLDS; DEFAULT_MATCHING {policy 'root-cause-location', lineWindow 3, requireFamilyOrCwe true, cweAloneSufficient false,
lineLessFindingsMatch false}; amendProtocol refuses POST_RESULT_CHANGE; deriveSuccessorProtocol refuses SEALED_REUSE; assertBoundToProtocol);
evaluation/runner.js run identity (protocol hash, engine, layer, provider, model, settings, cache, seed, budget, split, replicate, target
digests), OUTCOME_STATUSES completed, timeout, error, unavailable, quarantined; runReplicates needs >=3 for stochastic.
Score: DEFAULT_LINE_TOLERANCE 3 (unversioned); TP = same file + normalized CWE + line within span±3; miss classes wrong-location,
wrong-class, not-found, no-result:<status>; f1, macroF1, fileLevelRecall, localizationAccuracy, hardNegativeFalsePositiveRate; labels.js
matchFinding reasons cwe-only, wrong-file, no-line, outside-range, family-mismatch.
Stats: lab Student-t 95% over per-repeat values, MIN_REPRESENTATIVE_RUNS 3, no grouping; pairedComparisons wins/losses/ties vs
deterministic repeat 0, not rendered by report.js; evaluation/interval.js INTERVAL_METHODS grouped-bootstrap-95 (minGroups 10 else
unmeasured), wilson-95 (used by routing promotion, not lab).
Report: REPORT_FORMATS json, csv, md, html, chart; CLI eval run|report|compare|list (bin:8059), models benchmark|route (8056); null-with-
reason {value:null, reason}; '(not representative)' <3 runs; INCOMPLETE marker; lab has no synthetic/historical/independent tag;
evaluation/report.js POPULATIONS regression, development, sealed, operational, strata below threshold -> unmeasured.
Repeated runs: NO per-defect detection history, union/stable recall, stage attrition/survival; why-missed.js STAGES only for the
deterministic engine; completion lacks scheduled/started/unsupported.
Semantic matching: none; NON_TRUTH_SIGNALS includes 'model-judgement' (routing/outcomes.js:124); labels.js adjudication schemas
'agentic-security/adjudicated-defect-label' / 'adjudicated-negative', ADJUDICATION_STATUSES candidate, adjudicated, disputed, rejected;
needs >=2 reviewers not the proposer, all 'confirmed', independent:true; reviewQueue -> 'needs-adjudication' for unmatched findings.
Lab dataset does not use these labels.
Gates: protocol PREREGISTERED_THRESHOLDS raise-only; gates.js GATE_STATUSES pass, fail, insufficient-population, unmeasured; only real
scoreable sealed labels count; synthetic protocol always blocked; integrity gates answer-key-leaks, denominator-intact,
no-regression-vs-baseline; release-gate.js Ed25519 self-issued-local-key, independentlyCertified:false, sealed ledger,
'fresh-sealed-population-required'; scripts/evaluation.mjs release-gate|verify-gate. grouping.js union-find (pair, upstream, advisory,
commit, template), assignSplits hashes groups; bench/independent/splits.json 'grouped-hash-3way/1' 0.6/0.2/0.2, 423 groups/1004 entries.
Economics: lab usageOf cost reported | computed-from-reported-tokens | unknown | no-model; scoreEconomics tokens, tokensUnknownAttempts,
latency median/p95, timeouts, failures (no retries). routing/outcomes.js OUTCOME_STATUSES completed, partial, failed, timeout, cancelled,
provider-error, blocked; deriveRoutingLabel accepts correct/incorrect only with 'independent-adjudication' (human|verifier-service, not
model/provider, adjudicationVersion) or 'trusted-execution' (vrec:); append-only ledger; shadow.js paidCalls 0; promotion statuses
invalid, unmeasured, insufficient-population, fail, pass; synthetic -> unmeasured; calibration 'reliable-synthetic' refused by decide.js.
Stale docs: docs/implementation-status/eval-lab-and-model-router.md:5,18,50,54,59-60 (hunt arm 'not built', only Ollama adapter);
:12 and docs/ga-program/STATUS.md:302 cite arm-hunt.test.js as evidence though npm test never runs it; measurement-status.md:9 omits the
real-code lab run and the hunt adapter.
