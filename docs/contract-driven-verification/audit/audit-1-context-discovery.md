# Audit 1: context-intelligence + discovery (2026-11-22, agent read-only)

Bundles: hash-bound (contextHash 'context-hash/1' over graphSchema, entrypoint{kind,method,path,handler}, profile, maxTokens, prune,
package sha256s, integrity; NOT commit/graph hash/config). manifest 'context-manifest/1' fields incl. repository, graph{hash}, controls[],
protection, unknowns, status, contextHash, manifestHash. Store: bundles/<contextHash>/..., reviews/<jobKey>.json; readPackageText refuses
hash-mismatch. Citation check review.js resolveCitation: range-invalid, file-not-in-snapshot, beyond-end-of-file, outside-provided-context,
stale-context, claim-not-grounded-in-cited-lines; verifyReview declines whole answer on one bad citation. CONCLUSIONS potential_issue |
no_issue_observed | insufficient_evidence. Review record 'context-review/1'. candidates.js reviewsToCandidates -> adjudicate (confirmAll ->
disprovePanel only with opts.refute -> judgeCandidates). controls.js CONTROL_KINDS authentication, authorization-role, ownership,
tenant-scope; a control has NO id/revision/digest. reachability PROTECTION_DIMENSIONS authentication, authorization-role, ownership (tenant
folded into ownership); states present, evaluated_and_ineffective, not_present, not_resolved, omitted_due_to_budget, not_seen.
DCI invariants: context-intelligence-invariants.json schema 'agentic-security/dci-invariants' 1.0.0, VERDICTS satisfied, violated,
unknown, not_applicable, public_by_policy, expired; rules requires | public-by-design; fields id,title,rule,appliesTo,requires,waives,
public,validity,severity; id ^[A-Z][A-Z0-9-]{2,63}$; NO revision/digest/approval. evaluateInvariants called only from findings.js:124 and
cross-route.js:86; dciFindings/candidatesFromEvidence/verifyDciFix have NO caller outside tests; `context` CLI has no invariant subcommand.
findings.js TIER_OF proven->taint-confirmed, plausible->sink-adjacent, unresolved->unconfirmed; counterexample STATES proven, plausible,
refuted, unresolved; candidate.deterministic{rule{kind invariant|cross-route-consistency,id,title,declaredSeverity}, invariant, scope,
counterexample, fix, verification{status:'pending'}}.
Hunt: index.js HUNT_MAX_FILES 2000, makeBudget 200 calls/15 min/50 candidates (no tokens); pipeline partition(<=8) -> runHunter per area x
lens -> cap -> confirmAll(makeTaintProbe) -> memory skip -> disprovePanel -> judge -> saveMemory -> emitVerification -> optional
invariantProposals/promotions. Hunt does NOT use DCI bundles; raw files, 60k chars (allotBudget), redactPayload, fenced. Candidate fields:
id, focusAreaId, lens, title, file, line, family, cwe, cweBasis, lensCwe, proposedCwe?, cweRejected?, anchored, citedLine?, rationale,
entryPoint, sink. disprove.js REFUTE_ANGLES reachability, preconditions, sanitization; vote {"refuted":bool,"reason":str}; record
refutation{votes[{angle,refuted,reason}], voterCount, refuteCount, refuted, undecided, egressDecision?}; overridden only for
taint-confirmed. Refute prompt has NO source code (title, file:line, rationale, tier), not redacted. judge.js unvetted/very-low when
undecided; dedupe file|line|family then stableId; triage fp suppresses. memory.js key file:line:family (no code digest/model id);
disable: --no-memory (sets scanRoot undefined => egress/redaction read from cwd project: BUG), --forget-refuted. CLI cmdHunt flags: lens,
max-areas, max-llm-calls, max-wall-ms, max-candidates, max-cost-usd, no-memory, forget-refuted, endpoints, cost-per-call-usd, no-variants.
No MCP tool for hunt/context. Egress: llm-invoke resolveLlmInvokeWithDecision purposes discovery-hunter/discovery-disprove, endpoint only.
Missing: service contract, threat pack, contractRef, contract-gap, per-candidate attrition; invariantId only in DCI results and posture
ledger. Posture ledger: lifecycle.js LEDGER_SCHEMA 'agentic-security/invariant-ledger', ACTIONS propose, approve, reject, supersede;
hash-chained + HMAC; approval needs a human in reviewer policy/approver registry; identity key+revision+id (content hash); REVIEW_STATES
proposed, approved, rejected, superseded; consumed by run.js, export.js, coverage.js (gap kinds 'unapproved-contract','absent-contract'),
repair.js. Caches: jobKeyOf hashes {schema, entrypoints, contextHashes, packageIndex, pack id/version, model{provider,model}, settings:{}}
(settings always empty: anonymizePrompts/redaction/egress/endpoint NOT in key). runIdOf, batchIdOf. Hunt has no result cache.
BUG: coverage.citationsDiscarded always 0 (runs.push never copies the field).
Stale docs: capabilities.js + architecture.md:51 say cross-file router mounts unresolved (contradicted by entrypoints.js GA-03.2);
DCI CLAUDE.md:15 no_issue_observed rule only when pack has a dimension; CLAUDE.md:14/guide:59 remote approval not applied on --refute
path; discovery CLAUDE.md:28 'disprove only remover' (memory skip, cap, citation discards, triage fp, DCI adjudicate without refute);
architecture module table omits invariants/findings/cross-route/counterexample; commands/scan.md hunt flags incomplete; architecture:39
'same redaction as hunt' (DCI refuses proprietary paths instead); index.js:222 reason text; holdout ledger per machine.
