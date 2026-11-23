# Audit 4: deployment graph, runtime, registry, MCP (2026-11-22, agent read-only)

Federation (GA): lineage/cross-repo-link.js + federation-loader.js; `federate declare` writes cross-repo-links.json (backup, atomic,
audit event); endpoints {graphId, graphDigest, nodeId} + remote {repository, sourceFile}; no access scope/explicit revision; load reasons
missing|malformed|invalid-graph|digest-mismatch (mismatch is a warning under --yes); evidence {declared:true, observed:false}.
Deployment cross-repo (X-304, lineage/deployment/cross-repo.js): checkDeclaration caller/callee {repository, revision, service,
environment, tenant?} + callee.route; REV 40/64 hex; refuses joining environments/tenants; resolveCrossRepoBoundaries({graphs,
declarations, accessScope:{authorizedRepositories}}) -> no scope = 'invalid-input'; GAP_CODES (boundary-graph.js:58) access-denied,
repository-unavailable, version-mismatch, revision-unknown, unresolved-identity, identity-collision, graph-integrity, malformed-input;
unresolved links kept; no clone/credentials. NO CLI caller (tests only).
Boundary graph: NODE_KINDS repository, service, route, identity, tenant, resource, environment; TRUST_ZONES public, edge, internal,
privileged, tenant-isolated, unknown; BOUNDARY_TYPES network, identity, tenant, environment, repository; HTTP/RPC not distinguished, no
queue relation; identity nodes are workload identities; NO end-user principal/role/source-of-trust; headers dropped by trace importer;
transitions {entry, callerIdentities, calleePrivileges[...], crossings}. lineage/boundary-contract.js BOUNDARY_KINDS http, queue, storage
(operator-declared data-flow handoffs).
Runtime: deployment stack JSONL only (traces.jsonl); twin adapters native-jsonl, otel-json, envoy-access-log, k8s-audit-log,
http-access-log ('otlp' refused); sanitization closed key allowlists, :id path normalization; identity.token idt_…; environment-mismatch
refused; window {start,end}; CORRELATION_RULES R1-R4 (R4 inferred, confidence low); build identity linkObservationToSnapshot matched|
mismatched|unknown, correlateWithBuild corroborated|unattested|none BUT IDENTITY_ATTRIBUTE_KEYS not in RUNTIME_ATTRIBUTE_KEYS and no CLI
caller; completeness 'sampled'|'unknown' never complete; trafficCoverage 'not-established'; stale after 7 days; absence never blocks
(static edge stays possible); OBSERVATION_LAYERS runtime_observed, not_observed_in_window, not_evaluated; EDGE_STATES STATIC_ONLY vs
RUNTIME_NOT_OBSERVED; RUNTIME_STATUS_VALUES complete, partial, unavailable; exception: posture/runtime-correlation.js demote opt-in
(AGENTIC_SECURITY_RUNTIME_DEMOTE=1, >=100 records, sampleRate 1) lowers severity one tier, never removes. Drift: diffBoundaryGraphs/
planRescan, MATERIAL_CATEGORIES new-exposure, changed-privilege, tenant-weakening, removed-control; no CLI caller. NO observation-to-
regression workflow (repair observe records operator notes only). NO shadow baseline-vs-patched runtime comparison.
Proof binding: 'agentic-security/proof-binding' v1 envelope recordId, commit, artifactDigest, policyDigest, environment, tenant, actor,
route, action, pathId, claim exposure|impact, oracleVersion, effect, issuer, issuedAt, expires; Ed25519 vs operator trustRoot; codes
malformed, unsupported-version, missing-binding, untrusted-issuer, tampered, expired, context-mismatch, component-only, bound; used by
attack-paths labelPath 'exploitable-confirmed'; GAP boundaries-run.js/projection.js never pass records/bindings -> unreachable from CLI.
Registry: federation GA [linux:test-shard]; runtime-corroboration GA; live-runtime-observation Roadmap; code-boundaries Preview; NO entry
for deployment boundaries X-301..308/drift/proof binding (assurance/config.js 'deployment-boundaries' passive, linux/darwin/win32);
no invariants entry; exploit-proof GA [linux:proof-linux, linux:proof-container]; safe-fix/verified-remediation GA; contract-repair Labs;
proof-gated-fix GA; capability-enforcement Labs; agentic-discovery Preview; context-intelligence Preview; mcp-server GA 'two write tools'
(six tools write). Platform: Linux partially-verified (sandbox-linux), macOS host-proved not enforced, win32 unsupported.
MCP: 26 tools; none for context/hunt/runtime/boundaries/federation; invariant_scenario_export read-only; repair_plan read-only; writers
apply_fix, apply_sca_upgrade, verify_fix, append_scratchpad, append_agents_memory, prove_finding.
Stale: scanner/CLAUDE.md 'Linux unverified' (code: partially-verified); duplicate test rows; capabilities/CLAUDE.md vs probes.js on
corpus-in-sandbox; capability-enforcement platforms cite test-shard not sandbox-linux; contract-repair vs capabilities/CLAUDE.md on Linux
boundary; mcp 'two write tools'; observation-adapters.js header 'only ONE adapter'; deployment-aware-support.md:91 promotion unreachable;
lineage/CLAUDE.md X-304/X-306 no-caller omission; build identity documented but not importable; 'complete' means two things.
