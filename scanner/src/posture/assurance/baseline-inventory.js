// The recommendation mappings and the capability inventory that baseline capture
// (CORE-001) records. Pure data. Every path is relative to the repository root and
// is VERIFIED against the checkout at capture time: a path that does not exist is
// reported as a problem, never carried as if it did.
//
// Status vocabulary (one per capability, never combined):
//   implemented  the capability exists, has a source path and a test or artifact,
//                and no gap against the differentiation PRD is known.
//   partial      it exists and is tested, and `gap` names exactly what the PRD
//                still needs on top of it.
//   unsupported  the PRD calls for it and the checkout does not provide it; `source`
//                is the existing extension point it would attach to, `evidence` the
//                test that covers that neighbour, and `gap` says what is absent.
//   unmeasured   it exists but no current-revision measurement of it is recorded;
//                `evidence` is the artifact that exists and `gap` says why it is not a
//                current measurement.
//
// This is a statement about what was inspected, not a quality score. Moving an
// entry to a stronger status needs the new source and evidence paths to land first.

export const RECOMMENDATION_MAPPINGS = Object.freeze([
  {
    n: 1, title: 'Refresh real-code evaluation and repair measured misses', priority: 'P0', slice: 'QA-001..QA-008',
    extensionPoints: ['bench/independent', 'scanner/src/posture/accuracy-scorecard.js', 'scripts/scorecard.mjs', 'docs/scorecard.json'],
  },
  {
    n: 2, title: 'Unify verification and expand trusted runtime oracles', priority: 'P0', slice: 'X-201..X-208',
    extensionPoints: ['scanner/src/posture/fix-verify.js', 'scanner/src/posture/execution-proof.js', 'scanner/src/posture/verifier.js', 'scanner/src/sandbox/index.js', 'scanner/src/posture/autopilot.js', 'scanner/src/mcp/tools.js'],
  },
  {
    n: 3, title: 'Add a deployment-aware Code Boundaries graph', priority: 'P1', slice: 'X-301..X-308',
    extensionPoints: ['scanner/src/lineage/runtime-observation.js', 'scanner/src/lineage/observation-adapters.js', 'scanner/src/lineage/observation-correlation.js', 'scanner/src/lineage/cross-repo-link.js', 'scanner/src/lineage/federation-loader.js', 'scanner/src/lineage/drift-policy.js'],
  },
  {
    n: 4, title: 'Execute tenant and business invariants', priority: 'P1', slice: 'X-401..X-408',
    extensionPoints: ['scanner/src/posture/business-logic.js', 'scanner/src/posture/logic-claims.js', 'scanner/src/posture/specification-mining.js', 'scanner/src/discovery'],
  },
  {
    n: 5, title: 'Enforce coding-agent capabilities', priority: 'P1', slice: 'X-501..X-508',
    extensionPoints: ['hooks/pre-bash-guard.js', 'hooks/pre-edit-bodyguard.js', 'hooks/dispatch-pre-tool.js', 'scanner/src/egress/policy.js', 'scanner/src/egress/redact.js', 'scanner/src/egress/audit.js', 'scanner/src/sandbox/index.js', 'scanner/src/mcp/server.js'],
  },
  {
    n: 6, title: 'Calibrate model routing against outcomes', priority: 'P2', slice: 'X-601..X-608',
    extensionPoints: ['scanner/src/posture/model-routing.js', 'scanner/src/posture/model-trust.js', 'scanner/src/posture/cache-economics.js', 'scanner/src/posture/provider-catalog.js'],
  },
  {
    n: 7, title: 'Deliver portable release assurance and resumable portfolios', priority: 'P2', slice: 'X-701..X-708',
    extensionPoints: ['scanner/src/posture/fleet.js', 'scanner/src/posture/scan-checkpoint.js', 'scanner/src/posture/attestation.js', 'scanner/src/posture/evidence-bundle.js', 'scanner/src/posture/integrity.js', 'scanner/src/posture/retention-policy.js'],
  },
]);

const t = (p) => ({ kind: 'test', path: p });
const a = (p) => ({ kind: 'artifact', path: p });

export const CAPABILITY_INVENTORY = Object.freeze([
  {
    id: 'poc-replay', workstream: 2, title: 'Proof-of-concept generation and confined replay',
    status: 'partial',
    source: ['scanner/src/posture/poc-generator.js', 'scanner/src/posture/poc-inprocess.js', 'scanner/src/posture/execution-proof.js', 'scanner/src/posture/proof-tier.js'],
    entryPoints: [{ path: 'scanner/src/posture/execution-proof.js', symbol: 'proveFinding' }, { path: 'scanner/src/posture/proof-tier.js', symbol: 'attachProofTier' }],
    evidence: [t('scanner/test/poc-generator.test.js'), t('scanner/test/execution-proof.test.js'), t('scanner/test/proof-artifact.test.js')],
    gap: 'replay is JavaScript/taint oriented and records a proof tier on the finding; there is no class-specific oracle adapter, no patched-negative replay, and no single verification record',
    prd: ['X-201', 'X-202', 'X-203', 'X-204', 'X-205'],
  },
  {
    id: 'fix-verification', workstream: 2, title: 'Fix verification (rescan, lint, tests, honesty gate, PoC re-check)',
    status: 'partial',
    source: ['scanner/src/posture/fix-verify.js', 'scanner/src/posture/fix-verify-loop.js', 'scanner/src/fix/apply-fix-service.js', 'scanner/src/posture/fix-honesty-gate.js'],
    entryPoints: [{ path: 'scanner/src/posture/fix-verify.js', symbol: 'verifyFix' }, { path: 'scanner/src/fix/apply-fix-service.js', symbol: 'applyVerifiedFix' }],
    evidence: [t('scanner/test/fix-verify-loop.test.js'), t('scanner/test/fix-verify-tests.test.js'), t('scanner/test/apply-fix-service.test.js'), t('scanner/test/fix-honesty-gate.test.js')],
    gap: 'results are per-surface shapes, not one versioned record; original-positive, patched-negative and functional-regression evidence are not bound together by digest',
    prd: ['X-201', 'X-204', 'X-206'],
  },
  {
    id: 'verifier-separation', workstream: 2, title: 'Independent verifier and verification separation',
    status: 'partial',
    source: ['scanner/src/posture/verifier.js', 'scanner/src/posture/verification-separation.js', 'scanner/src/posture/verifier-target.js', 'scanner/src/posture/verifier-ephemeral.js'],
    entryPoints: [],
    evidence: [t('scanner/test/verifier.test.js'), t('scanner/test/verifier-independence.test.js'), t('scanner/test/verification-separation.test.js')],
    gap: 'separation is enforced for the existing verifier path; key and label isolation for the new oracle workers is the CORE-003 trust-boundary work',
    prd: ['CORE-003', 'X-202'],
  },
  {
    id: 'sandbox-confinement', workstream: 2, title: 'Confinement sandbox (namespace, userspace and disabled backends)',
    status: 'partial',
    source: ['scanner/src/sandbox/index.js', 'scanner/src/sandbox/capabilities.js', 'scanner/src/sandbox/limits.js', 'scanner/src/sandbox/backend-namespace.js', 'scanner/src/sandbox/backend-userspace.js', 'scanner/src/sandbox/backend-disabled.js'],
    entryPoints: [{ path: 'scanner/src/sandbox/index.js', symbol: 'runConfined' }],
    evidence: [t('scanner/test/sandbox.test.js'), t('scanner/test/sandbox-escape.test.js')],
    gap: 'isolation is probed per backend; descendant-process cleanup, read confinement and per-backend active probes are the CORE-003 work, and enforcement is only advertised on Linux',
    prd: ['CORE-003', 'X-502', 'X-503'],
  },
  {
    id: 'runtime-observation-imports', workstream: 3, title: 'Runtime observation imports and correlation',
    status: 'partial',
    source: ['scanner/src/lineage/runtime-observation.js', 'scanner/src/lineage/observation-adapters.js', 'scanner/src/lineage/observation-store.js', 'scanner/src/lineage/observation-correlation.js', 'scanner/src/posture/telemetry-ingest.js'],
    entryPoints: [{ path: 'scanner/src/lineage/runtime-observation.js', symbol: 'validateRuntimeObservation' }, { path: 'scanner/src/lineage/observation-store.js', symbol: 'persistObservationImport' }],
    evidence: [t('scanner/test/lineage/runtime-observation.test.js'), t('scanner/test/lineage/observation-adapters.test.js'), t('scanner/test/lineage/observation-store.test.js'), t('scanner/test/lineage/observation-correlation.test.js')],
    gap: 'one adapter (native-jsonl) is implemented; observations corroborate lineage edges but do not yet bind to vulnerability hypotheses, and freshness and sampling are not modelled as path states',
    prd: ['X-302', 'X-303', 'X-305'],
  },
  {
    id: 'cross-repo-federation-drift', workstream: 3, title: 'Cross-repository links, federation and drift policy',
    status: 'implemented',
    source: ['scanner/src/lineage/cross-repo-link.js', 'scanner/src/lineage/federation-loader.js', 'scanner/src/lineage/drift-policy.js', 'scanner/src/lineage/graph-diff.js'],
    entryPoints: [{ path: 'scanner/src/lineage/cross-repo-link.js', symbol: 'validateCrossRepoLink' }],
    evidence: [t('scanner/test/lineage/cross-repo-link.test.js'), t('scanner/test/lineage/federation-loader.test.js'), t('scanner/test/lineage/drift-policy.test.js')],
    gap: null,
    prd: ['X-304', 'X-306'],
  },
  {
    id: 'business-logic-claims', workstream: 4, title: 'Business-logic detection, logic claims and specification mining',
    status: 'partial',
    source: ['scanner/src/posture/business-logic.js', 'scanner/src/posture/logic-claims.js', 'scanner/src/posture/specification-mining.js'],
    entryPoints: [],
    evidence: [t('scanner/test/business-logic.test.js'), t('scanner/test/logic-claims.test.js'), t('scanner/test/phase3-v3.test.js')],
    gap: 'claims are advisory findings; there are no declarative approved invariants and no bounded stateful scenario execution',
    prd: ['X-401', 'X-402', 'X-403', 'X-404'],
  },
  {
    id: 'stateful-invariant-execution', workstream: 4, title: 'Approved invariants, stateful scenarios, state oracles and sequence shrinking',
    status: 'unsupported',
    source: ['scanner/src/posture/logic-claims.js', 'scanner/src/discovery'],
    entryPoints: [],
    evidence: [t('scanner/test/logic-claims.test.js')],
    gap: 'no executable invariant contract, approval state, scenario generator, durable-effect oracle or minimizer exists in the checkout',
    prd: ['X-401', 'X-403', 'X-404', 'X-405'],
  },
  {
    id: 'egress-policy-redaction-audit', workstream: 5, title: 'Central egress policy, outbound redaction and tamper-evident audit',
    status: 'implemented',
    source: ['scanner/src/egress/policy.js', 'scanner/src/egress/redact.js', 'scanner/src/egress/audit.js'],
    entryPoints: [{ path: 'scanner/src/egress/policy.js', symbol: 'evaluateEgress' }, { path: 'scanner/src/egress/redact.js', symbol: 'redactPayload' }, { path: 'scanner/src/egress/audit.js', symbol: 'recordEgressCall' }],
    evidence: [t('scanner/test/egress-policy.test.js'), t('scanner/test/egress-redact.test.js'), t('scanner/test/egress-audit.test.js'), t('scanner/test/egress-policy-completeness.test.js')],
    gap: null,
    prd: ['CORE-004', 'X-504'],
  },
  {
    id: 'agent-hooks', workstream: 5, title: 'Pre-edit, pre-bash and dispatch hooks',
    status: 'partial',
    source: ['hooks/pre-bash-guard.js', 'hooks/pre-edit-bodyguard.js', 'hooks/dispatch-pre-tool.js', 'hooks/hooks.json'],
    entryPoints: [],
    evidence: [t('scanner/test/pre-bash-guard.test.js'), t('scanner/test/bodyguard.test.js'), t('scanner/test/dispatch-pre-tool.test.js')],
    gap: 'hooks explain and advise at the prompt layer; no runner mediates filesystem, command or network access, so a hook response is not an enforcement receipt',
    prd: ['X-501', 'X-502', 'X-505', 'X-507'],
  },
  {
    id: 'mcp-server', workstream: 2, title: 'MCP server tools (including the write-gated fix tools)',
    status: 'partial',
    source: ['scanner/src/mcp/server.js', 'scanner/src/mcp/tools.js', 'scanner/src/mcp/validate.js', 'scanner/src/mcp/audit.js'],
    entryPoints: [],
    evidence: [t('scanner/test/mcp.test.js'), t('scanner/test/mcp-audit.test.js'), t('scanner/test/mcp-protocol-smoke.test.js')],
    gap: 'tool results are not yet emitted as the unified verification record',
    prd: ['X-206'],
  },
  {
    id: 'model-routing-and-trust', workstream: 6, title: 'Model routing, measured trust, cache economics and provider catalog',
    status: 'partial',
    source: ['scanner/src/posture/model-routing.js', 'scanner/src/posture/model-trust.js', 'scanner/src/posture/cache-economics.js', 'scanner/src/posture/provider-catalog.js'],
    entryPoints: [{ path: 'scanner/src/posture/model-trust.js', symbol: 'createTrustLedger' }, { path: 'scanner/src/posture/model-routing.js', symbol: 'routeModelWithTrust' }],
    evidence: [t('scanner/test/model-routing.test.js'), t('scanner/test/model-trust.test.js'), t('scanner/test/cache-economics.test.js'), t('scanner/test/providers.test.js'), a('bench/router-replay/baseline.json')],
    gap: 'trust is a per-key miss-rate ledger; there are no adjudicated task strata, calibrated quality intervals, shadow validation or drift circuit breakers',
    prd: ['X-601', 'X-603', 'X-604', 'X-605'],
  },
  {
    id: 'fleet-checkpoints', workstream: 7, title: 'Fleet runs and scan checkpoints',
    status: 'partial',
    source: ['scanner/src/posture/fleet.js', 'scanner/src/posture/scan-checkpoint.js', 'scripts/fleet.mjs'],
    entryPoints: [{ path: 'scanner/src/posture/scan-checkpoint.js', symbol: 'openCheckpoint' }],
    evidence: [t('scanner/test/fleet.test.js'), t('scanner/test/scan-checkpoint.test.js')],
    gap: 'checkpoints resume a single scan; there are no durable leased work units, dependency-hash invalidation or portfolio budgets',
    prd: ['X-704', 'X-705', 'X-706'],
  },
  {
    id: 'attestation-and-evidence-bundles', workstream: 7, title: 'Run attestation, signed per-finding evidence bundles, integrity and retention',
    status: 'partial',
    source: ['scanner/src/posture/attestation.js', 'scanner/src/posture/evidence-bundle.js', 'scanner/src/posture/integrity.js', 'scanner/src/posture/retention-policy.js'],
    entryPoints: [{ path: 'scanner/src/posture/evidence-bundle.js', symbol: 'signEvidenceBundle' }, { path: 'scanner/src/posture/attestation.js', symbol: 'computeRunAttestation' }],
    evidence: [t('scanner/test/attestation.test.js'), t('scanner/test/evidence-bundle.test.js'), t('scanner/test/retention-policy.test.js'), t('scanner/test/verify-attestation-cli.test.js')],
    gap: 'bundles are per finding with a local signer; there is no release assurance manifest, portable package or explicit trust-root policy',
    prd: ['X-701', 'X-702', 'X-703', 'CORE-003'],
  },
  {
    id: 'accuracy-scorecard', workstream: 1, title: 'Published accuracy scorecard and corpus replay',
    status: 'implemented',
    source: ['scanner/src/posture/accuracy-scorecard.js', 'scripts/scorecard.mjs'],
    entryPoints: [],
    evidence: [t('scanner/test/accuracy-scorecard.test.js'), t('scanner/test/scorecard.test.js'), a('docs/scorecard.json')],
    gap: null,
    prd: ['QA-004'],
  },
  {
    id: 'independent-accuracy-current-engine', workstream: 1, title: 'Current-engine accuracy on independent real code',
    status: 'unmeasured',
    source: ['bench/independent/runner.mjs', 'bench/independent/manifest.json'],
    entryPoints: [],
    evidence: [a('docs/scorecard.json'), a('docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md')],
    gap: 'the recorded independent result belongs to an older engine revision; no current-engine adjudicated measurement exists in the checkout',
    prd: ['QA-001', 'QA-002', 'QA-003'],
  },
  {
    id: 'loop-controller', workstream: 'foundation', title: 'Supervised background implementation controller (Haskell/Nix profile)',
    status: 'partial',
    source: ['scripts/loop-engineering/run.mjs', 'scripts/loop-engineering/profiles/haskell-nix.json'],
    entryPoints: [],
    evidence: [t('scripts/loop-engineering/test/loop-manifest.test.js'), t('scripts/loop-engineering/test/loop-watchdog.test.js'), t('scripts/loop-engineering/test/loop-recovery.test.js')],
    gap: 'only the Haskell/Nix profile exists; the assurance-differentiation profile and its protected acceptance suites are not present',
    prd: ['LOOP-001', 'LOOP-002', 'LOOP-003'],
  },
  {
    id: 'lineage-graph', workstream: 3, title: 'Data Flow Explorer lineage graph (DataFlowGraph v1)',
    status: 'implemented',
    source: ['scanner/src/lineage/graph-builder.js', 'scanner/src/lineage/ids.js', 'scanner/src/lineage/schema.js', 'scanner/src/lineage/dataflow-graph.schema.json'],
    entryPoints: [{ path: 'scanner/src/lineage/ids.js', symbol: 'graphId' }],
    evidence: [t('scanner/test/lineage/schema.test.js'), t('scanner/test/lineage/ids.test.js')],
    gap: null,
    prd: ['X-301'],
  },
]);
