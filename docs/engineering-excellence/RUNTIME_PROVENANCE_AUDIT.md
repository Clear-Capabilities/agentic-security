# Runtime and deployment provenance: integration audit (E5-01)

Generated from `docs/engineering-excellence/runtime-integration.json` by `node scripts/engineering-excellence/runtime-audit.mjs`. Every entry point below was checked to exist. The identity columns say what each source can and cannot tie to a deployed build.

## Identity each source carries

| Source | commit | buildHash | imageDigest | sbomRef | environment | service | routeId | functionSymbol | fileSpan | window |
|---|---|---|---|---|---|---|---|---|---|---|
| Runtime observation import (lineage) | - | - | - | - | carries | - | - | - | - | carries |
| Runtime trace correlation (older eBPF path) | - | - | - | - | - | - | carries | carries | carries | carries |
| Static data-flow graph | carries | - | - | - | - | - | - | - | - | - |
| Dependency reachability | - | - | - | - | - | - | - | - | carries | - |
| Service topology | - | - | - | - | - | carries | carries | - | carries | - |
| Git finding provenance | carries | - | - | - | - | - | - | - | carries | carries |
| Artifact attestations | carries | carries | carries | carries | carries | - | - | - | - | - |

Read the table for what is missing: no runtime source carries a commit, a build hash or an image digest, which is why an observation cannot yet be said to corroborate a finding about a particular build (E5-02).

## Runtime observation import (lineage)

Entry points: `scanner/src/lineage/observation-adapters.js` (`parseNativeJsonlObservations`, `parseOtelJsonObservations`, `parseEnvoyAccessLogObservations`, `parseK8sAuditLogObservations`, `parseHttpAccessLogObservations`, `adapterFor`); `scanner/src/lineage/observation-correlation.js` (`matchObservationToGraph`, `correlateObservations`); `scanner/src/lineage/observation-store.js` (`validateObservationImport`, `persistObservationImport`, `loadObservationImports`, `deleteObservationImport`); `scanner/src/lineage/runtime-observation.js` (`validateRuntimeObservation`); `scanner/src/lineage/runtime-assurance.js` (`computeRuntimeAssurance`)

- Carries: environment, window. Missing: commit, buildHash, imageDigest, sbomRef, service, routeId, functionSymbol, fileSpan.
- Matching: a three-rung ladder to category-level graph nodes: destination literal (high), store table (medium), queue topic (exact); several nodes is ambiguous.
- Evidence level: category-level graph node or flow; not function-level.
- When something is not observed: reported as not_observed_in_window per flow; never changes severity, never marks anything unreachable.
- Retention and privacy: closed-world attribute allowlist, payload-shaped fields rejected, counts banded; retention.expiresAt is validated but not enforced.

## Runtime trace correlation (older eBPF path)

Entry points: `scanner/src/posture/runtime-correlation.js` (`loadTrace`, `findingObservedInRuntime`, `annotateRuntimeCorrelation`)

- Carries: functionSymbol, fileSpan, routeId, window. Missing: commit, buildHash, imageDigest, sbomRef, environment, service.
- Matching: exact qid, then file plus line within two lines, then route path (substring when route-rooted).
- Evidence level: function and line.
- When something is not observed: runtimeObserved false and runtimeEvidence not_observed_in_window; severity is NOT changed unless the opt-in demotion policy is on and cites evidence.
- Retention and privacy: 30-day record window only; host is parsed and discarded; no redaction.

## Static data-flow graph

Entry points: `scanner/src/lineage/graph-builder.js` (`buildDataFlowGraph`); `scanner/src/lineage/graph-snapshot.js` (`buildGraphSnapshot`, `persistGraphSnapshot`, `loadSnapshot`); `scanner/src/lineage/ids.js` (`nodeId`, `edgeId`, `flowId`)

- Carries: commit. Missing: buildHash, imageDigest, sbomRef, environment, service, routeId, functionSymbol, fileSpan, window.
- Matching: node ids are 12-hex hashes of (repository, subtype, coverage, externality): stable across commits because no commit, file or line enters them; only graphId embeds the commit.
- Evidence level: registry-level nodes; a node has no location and several sites collapse onto one node.
- When something is not observed: not applicable.
- Retention and privacy: snapshots keyed by git HEAD.

## Dependency reachability

Entry points: `scanner/src/sca/import-reachability.js` (`augmentReachabilityViaImports`, `findImportAwareCallSites`); `scanner/src/posture/reachability-filter.js` (`demoteUnreachable`)

- Carries: fileSpan. Missing: commit, buildHash, imageDigest, sbomRef, environment, service, routeId, functionSymbol, window.
- Matching: static, by vulnerable function name and import; unit is (package, function).
- Evidence level: function (call sites {pkg, fn, file, line}).
- When something is not observed: no runtime input; inconclusive static results are unknown, not unreachable.
- Retention and privacy: none.

## Service topology

Entry points: `scanner/src/dataflow/service-edges.js` (`buildServiceEdges`, `traceFrom`, `extractFacts`); `scanner/src/dataflow/cross-service-taint.js` (`loadServiceGraph`, `annotateCrossServiceFindings`); `scanner/src/dataflow/cross-repo.js` (`buildFederatedGraph`, `federatedFindings`); `scanner/src/lineage/cross-repo-link.js` (`validateCrossRepoLink`); `scanner/src/posture/fleet.js` (`runFleet`, `rollupFleet`)

- Carries: service, routeId, fileSpan. Missing: commit, buildHash, imageDigest, sbomRef, environment, functionSymbol, window.
- Matching: declared service names and hosts (service-edges); package name or directory basename (cross-service-taint); manifest names (fleet).
- Evidence level: route, topic or table; edge evidence is observed, inferred or unknown.
- When something is not observed: not applicable.
- Retention and privacy: none.

## Git finding provenance

Entry points: `scanner/src/posture/provenance/coordinator.js` (`annotateGitProvenance`)

- Carries: commit, fileSpan, window. Missing: buildHash, imageDigest, sbomRef, environment, service, routeId, functionSymbol.
- Matching: line-level blame to the commit that introduced the finding.
- Evidence level: finding line.
- When something is not observed: not applicable.
- Retention and privacy: cache keyed on HEAD; raw record on disk (mode 0700), redacted at presentation.

## Artifact attestations

Entry points: `scanner/src/artifact/image-archive.js` (`parseImageArchive`); `scanner/src/artifact/inventory.js` (`buildImageInventory`); `scanner/src/artifact/signature.js` (`verifyImageSignature`, `verifyProvenanceAttestation`); `scanner/src/artifact/provenance-graph.js` (`buildArtifactProvenanceGraph`, `traceArtifactProvenanceGraph`); `scanner/src/artifact/mismatch.js` (`detectSourceArtifactMismatch`)

- Carries: commit, buildHash, imageDigest, sbomRef, environment. Missing: service, routeId, functionSymbol, fileSpan, window.
- Matching: commit only through the org.opencontainers.image.revision label; deployment is operator-declared and its digest is compared with the image; mismatch is keyed on advisory id and package presence.
- Evidence level: package or advisory; SAST and secret findings have no link to an artifact.
- When something is not observed: not applicable.
- Retention and privacy: scans stored per digest under the state directory; tar input only.

## Source of truth

| Question | Canonical answer | Rule |
|---|---|---|
| Was this code path observed running? | scanner/src/lineage/observation-correlation.js (flow level) and scanner/src/posture/runtime-correlation.js (function level), reported as separate evidence, never merged into one verdict | absence of observation is never evidence of unreachability or safety |
| Does a finding's severity depend on runtime observation? | no, by default | demotion is an opt-in policy that cites evidence (record count, file observed); it never removes a finding |
| Which build is this observation about? | an observation must carry commit, build hash or image digest (E5-02); until it does, it cannot be labelled as corroborating a static finding | a mismatched or unknown build is unknown, not corroborated |
| Which service is this? | the declared service name and hosts in the service map (dataflow/service-edges.js input); fleet manifest names and runtime service.name must match a declared name or host, otherwise the link is unknown | no link from a basename or a package name alone |
| Which commit is the static graph? | the git HEAD recorded by graph-snapshot.js; graphId embeds a commit only when the caller supplies one, so they can disagree and graphId is not used as the commit of record | compare commits, not graph ids |

## Conflicts

| Id | Status | Conflict | Resolution |
|---|---|---|---|
| C1 | resolved in E5-01 | posture/runtime-correlation.js lowered the severity of every finding not seen in the trace, while the lineage observation path never demotes and the reachability filter says unknown, not unreachable. Absence of observation was being read as dead code. | annotateRuntimeCorrelation no longer changes severity by default. It records runtimeEvidence in words. Demotion is opt-in (opts.demote or AGENTIC_SECURITY_RUNTIME_DEMOTE=1), needs a minimum record count and route-level traffic evidence (a route-rooted finding whose route was not hit while other routes were), and records the evidence it relied on. |
| C2 | resolved in E5-01 | A finding in a file that was never instrumented came back runtimeObserved false and was demoted the same as one in a traced file. | the demotion condition now requires route-level traffic evidence; a finding in an uninstrumented file or without a route is left alone. |
| C3 | decided (implemented by E5-02) | Neither runtime path carries commit, build hash or image digest, and lineage node ids are not commit-keyed, so an observation taken on one build matches another build's graph as if identical. | decided: an observation needs a build identity to count as corroboration; E5-02 adds it and rejects mismatches. |
| C4 | decided (implemented by E5-02) | No join between a runtime observation's environment and the artifact graph's deployment node; graphId's commit and graph-snapshot's HEAD can disagree. | decided: the artifact deployment record (declared digest, environment) is the join key; the commit of record is the snapshot HEAD. |
| C5 | decided (implemented by E5-03) | retention.expiresAt on an observation import is validated and never enforced; expired imports still feed correlation and assurance. | decided: expiry is enforced at read time (E5-03). |
| C6 | decided (implemented by E5-04) | The eBPF path is function and line level, the lineage path is category level, and no mapping exists between them. | decided: they stay separate evidence; E5-04 maps both onto the semantic graph's qualified symbols and spans and states each edge as statically_inferred, runtime_observed, both, conflicted or unknown. |
| C7 | decided (implemented by E5-04) | Service identity differs per module: declared names (service-edges), package name or basename (cross-service-taint), manifest names (fleet), service.name attribute (runtime). | decided: the declared service map is canonical (see sourceOfTruth); the others must resolve to it. |
| C8 | resolved in E5-01 | annotateCrossServiceFindings can raise severity on a static edge and annotateRuntimeCorrelation could lower it, so annotator order decided the final severity. | with demotion off by default the two no longer fight; with it on, the demotion records its evidence and the order is the engine's fixed annotator order. |

## Not determined

- whether the CLI passes opts.commit to buildDataFlowGraph (graphId may therefore read 'uncommitted')
- whether anything outside engine.js reads runtimeObserved or _runtimeDemoted
- where lineage/deployment/ fits the digest story
