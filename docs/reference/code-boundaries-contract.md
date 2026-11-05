# Code Boundaries graph artifacts: contract

The frozen shape and behaviour of the artifacts the Code Boundaries security graph, the graph precision work and deterministic context intelligence produce and consume: the signed lineage graph, witness bundles, boundary contracts, context bundles, demand sink queries and control-placement plans. Each has a versioned schema, an integrity check, a replay or re-verification path, a wrong-revision refusal where a revision is recorded, and a rule for how partial analysis state propagates into it. The test `scanner/test/contracts/code-boundaries.contract.test.js` holds the implementation to every table and every rule on this page, in both directions: a field that disappears fails, and so does a field this page does not list.

These capabilities are Preview. Freezing the contract does not promote them: the real-code graph precision and recall of the frozen evaluation protocol are unmeasured (GA-02), and what each artifact does NOT establish is stated beside what it does.

## The signed lineage graph

A scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` writes `.agentic-security/lineage-graph.json` and a sibling `.sig` (an HMAC under the per-install key, the same one that signs `last-scan.json`). Every consumer reads it through one loader (`scanner/src/server/graph-loader.js`), which refuses a missing, unsigned, tampered or malformed file with a distinct reason and never serves an unverifiable graph.

**Graph envelope** (`DataFlowGraph v1`; the full schema is `scanner/src/lineage/dataflow-graph.schema.json`)

| Field | Meaning |
|---|---|
| `schemaVersion` | The envelope version, `1.0.0`. |
| `graphId` | Stable id over repository, revision and configuration. |
| `generatedAt` | Build time; a fixed epoch under `--deterministic`. |
| `scope` | `source` (`scan` or `fixture`) and, when the scan ran inside a repository, `revision`. |
| `scanHealth` | `complete`, `partial` or `cancelled`, with the analysis completion record. |
| `taxonomy` | The data-class taxonomy version. |
| `nodes` | Registry decisions: sources, stores, queues, sinks, external systems, process nodes, unresolved endpoints. |
| `edges` | Field-level data flow edges with protection, provenance and boundary crossings. |
| `dataElements` | The fields, with data classes and every source location. |
| `transformations` | Recognised transformations on a path, with `appliesToAllPaths`. |
| `flows` | Source-to-sink flows with evidence grade, handling and limitations. |
| `controls` | Reserved; empty in Milestone 1. |
| `policies` | Reserved; empty in Milestone 1. |
| `evidence` | Reserved; empty in Milestone 1. |
| `coverage` | The coverage ledger: sources, sinks, paths, provenance, handoff joins. |
| `limitations` | Sentences stating what this graph does not claim. |
| `extensions` | Reserved for operator extensions. |
| `recipientProfiles` | Third-party recipient profiles joined from the operator's recipient config (FR-506); empty without one. |
| `crossRepoLinks` | Declared cross-repository links (FR-304); empty without a links file. |

**Graph revision** (`scope.revision`, present when the scan ran inside a git repository)

| Field | Meaning |
|---|---|
| `commit` | The repository head the graph was built from. |
| `worktreeDirty` | Whether the tree had uncommitted changes, or `null` when unknown. |

Rules:

- **Integrity.** The loader verifies the body against the signature before parsing. A body changed after signing is `tampered`; a graph without its `.sig` is `unsigned`; neither is served.
- **Wrong revision.** `dataflow view --expect-revision <sha|HEAD>` (and any caller passing `expectRevision` to the loader) is refused with `wrong-revision` when the graph records another commit, and also when it records none: a graph that cannot show its revision is not assumed to match.
- **Partial state.** A graph whose analysis stopped early, hit a construction limit or exhausted its handoff rounds reports `scanHealth.status: partial` with the reason in `scanHealth.analysisCompletion`; `dataflow view`, the explore server and every derived artifact read that status from the graph and never promote it to `complete`.

## Witness bundles

`witness build` writes a signed (Ed25519), replayable record of one reconstructed path. `witness verify` checks the signature and, with the artifacts, replays every edge and call/return binding against the exact graph and provenance export it names.

**Witness bundle** (`schema` is `agentic-security/witness-bundle@1`)

| Field | Meaning |
|---|---|
| `schema` | The bundle schema id. |
| `graphRef` | The graph id, its digest and the analysis configuration digest the path was reconstructed over. |
| `query` | The sink-rooted query that produced the path. |
| `references` | Source, sink and field references, and source files the bundle could not bind. |
| `path` | The path id, node ids, hop count, edge records and terminal. |
| `artifacts` | The provenance export's schema, digest, hop and truncation counts. |
| `sources` | Digests of the source blobs the path cites. |
| `config` | The path-query budget and store limits in force. |
| `transferModels` | Fingerprints of the transfer models the engine applied. |
| `controlEvidence` | Control evidence on the path, each item separately graded. |
| `completion` | Whether the path and the analysis behind it were complete. |
| `evidence` | The four evidence statuses, kept separate. |
| `runtime` | Runtime support assessment, or its absence. |
| `exploit` | Bound exploit-proof inputs, or their absence. |
| `graphBinding` | The flow in the graph this witness is bound to. |
| `redaction` | What was redacted and how identities are tokenised. |
| `engine` | Engine version, bundle digest and commit, when known. |
| `proves` | What a replayed bundle establishes. |
| `doesNotProve` | What it does not. |
| `signature` | The Ed25519 signature over the canonical bundle (present after signing). |

Rules:

- **Integrity.** A bundle whose signed bytes changed, or whose signature was made under another key, verifies as `invalid`.
- **Replay.** With the artifacts, every edge must be found in the provenance export with the same record and the call/return bindings must balance; a bundle replayed against a graph with another digest fails replay. Without artifacts the verdict is `integrity-only`, never `replayed`.
- **Partial state.** A path through an analysis unit that was truncated carries `completion.overall: partial` and the evidence statuses say so; replay does not promote it.

## Boundary contracts

An operator declaration (`.agentic-security/boundary-contracts.json`, DAG-08) that a producer site hands named fields to a consumer site across an HTTP, queue or storage edge. It establishes a modeled input, never an observed one.

**Boundary contract** (`version` is `1.0.0`)

| Field | Meaning |
|---|---|
| `id` | `boundary:` prefixed id. |
| `version` | The contract version. |
| `kind` | `http`, `queue` or `storage`. |
| `persistence` | `immediate` for an HTTP call, `persisted` for a queue or store. |
| `channel` | Route, topic, or store/table/key. |
| `schema` | Schema name and version of the record that crosses. |
| `producer` | Service and, optionally, the producer site. |
| `consumer` | Service and the consumer site with its handler parameter. |
| `fieldMappings` | Producer field to consumer field, renames included. |
| `provenance` | How the declaration was made. |
| `evidence` | Always `{declared: true, observed: false}`. |
| `configDigest` | A digest of what the contract says, not who declared it. |
| `declaredBy` | The declaring person or system. |

Rules:

- **Integrity.** `configDigest` covers the meaning (kind, channel, schema, sites, mappings); a changed mapping fails the digest check. The declaration metadata is outside it.
- **Validation.** An unknown version, kind or persistence, a missing consumer site or parameter, a claim of `observed: true`, or a bad mapping makes the contract invalid; a contract that does not bind to a parser-resolved site is a gap, never a finding.
- **Partial state.** A gap or a rejected contract makes the contracts report `partial`; a declared edge the lineage graph joins carries `provenance: manual` and `modeledInput: true`.

## Context bundles

`context build` writes one hash-bound bundle per entry point: a manifest naming the exact source spans with their hashes, and packaged source text with its own hash.

**Context manifest** (`schemaVersion` is the manifest schema version)

| Field | Meaning |
|---|---|
| `schemaVersion` | The manifest schema version. |
| `entrypointId` | The entry point id. |
| `entrypoint` | Kind, method, composed path, framework, language, handler, registration site, auth scheme, middleware. |
| `repository` | Commit, dirty flag and snapshot hash. |
| `graph` | The symbol graph's schema version, hash and semantic source. |
| `context` | Profile, budget, integrity, and each package with its hash and segments. |
| `reachableSymbols` | Every symbol reached, with span hash and whether it was included. |
| `controls` | Controls observed on the reach, with basis and evidence. |
| `sensitiveOperations` | Sensitive operations on the reach. |
| `protection` | The protection evaluation. |
| `unknowns` | Unresolved edges, with whether each is material. |
| `boundaries` | Boundaries the reach stopped at. |
| `omissions` | What the packer left out and why. |
| `traversal` | Caps, cycles, limits and unvisited symbols. |
| `status` | Entry point disposition, reachability and bundle integrity. |
| `resolutionReasons` | Why the entry point is not fully resolved, when it is not. |
| `contextHash` | Hash over the entry point, packages and graph schema. |
| `manifestHash` | Hash over the manifest itself. |

Rules:

- **Integrity.** A stored package whose text no longer matches its hash is an error on read; a manifest whose body no longer matches `manifestHash` is `manifest-hash-mismatch`.
- **Stale spans.** Validated against the current snapshot, a segment whose lines no longer hash to its `spanHash` is `stale-span`; a review citation inside such a segment is refused as `stale-context`, and a citation outside the provided context or not grounded in its lines is refused too.
- **Partial state.** A material unresolved edge, a budget omission or a cap keeps `context.integrity` at `partial`; a manifest claiming `complete` with such gaps fails validation.

## Demand sink queries

`dataflow sink-query` answers one sink site over the functions that can feed it, corroborated by the forward engine. A query is keyed by the sink site, argument, field, context, rule family and the digests of the graph and configuration it was answered over.

**Sink query key**

| Field | Meaning |
|---|---|
| `file` | The sink's file. |
| `line` | The sink's line. |
| `nodeId` | The CFG node, when known. |
| `fnQid` | The enclosing function. |
| `callee` | The sink callee. |
| `sinkId` | The catalog sink id. |
| `argIndex` | The argument index queried. |
| `accessPath` | The field inside the argument, when queried. |
| `context` | `whole-program`; anything else is unavailable. |
| `ruleFamily` | The rule family or CWE. |
| `graphDigest` | Digest of the call graph the answer holds for. |
| `configDigest` | Digest of the analysis configuration. |

Rules:

- **Wrong revision.** A key is bound to the graph and configuration digests: the same query over another graph has another key, so an answer never carries over.
- **Negative claims.** `negativeClaimAllowed` is false for any limit, unsupported construct, unresolved callee or incomplete engine run; the vocabulary is `flow-found`, `no-flow-in-modeled-scope` and `unknown`.

## Control-placement plans

`dataflow plan-cuts` proposes a minimum-cost control placement over the modeled flow network. A plan is hypothetical: only a rescan through the remediation gate verifies a fix.

**Cut plan**

| Field | Meaning |
|---|---|
| `hypothetical` | Always true. |
| `verified` | Always false. |
| `query` | The query the network was built for. |
| `network` | Node and edge counts, sources, sinks, pre-existing protected edges. |
| `completeness` | Whether the modeled graph is known complete. |
| `excludedCandidates` | Candidates screened out, with reasons. |
| `limitations` | Sentences stating what the plan does not claim. |
| `note` | The hypothetical-only statement. |
| `status` | `complete-cut`, `partial`, `no-flow` or `no-feasible-cut`. |
| `cut` | The chosen controls and their cost. |
| `validation` | Residual bypass validation, or `null` for `no-flow`. |
| `uncuttableLocations` | Locations no eligible control can cut (present when a cut was computed). |
| `perSink` | Per-sink minimum cut costs (present when a cut was computed). |

Rules:

- **Partial state.** A graph not known complete scopes the plan to the modeled subgraph and says so in `limitations`; `no-flow` is `partial` with the reason `no-modeled-path` in the command's completion contract.

## Limits

<!-- limits-verified: 2026-11-04 -->

- The lineage graph's signature is a per-install HMAC: it is tamper evidence for the operator, not third-party non-repudiation. The witness bundle's Ed25519 signature is the portable one.
- A graph built outside a git repository records no revision, and a consumer that expects one refuses it rather than guessing.
- A boundary contract and a handoff join are modeled from declarations and literal identities; neither observes a message or a row.
- A context bundle is bound to the snapshot it was built from; a review against a changed file is refused, not re-run.
- Demand queries never answer from a cached key; parity with the full analysis is measured, not assumed (`bench/dag-demand`).
- A cut plan is a proposal over the modeled network; a flow the model does not contain cannot be cut by it.
