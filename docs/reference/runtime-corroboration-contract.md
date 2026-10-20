# Runtime corroboration: contract

<!-- seo: title="Runtime corroboration contract: the adapters, the runtime status and the edge states" description="The telemetry formats the importer reads, what each adapter keeps and drops, the complete, partial and unavailable runtime status, and the six edge states, with the real exports each adapter is tested against." -->

**Maturity:** GA

Runtime corroboration compares telemetry you export from your own systems with the scanned graph of what your code can do. It tells you which statically found paths were seen in traffic, which were not, and which traffic matches nothing the scan modeled. It is **import only**: it reads files you give it, offline, and never connects to a collector, a cluster or a log service. Stage context: [Observe](../observe/README.md). The walkthrough and a worked fixture: [the runtime twin guide](../guides/runtime-twin.md).

## Commands

```bash
agentic-security runtime ingest [path] --adapter <name> --input <file> --window-start <iso> --window-end <iso> [--environment <name>] [--yes]
agentic-security runtime status [path] [--environment <name>] [--format json]
agentic-security runtime edges [path] [--format markdown]
agentic-security runtime reconcile [path]
agentic-security runtime query [path] <name>
```

`ingest` is a dry run unless you pass `--yes`.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | The command ran, including a status of `unavailable` |
| `1` | There is no scanned graph to correlate against, or the last scan failed its integrity check |
| `2` | A usage problem, an unknown adapter, or an import refused because a record failed to parse or validate |

## The adapters

Each adapter is a pure text parser. It reads only approved metadata and drops everything else.

**Adapters**

| Adapter | Input | Reads | Drops |
|---|---|---|---|
| `native-jsonl` | One JSON record per line in this tool's own format | The approved record keys | Any record with a key that is not approved is refused |
| `otel-json` | One OTLP/JSON export document with `resourceSpans` | The service name, the server address and port, the scheme, the protocol, the database system and name, the messaging destination | Trace and span ids, URLs and query strings, headers, database statements, message payloads, every other attribute |
| `envoy-access-log` | Envoy's JSON access log, one object per line | The upstream host and port, the upstream cluster, the protocol, the response flags, the times | The client address, the request path and query, the user agent, the request id, the response code |
| `k8s-audit-log` | Kubernetes audit events, one per line | The namespace and resource, the response code, the times | The object name, request and response bodies, the groups, the source addresses. The user name is stored only as a keyed hash, and only when the importer supplies the tokenizer |
| `http-access-log` | A JSON-lines access log with `host`, `upstream` and `scheme` keys | The host, the upstream and the scheme | The path and query, the client address, the user agent, every header, the status value |

An adapter name that is not in this table is refused, never guessed.

## What counts as a security decision

An observation carries a decision only when the source recorded an authorization outcome. Anything else is an operational outcome and carries no decision, in either direction.

- **Envoy:** a response flag of `UAEX` (the external authorization service denied the request) is `denied`; no flag is `allowed`. A failed upstream (`UF`), a missing route (`NR`), a timeout (`UT`) and a client disconnect (`DC`) carry no decision.
- **Kubernetes:** a response code below 400 is `allowed`; `401` and `403` are `denied`. A `404`, a `409`, a `422` or a server error carries no decision.

## Runtime status

`runtime status` reports one of three values and the facts behind it.

**Runtime status**

| Value | Meaning |
|---|---|
| `complete` | Telemetry was imported, every observation matched a node in the graph, and the newest observation is within the staleness bar (30 days by default) |
| `partial` | Telemetry was imported, and either some observations matched nothing, or the newest is older than the staleness bar, or the import held no observations |
| `unavailable` | No telemetry was ever imported for this scan. This is never read as "no runtime risk" |

**Status report**

| Field | Meaning |
|---|---|
| `runtimeStatus` | One of the values above |
| `telemetryWindow` | The earliest start and latest end over the imports, or `null` |
| `freshness` | When the newest observation happened, when the newest import was made, how many hours old it is, and whether that is stale |
| `parseFailures` | Always 0: a failed import is refused whole and never stored, so there is no history of failures to count |
| `parseFailuresNote` | Says why `parseFailures` is 0 |
| `mappingPercentage` | The share of observations that matched a node, or `null` with none |
| `unmatchedObservationCount` | Observations that matched nothing |
| `totalObservationCount` | Observations imported |
| `missingTelemetry` | `true` when nothing was imported |
| `limitations` | Every reason the status is not `complete`, in words |

## Edge states

`runtime edges` gives every static edge one or more of these states.

**Edge states**

| State | Meaning |
|---|---|
| `STATIC_ONLY` | No telemetry was consulted |
| `RUNTIME_NOT_OBSERVED` | Telemetry was consulted and nothing trusted was seen in the window. This never means unreachable |
| `RUNTIME_OBSERVED` | Traffic matching the edge was seen |
| `RUNTIME_BLOCKED` | Every recorded decision for the edge was `denied` |
| `RUNTIME_POLICY_VIOLATION` | Traffic was seen on a flow the privacy policy prohibits |
| `RUNTIME_EXPLOIT_CORRELATED` | Traffic was seen and you supplied evidence of an attack that names this edge, flow or node. Seeing traffic is never taken as seeing an attack |

## Rules that hold

- **Import only.** Nothing is fetched. A source is a file you exported.
- **Closed world.** An observation holds only approved metadata. A record carrying a key outside the approved set is refused, not scrubbed.
- **No payload values.** Query strings, headers, bodies and statements are dropped by every adapter. Identities are stored only as keyed hashes (`idt_` plus 16 hex characters).
- **Counts are bands.** An observation says `1` or `2-10`, never an exact count.
- **A failed import changes nothing.** One bad record refuses the whole import.
- **The graph is never edited.** A runtime fact is an overlay on the static graph.
- **Unmatched is shown.** An observation that matches no node is counted and listed, never dropped.

## Tested against real exports

A hosted job runs the real tools and records the files they write, untouched: the OpenTelemetry JavaScript SDK with its OTLP exporter, Envoy, nginx, and a kind cluster with the Kubernetes audit log on. The recorded files are in `scanner/test/fixtures/telemetry-packs/` next to a manifest naming the tool, its version and the digest of each file. A compatibility test (`scanner/test/contracts/runtime-corroboration.contract.test.js`) checks the packs against the manifest, parses each with its adapter, and holds the status report, the status values and the edge states to the tables above in both directions.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **It does not collect.** There is no live ingestion, no streaming and no connection to any telemetry system. An export is a snapshot you made.
- **A silent source is not a safe source.** `RUNTIME_NOT_OBSERVED` and `unavailable` say nothing was seen in what you imported. They do not say the path is unused.
- **Matching is by destination, table and topic.** An observation is placed on a node when its destination, store or queue resolves to a literal in the code. A destination built at runtime cannot be matched, and a flow to it stays `RUNTIME_NOT_OBSERVED` however much traffic there is.
- **Four formats, as the tools write them in one configuration each.** The Envoy and nginx packs are produced from the log formats named in the manifest. Another log format, a different Envoy configuration, a different OpenTelemetry convention version or a different audit policy level can write fields the adapter does not read. A format outside the table is refused.
- **Identity is a keyed hash or nothing.** A user name or end-user id is turned into an `idt_` token with a key you hold, and with no key it is dropped. A raw name is never stored, and a hash without a key is never made, because an unkeyed hash of a name can be reversed by guessing.
- **It describes the window you imported.** Anything outside it is not in the picture, and staleness is judged against the newest observation, not against today.
