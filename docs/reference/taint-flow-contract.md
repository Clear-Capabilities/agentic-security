# Taint flow finding: contract

<!-- seo: title="Taint flow contract: the core fields, the proof verdicts and what reachable means" description="The fields every data-flow finding carries, the proof and falsification verdicts it can report, and the rules that keep a sanitized or dead-code flow from reading as an exploitable one." -->

**Maturity:** GA

A taint flow finding says that data from an untrusted source reaches a dangerous sink, names each hop, and states what was and was not proven about the path. This page freezes the core of that finding. The finding also carries scoring and enrichment fields (exploitability, risk, mappings to attack frameworks and similar), and those are additive: they may be added to, and the core fields below are never removed or renamed without a version note here. Stage context: [Corroborate](../corroborate/README.md). Reading one finding field by field: [finding evidence](../walkthroughs/finding-evidence.md).

## The core of the finding

A compatibility test (`scanner/test/contracts/taint-flow.contract.test.js`) deep-scans fixture projects and holds every taint finding to the table below. A core field that goes missing fails it.

**Core fields**

| Field | Meaning |
|---|---|
| `id` | A readable id: `ir-taint:`, the file, the line and the sink kind |
| `stableId` | An id that survives edits elsewhere in the file |
| `file` | The file of the sink |
| `line` | The line of the sink |
| `vuln` | The weakness and the sink, such as `SQL Injection (db.query)` |
| `cwe` | The weakness class |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `family` | The weakness family, such as `command-injection` |
| `parser` | `IR-TAINT` for a flow found by the data-flow engine |
| `source` | Where the untrusted data entered, or `null` when the engine could not name one |
| `sink` | Where it ends up: `file`, `line` and a `label` |
| `chain` | The hops between them, in order. Empty when the flow is a single statement |
| `callee` | The sink call as the engine read it |
| `argIndex` | Which argument of the sink carries the data |
| `sourceProvenance` | How the data got there: `null` for a direct read, `interproc` for a value returned from another function |
| `confidence` | A number from 0 to 1 |
| `confidenceTier` | The number as `high`, `medium` or `low` |
| `evidence` | The analyzers that agree, such as `IR-TAINT` and `REGEX`. Present only when more than one analyzer reports the finding |
| `corroboration` | How many analyzers agree and which |
| `proof` | What was established about the path (below) |
| `falsification` | What an attempt to refute it found (below). Present when the finding names a source. A finding with `source: null` has no path to try to refute and carries none |
| `remediation` | What to change |

**A hop in `chain`**

| Field | Meaning |
|---|---|
| `file` | The file of the hop, when it is not the finding's file |
| `line` | The line |
| `label` | What happens there |
| `provenance` | How the value got there, when known |
| `kind` | `sink` on the last hop, which is always the sink itself |

**Proof verdicts**

| Value | Meaning |
|---|---|
| `feasible` | The flow reaches the sink and no proof that it is clean or impossible was discharged. This is not proof that it can be exploited |
| `proven-clean` | A sanitizer or parameterizer on every path neutralizes it for this sink |
| `proven-infeasible` | The path cannot execute |
| `unproven` | No flow proof applies to this kind of finding |

**Falsification verdicts**

| Value | Meaning |
|---|---|
| `survived` | No control that fits this sink's context was found between source and sink |
| `blocked` | A control that fits the sink's context is on the path |
| `unproven` | Falsification could not be attempted |

## Rules that hold

- **A sanitized flow is marked, not hidden.** A flow neutralized for its sink keeps appearing, with `proof.verdict: proven-clean` and a lower confidence, so a reader can see what the engine judged.
- **A control for another context does not count.** A sanitizer that does not neutralize this sink's kind of injection leaves `falsification.verdict` at `survived`.
- **The last hop is the sink.** Every non-empty `chain` ends with a hop whose `kind` is `sink`, so a code-flow view ends where the finding is reported.
- **Unknown is stated.** A flow with no nameable source has `source: null`. The engine does not invent one.
- **A skipped analysis says so.** Deep data-flow analysis is skipped in a CI environment unless `AGENTIC_SECURITY_DEEP_IN_CI=1` is set. A scan that skipped it reports an `info` finding with the id `ir-taint-ci-skipped` and `scanHealth.deepAnalysis.enabled: false`, and claims no flow. A scan with no taint findings and that notice has not been checked for flows.
- **Dead code is marked.** A flow in code that cannot run is flagged and scored down, not removed.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **A flow is not an exploit.** `feasible` means nothing disproved the path. For execution evidence use [exploit proof](../guides/exploit-proof-fabric.md).
- **It does not model everything.** Return values are tracked one call deep, aliasing and dynamic dispatch are partly modeled, and frameworks it has no model for are not followed. The per-language figures are in the [metrics](../METRICS.md#reading-it-honestly).
- **A missing flow is not a clean result.** The recall figures are measured on a corpus of known vulnerabilities, not on your code.
- **Scores are estimates.** The confidence and the fields built on it are calibrated on the project's own labelled corpus.
