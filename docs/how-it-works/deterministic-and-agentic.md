# Deterministic and agentic

<!-- seo: title="Deterministic plus agentic security analysis: where models help and where they never decide" description="Agentic Security uses security agents where reasoning adds value and mechanical, reproducible evidence everywhere it can. Here is exactly where each is used." -->

Agentic Security uses **agents where reasoning adds value** and **mechanical evidence wherever it is possible**. The split is deliberate, and it is checkable.

## The rule

> Discovery may be aggressive. Confirmation must be skeptical and adversarial.

A model is allowed to *propose*. It is never allowed to be the only reason a security claim is made.

## Where each is used

| Job | Deterministic | Agentic | Who decides |
|---|---|---|---|
| Find known weakness shapes | SAST, secrets, IaC, dependency analysis (GA) | | The rules |
| Find weaknesses no rule encodes | | `hunt` lenses (Preview) | Candidates only; the deterministic engine confirms or refutes |
| Trace untrusted data | Taint and reachability (GA) | | The engine |
| Try to disprove a finding | Falsification pass (GA) | Optional model validation (Preview) | Falsification lowers confidence; a model verdict is recorded separately |
| Demonstrate exploitation | Sandbox and oracle (Preview) | | The deterministic oracle, never a model |
| Compose a patch | Deterministic swaps for context-independent classes | An agent composes the rest | The verification legs |
| Verify a patch | Rescan, lint, tests (GA) | | The legs and the completeness tier |
| Turn a finding into a rule | Promotion machinery (Labs) | A model or human proposes the pattern | The rule's own regression corpus |

## What a model can and cannot do here

A model **can**:

- propose candidate weaknesses across a partitioned call graph;
- compose a patch for a finding with no stored fix;
- supply a second-opinion verdict, recorded in its own field (`validator_verdict`, `llm_confidence`), never merged into severity.

A model **cannot**:

- set or raise severity (agentic discovery cannot emit `critical`);
- remove a finding;
- declare an exploit confirmed;
- mark a fix verified;
- cause a clean result when the scan was incomplete.

## Honesty about the model leg

- With no model endpoint configured, the model-assisted layers are a no-op. An unrelated environment variable can never trigger a network call.
- If an endpoint is missing or goes silent mid-run, the report says so in plain words. In the demo app, `hunt` reported `degraded runs: 35/35` and "this result says nothing about the code" instead of a clean run it did not earn. See [One finding's journey](../workflows/one-findings-journey.md).
- Model egress is governed by an allow, deny or local-only policy applied before a prompt is even built, with redaction. A failed local model call never falls back to a cloud provider. See [Model egress](../trust/model-egress.md).
- Local models are supported (Preview): [Local AI with Ollama](../guides/ollama.md).

## Why not just ask a model?

Because a pipeline of model calls cannot prove it did not regress, and its findings are candidates rather than conclusions. The deterministic core is gated by a regression corpus, a mutation gate that scores verdict-flip correctness rather than detection count, and held-out calibration. The agentic layers are valuable *because* they sit on top of something that can say no. The honest limits of those gates are on the [benchmarking methodology](../trust/benchmarking-methodology.md) page.

## Related

- [Evidence model](evidence-model.md)
- [Concepts: deterministic vs. model-assisted](../concepts.md#deterministic-vs-model-assisted)
- [Agent threat model](../trust/agent-threat-model.md)
