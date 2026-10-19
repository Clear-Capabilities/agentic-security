# Learn

<!-- seo: title="Learn: Can a confirmed novel weakness become reusable deterministic knowledge?" description="Stage 4 of the Agentic Security assurance lifecycle: Can a confirmed novel weakness become reusable deterministic knowledge?" -->

**Stage 4 of 10.** Can a confirmed novel weakness become reusable deterministic knowledge?

**Maturity of this stage:** see the table below. Every capability carries its own label.

**This stage is Labs.** The idea: a weakness confirmed once should not need to be rediscovered by a model every time. It should become a rule, a test or a control that costs nothing to run.

What exists:

- **The finding-to-rule compiler** (`rules synthesize|evaluate|promote|status|rollback|cost|regress`; also `labs synthesize-rule <finding-id>`). From one proven finding it builds a rule IR (source, propagator, sink, sanitizer, dominating guard, framework constraint and exclusions, all enforced as regular expressions), a corpus (positive, patched, nearby-clean and protected variants), seven syntactic mutators and a shared false-positive corpus. `rules synthesize --auto` can propose the rule itself, scores every attempt on the real corpus, revises from why it failed, and stops after a bounded number of attempts with a CANDIDATE. Promotion is still decided by evidence, never by a model.
- **Detector spec synthesis** (`labs --synthesize-rule`): a proposal drafted from sample vulnerable files, written for a human to review and never incorporated automatically.

What is not there:

- A rule is regular expressions over text, with structure. There is no AST pattern and no data-flow rule; "source within N lines of the sink" is proximity, not a proven flow.
- The mutators are syntactic and table-driven. They show a rule survives a different author's version of the code, not every one.
- Regression fixtures live in the operator's own `.agentic-security/`, not in this repository's gated benchmarks. There is no MCP tool for synthesis.
- The **Security Learning Rate**, the metric that would say how much of what is learned becomes reusable, is **Roadmap** and not measured.

**Evidence this stage creates:** A promoted rule with its own regression corpus and a rollback path.

## Capabilities at this stage

<!-- generated:capabilities:learn:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Finding-to-rule compiler](../guides/rule-compiler.md) | Learn | **Labs** | Whether one proven finding can be promoted to a reviewed, deterministic detection rule (regular expressions over text, with structure) that passes its own corpus, a mutation set and a shared false-positive corpus. `rules synthesize --auto` can propose the rule; promotion is still decided by evidence. |
| [Detector spec synthesis](../../commands/labs.md) | Learn | **Labs** | A detector-spec proposal drafted from sample vulnerable files, written for a human to review and never incorporated automatically. |
| [Security learning rate metric](../roadmap/README.md) | Learn | **Roadmap** | The long-term measure of how many novel confirmed weakness patterns became reusable rules, tests or controls. Not an existing KPI. |
<!-- generated:capabilities:learn:end -->

## Read more

- [Rule compiler](../guides/rule-compiler.md)
- [Maturity model](../how-it-works/maturity-model.md)
- [Roadmap](../roadmap/README.md)

---

Previous: [Prove](../prove/README.md) · Next: [Scale](../scale/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
