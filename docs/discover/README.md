# Discover

<!-- seo: title="Discover: What might be wrong?" description="Stage 1 of the Agentic Security assurance lifecycle: What might be wrong?" -->

**Stage 1 of 10.** What might be wrong?

**Maturity of this stage:** see the table below. Every capability carries its own label.

Discovery produces **candidates**, not conclusions. Two families feed it, and they are kept distinct in the evidence.

**Deterministic discovery.** A 12-pillar scan in one command: SAST, dependency analysis (OSV, the CISA exploited-vulnerability catalog, function-level reachability), secrets, infrastructure-as-code, prompt-injection and LLM safety, MCP and agent-tool audit, auth and authorization, pipeline integrity, container build files and deploy configuration. It covers nine first-class languages plus Haskell and Nix/NixOS, each measured per capability. It needs no model and no network beyond lazily cached advisory feeds.

**Agentic discovery.** `hunt` partitions the call graph into focus areas and sends each through seven lenses (injection, authorization, crypto, business logic, feature abuse, chained, wildcard) to propose what no rule encodes. It needs a configured model endpoint, is token-expensive, is capped at 2000 files, and is advisory: it never gates a build and never writes to the scan record. Every candidate is routed back through the deterministic engine.

Run it:

```bash
agentic-security scan .
agentic-security hunt --root .
```

Without a model endpoint, `hunt` says so. On the demo app the captured result was `degraded runs: 35/35` with "EVERY hunter run degraded: this result says nothing about the code." A degraded hunt is never a clean hunt.

**Evidence this stage creates:** Candidates with a file, line, CWE, family and the parser that raised them. A candidate is not yet a conclusion.

## Capabilities at this stage

<!-- generated:capabilities:discover:start -->
| Capability | Lifecycle Stage | Maturity | What It Establishes |
|---|---|---|---|
| [Deterministic security analysis](../guides/scanning.md) | Discover | **GA** | A candidate weakness at a file and line, found by mechanical rules (SAST, secrets, IaC, auth, prompt-injection, MCP audit), with no model in the loop. |
| [Dependency risk with function-level reachability](../guides/scanning.md) | Discover, Corroborate | **GA** | Which vulnerable dependencies exist, which are actively exploited, and whether the vulnerable function is actually reachable. |
| [Agentic discovery (hunt)](./README.md) | Discover | **Preview** | Model-proposed candidate weaknesses that no rule encodes, each routed back through the deterministic engine before it is reported. Advisory; needs a configured model endpoint. |
| [Deterministic context intelligence](../guides/context-intelligence.md) | Discover, Corroborate | **Preview** | Per-entry-point, hash-bound context bundles and citation-checked focused reviews. Opt-in. |
| [Haskell and Nix/NixOS analysis](../language-support.md) | Discover, Corroborate | **Preview** | Static findings for Haskell and Nix/NixOS, with support measured per capability on a synthetic corpus and some legs honestly blocked. |
| [AI-written-code guardrails](../roles/ai-engineering.md) | Discover | **GA** | Insecure edits (injectable SQL, hardcoded keys, eval on user input) intercepted before they reach disk, and destructive shell commands blocked. |
| [MCP server and agent-tool audit](../reference/mcp-tool-contract.md) | Discover | **GA** | A hardened MCP surface for agents (including two write tools) and an audit of the agent tools a project exposes. |
| [Local model support](../guides/ollama.md) | Discover | **Preview** | Validation, fix proposal and hunt against a model on loopback, refusing non-loopback endpoints and never falling back to a cloud provider. |
<!-- generated:capabilities:discover:end -->

## Read more

- [Scanning](../guides/scanning.md)
- [Deterministic and agentic](../how-it-works/deterministic-and-agentic.md)
- [Local AI with Ollama](../guides/ollama.md)
- [Deterministic Context Intelligence](../guides/context-intelligence.md)
- [Haskell and Nix support](../language-support.md)

---

Next: [Corroborate](../corroborate/README.md) · [All stages](../how-it-works/assurance-lifecycle.md)
