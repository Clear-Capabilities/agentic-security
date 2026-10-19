# AI engineering

<!-- seo: title="AI engineering guide: secure AI-written code, MCP tools and agent workflows" description="Guardrails for AI-written code, MCP and tool security, local models, model egress, agent workflows and token cost optimization." -->

**Primary question:** How do I secure AI-written code, agents and MCP tools?

**Core workflow:** [Model egress](../trust/model-egress.md)

## Guard AI-written code

- **Bodyguard** (`/agentic-security:setup --bodyguard`) intercepts insecure edits before they reach disk: injectable SQL, hardcoded keys, `eval` on user input.
- The **destructive-command guard** blocks deletions outside the allowed root.
- Generated patches pass the same verification legs as any other: [verified remediation](../trust/verified-remediation.md).

## Secure MCP and agent tools

- The scanner audits the MCP servers and agent tools a project exposes, and prompt-injection paths into model calls.
- The bundled MCP server is hardened against the OWASP MCP Top 10 and exposes two write tools behind path confinement. See the [MCP tool contract](../reference/mcp-tool-contract.md).
- The attack surface of the tool itself: [agent threat model](../trust/agent-threat-model.md).

## Decide what leaves the machine

[Model egress](../trust/model-egress.md): allow, deny or local-only, decided before a prompt is built, with redaction and no silent cloud fallback.

## Use local models

Validation, fix proposal and `hunt` can run against a model on loopback: [Local AI with Ollama](../guides/ollama.md) (Preview). A failed local call never falls back to a cloud provider.

## Agent workflows

- Agentic discovery (`hunt`) is Preview, advisory, and never gates a build. See [deterministic and agentic](../how-it-works/deterministic-and-agentic.md).
- In Claude Code, delegate to the bundled agents: triager, fixer, PoC generator, logic reviewer, chain synthesizer and material-change scorer. Edit-capable agents follow a path-confinement contract.
- Deterministic Context Intelligence builds hash-bound context bundles for focused, citation-checked reviews (opt-in, Preview): [guide](../guides/context-intelligence.md).

## Model and token cost

A per-prompt advisor suggests a cheaper model or lower reasoning depth when one would do, accounting for the prompt cache a model switch would discard. It is advisory and on by default. See [cache economics](../MODEL_COST_OPTIMIZATION.md).

## Inventory AI components

`agentic-security supply --sbom` covers dependencies and AI components (AI-BOM). See [SBOM and AI-BOM](../guides/sbom-and-ai-bom.md).
