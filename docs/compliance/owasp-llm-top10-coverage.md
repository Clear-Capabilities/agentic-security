# OWASP LLM Top 10 (2025) scanner coverage map

**Framework version:** OWASP Top 10 for Large Language Model Applications — 2025 edition

## Coverage summary

| Risk | Name | Coverage level | Scanner modules |
|---|---|---|---|
| LLM01 | Prompt Injection | **Full** | `sast/llm.js`, `sast/prompt-firewall.js`, `posture/llm-redteam.js` |
| LLM02 | Insecure Output Handling | **Full** | `sast/llm.js` — `UNSANITIZED_LLM_OUTPUT`; `sast/client-side.js` — XSS/eval |
| LLM03 | Training Data Poisoning | **Partial** | `posture/aibom.js` — data provenance fields; no runtime detection |
| LLM04 | Model Denial of Service | **Partial** | `sast/prompt-firewall.js` — missing `max_tokens`; no traffic-rate checking |
| LLM05 | Supply Chain Vulnerabilities | **Full** | `posture/aibom.js`; `sca/dep-confusion.js`; `posture/sbom.js`; CISA KEV |
| LLM06 | Sensitive Information Disclosure | **Full** | `secrets/`; `sast/env-hygiene.js`; `posture/aibom.js` — PII fields |
| LLM07 | Insecure Plugin Design | **Full** | `sast/mcp-audit.js`; `sast/prompt-template.js` |
| LLM08 | Excessive Agency | **Partial** | `sast/mcp-audit.js` — over-permissioned tools; no runtime scope enforcement |
| LLM09 | Overreliance | **Partial** | `sast/llm-owasp.js` — LLM09 rule; no factuality testing |
| LLM10 | Model Theft | **Partial** | `posture/aibom.js` — model registry; `sast/model-load.js` — unsafe load |

## LLM01: Prompt Injection

**Status: Full**

The scanner detects three injection shapes:

| Finding | Rule | Evidence |
|---|---|---|
| Direct prompt injection — HTTP user input in system prompt | `sast/llm.js` | `req.body.*` / `req.query.*` flows into `messages[{role:'system'}]` |
| Indirect prompt injection — external data in system prompt | `sast/llm.js` | `fetch()` / `axios()` response used as system prompt content |
| Template injection — `${userInput}` interpolated in prompt template | `sast/prompt-template.js` | Template literal containing request-derived variable |

Active red-team testing with 30+ adversarial prompt families (DAN, base64, role-play, etc.)
is available via `posture/llm-redteam.js` (`/llm-redteam`).

**Gap:** Multi-turn prompt injection across conversation turns is not statically detectable.

## LLM02: Insecure Output Handling

**Status: Full**

| Finding | Rule |
|---|---|
| Unsanitized LLM output rendered as HTML | `sast/llm.js` — `UNSANITIZED_LLM_OUTPUT` |
| LLM output passed to `eval()` / `Function()` | `sast/client-side.js` — code injection |
| LLM output inserted into SQL | `sast/engine` — SQL injection via LLM output flow |

**Gap:** Server-side template injection via LLM output is partially covered.

## LLM03: Training Data Poisoning

**Status: Partial**

`posture/aibom.js` records training data sources and flags missing provenance fields in
the AI-BOM. Static analysis cannot detect runtime data poisoning.

**Gap:** Model behaviour drift detection requires a separate evaluation harness.

## LLM04: Model Denial of Service

**Status: Partial**

`sast/prompt-firewall.js` flags LLM API calls missing `max_tokens` — the primary static
signal for unbounded generation cost. Missing rate limiting on LLM endpoints is flagged by
`sast/rate-limit.js`.

**Gap:** Per-user token budgets and adaptive rate-limiting logic are not statically
detectable; they require runtime instrumentation.

## LLM05: Supply Chain Vulnerabilities

**Status: Full**

| Finding | Rule |
|---|---|
| Known-vulnerable ML dependencies | `sca/` — OSV + CISA KEV |
| Dependency confusion risk | `sca/dep-confusion.js` |
| Missing model provenance | `posture/aibom.js` — `integrity_hash` field check |
| Unsafe model load (`torch.load`, `pickle`, `trust_remote_code`) | `sast/model-load.js` |

## LLM06: Sensitive Information Disclosure

**Status: Full**

| Finding | Rule |
|---|---|
| Hardcoded API keys / secrets | `secrets/` |
| `NEXT_PUBLIC_` variables containing secrets | `sast/env-hygiene.js` |
| PII/sensitive data in training data fields | `posture/aibom.js` |
| Supabase service-role key exposure | `sast/db-rls.js` |

## LLM07: Insecure Plugin / Tool Design

**Status: Full**

`sast/mcp-audit.js` audits MCP server tool definitions for:
- Missing input validation on tool parameters
- Over-broad tool descriptions that expand attack surface
- Tools accepting unvalidated user-controlled input

## LLM08: Excessive Agency

**Status: Partial**

`sast/mcp-audit.js` flags tools with filesystem, shell, or network permissions not
justified by their documented purpose. Runtime scope enforcement and least-privilege
validation require manual review.

## LLM09: Overreliance

**Status: Partial**

`sast/llm-owasp.js` LLM09 rule flags patterns where LLM output is used in
safety-critical decisions without human review gating. Factuality testing (hallucination
rate) requires a golden evaluation dataset.

## LLM10: Model Theft

**Status: Partial**

`sast/model-load.js` flags unsafe model loading paths. `posture/aibom.js` records which
model registries and weights are used. Runtime inference-API rate limiting and model
extraction attack detection are out of static-analysis scope.

## How to generate an attestation report

```bash
/compliance --report owasp-llm-top-10
```

Produces `owasp-llm-top10-attestation.md` with per-risk finding counts and coverage status.
Risks with partial or no coverage are listed with "Manual review required" and a gap description.
