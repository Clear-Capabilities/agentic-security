# Model egress

<!-- seo: title="Model egress policy: allow, deny, local-only and redaction before any prompt leaves" description="Every outbound model call is decided before a prompt is built. Allow, deny or local-only, redaction, an audit trail, and no silent cloud fallback." -->

**Maturity:** GA

Model use is optional. The deterministic scanner never needs a model. When you do enable the model-assisted layers, egress is decided *before* a prompt is built and *before* any HTTP client dials out.

## The decision

`egress/policy.js` returns `allow` or `deny` for every outbound call. A denied call leaves a persisted, tamper-evident audit entry instead of a silent no-op.

| Mode | Behavior |
|---|---|
| `allow` (default) | Calls may go out, subject to the other policy keys |
| `deny` | No call goes out |
| `local-only` | Only literal loopback endpoints are allowed |

Other policy keys narrow it further: `allowedProviders`, `deniedPaths`, `maxContextTokens`, `proprietaryPaths`, and a regulated profile that requires approved providers. The policy file is `.agentic-security/egress-policy.yml`.

## Redaction

`egress/redact.js` decides what is in a call once it is allowed: PII (`redactPii`), configured customer-data patterns and proprietary paths are removed or masked first. The two gates are separate; only the first can produce a `deny`.

## No silent cloud fallback

- With no endpoint configured, the model layers are a no-op. An unrelated environment variable cannot trigger a network call.
- A local-model request is refused before it is built if the endpoint is not a literal loopback address.
- A failed or unavailable local model call never falls back to a cloud provider. The finding stays exactly as the deterministic scanner found it.

## What does not use a model

`explore`, the Code Boundaries server, makes no model calls: it loads the already-scanned, already-signed graph and serves it on loopback. The scan step that builds the graph is the one covered by the egress policy.

## Go deeper

- [Walkthrough: model egress policy](../walkthroughs/model-egress.md), with a real policy and audit log
- [Local AI with Ollama](../guides/ollama.md)
- [Configuration and environment variables](../reference/configuration.md)
