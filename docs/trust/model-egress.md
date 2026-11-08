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

### Execution profiles

`AGENTIC_SECURITY_EGRESS_PROFILE` selects how a policy that cannot be read is treated.

| Profile | Policy | When the policy is missing or invalid |
|---|---|---|
| `standard` (default) | the repository file, as above | the documented default applies (allow), and the decision carries `configurationWarning` and `policyState` saying the file is `malformed`, `unreadable` or `unsupported` |
| `restricted` | the operator's file, named by `AGENTIC_SECURITY_EGRESS_POLICY`, is authoritative; the repository file can only narrow it | every request is denied before transport, with `reasonCode` `operator-policy-absent`, `-malformed`, `-unreadable` or `-unsupported`, or `repository-policy-...` for an invalid repository file |

Under `restricted`, a deny in either file denies, and a repository `mode: allow` cannot lift an operator `local-only`. An unknown profile, or an unknown `AGENTIC_SECURITY_EGRESS_MODE`, denies under any profile. `AGENTIC_SECURITY_EGRESS_DENY=1` always wins. Every decision records `profile`, `policyState`, `reasonCode`, `enforcement` (`enforced` or `legacy-default`) and, under `restricted`, `policyIdentity` (a digest of the operator policy, never its path). The decision is made before the prompt is built, so a denied request reaches no network client.

## Redaction

`egress/redact.js` decides what is in a call once it is allowed: PII (`redactPii`), configured customer-data patterns and proprietary paths are removed or masked first. The two gates are separate; only the first can produce a `deny`.

## No silent cloud fallback

- With no endpoint configured, the model layers are a no-op. An unrelated environment variable cannot trigger a network call.
- A local-model request is refused before it is built if the endpoint is not a literal loopback address.
- A failed or unavailable local model call never falls back to a cloud provider. The finding stays exactly as the deterministic scanner found it.

## Every model path

Each path that sends a prompt evaluates the policy before the prompt is built, redacts, bounds and audits the call. The release gate's GA programme ledger (`docs/ga-program/`) checks the source tree for a file that sends a prompt without doing so and names it, and (since 0.195.23) for a file that sends through a bare `fetch` instead of the shared transport.

## One transport

Since 0.195.23 every model request leaves the process through `scanner/src/egress/transport.js` (`modelFetch`), including the Ollama provider, the red-team sender and the adversary agent's probes of its target, so the same bounds hold on every path:

- **No redirect is followed.** A loopback endpoint that answered with a redirect to a remote host would carry the prompt off the machine; the call fails with `redirect` instead.
- **Every call has a deadline** (`AGENTIC_SECURITY_LLM_TIMEOUT_MS`, else 60 s, or the caller's shorter bound), so a connection that is accepted and never answered, or a body that stalls after the headers, cannot hold a scan open.
- **The reply is capped while it is read** (`AGENTIC_SECURITY_LLM_MAX_RESPONSE_BYTES`, else 4 MiB): the request is aborted at the limit, not buffered and trimmed afterwards.
- **A wall budget across calls** is optional: with `AGENTIC_SECURITY_LLM_WALL_BUDGET_MS` set, the time spent inside model calls in one process is accounted and a call past the budget is refused as `budget-exhausted`. Without it, the per-call deadline and the validator's dollar ceiling are the bounds.
- **Proxy variables are ignored.** Node's fetch reads no `HTTP_PROXY`, `HTTPS_PROXY` or `NO_PROXY`, and the transport installs no proxy agent, so the endpoint literal is where the request goes. A proxy is not a supported way to route model calls.
- **The `local` preset is honoured by every caller.** The flow narration, the dependency function extractor and the adversary agent resolve their provider the way the validator does, so a non-loopback endpoint under the `local` preset is refused there too instead of being read from the raw variable and called. A vendor API key is sent only with that vendor's own preset. The paths: the finding validator (`scanner/src/llm-validator/`), its fix, explanation and proof proposals, discovery (`scanner/src/discovery/llm-invoke.js`), the dependency function extractor, model routing (`posture/routing/adapter.js`, through the shared bounded call), the autopilot's fix proposals (`scripts/autopilot.mjs`, since 0.195.22) and detector-spec synthesis (`scripts/synthesize-detector.mjs`, through the shared bounded call since 0.195.22: the policy is evaluated before any sample file is read, so a denied call reads nothing).

## What does not use a model

`explore`, the Code Boundaries server, makes no model calls: it loads the already-scanned, already-signed graph and serves it on loopback. The scan step that builds the graph is the one covered by the egress policy.

## What egress policy does not do

<!-- limits-verified: 2026-10-19 -->

- **It governs the model calls this tool makes.** A model your editor or agent host calls on its own is outside it.
- **Vulnerability-feed lookups are a separate path.** OSV, KEV and EPSS lookups are deterministic network reads that carry no source code, and the policy does not describe them. A scan is never described as fully offline because model egress is denied.
- **Redaction is pattern-based.** It masks PII, configured customer-data patterns and proprietary paths. Sensitive text that matches none of them is not recognized, so `local-only` or `deny` is the setting for code that must not leave at all.
- **The audit log is local.** A denied call leaves a tamper-evident entry on the machine that made the call; nothing is sent to a third party.

## Go deeper

- [Walkthrough: model egress policy](../walkthroughs/model-egress.md), with a real policy and audit log
- [Local AI with Ollama](../guides/ollama.md)
- [Configuration and environment variables](../reference/configuration.md)
