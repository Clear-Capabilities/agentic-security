# Local model support: contract

<!-- seo: title="Local model support contract: the loopback rule, the configuration shapes and the error codes" description="Which endpoints count as loopback, the fields each local preset reports, the closed set of Ollama error codes, and the guarantee that a refused or failed local model never falls back to a cloud provider." -->

**Maturity:** Preview (contract frozen)

Validation, fix proposal and hunt can run against a model on your own machine. The point of the local path is that the prompt, which contains your source, never leaves it. This page freezes the rule that decides what counts as your machine, the configuration each preset reports, and the errors a failed local call can produce. Setup and model choice: [Local AI with Ollama](../guides/ollama.md). Stage context: [Discover](../discover/README.md).

## Presets

| Preset | Wire shape | Loopback enforced |
|---|---|---|
| `ollama` | The native Ollama chat API | Yes. A remote host needs `AGENTIC_SECURITY_OLLAMA_ALLOW_REMOTE=1` and is then reported as `remote` |
| `local` | A generic `{prompt, model}` request | Yes, always, with no opt-out |
| A bring-your-own endpoint | The same generic request | No. You chose where the prompt goes |

Select one with `AGENTIC_SECURITY_LLM_PRESET`. Setting `AGENTIC_SECURITY_OLLAMA_DISABLED=1` turns the Ollama provider off for every role, including a role that has its own preset override.

## The loopback rule

An endpoint is loopback only when its host, as the URL parser reads it, is one of these. The check is on the host and never on a name lookup, because a resolver can be made to answer anything.

**Loopback endpoints**

| Endpoint | Accepted |
|---|---|
| `http://127.0.0.1:11434` | Yes |
| `http://127.1.2.3` | Yes: all of 127.0.0.0/8 |
| `http://[::1]:11434` | Yes |
| `http://localhost:11434/v1` | Yes: `localhost` is the one name accepted |
| `https://localhost` | Yes |
| `http://0.0.0.0:11434` | Yes |
| `http://0x7f.0.0.1` | Yes: the parser reads it as 127.0.0.1, which is where the request goes |
| `http://evil.example@127.0.0.1` | Yes: the host is 127.0.0.1 and `evil.example` is a user name |
| `http://127.0.0.1@evil.example` | No: the host is `evil.example` |
| `http://localhost.evil.example` | No |
| `http://127.0.0.1.evil.example` | No |
| `http://192.168.1.5:11434` | No: a LAN address is a remote endpoint for this guarantee |
| `http://[::ffff:127.0.0.1]` | No: refused rather than guessed |
| `ftp://127.0.0.1`, `file:///x`, an empty string, text that is not a URL | No |

A compatibility test (`scanner/test/contracts/local-models.contract.test.js`) holds the rule to this table in both directions.

## What each preset reports

**`local` configuration**

| Field | Meaning |
|---|---|
| `endpoint` | The loopback endpoint, from `AGENTIC_SECURITY_LLM_ENDPOINT`, else `http://127.0.0.1:11434/v1/chat/completions` |
| `apiKey` | `AGENTIC_SECURITY_LLM_API_KEY`, or `null`. The preset never invents a credential |
| `model` | `AGENTIC_SECURITY_LLM_MODEL`, else `local-model` |
| `preset` | `local` |
| `timeoutMs` | `AGENTIC_SECURITY_LLM_TIMEOUT_MS`, else 20000 |
| `egress` | `loopback-only` |

**`ollama` configuration**

| Field | Meaning |
|---|---|
| `host` | `AGENTIC_SECURITY_OLLAMA_HOST`, else `http://127.0.0.1:11434`, without a trailing slash |
| `offline` | `true` when the host is loopback |
| `egress` | `loopback-only`, or `remote` for an opted-in remote host. A remote host is never reported as loopback-only |
| `requestTimeoutMs` | `AGENTIC_SECURITY_LLM_TIMEOUT_MS`, else 300000. A cold model load can take minutes |
| `connectTimeoutMs` | `AGENTIC_SECURITY_OLLAMA_CONNECT_TIMEOUT_MS`, else a short default, so a dead port fails fast |
| `keepAlive` | `AGENTIC_SECURITY_OLLAMA_KEEP_ALIVE`, else `5m` |
| `maxConcurrency` | `AGENTIC_SECURITY_OLLAMA_MAX_CONCURRENCY`, else 1 |

## Error codes

Every Ollama failure carries exactly one of these codes, never free text alone.

**Error codes**

| Code | Meaning |
|---|---|
| `ollama-disabled` | `AGENTIC_SECURITY_OLLAMA_DISABLED=1` |
| `ollama-not-running` | Listing or inspecting models found no server listening on the host |
| `ollama-unreachable` | A request could not connect, or the server answered with an error status |
| `ollama-non-loopback-refused` | The host is not loopback and remote use was not opted into. Refused before any prompt is built |
| `ollama-model-not-installed` | The named model is not installed |
| `ollama-model-load-failed` | The model could not be loaded |
| `ollama-model-out-of-memory` | The model did not fit in memory |
| `ollama-context-overflow` | The prompt did not fit the model's context |
| `ollama-capability-missing` | The model lacks a capability the call needs, such as tool calls |
| `ollama-timeout` | The request timed out |
| `ollama-malformed-response` | The reply could not be read |
| `ollama-tool-call-invalid` | A tool call from the model was not valid |
| `ollama-tool-loop-limit` | The tool loop hit its step limit |
| `ollama-version-unsupported` | The server is older than the supported range |

## Guarantees

- **A refused endpoint is never called.** A non-loopback host under the `local` or `ollama` preset is refused before a prompt is built. No network request is made, and the finding is `unvalidated` with the status `policy-blocked`.
- **There is no fallback to a cloud provider.** An unreachable server, a missing model, a timeout or a malformed reply leaves the finding as detected, with the model stage marked `unavailable`, `malformed` or `disabled`. It never moves to another provider. Another local model is used only if you configured it.
- **An absent server is normal.** A local server that is not running leaves the scan complete and the findings `unvalidated`, with the reason in the report.
- **Egress is stated.** Every configuration reports `loopback-only` or `remote`.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **Loopback means this machine, not this process.** Anything else running on your machine can answer on a loopback port. The rule decides where the prompt is sent, not who receives it.
- **Only inference is constrained.** Advisory data lookups for dependencies and similar network paths are separate and unaffected by this rule.
- **`localhost` is accepted by name.** It is the one hostname the rule accepts. A machine whose hosts file points `localhost` elsewhere defeats the rule. Use `127.0.0.1` when that matters.
- **A bring-your-own endpoint is not constrained.** The generic endpoint preset sends the prompt wherever you point it.
- **Small models are weak at this work.** The hosted job runs the smallest supported model to prove the path works end to end. It did not produce accepted results for validation or hunt in that job, and it is not evidence of what a larger model does.
