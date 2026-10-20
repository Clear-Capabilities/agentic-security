# Model-assisted validation: contract

<!-- seo: title="Model-assisted validation contract: verdicts, statuses and what a model can never do" description="The fields model-assisted validation writes onto a finding, the verdicts and statuses it can report, and the rules that stop a model reply from deleting or re-rating a finding." -->

**Maturity:** Preview (contract frozen)

When a model endpoint is configured, the validator asks it to judge each finding that a rule or the taint engine produced. It is advisory and it is off unless you configure an endpoint. The model's answer is recorded next to the finding, separate from the severity, and it can never raise or lower that severity. Stage context: [Corroborate](../corroborate/README.md). Setup for a model on your own machine: [local models](../guides/ollama.md).

## What it does

The validator sends critical and high findings, findings with a confidence below 0.6 and findings from the syntax-tree analyzer. Other findings are not sent: they are `unvalidated` and carry no `llmValidationStatus`, because a finding nobody asked about is not a model failure. For each one it sends, with a file and a line, the validator builds a prompt around the code excerpt, sends it to the configured endpoint and reads one JSON verdict back. The reply must echo a per-request challenge, the file and the line. A reply that does not is not used. A finding the model could not judge keeps its place in the report and says why.

## Configuration

| Variable | Meaning |
|---|---|
| `AGENTIC_SECURITY_LLM_ENDPOINT` | The endpoint. With none set, the validator does nothing and says `model-disabled` |
| `AGENTIC_SECURITY_LLM_VALIDATE` | `0` turns the validator off even with an endpoint set |
| `AGENTIC_SECURITY_LLM_MODEL` | The model name sent to the endpoint |
| `AGENTIC_SECURITY_LLM_API_KEY` | Sent as a bearer credential, when the endpoint needs one |
| `AGENTIC_SECURITY_LLM_TIMEOUT_MS` | The request timeout |

## Fields written onto a finding

A compatibility test (`scanner/test/contracts/model-validation.contract.test.js`) plays recorded model replies through the validator and holds the fields it adds to a finding to this table in both directions. Fields that start with an underscore are internal and may change.

**Finding fields**

| Field | Meaning |
|---|---|
| `validator_verdict` | One of the verdicts below |
| `llm_confidence` | The model's confidence from 0 to 1, or 0.5 when the reply could not be used |
| `validator_reasoning` | The model's one-sentence reason, with markup and control characters removed |
| `llmValidationStatus` | One of the statuses below. Absent when the finding was skipped for a reason that is not about the model |
| `unvalidated` | `true` when no verdict was obtained |
| `validator_skipped_reason` | Why a call was not made, such as a spend ceiling |
| `validator_reject_refused` | Present when a `reject` was turned into `escalate` because the finding is too strongly established to delete |

**Verdicts**

| Value | Meaning |
|---|---|
| `accept` | The model judged the finding real |
| `reject` | The model judged it a false positive. See the rules below for what that does |
| `escalate` | The model could not tell, or its reply could not be trusted. The finding is kept |
| `unvalidated` | No verdict was obtained. The finding is kept |
| `not-applicable` | A dependency finding, which has no code line to judge. The finding is kept |

**Statuses**

| Value | Meaning |
|---|---|
| `model-disabled` | No endpoint is configured. Nothing was attempted |
| `policy-blocked` | An endpoint was configured and a rule refused to use it: the egress policy, the local preset's loopback rule or a spend ceiling |
| `unavailable` | The call was attempted and failed: a network error, a timeout or an error status |
| `malformed` | A reply came back that was not usable: no JSON, a wrong challenge, file or line, or a verdict that is not one of the three |
| `completed` | A real, checked verdict was obtained, including one reused from the cache |

## Rules that hold

- **The verdict is recorded, the severity is not touched.** No verdict changes a finding's `severity`. An `accept` can raise the finding's confidence; nothing else about it changes.
- **A model cannot delete a strongly established finding.** A `reject` on a finding from the taint engine, from a multi-sink correlation or with an execution-proven result becomes `escalate`, with `validator_reject_refused` set.
- **A reject on any other finding is a suppression, not a deletion.** The finding leaves the main list and appears in the suppression ledger with the reason `llm-validator:reject:`, so `--include-suppressed` shows it.
- **An untrusted reply keeps the finding.** A reply with the wrong challenge, file or line, no JSON, an unknown verdict, or reasoning that reports an injection attempt becomes `escalate`. A reply is never read from the first JSON object, only the last.
- **No answer is not a clean answer.** A finding the model did not judge is `unvalidated` or `escalate` with a status that names the reason. It is never `accept`.
- **Nothing is called without an endpoint.** With none configured the validator makes no network call.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **It does not make a finding real.** `accept` is a model's opinion about a code excerpt. For execution evidence use [exploit proof](../guides/exploit-proof-fabric.md).
- **It is not measured as an accuracy figure.** The decision logic around the model is tested deterministically with recorded replies, and the live path runs in a hosted job against a small local model. There is no published precision for the model's own judgments, and the small model used in the hosted job is not a measure of what a larger one would do.
- **A persuasive excerpt can persuade the model.** The code it reads is untrusted. The challenge and echo checks stop forged replies, not a model that was talked into a verdict. That is why a reject cannot delete a strongly established finding.
- **Redaction is best effort.** Secrets and obvious credentials in the excerpt are masked before the call. An endpoint you configure still receives the rest of the excerpt, so use a model on your own machine when the code must not leave it.
- **It is off by default.** Without an endpoint the tier is `model-disabled`, which is not a finding that was checked and passed.
