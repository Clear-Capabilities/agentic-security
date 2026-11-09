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
| `validator_reject_retained` | `true` when a `reject` was kept in the actionable list because a model opinion alone does not remove a finding |
| `validator_reject_refused` | Present when a `reject` was turned into `escalate` because the finding is too strongly established to delete |
| `validator_context` | The spans the model was shown (`id`, `role`, `file`, `start`, `end`, never the text) and `gaps`, what was not collected |
| `validator_citation_status` | `valid` (every citation names a span line that was sent), `none` (the reply cited nothing) |
| `validator_citations` | The cited lines resolved to `span`, `file` and `line` |
| `validator_model_verdict` | The model's own verdict (`reject`) when it was refused and `validator_verdict` became `escalate`; the opinion is kept beside the evidence, never erased (since 0.195.31) |

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
| `malformed` | A reply came back that was not usable: no JSON, a wrong challenge, file or line, a verdict that is not one of the three, or a citation of a span or line that was not sent |
| `completed` | A real, checked verdict was obtained, including one reused from the cache |

## Rules that hold

- **The verdict is recorded, the severity is not touched.** No verdict changes a finding's `severity`. An `accept` can raise the finding's confidence; nothing else about it changes.
- **A model cannot delete a strongly established finding.** A `reject` on a finding from the taint engine (`IR-TAINT`, `MULTI-SINK`, and since 0.195.31 the C/C++ dataflow engine `CPP_DATAFLOW`), from a multi-sink correlation, with an execution-proven result, or (since 0.195.31) with a verification record a trusted oracle settled as `confirmed`, becomes `escalate`, with `validator_reject_refused` set and the model's own verdict kept in `validator_model_verdict`. The opinion and the evidence are both visible; the opinion changes neither the list nor the severity.
- **A reject is an opinion, not a suppression.** Since the disposition rules below, a `reject` on any finding keeps it in the actionable list as `needs-review` with `validator_reject_retained` set. Only an evidence-backed refutation or a reviewed suppression removes a finding, and it is then retained in the suppression ledger with its reason and evidence. `AGENTIC_SECURITY_LLM_REJECT_SUPPRESS=1` restores the earlier behavior of moving a rejected finding to the ledger.
- **An untrusted reply keeps the finding.** A reply with the wrong challenge, file or line, no JSON, an unknown verdict, or reasoning that reports an injection attempt becomes `escalate`. A reply is never read from the first JSON object, only the last.
- **No answer is not a clean answer.** A finding the model did not judge is `unvalidated` or `escalate` with a status that names the reason. It is never `accept`.
- **Nothing is called without an endpoint.** With none configured the validator makes no network call.

## Dispositions

Each finding also carries `disposition` and `dispositionDetail` (reason, evidence, missing evidence, next check), assigned after validation by `scanner/src/llm-validator/disposition.js`. The model's verdict is one input and never the deciding one.

| Disposition | What assigns it |
|---|---|
| `confirmed` | An executed test (`proofTier: execution-proven`) or a reviewer verdict that names the reviewer and cites evidence. A model `accept` cannot assign it |
| `needs-review` | A model accept without independent evidence, a model escalate, or conflicting evidence. The detail names the missing evidence and the next check |
| `refuted` | A refutation with a kind that disproves the claim, cited evidence, a verifier and a source hash matching the current file, or a reviewed suppression with rationale, owner, scope, expiry and a content fingerprint that still match |
| `hardening` | A finding marked as an improvement with no claimed exploitable weakness |
| `unvalidated` | Review not attempted or failed (no endpoint, a model error, a spend ceiling), or the finding no longer matches the file (deleted, line outside the file, changed hash). Never converted to `refuted` |

A refutation that rests on where the code lives (a test, a developer tool, a private repository, member-only use) or on the absence of a proof of exploit is not accepted. An expired suppression, or one whose source or rule changed, reopens the finding.

### Bounded context and citations

The model is shown numbered spans, each with an id, a role and exact line bounds (`scanner/src/llm-validator/bounded-context.js`): the code around the finding, the source and the sink when they lie outside it, each traced path step, and the related files on a Haskell or Nix evidence chain. Each span is redacted under its own file's path. Guards the scanner saw are listed beside the path.

Callers and configuration are collected by name, and the prompt says so. Callers: the nearest function definition above the finding, then up to three call sites of that name in scanned files of the same language (`caller` spans). They are matched by name, not resolved through imports or dispatch, so a same-named function can appear and calls through aliases, callbacks or dynamic dispatch are missed. Configuration: environment keys read near the finding (`process.env`, `os.environ`, `getenv`, `getEnv`/`lookupEnv`, `System.getenv`, `ENV`, `os.Getenv`, `env::var`), then up to two lines in scanned configuration files that set them (`configuration` spans: YAML, TOML, INI, properties, Nix, compose and Docker files, and `.env.example`-style templates). A real `.env` file is never read, and the value of a secret-like key is masked before the usual redaction.

What was not collected is stated in the prompt: no enclosing function found, no call site found, call sites beyond the first three, keys that no scanned configuration file sets (they may be set at deploy time), and deployment configuration outside the repository, which is never collected.

The reply lists `citations`, the span lines its verdict rests on (`"S1:42"`). A citation that names a span or a line that was not sent voids the reply: it becomes `escalate` with status `malformed`, because the model reasoned about code it was not shown. A reply with no citations keeps its verdict and is recorded as `none`; a model `accept` without citations still lists the missing citation in the disposition. Citations never make a finding `confirmed`.

### Equivalent claims and count reconciliation

Before dispositions are assigned, `scanner/src/llm-validator/claim-groups.js` groups claims that two detectors made about one weakness: same report category, same file, same line and same CWE, from different detectors, with no conflicting sink lines. The primary is the claim that locates the most of the path (source and sink, then the sink alone), then one the IR taint engine produced over a lexical rule, then the highest severity, then the lowest identifier. It carries `claims`, which lists every detector in the group. The other claims leave the actionable list and are kept in the scan's `groupedClaims` (and the JSON report), each with `groupedInto` naming its primary and its own disposition. Two claims from one detector, claims about different sinks, composite chain claims and dependency findings are never grouped. Severity and confidence are not changed, and drift treats a grouped claim as still present.

`candidateReconciliation` in the JSON report states the counts once: `raw` (candidates reaching this stage), `grouped`, `refuted`, `deduplicated` (`raw` minus `grouped`), and `confirmed`, `needsReview`, `hardening` and `unvalidated`. `balanced` is true when `raw` equals `grouped` plus `refuted` plus the four active dispositions. `suppressedBeforeValidation` counts candidates removed earlier by a pragma, a rule or accepted risk; it is reported beside `raw`, not inside it. Stale findings are counted in `unvalidated`.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **It does not make a finding real.** `accept` is a model's opinion about a code excerpt. For execution evidence use [exploit proof](../guides/exploit-proof-fabric.md).
- **It is not measured as an accuracy figure.** The decision logic around the model is tested deterministically with recorded replies, and the live path runs in a hosted job against a small local model. There is no published precision for the model's own judgments, and the small model used in the hosted job is not a measure of what a larger one would do.
- **A persuasive excerpt can persuade the model.** The code it reads is untrusted. The challenge and echo checks stop forged replies, not a model that was talked into a verdict. That is why a reject cannot delete a strongly established finding.
- **Redaction is best effort.** Secrets and obvious credentials in the excerpt are masked before the call. An endpoint you configure still receives the rest of the excerpt, so use a model on your own machine when the code must not leave it.
- **It is off by default.** Without an endpoint the tier is `model-disabled`, which is not a finding that was checked and passed.
