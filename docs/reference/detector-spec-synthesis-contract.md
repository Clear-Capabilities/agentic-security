# Detector spec synthesis: contract

<!-- seo: title="Detector spec synthesis contract: the proposal shape, where it is written and why nothing installs it" description="The frozen detector-spec proposal fields, the model reply it is validated from, the exit codes of the synthesis command, and the limits of a proposal that a human must review." -->

**Maturity:** Labs

This page freezes, as of 0.195.22, what `/labs --synthesize-rule` (the `scripts/synthesize-detector.mjs` command over `scanner/src/discovery/detector-spec-synthesis.js`) produces: a detector-spec proposal drafted by a model from sample vulnerable files, for a human to review. A compatibility test (`scanner/test/contracts/detector-spec-synthesis.contract.test.js`) runs the real synthesis with an injected model transport and an injected file reader (no network, no model) and holds the proposal, its sinks and sanitizers, the accepted reply keys and the exit codes to the tables below in both directions, so a field cannot be added or removed without changing this page. It also exercises the rule that a proposal is never incorporated automatically.

## Running it

The feature is off by default. It runs only when the `detector-spec-synthesis` assurance feature is on (`AGENTIC_SECURITY_ASSURANCE_DETECTOR_SPEC_SYNTHESIS=1`, or the project's `.agentic-security/assurance.yml`) and `AGENTIC_SECURITY_LLM_ENDPOINT` names the operator's model endpoint; there is no default endpoint. The order is fixed: the feature gate, then the egress policy (deny, local-only) before any sample file is read, then bounded reads (at most 12 files, 64 KiB each, 192 KiB in total), then the shared bounded model call (redaction, request cap, deadline, audit), then a closed-world validation of the reply.

```
node scripts/synthesize-detector.mjs --cwe CWE-89 --lang java --files Bad1.java Bad2.java [--out proposal.json] [--force] [--model <name>]
```

`--lang` is one of `java`, `csharp`, `cpp`, `javascript`, `typescript`, `python`, `go`, `ruby`, `php`, `kotlin`, `rust`. `--cwe` is `CWE-` and digits.

## The proposal

Written as indented JSON to the `--out` file, or printed to standard output when there is no `--out`. Nothing else is written by the command apart from the egress audit entry under `.agentic-security/`.

**Proposal**

| Field | Meaning |
|---|---|
| `cwe` | The CWE requested; the reply must echo it |
| `language` | The language requested; the reply must echo it |
| `sinks` | 1 to 20 sink entries (below) |
| `sanitizers` | 0 to 20 sanitizer entries (below); an empty list when the reply had none |
| `severity` | `critical`, `high`, `medium` or `low` |
| `remediation` | One line, 10 to 1000 characters, trimmed |
| `synthesizedAt` | When the proposal was made (ISO 8601) |
| `synthesizedFrom` | The base names of the sample files, in the order given |
| `review` | The fixed text `PROPOSAL: review before incorporating into a detector module; nothing installs this automatically` |

**Sink**

| Field | Meaning |
|---|---|
| `method` | An identifier (letters, digits, `_`, `$`; up to 100 characters), never a pattern |
| `receiverType` | A type name, or `null` when the reply gave none |
| `argIdx` | The argument that carries the sensitive value: an integer from 0 to 63, or `any` |
| `taintRequired` | `true` when the detector should fire only on a tainted argument |
| `note` | Optional, one line of at most 300 characters; absent when the reply gave none |

**Sanitizer**

| Field | Meaning |
|---|---|
| `method` | An identifier, never a pattern |
| `note` | Optional, one line of at most 300 characters |

## The model reply

The reply is parsed string-aware (the last JSON object in the text) and validated closed-world: a key not listed here, at any level, refuses the whole reply. The raw reply is never printed or returned, only the validation reasons.

**Model reply**

| Field | Meaning |
|---|---|
| `challenge` | A nonce from the system random source, sent in the prompt; the reply must echo it, and it is dropped from the proposal |
| `cwe` | Must equal the CWE requested |
| `language` | Must equal the language requested |
| `sinks` | As in the proposal |
| `sanitizers` | As in the proposal; may be omitted |
| `severity` | As in the proposal |
| `remediation` | As in the proposal |

## Exit codes

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | A valid proposal, written or printed |
| `2` | Refused: the feature is off, no model endpoint is configured, the egress policy denied the call, or the bounded model call did not complete (timeout, size, error) |
| `3` | The reply was not a valid proposal; the reasons are printed |
| `4` | A usage or limit problem: a bad argument, too many or too large samples, an unreadable sample, or an output path that was refused |

## Never incorporated automatically

- **The proposal is written only where `--out` says.** The path must resolve inside the working directory, must not contain a `scanner/src` segment, and must not replace an existing file without `--force` (or a directory at all). A refused path writes nothing and exits 4.
- **Nothing loads it.** No module of the scanner or its CLI imports the synthesis module; only `scripts/synthesize-detector.mjs` does, and no loader reads the proposal format. Turning a proposal into a detector is a human editing a detector module.
- **The proposal says so.** Every proposal carries the fixed `review` text above.

## What this does not do

<!-- limits-verified: 2026-11-13 -->

- **The output confinement is by path text.** `scanner/src` is refused as a literal pair of path segments after resolving `.` and `..`; a symbolic link that points into it is not followed or detected, and any other place inside the working directory (including `.agentic-security/`) is accepted.
- **"Nothing loads it" is the absence of a reader, not a check.** No code refuses a proposal file that a person copies into a rule directory; it is simply not a format any loader reads. The contract test pins the absence by searching the scanner source and CLI for an import.
- **The method names are not checked against the samples.** The prompt asks for names that appear in the samples, and the validator checks only that each is an identifier.
- **A valid proposal is a well-formed one, not a correct one.** Nothing runs the proposed sink against the samples or any corpus; the proposal has no score, precision or recall.
- **Redaction is pattern-based.** A secret in a sample whose shape the shared redactor does not cover reaches the model endpoint.
- **A truncated reply can still pass.** When the reply is cut at the output cap and the remaining text still parses and validates, the proposal is produced; the command says the reply was truncated.
- **One CWE and one language per run.** There is no batch mode and no MCP tool for this.
