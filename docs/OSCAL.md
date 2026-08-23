# OSCAL output

`agentic-security` emits [NIST OSCAL](https://pages.nist.gov/OSCAL-Reference/models/)
`assessment-results` documents from two places:

```bash
agentic-security scan . --format oscal                       # the scan itself
agentic-security compliance --report <framework> --format oscal   # a control assessment
agentic-security compliance --format oscal                   # NIST Privacy Framework 1.1 (default)
```

Both produce OSCAL 1.1.2 JSON on stdout. Both are covered by the determinism
gate, so re-emitting the same scan yields the same bytes and an attestation
taken over the document still verifies.

---

## Why `assessment-results`, and not one of the other six models

OSCAL has seven models. Only one of them describes "something examined a system
and reports what it found", and that is `assessment-results`.

| Model | Why this tool does not author it |
|---|---|
| catalog / profile | These *define* controls. A scanner does not get to author a control catalog. |
| component-definition | Describes how a component satisfies controls — a vendor claim, not an observation. |
| system-security-plan | Describes a system's *design*. Nothing in a scan is evidence of a design. |
| assessment-plan | Describes what an assessor *intends* to do. Written before the assessment, by a human. |
| plan-of-action-and-milestones | Requires owners, dates and accepted risk. A scanner has none of those. |
| **assessment-results** | **What was observed, what it means, and — where a control was in scope — whether it was satisfied.** |

---

## The part that matters: what is *not* in the document

An OSCAL `finding` is a statement **about a control**. The model requires a
`target` with a `target-id` and a `status.state` that is binary: `satisfied` or
`not-satisfied`. There is no `unknown`, no `not-applicable`, and no "we did not
look". That constraint is the honest part of OSCAL, and it decides the shape of
everything this tool emits.

### A raw scan emits **no findings**

`scan --format oscal` produces `observations` (what the scanner saw) and `risks`
(what it would mean), and no `findings` at all. A SQL-injection hit is not an
opinion about any control, because no catalog is in scope. Emitting findings
would mean publishing a CWE→control mapping that nobody wrote and no assessor
agreed to.

For the same reason `reviewed-controls` does **not** say `include-all`. It says,
in the document, that no control catalog was reviewed. `include-all` would
assert this scan reviewed every control of an unnamed catalog.

### A control the engine could not decide gets **no finding**

The compliance exporters emit a finding only for controls the engine actually
decided. Everything else becomes an `observation` with method `EXAMINE` and a
remark saying a human must assess it.

Both upstream assessors distinguish "decided" from "not assessed", and the
distinction survives into the document as an `assessment-status` property, even
though OSCAL itself has no way to express it:

| Upstream status | OSCAL result | Property |
|---|---|---|
| `present` (all mapped signals cleared) | finding, `satisfied` | `assessment-status: present` |
| `partial` (some signal did not clear, or the mapping is unverifiable) | finding, `not-satisfied` | `assessment-status: partial` |
| `absent` (signals exist, none cleared) | finding, `not-satisfied` | `assessment-status: absent` |
| `manual` (no automated mapping at all) | **observation only**, method `EXAMINE` | `assessment-status: manual` |

and for the NIST Privacy Framework path, which uses its own buckets:

| Bucket | OSCAL result | Why |
|---|---|---|
| `satisfied` | finding, `satisfied` | |
| `gap` | finding, `not-satisfied`, plus an open risk | |
| `manual` | observation only | Requires human judgement. |
| `engine-gap` | **observation only** | NIST rates the control code-testable and *this scanner has no check for it*. That is a hole in the tool, not a defect in the assessed system. Folding it into `not-satisfied` would blame the system for our coverage. |

`satisfied` in these documents means **the automated signals mapped to that
control cleared**. It is scanner evidence toward a control. It is not an
attestation that the control is implemented and operating, and every finding
carries a `remarks` field saying so.

---

## Control identifiers are rewritten, and the original is kept

OSCAL's `token` datatype is an NCName: it must start with a letter or `_`, and
may then contain only letters, digits, `.`, `-` and `_`.

Real control identifiers routinely are not tokens. The CCPA catalog bundled with
this engine uses ids like `§1798.100`; GDPR uses `Art. 32(1)(a)`. Emitting those
raw as a `control-id` or `target-id` produces a document that a validator
rejects at the first control — which is the usual failure mode of an OSCAL
export that was never run through one.

So every identifier is sanitised into a legal token, and the publisher's
original identifier is carried alongside it on every observation and finding as
a `source-control-id` property. `test/oscal-conformance.test.js` pins both
halves: that every emitted id is a legal token, and that no original id is lost.

---

## Extensions

Everything this tool adds beyond the model lives under one namespace:

```
https://github.com/Clear-Capabilities/agentic-security/ns/oscal
```

so a consumer can drop everything it does not understand with a single filter.

Two things are deliberately **not** in the extension props: the raw `confidence`
and `exploitability` scores. Those are ordinal priority rankings, not calibrated
probabilities, and a compliance reader is exactly the reader most likely to read
a decimal in a NIST-shaped document as a percentage. Only the tier labels are
published. The full caveat text travels with the document as `back-matter`
resources — the same two caveats SARIF carries as run notifications, from the
same source constant, so they cannot drift apart.

---

## What is checked, and what is not

`scanner/test/oscal-conformance.test.js` performs **structural** validation:
required fields, the constrained datatypes (`uuid`, `token`,
`dateTime-with-timezone`), the closed value sets (`methods`, risk `status`,
target `type` and `state`, remediation `lifecycle`), and referential integrity —
every `*-uuid` reference and every `#fragment` link must resolve inside the
document.

It is **not** full JSON-Schema validation against NIST's published schema.
Fetching that schema at test time breaks this project's no-network rule, and
vendoring it adds a large file that rots silently against upstream. This is the
same call, for the same reason, as `test/sbom-conformance.test.js` makes for
CycloneDX and SPDX. If you need schema-level assurance, validate the emitted
document with your own OSCAL toolchain — the output is plain JSON on stdout.
