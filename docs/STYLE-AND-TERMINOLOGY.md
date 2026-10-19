# Style and terminology

How Agentic Security documentation talks about itself. The goal is one vocabulary, used the same way on every page, that never claims more than the evidence supports.

`node scripts/check-positioning-docs.mjs` enforces the mechanical parts of this guide. Where natural-language linting is imperfect, a line can carry `<!-- positioning-ignore: reason -->` (a reason is required).

## The category and the promise

| Use | Exactly |
|---|---|
| Category | **Autonomous Security Assurance Platform** |
| Descriptor | **Autonomous Security Assurance for the AI Software Era** |
| Promise | **Discover vulnerabilities. Prove what's exploitable. Understand what's exposed. Fix it safely. Learn from every finding.** |

"Agentic security harness" stays in repository topics, SEO metadata, comparison material and discoverability copy. It is not the headline.

## One lifecycle ordering

The platform lifecycle has ten stages, always written in this order:

`Discover → Corroborate → Prove → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻`

The operational finding workflow is a **subset** of it, and is always described that way:

`Find → Prove → Hunt → Scope → Fix → Verify → Detect`

The simplified public view (Discover, Prove, Understand, Fix, Verify, Learn) is a summary of the ten stages, never a competing ordering. Any line that writes out six or more stages must use the canonical chain exactly; the checker fails otherwise.

## Preferred terms

| Term | Means | Do not use for |
|---|---|---|
| **Agentic Security** | The product | "the harness" as a headline |
| **autonomous security assurance** | The category: evidence-backed security work that runs with minimal supervision and states its own limits | Anything that implies no human review is needed |
| **deterministic analysis** | Mechanical analysis whose output is reproducible: parsing, rules, taint, reachability | Anything a model decided |
| **agentic analysis** | Work where a model reasons, such as hunting, validating or composing a patch | Evidence by itself |
| **evidence** | A recorded, inspectable fact that supports or refutes a claim | An opinion, a score, a model's confidence |
| **corroboration** | Independent analyses agreeing on a finding | A single detector firing twice |
| **falsification** | A deliberate attempt to disprove a finding by looking for the control that would block it | Dropping findings (it only lowers confidence) |
| **scan health** | The `scanHealth` record of whether the analysis itself finished | Whether the code is healthy |
| **assurance** | How much the evidence supports a claim, including how complete the analysis was | A promise of safety |
| **verified remediation** | A fix that passed named verification legs, stated with the legs that ran and the legs skipped | A fix that is merely applied |
| **security graph** | The connected model of code, data, findings and evidence | A diagram |
| **Code Boundaries** | The product name for the field-level security graph and its local explorer (the Data Flow Explorer) | A generic "dependency graph" |

## Maturity words

Every major capability carries exactly one of four maturity labels, taken from `docs/capabilities.yaml` and nowhere else:

| Label | Meaning |
|---|---|
| **GA** | Production-supported |
| **Preview** | Implemented and usable, still being hardened |
| **Labs** | Experimental; the interface may change materially |
| **Roadmap** | Strategic direction; not shipped |

Rules:

1. A Roadmap capability is written in the future or conditional tense, never as something the product does.
2. A Labs capability is never called production-ready, stable or fully supported.
3. A page may not state a maturity that disagrees with the registry. Write a badge as `[Preview]` on the line that names the capability, or a page-level `**Maturity:** Preview` line at the top of the capability's primary page. The checker reads both.
4. Do not promote a capability because the positioning would read better. Change the registry, with evidence, in the same change.

## Avoid, unless qualified

| Avoid | Why | Write instead |
|---|---|---|
| secure, safe | Absence of found problems is not safety | "no actionable findings, and the scan completed" |
| proved safe | A clean result is not a proof | "nothing exploitable was found by the analyses that ran" |
| zero false positives | Unmeasurable and false | State the measured precision and its corpus |
| guarantees | Nothing here is a guarantee | "is designed to", or state the mechanism |
| compliant | Only an assessor can say so | "automated technical-control evidence mapped to <framework>" |
| certified | Only a certifying body issues one | "not a certification" |

The checker flags these words unless the same line negates them or the word sits in code formatting.

## The "verified" rule

"Verified" must always say **what** was verified and whether verification was **full or degraded**.

- Good: "Verified: rescan clean, lint clean, tests skipped (no runner detected). Tier: MITIGATION. Verification was degraded."
- Bad: "The fix was verified."

A skipped, timed-out or unavailable leg is named. It is never folded into a pass.

## The "proven" rule

Use **proven** or **exploit confirmed** only when the execution-backed proof machinery produced the result (`triage exploit --prove`, reproduced the required number of times, confirmed by an independent replay). A static path, a taint chain, a model verdict or a plausible payload is **corroborated**, not proven. A `not-reproduced` result is not a safety proof either.

## Evidence words, kept separate

These are different things and are never blended into one word or one score:

severity, confidence, scan completeness, reachability, exploit evidence, runtime evidence, remediation completeness. See [Evidence model](how-it-works/evidence-model.md).

## Formatting

- **No em-dashes in prose.** Use a comma, a colon or a full stop. (Code, command output and quoted text are unchanged.)
- Write commands exactly as they run. Never invent a command or a flag; the checker verifies the command name and the documented subcommands exist.
- Captured output is labelled as captured, with the command that produced it. Never edit captured output to look nicer.
- Say what a thing does not establish next to what it does.
- No raw feature counts as a headline. Lead with the question the capability answers.
- Do not keyword-stuff. The discoverability terms live in metadata (see [website metadata](website/metadata.md)).
