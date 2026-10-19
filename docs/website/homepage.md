# Homepage copy

Sections in the required order. Each section lists its copy, its call to action where it has one, and the doc it must link to.

## 1. Hero

**H1:** Autonomous Security Assurance for the AI Software Era

**Subhead:** Discover vulnerabilities. Prove what's exploitable. Understand what's exposed. Fix it safely. Learn from every finding.

**Supporting line:** Agentic Security pairs deterministic analysis with security agents. Agents propose and fix; mechanical evidence decides. Anything it could not check is shown, never rounded up to green.

**Primary CTA:** See How It Works (links to [How it works](../how-it-works/assurance-lifecycle.md))

**Secondary CTA:** Try the 5-Minute Demo (links to [5-minute demo](../quickstart/5-minute-demo.md))

**Tertiary link:** Read the Evidence Model (links to [evidence model](../how-it-works/evidence-model.md))

**Visual:** `assurance-lifecycle.svg` or a calmer static crop of it. See [components](components.md).

## 2. Traditional vs Agentic Security

**Heading:** From a ticket to a closed loop

**Visual:** `traditional-vs-agentic.svg`

```text
Traditional security
SCAN → FIND → TICKET

Agentic Security
DISCOVER → PROVE → UNDERSTAND → FIX → VERIFY → LEARN ↻
```

**Body:** A scanner hands you a list. Agentic Security asks whether each item is real, shows how it knows, shows what it touches, fixes it through a gate, checks the fix, and keeps what it learned. Learning and detection are the longest-term parts and are labeled Labs and Roadmap where they are.

**Link:** the complete ten-stage lifecycle.

## 3. Assurance lifecycle

**Heading:** Ten stages, each with its real maturity

Render the ten stages from `docs/capabilities.yaml` with a one-sentence definition, the stage's guiding question, a maturity badge for each capability, and a link to the stage page. Badges carry a text label (GA, Preview, Labs, Roadmap); never color alone.

**Note under the lifecycle:** The operational finding workflow, Find → Prove → Hunt → Scope → Fix → Verify → Detect, is the part of this a person touches while working one finding.

## 4. Evidence and trust differentiation

**Heading:** Evidence, not magic

**Lead:** Agentic Security never treats an unavailable analyzer, skipped validation step, partial scan, or failed verification leg as proof that code is safe.

**Four short proof points** (each a card, each linked):

| Card | One line | Link |
|---|---|---|
| Evidence before severity | A model opinion is not enough for a security claim | [Evidence model](../how-it-works/evidence-model.md) |
| Challenge your own findings | Discovery is aggressive; confirmation is skeptical | [Falsification](../corroborate/README.md) |
| Never fake green | A scan that did not finish is never a clean scan | [Scan health](../trust/scan-health.md) |
| Verified means named | Every fix names the checks that ran and the ones that did not | [Verified remediation](../trust/verified-remediation.md) |

**Visual:** `evidence-model.svg`

## 5. Security graph and Code Boundaries

**Heading:** The security graph underneath

**Body:** Findings tell you a line is dangerous. Code Boundaries shows where data comes from, where it goes and what protects it on every hop, then connects it to findings, blast radius and provenance. Runtime and artifact evidence are shown with their actual status.

**Visual:** `security-graph.svg`

**CTA:** Explore Code Boundaries (links to [Code Boundaries](../security-graph/code-boundaries.md))

## 6. Executive outcomes

**Heading:** Questions your leadership can ask

Seven outcome questions, as a list, each with its maturity and a link to where the answer lives. Do not show numbers unless they come from a real scan.

- How much of the estate completed a trustworthy scan? (Roadmap as an aggregate; per-scan status is GA)
- How many findings are reachable?
- How many survived falsification?
- How many are proof-backed?
- What sensitive data is in the blast radius?
- How many fixes are fully verified?
- Which weakness classes are recurring? (Roadmap)

**Link:** [CISO lane](../roles/ciso.md)

## 7. Role paths

**Heading:** Start where you work

Eight cards: Developer, AppSec, CISO and security leadership, Platform engineering, AI engineering, Privacy, Compliance, Detection engineering. Each shows the role's primary question and links to its page under [docs/roles](../roles/developer.md).

## 8. Source-available quickstart

**Heading:** Try it on the demo app in one command

**Licensing note:** the repository is source-available under the PolyForm Internal Use license. Do not label it "open source" on the site; the PRD's "open-source quickstart" slot means the clone-and-run path, and the license is stated beside it.

```bash
npx @clear-capabilities/agentic-security-scanner ci examples/demo-app --assurance strict
```

Show the real captured output from the [5-minute demo](../quickstart/5-minute-demo.md), including the failed assurance line, with a caption explaining that it is a feature.

## 9. Trust and limitations

**Heading:** What it will not claim

Short form: not proof of absence; not an auditor-issued certification; not a replacement for human review or pentesting; not an excuse to call degraded verification fully verified.

**CTA:** Read Trust and Limitations (links to [trust and limitations](../trust/trust-and-limitations.md))

## Footer

Links to the repository, license, security policy, docs home, capability registry and the roadmap. Include "Built by Clear Capabilities".
