# Privacy

<!-- seo: title="Privacy guide: trace sensitive data flows with Code Boundaries" description="Trace PII, PHI and payment data through your code, see protection state on every hop, export a DPIA or RoPA, and read the Privacy Framework results without overstating them." -->

**Primary question:** Where does sensitive data actually go, and what protects it?

**Core workflow:** [Code Boundaries](../security-graph/code-boundaries.md)

## Trace the data

[Code Boundaries](../security-graph/code-boundaries.md) is the field-level graph: where a field enters, everywhere it flows, and the protection state on each hop. A flow the scanner cannot evidence is never labeled protected.

```bash
AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan .
agentic-security explore .
```

Then watch one field hop by hop: [Watch one field's journey](../walkthroughs/privacy-data-flow.md).

## Export for the record

`agentic-security dataflow export` writes a DPIA, a RoPA, recipients and coverage reports, an executive briefing (with `--audience`), `json`, `csv`, `html`, `png`, `svg` and `pdf`. Compare two scans with `dataflow diff` to catch newly introduced disclosures, simulate a change with `dataflow scenario apply` (always labeled `HYPOTHETICAL`), and assess impact with `dataflow impact assess`.

## What leaves the machine

[Model egress](../trust/model-egress.md) decides before a prompt is built and redacts PII first. `explore` makes no model calls.

## NIST Privacy Framework 1.1

`agentic-security compliance --privacy` assesses all 104 controls and says plainly that most are not code-testable. Each control is a gap, not assessed, manual or satisfied, and the satisfied rate is reported over assessed controls only. Read [Compliance](../guides/compliance.md) before quoting it.

## Limits

Coverage tiers are partial per language and the graph carries them. Governance facts such as purpose, lawful basis, retention and consent are `manual_required` until you declare them (`governance propose-edit`). See [trust and limitations](../trust/trust-and-limitations.md).
