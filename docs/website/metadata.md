# Metadata

Unique titles and descriptions per page. Titles are at most 60 characters and descriptions at most 160, so search results do not truncate them. Do not stuff keywords into visible copy; they live here, in structured data and in repository topics.

| Page | Title | Description |
|---|---|---|
| Homepage | Agentic Security: Autonomous Security Assurance | Discover vulnerabilities, prove what is exploitable, understand what is exposed, fix it safely and learn from every finding. Security assurance for AI-written code. |
| How it works | How Agentic Security Works: The Assurance Lifecycle | Ten stages from discovering a weakness to detecting its recurrence, each labeled with its real maturity and the evidence it creates. |
| Evidence model | Evidence Model: Severity, Confidence and Proof | Why a security claim needs more than a model opinion: severity, confidence, reachability, exploit proof and fix verification are separate facts. |
| Code Boundaries | Code Boundaries: The Security Graph for Code and Data | Trace sensitive data from source to sink with protection state on every hop, then connect it to findings, blast radius and provenance. |
| Trust | Trust and Limitations: What Agentic Security Won't Claim | A clean scan is not proof of absence. See what the tool refuses to claim, how scan health works and where its limits are. |
| CISO | Security Leadership: Questions to Ask of Your Program | Did the analysis complete, how many findings are reachable or proven, and which fixes are fully verified? Eight questions with answers. |
| AppSec | AppSec Guide: Trust, Tune and Govern the Analysis | Read the evidence, tune rules and suppressions, set assurance gates and see what the analysis did not cover. |
| Developer quickstart | Developer Quickstart: Scan, Fix and Verify in 15 Minutes | Install Agentic Security, scan the demo app, fix a finding through verification and run it on your own project. |

## Social cards

Use `docs/brand/social-preview.png` until a per-page card exists. Alt text states the page's subject, not the brand.

## Discoverability terms

The terms below should appear in metadata, structured data (`keywords`), repository topics and comparison material, and in running copy only where they read naturally.

- agentic security harness
- AI security scanner
- AI code security
- Claude Code security
- Codex security
- Cursor security
- secure AI-generated code
- agentic AppSec
- autonomous security assurance
- AI SAST

"Agentic security harness" stays as a secondary descriptor in the repository description and topics, and in comparison pages; the category in running copy is Autonomous Security Assurance Platform.

## Structured data

- Homepage: `SoftwareApplication` (name, applicationCategory `SecurityApplication`, license, codeRepository).
- Docs pages: `TechArticle` with `headline` equal to the page title.
- Quickstart: `HowTo` with the real steps from the 5-minute demo.
- Do not add `aggregateRating` or any quantitative claim that is not published in [METRICS](../METRICS.md).
