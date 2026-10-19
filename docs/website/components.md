# Components and visuals

## Maturity badge

Text label inside a bordered pill: `GA`, `Preview`, `Labs`, `Roadmap`. Color may reinforce the label but never carries it: the text is always present, the border style differs (solid for GA and Preview, dashed for Labs, dotted for Roadmap), and the accessible name is "Maturity: <label>". Contrast at least 4.5:1 in light and dark themes.

## Lifecycle rail

Ten stage chips in the canonical order, each with a name, the guiding question on hover and focus, and a stage maturity line. The Detect chip shows "Labs, Roadmap". Keyboard navigable; never encodes status by position or color alone.

## Capability table

Columns: Capability, Lifecycle Stage, Maturity, What It Establishes. Rendered from `docs/capabilities.yaml`. Sortable by stage; default order is registry order. On narrow screens collapse to cards, one per capability.

## Evidence ladder

Eight rungs, from Candidate to Fix Verified. Each rung expands to "What this establishes" and "What this does not establish". Rungs that are not literal product fields are marked so. Source: [evidence model](../how-it-works/evidence-model.md).

## Journey stepper

Ten steps for [One finding's journey](../workflows/one-findings-journey.md). Each step shows its badge, a captured-output block (monospace, copyable), and the evidence created. A step that did not run shows the real "nothing ran" message, not a placeholder.

## Role cards

Eight cards, each with the role name, its primary question and one link. See [navigation](navigation.md).

## Captured-output block

Monospace, horizontally scrollable, labeled "Captured output" with the command that produced it. Never restyled to alter the text.

## Visual assets

Six SVGs in `docs/assets/positioning/`:

| File | Use |
|---|---|
| `assurance-lifecycle.svg` | Hero and How it works |
| `traditional-vs-agentic.svg` | Traditional vs Agentic section |
| `evidence-model.svg` | Evidence and trust section |
| `security-graph.svg` | Code Boundaries section |
| `one-finding-journey.svg` | Journey page header |
| `platform-architecture.svg` | Architecture page |

Requirements: readable on a GitHub README at 800 px width; accessible `<title>` and `<desc>`; maturity written as text; no invented quantitative claims; responsive to a 320 px viewport by scaling, with a text-only fallback list beneath each.

## Performance and accessibility

Static pages, no client-side requirement to read the content. Semantic headings, visible focus states, reduced-motion respected, color-independent status everywhere.
