# Website package

No website source exists in this repository (there is no `website/` or `site/` directory). This folder is the implementation-ready package for whoever builds or updates the site: page copy, navigation, metadata, calls to action, visual requirements and component specs.

Everything here is derived from the same sources as the README and docs, and obeys [the style and terminology guide](../STYLE-AND-TERMINOLOGY.md). The same rules apply on the site as in the docs. License wording matters: the project is PolyForm Internal Use (source-available), so the site must not call it open source.

Three rules in particular:

1. Maturity comes from [`docs/capabilities.yaml`](../capabilities.yaml). A site page may not label a capability differently from the registry.
2. A Roadmap capability is described in the future or conditional tense.
3. Do not lead with raw feature counts.

| File | Contents |
|---|---|
| [homepage.md](homepage.md) | The homepage, section by section, in the required order |
| [navigation.md](navigation.md) | Global navigation, footer, and the role paths |
| [metadata.md](metadata.md) | Unique title, description and social metadata per page, and the discoverability terms |
| [components.md](components.md) | Component and visual specs, with accessibility requirements |

## Pages the site needs

| Page | Source of truth in this repo |
|---|---|
| Homepage | [homepage.md](homepage.md) |
| How it works | [assurance-lifecycle.md](../how-it-works/assurance-lifecycle.md) |
| Evidence model | [evidence-model.md](../how-it-works/evidence-model.md) |
| Code Boundaries | [code-boundaries.md](../security-graph/code-boundaries.md) |
| Trust and limitations | [trust-and-limitations.md](../trust/trust-and-limitations.md) |
| Role pages (eight) | [docs/roles](../roles/developer.md) |
| Quickstart | [5-minute demo](../quickstart/5-minute-demo.md), [15-minute quickstart](../quickstart/15-minute-quickstart.md) |
| One finding's journey | [one-findings-journey.md](../workflows/one-findings-journey.md) |
| Capabilities | Rendered from `docs/capabilities.yaml`; never hand-edited |

## Build notes

- Render the capability table and the lifecycle stage badges from `docs/capabilities.yaml` at build time. The README and docs do the same through `node scripts/check-positioning-docs.mjs --write`.
- Reuse the six SVGs in `docs/assets/positioning/`. They are plain SVG with `<title>` and `<desc>`, readable without color.
- Link every claim of quality to [benchmarking methodology](../trust/benchmarking-methodology.md) or omit it.
