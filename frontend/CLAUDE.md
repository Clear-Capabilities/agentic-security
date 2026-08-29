# frontend/

Data Flow Explorer's clickable prototype. See `README.md` for the
zero-build-step rationale and how to run it.

| Module | Responsibility |
|---|---|
| `src/lib/escape-html.js` | The one safe way to insert graph-derived text as HTML-ish content. Quote-complete (escapes `&<>"'`) — neither existing in-repo escaper (`scanner/src/posture/fleet.js`, `scanner/src/badge.js`) is. |
| `src/lib/contrast.js` | WCAG relative-luminance contrast ratio, from first principles — no existing contrast tooling anywhere in this repo. |
| `src/lib/dom.js` | Safe DOM element builder (`el()`) — never `innerHTML`. Browser-only, not unit-tested (too thin to justify a `jsdom` dependency); exercised via manual browser smoke-checks. |
| `src/lib/state.js` | Cross-view selection/filter state, persisted in the URL hash (AC-16). Pure functions, fully unit-tested. |
| `src/data/flagship-graph.js` | **Generated** — do not hand-edit. Run `npm run generate-fixture` after any change to `scanner/src/lineage/fixtures/flagship-graph.json`. `test/fixture-module-parity.test.js` enforces this file stays byte-identical to the backend fixture and passes the real `validateGraph()`. |
| `src/shell.js` | The `AppShell` — header, view tabs, left rail, canvas, inspector, context rail (PRD §7.7). |

## Conventions

- **No `innerHTML` with graph-derived content, ever.** Use `el()` (`lib/dom.js`) or `document.createTextNode`/`textContent`. The formal adversarial-fixture XSS test suite is Milestone 3's (per `docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md`'s T1 entry), but this hygiene rule is not optional now that rendering code exists.
- **No new runtime dependency without updating this file's own "why no build step" reasoning first** — the zero-build-step decision is deliberate, not an oversight; see `README.md`.
- **The prototype consumes the real fixture shape, not the PRD's abstract prose.** Field names like `flow.source`/`flow.sink`, `evidence.evidenceType`, and `dataElement.dataClasses` being UPPERCASE were confirmed against the actual committed JSON — if the backend fixture's shape changes, re-run `npm run generate-fixture`, re-run `npm test`, and update any view code that assumed the old shape.
