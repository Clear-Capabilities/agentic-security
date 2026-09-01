# Milestone 3 scoping: interactive website

Per the PRD's §26 "Milestones and priority" (`AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`,
line ~1810): *"local server and secure API; Architecture, Privacy, Trace,
and inventory views; shared product shell, design-token package, and
reusable graph/evidence components; the exact screen compositions and
view states defined in Sections 7.7–8.4; semantic zoom, search, query
language, focus controls; evidence inspector and alternate paths;
responsive layout, accessibility, and performance optimization. Exit
gate: representative architect and privacy-officer usability tests
complete their core questions without source-code assistance, and AC-16
through AC-22 pass at every supported desktop viewport."*

Milestones 1 and 2 (the `DataFlowGraph v1` engine, `scanner/src/lineage/`)
are COMPLETE, with real, verified proofs — see that package's own
`CLAUDE.md`. This document scopes the very different work that remains.

## 0. What Milestone 3's own exit gate means for autonomous execution

**Two genuinely different halves.** AC-16 through AC-22 are ALL
code-testable — golden-DOM/screenshot assertions against the committed
flagship fixture at fixed viewports, contrast-ratio math, and
forced-state assertions against the §8.4 state matrix. None require a
live human. **The exit gate's OTHER clause — "representative architect
and privacy-officer usability tests complete their core questions
without source-code assistance" — cannot be closed by an agent.** It
requires real usability-test sessions with real personas. This document
therefore scopes and closes everything AC-16–22 requires, and explicitly
names the usability-test clause as permanently out of this document's own
reach — Milestone 3's own "done" checkpoint (an M3-I equivalent to M2's
Sub-project I) can only ever report "every agent-closable requirement is
closed; the human-usability clause requires the user's own action," never
claim the whole exit gate passed.

## 1. What already exists (confirmed by direct investigation this session)

- **`frontend/`** (Milestone 0's "clickable prototype") is a real, working,
  tested implementation of THREE of the four required views — Architecture,
  Privacy, Trace (`frontend/src/views/{architecture,privacy,trace}-view.js`)
  — following the exact `compute*ViewModel()` + thin `render*View()` split
  §8.3's component contract requires. **Inventory does not exist at all**
  — confirmed: `shell.js`'s `VIEWS` constant has no fourth entry, and a
  repo-wide grep for "Inventory" across `frontend/src/**/*.js` returns
  nothing.
- **Deliberately zero-build-step, plain ES modules, no React/TypeScript/
  Cytoscape/ELK** — a documented, reasoned deferral, not an oversight:
  `frontend/README.md` states the PRD's own §17.2 "recommended" stack is
  explicitly conditional ("must pass the performance gates before being
  finalized") on §21's 5,000-node/10,000-edge budget, and the flagship
  fixture is only 14 nodes/15 edges — "solving a problem this milestone
  doesn't have." **This decision was never actually tested against a
  large graph — it is a reasoned deferral, not a measured one.**
- **No local server or API exists anywhere in the repo.** Confirmed: no
  Express/Fastify/`http.createServer`-style web server under `scanner/
  src/` or elsewhere; the only `createServer`/`listen(` hits anywhere are
  SAST detection-rule regex patterns matching THAT SHAPE IN SCANNED CODE,
  not an actual implementation. `scanner/src/mcp/` (JSON-RPC-over-stdio
  MCP tool server) and `scanner/src/lsp/` (Language-Server-Protocol-over-
  stdio) are both confirmed unrelated — neither is an HTTP/loopback API,
  neither has any relationship to this milestone's `/api/v1/*` design.
  **The entire "local server and secure API" deliverable is greenfield.**
- **`frontend/`'s current data path is static, not live**: a Node-only
  build script (`frontend/scripts/generate-fixture-module.mjs`) reads
  `scanner/src/lineage/fixtures/flagship-graph.json`, validates it with
  the REAL `validateGraph()` (imported directly from `scanner/src/
  lineage/validate.js` — the only place the frontend tree touches the
  engine at all, and only at build time, never at runtime/in-browser),
  and writes a generated ES module the browser statically imports.
  Milestone 3's real architectural work is replacing this with genuine
  `GET /api/v1/graph`-style live consumption — not merely adding a server
  alongside the existing code path.
- **`docs/DATA_FLOW_EXPLORER_THREAT_MODEL.md` already exists**, written
  at Milestone 0, before any server/UI code — an 8-threat (T1–T8) living
  document, each mapped to its PRD mitigation and an explicit "Status"
  line. T2 (DNS rebinding), T3 (CSRF), T4 (path traversal), and the
  server-side half of T5 (oversized/cyclic-graph DoS) are ALL explicitly
  named "Milestone 3 (server does not exist yet)." T1 (XSS) already has
  baseline DOM-escaping hygiene in `frontend/` (`escape-html.js`,
  `dom.js`) but its own "formal adversarial-fixture XSS test suite, CSP
  hardening, and server-side defenses" are explicitly scoped to
  Milestone 3, with the doc PRE-SPECIFYING the required test shape: *"an
  adversarial fixture (HTML/script tags/control chars/very long
  identifiers in file and symbol names) and a test asserting the rendered
  DOM contains no live `<script>`, `javascript:` URL, or unescaped tag
  from that fixture."* **This document is the closest thing to a
  pre-built Milestone 3 security backlog that exists in the repo — read
  it directly before scoping any security-adjacent sub-project below.**
- **§17.4's server security list** (verbatim, PRD): bind only to
  `127.0.0.1`/`::1`; random port unless configured; random session token;
  validate `Host` header (anti-DNS-rebinding); restrictive CSP; CORS
  disabled by default; same-site cookie or request token on
  state-changing endpoints; never serve arbitrary repository paths;
  confine file/line evidence lookups to the scanned root; cap request
  size/query complexity/path enumeration; never cache sensitive evidence
  unless explicitly exported; idle-timeout auto-stop (`--keep-open`
  opt-out); metadata-only logging; outbound calls only through the
  scanner's existing egress policy.
- **§17.3's API table** has ~19 endpoints, but only a READ-ONLY subset is
  Milestone 3 scope per the milestone table: `GET /api/v1/scan`, `GET
  /api/v1/graph`, `GET /api/v1/nodes/:id`, `GET /api/v1/edges/:id`, `GET
  /api/v1/flows/:id`, `POST /api/v1/query` (a DETERMINISTIC TYPED
  projection query — explicitly "no arbitrary code"), and `POST /api/v1/
  export`. Every other endpoint (`stories/compose`, `scenarios/evaluate`,
  `snapshots`, `diffs`, `obligations/query`, `runtime/query`,
  `recipients/query`, `impact`, `remediation`, `events`, `rescan`) is a
  decision-intelligence endpoint tied to Milestone 4/5's own flagship
  capabilities (FR-501–507) — **do not build these now**, the milestone
  table assigns them elsewhere.
- **AC-16 through AC-22**, per-AC testability already classified (see the
  research report this scoping is built from): every one is code-testable
  via golden-DOM/state-matrix/contrast/viewport assertions against the
  committed flagship fixture. `frontend/src/lib/contrast.js` already
  exists, apparently built anticipating AC-20 specifically.

## 2. Decisions this scoping makes explicitly

**Decision 1 — the React/Cytoscape/ELK stack decision gets resolved by
MEASUREMENT, first, before any other Milestone 3 sub-project that would
be architecturally affected by it.** `frontend/`'s own deferral reasoning
was sound at Milestone 0 (no large graph existed to test against) but is
now untested, not merely unresolved — and every downstream sub-project
(Inventory view, semantic zoom, live-API wiring) would be built
differently depending on the answer. Recommendation: a small, first
sub-project (M3-Perf) generates a synthetic graph at §21's own budget
(5,000 nodes/10,000 edges) — a generator, not hand-authored — and
measures the CURRENT vanilla-JS renderer against §21's own performance
targets (read the PRD's §21 directly for the exact numeric target before
writing this sub-project's own plan; do not assume a number here). If it
passes, the current zero-build-step architecture is confirmed and every
later sub-project builds on it, unchanged. If it fails, this becomes a
real, larger, separately-scoped architecture-migration sub-project
BEFORE Inventory/live-API work proceeds — do not discover this
mid-build of something else.

**Decision 2 — the local server is the highest-priority, most
foundational sub-project, and security is built in from the start, not
bolted on after.** T2/T3/T4's own "Status" lines in the threat model doc
read "Milestone 3 (server does not exist yet)" — meaning BUILDING the
server is what CREATES these threat surfaces. §17.4's full security list
is therefore in scope for the SAME sub-project that builds the server's
basic routing, never a follow-up hardening pass. Recommendation: M3-Server
implements ONLY the read-only P0 endpoint subset named in §1 above
(never the Milestone 4/5 decision-intelligence endpoints), with every
§17.4 bullet as a first-class requirement of the SAME plan, and reuses
the threat model doc's own pre-specified test shapes for T2/T3/T4
directly rather than inventing new ones.

**Decision 3 — wiring the existing frontend to the new live API is its
own, separate sub-project from building the server itself**, mirroring
this session's own "plumbing vs. logic" discipline from Milestone 2 (e.g.
Sub-project B1's own fileContents-plumbing-first pattern). M3-Server
produces a working, tested API in isolation (its own test suite hitting
it directly, e.g. via `fetch`/`supertest`-equivalent); M3-Wire then
replaces `frontend/`'s static-generated-module import with a real fetch
against that API, and is the RIGHT place to prove the "same fixture
graph renders identically across three prototype lanes" property AC-16
implicitly depends on (live-API-backed rendering must be byte-for-byte
equivalent to today's static-import rendering, or AC-16/17/18/19's own
already-passing assertions would need re-proving against a moving
target).

**Decision 4 — Inventory view is new, isolated work, sequenced AFTER
M3-Wire (so it is built against the real API from the start, never
against the soon-to-be-replaced static import), and BEFORE the golden
state-matrix test suite (M3-Golden), since AC-16's "all primary views"
property and §8.3's shared-component contract are strongest proven once
all four views exist.**

**Decision 5 — the T1 XSS adversarial-fixture test suite is its own
small, sharply-scoped sub-project (M3-XSS), not folded into M3-Server**,
since the threat model doc already fully specifies its shape (a fixture
with hostile file/symbol names + a DOM-assertion test) and it exercises
the FRONTEND's own rendering path, not the server — building it alongside
M3-Server would conflate two different code surfaces' own security work.

**Decision 6 — AC-20 (contrast) and AC-21 (viewport reflow) are one
sub-project (M3-A11y), since both are cross-cutting shell/CSS-level
properties, not per-view logic** — distinct from AC-16/17/18/19/22
(M3-Golden), which are per-view/per-state content assertions.

**Decision 7 — semantic zoom, search, query language, focus controls,
and saved views (§7.2/§17.2's own "and" list) are named here but
DELIBERATELY NOT broken down into increments in this document.** This is
the single largest remaining Milestone 3 deliverable, its own shape
depends entirely on Decision 1's own outcome (a query language/semantic
zoom implementation looks very different in Cytoscape+ELK vs. hand-rolled
SVG/Canvas), and attempting to pre-scope it before that measurement
exists would repeat exactly the mistake Decision 1 corrects. **A future,
dedicated scoping pass, after M3-Perf resolves the stack question, is
the honest way to handle this** — named here as M3-UX, explicitly
unscoped.

## 3. Sub-project breakdown (recommended order)

| # | Sub-project | Depends on | Size | What it delivers |
|---|---|---|---|---|
| Perf | **Performance-gate measurement** — **COMPLETE, measured 2026-09-01** | none | Small | Real Chrome measurement against a real 5,000-node/10,000-edge synthetic graph: **first-meaningful-paint FAILS badly at reference scale** (no real paint after 20+s; the current renderer's own JS-timer falsely reported "done"); pan/zoom doesn't exist as a feature yet. Real result at `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-perf-result.md`. Does NOT block Server/Wire (current flagship-fixture scale, 14 nodes, is unaffected) — but adds a new, real, necessary sub-project, **M3-Render**, below. |
| Render | **Rendering-architecture migration** (NEW, added after Perf's real measurement — not in this document's original breakdown) | Perf | Large, unscoped | Perf's own finding: the current unclustered, hand-rolled-SVG-per-element renderer cannot paint the PRD's own §21 reference-scale graph. Whether this means adopting §17.2's full React+Cytoscape+ELK recommendation, or a narrower fix (canvas/WebGL rendering, or SVG + real clustering/level-of-detail/virtualization), needs its own dedicated scoping pass, grounded in the Perf result's real numbers — deliberately not decided here. Must land before Inventory/large-scale interactive work (semantic zoom, search — M3-UX) is built on the current renderer. |
| Server | **Local server + secured read-only API** — **increment 1 COMPLETE, 2026-09-01** | Perf (architecture-neutral, but sequenced after so no server-side rendering assumption is baked in before the stack question settles) | Large | **S1 shipped**: the five read-only GET endpoints (`scan`/`graph`/`nodes/:id`/`edges/:id`/`flows/:id`) plus the FULL §17.4 security list as a first-class S1 requirement — T2 (DNS rebinding)/T3 (CSRF, via required session token on every request)/server-side T5 (request-size caps) all closed with real, live-request regression tests against a real running server, independently re-verified by the coordinator via a third path (manual `curl`). See `scanner/src/server/CLAUDE.md`. `POST /api/v1/query`/`POST /api/v1/export` are real design work of their own, deferred to a future S2/M4 — not attempted in S1. |
| Wire | **Live-API wiring for the existing three views** — **COMPLETE, 2026-09-01** | Server | Medium | **Shipped**: replaced `frontend/`'s static-generated-module import with real, live `fetch()` consumption of `GET /api/v1/graph`, authenticated via a URL-fragment-delivered session token. Found and closed a real, load-bearing gap before implementation: CORS is deliberately disabled, so the frontend had to be served from the SAME origin as the API — `explore` now also serves `frontend/`'s static assets via a new, explicit allowlist (never a bare `../`-traversal guard — `test/`/`scripts/`/`package.json`/`README.md`/`CLAUDE.md` are real files that must never be servable). The AC-16 byte-for-byte rendering-equivalence proof passed. See `scanner/src/server/CLAUDE.md`'s own "Sub-project Wire" section. |
| Inventory | **Inventory view (net new)** | Wire, **and M3-Render if built against a graph anywhere near §21 scale** | Medium | The fourth required view (§7.6), built against the live API from the start — sortable tables for sources/sinks/fields/destinations/stores/AI-systems/transformations/unprotected-edges/policy-permitted-flows/manual-governance-gaps/unsupported-candidates, sharing filters/canonical IDs with the graph views per §7.6's own explicit requirement. Table-shaped views are far less exposed to Perf's own SVG-scaling failure than the graph views (virtualized tables were always §17.2's own recommendation regardless of the graph-canvas decision) — re-confirm this assumption when Inventory is actually scoped, don't just assume it. |
| XSS | **T1 adversarial-fixture XSS test suite + CSP hardening** | Wire (needs the real rendering path, not the static one, to test against) | Small | The threat model doc's own pre-specified adversarial fixture (hostile file/symbol names) + DOM-assertion test; CSP header hardening on the server (coordinates with Server's own CSP bullet, but the test suite itself belongs here, against the frontend's real render path). |
| A11y | **Contrast + viewport reflow (AC-20/AC-21)** | Wire, Inventory (needs all four views to prove the shell-level property fully) | Medium | Formal contrast-ratio tests (extends the existing `contrast.js`), keyboard-focus parity, and layout assertions across the four named viewports (1280×720/1440×900/1680×945/2560×1440) per §7.7's own collapse/overlay rules. |
| Golden | **Golden/state-matrix reference-composition tests (AC-16/17/18/19/22)** | Wire, Inventory, A11y | Medium-Large | Per-view golden-DOM/screenshot assertions against the flagship fixture's own named reference compositions (§7.8's `PCI Exposure` saved view, §7.9's lifecycle-stage layout, §7.10's 5-step trace), plus the §8.4 11-state matrix forced-state assertions (AC-22 — no non-clean state may ever resemble a clean scan). |
| I | **Exit-gate closure (agent-closable half only)** | All above | Small | Runs every agent-closable AC-16–22 test against the real build; documents, honestly, that the usability-testing clause of the exit gate remains open and names exactly what a real usability-test session would need (the same "what this does NOT mean" disclosure discipline Milestone 2's own Sub-project I established). |

**M3-UX** (semantic zoom, search, query language, focus controls, saved
views) is named in §2 Decision 7 as real, large, deliberately unscoped
work — its own future scoping pass, gated on M3-Perf's own outcome.

## 4. What this document does NOT do

Scope M3-UX in any detail (Decision 7). Attempt the usability-testing
clause of the exit gate (§0 — permanently out of an agent's reach).
Build any Milestone 4/5 decision-intelligence endpoint (`stories/`,
`scenarios/`, `snapshots/`, `diffs/`, `obligations/`, `runtime/`,
`recipients/`, `impact/`, `remediation/`, `rescan`) — all explicitly
named out of Milestone 3's own scope by the milestone table. Build the
self-contained HTML/PDF/PNG/SVG/CSV/DPIA/RoPA export pipeline (§17.5) —
largely Milestone 4 territory per the milestone table, even though it
shares components with the live app; a future scoping pass' own call
whether any minimal export slice belongs earlier. Resolve §8.1's exact
design-token hex values beyond what already exists in `frontend/`'s own
CSS (the PRD states "semantic names and usage are normative, exact
values tunable" — not this document's job to re-litigate).

## 5. Recommended next step

**Updated after Perf's own real measurement (2026-09-01).** M3-Perf is
done; it found a real, large-graph rendering failure and added M3-Render
to this table (§3 above). Two independent tracks can now proceed:
M3-Server (architecture-neutral, greenfield, the highest-priority
foundational piece per Decision 2) and — separately, its own future
scoping pass — M3-Render (resolving the stack-migration-vs-narrower-fix
question Perf's real numbers now ground). M3-Wire only needs Server, not
Render, since the current flagship-fixture scale is unaffected by Perf's
finding. Recommended: scope and start M3-Server next.
