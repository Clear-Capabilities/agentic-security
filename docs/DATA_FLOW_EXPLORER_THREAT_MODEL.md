# Data Flow Explorer — Threat Model

Status: living document, first written for Milestone 0 (contract/fixture
phase, before any server or UI code exists). Threats below are organized
by the asset they target. Each entry names the PRD requirement that is
the mitigation, and — where the mitigating code does not exist yet — the
milestone responsible for landing it. This file must be revisited at
every milestone exit gate (PRD section 26) and updated, not left to rot.

## Assets

1. **The graph artifact itself** — may reveal architecture, field names,
   vendors, endpoints, database schemas, and security controls (PRD
   section 24). Confidential by default.
2. **The local read-only API / server** (Milestone 3) — a loopback HTTP
   server serving graph queries and evidence.
3. **The browser client** — renders untrusted repository text (file
   paths, symbol names, string literals, comments) as part of node
   labels, evidence snippets, and policy reasons.
4. **Exported artifacts** (self-contained HTML, PNG/SVG, JSON/CSV,
   DPIA/RoPA) — leave the local machine once exported; must not
   over-disclose by default.
5. **State on disk** (`.agentic-security/` graph cache, layout cache,
   attestations) — subject to the same retention/reset/legal-hold rules
   as every other scanner artifact (PRD section 24, first bullet).

## Threats and mitigations

### T1 — Hostile repository text executes in the browser (XSS via scanned content)

A malicious or adversarially-crafted repository can contain HTML, script
tags, control characters, or extremely long identifiers in file/symbol
names, string literals, comments, or route paths. Any of these can reach
a node label, evidence snippet, or policy-reason string in the graph.

- **Mitigation:** every label and snippet is escaped and inserted via
  safe DOM/text APIs; no scanned HTML or Markdown may execute (PRD
  section 16, AC-15). Bounded string length on any rendered label.
- **Status:** a static, zero-build-step prototype now exists (`frontend/`),
  applying ordinary escaping hygiene via `frontend/src/lib/escape-html.js`
  (quote-complete, escaping `&<>"'`) and `frontend/src/lib/dom.js` (never
  `innerHTML` with graph-derived content) as baseline precautions. The
  formal adversarial-fixture XSS test suite, CSP hardening, and server-side
  defenses remain scoped to Milestone 3 (UI). Milestone 3's plan MUST
  include an adversarial fixture (HTML/script tags/control chars/very long
  identifiers in file and symbol names) and a test asserting the rendered
  DOM contains no live `<script>`, `javascript:` URL, or unescaped tag from
  that fixture.

### T2 — DNS rebinding / hostile Host header against the local server

A malicious webpage open in the same browser could point requests at
`127.0.0.1:<port>` if the server trusts an arbitrary `Host` header or
allows cross-origin requests.

- **Mitigation (PRD section 17.4):** bind only to `127.0.0.1`/`::1`,
  random port by default, random session token required, validate the
  `Host` header, restrictive CSP, CORS disabled by default, same-site
  cookie or request token for state-changing endpoints.
- **Status:** not yet built (Milestone 3). Recorded here so the Milestone
  3 plan is written against this threat, not discovered afterward.

### T3 — CSRF against write/rescan endpoints

Once state-changing endpoints exist (`POST /api/v1/rescan`, remediation
writes — PRD section 17.3), a page the user has open elsewhere could
trigger a same-origin-looking request.

- **Mitigation:** session-token or same-site-cookie requirement on every
  state-changing endpoint (PRD section 17.4); P0 API is otherwise
  read-only with respect to source and policy (PRD section 17.3).
- **Status:** Milestone 3 (server does not exist yet).

### T4 — Path traversal through evidence/file-line lookups

An evidence reference or exported location string could be crafted (or a
bug could construct one) to escape the scanned repository root when the
server resolves it back to a file on disk.

- **Mitigation:** confine file/line evidence lookups to the scanned root
  (PRD section 17.4); reject any resolved path outside it.
- **Status:** Milestone 3. This milestone's evidence schema
  (`evidence.location`) is a plain object with no path-resolution logic
  attached to it yet, so there is no traversal surface today — the
  requirement is recorded for when Milestone 3 adds a resolver.

### T5 — Oversized or cyclic graph input causes denial of service

A pathological repository (huge fan-out, generated code, adversarially
constructed cycles) could produce a graph whose validation, layout, or
path-reconstruction is superlinear or non-terminating.

- **Mitigation:** the graph-build phase bounds interprocedural contexts
  and alternate paths per source/sink pair with explicit truncation (PRD
  section 18.4, Milestone 1/2 scope); the server caps request size, graph
  query complexity, and path enumeration (PRD section 17.4, Milestone 3).
- **Status today:** `validateGraph` (Task 5, this milestone) is a single
  linear pass over `nodes`/`edges`/`dataElements`/`flows` with no
  recursion into cyclic structures — it cannot itself loop forever on a
  cyclic graph, because it never walks edges transitively, only checks
  that referenced ids exist. The performance harness (Task 11, this
  milestone) establishes the baseline timing for a synthetic 5,000
  node / 10,000 edge graph so a future regression is measurable, not
  just asserted safe.

### T6 — Secret values or unredacted source leak into an export or the URL

PRD section 24: keep source snippets out of URLs/browser history/
telemetry; default shared exports to short, redacted snippets.

- **Mitigation:** evidence `snippet` fields default to redacted/short;
  URL state carries only canonical IDs and non-sensitive filter
  expressions (PRD section 7.11); export defaults require explicit
  opt-in for unredacted evidence (PRD section 17.5).
- **Status:** this milestone's `evidence` contract (Task 5/6) makes
  `snippet` an optional, independently-settable field — the fixture
  builder (Task 7) never populates it, so today's only evidence consumer
  (tests) never observes an unredacted snippet. The redaction POLICY
  itself (what counts as "short," default-on vs. explicit opt-in) is
  Milestone 3/4 (export code).

### T7 — Fixture content leaks into or is mistaken for a real scan

Appendix D.1: fixture-backed screens/exports must be marked "Illustrative
demo data" and must never leak synthetic filenames, endpoints, commits,
authors, or governance metadata into a real repository scan; production
code must not special-case fixture names.

- **Mitigation:** `scope.source` is a generic, always-present envelope
  field (`'scan' | 'fixture'`) — Task 1 defaults it to `'scan'`, and only
  the fixture builder (Task 7) sets it to `'fixture'` explicitly. No
  module in `scanner/src/lineage/` checks a filename, node id, or commit
  hash to decide fixture-ness.
- **Status:** enforced today by construction (there is no name-based
  special case to regress) and pinned by
  `test/lineage/flagship-fixture.test.js`'s `scope.source` assertion
  (Task 7). Milestone 3's UI must read `scope.source`, not a name, to
  render the "Illustrative demo data" ribbon (AC-24).

### T8 — Manual overrides or scenario data launder as scanner evidence

PRD section 24 / risk table: a manual classification override or a
What-If scenario (Milestone 5) could be displayed indistinguishably from
code-derived evidence, producing false assurance.

- **Mitigation:** `dataElement.manualOverride` is a required boolean
  field in the contract (Task 1/5/6, this milestone) — a manual override
  can never be silently indistinguishable from taxonomy-derived
  classification at the schema level. Scenario/`HYPOTHETICAL` evidence
  grading is Milestone 5 scope (DFG-036) and is out of scope for this
  document until that milestone's plan is written, but the
  `protection.js` evidence-grade enum (Task 3) already reserves
  `'declared'` and `'manual'` as distinct grades from `'code'` /
  `'runtime'` — a future scenario evidence type has a place to land
  without overloading an existing grade.

## What this milestone does NOT yet threat-model

Everything that requires the server, browser client, or export pipeline
to exist: XSS rendering behavior (T1's actual DOM assertions), DNS
rebinding/CSRF/traversal defenses (T2–T4, no server exists), and export
redaction defaults (T6, no export pipeline exists). These are named
above specifically so the milestone that builds each capability starts
from a stated threat, not a blank page.
