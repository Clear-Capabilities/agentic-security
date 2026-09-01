import { test } from 'node:test';

// AC-22 / PRD §8.4's 11-state visual matrix. 3 states (Error, Selected,
// Hovered) have real, tested UI — see golden-state-matrix.test.js. The 8
// below have NO dedicated visual treatment anywhere in src/ or styles/
// today, confirmed by direct grep this sub-project's own scoping pass
// (docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-golden-scoping.md).
// Each entry names exactly what would need to exist before it's
// testable — visible in `npm test` output forever, not a doc that can
// go stale silently. Do NOT invent placeholder UI to make these pass —
// see the scoping doc's own "Do NOT touch" section.

test.todo('AC-22 Loading/scanning: needs a skeleton-topology + named-phase UI — no loading state exists in src/ today');
test.todo('AC-22 Partial: needs a persistent amber banner + hatched/badged affected regions — coverage.status is read but has no dedicated partial-scan visual treatment');
test.todo('AC-22 Truncated: needs a path/graph-budget notice on contributing nodes — no truncation UI exists');
test.todo('AC-22 Unsupported (persistent banner, distinct from Inventory\'s own unsupportedCandidates table row): needs a graph-level "candidate remains in inventory with unsupported reason" banner — only the Inventory table row exists today, not a standalone banner');
test.todo('AC-22 Unresolved destination (the specific dashed-edge/question-mark glyph treatment named in §8.4, distinct from the node itself rendering): the node renders today (confirmed), but the SPECIFIC dashed-edge/question-mark visual treatment is unconfirmed — verify at a future increment whether architecture-view.js already does this or needs it added');
test.todo('AC-22 Zero filtered results: needs an active-filter-explanation + reset-action empty state — filtering hides rows today (data-visible=false) but shows no explanatory empty state when ALL rows are hidden');
test.todo('AC-22 Error, phase 2 (retry/export-diagnostics action): main.js\'s real error UI shows a message but has no retry or export-diagnostics action — only the base "failed" state is real');
test.todo('AC-22 Stale artifact: needs a commit-mismatch + rescan-action banner with visibly timestamped old evidence — no staleness UI exists');
