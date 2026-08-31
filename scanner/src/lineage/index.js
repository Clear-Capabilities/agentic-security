//
// index.js — Sub-project E, increment 5 (E5). The scan-facing entry point
// for the Data Flow Explorer lineage engine. This is the ONLY file under
// src/lineage/ that engine.js/bin/agentic-security.js import — every other
// module in this package stays isolated per its own established reuse
// boundary (see src/lineage/CLAUDE.md's header).
//
// Mirrors runFullScan's own `_deepEnabled` block's CONTRACT (opt-in,
// best-effort, every outcome returned as a structured status a caller folds
// into scanHealth) — NOT `dataflow/index.js`'s `AGENTIC_SECURITY_PRIVACY_DEEP`
// block, whose bare `catch {}` silently swallows failure with no scanHealth
// signal at all (measured and disclosed in
// docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-e5-scoping.md
// §1 — DESIGN_GRAPH_BUILDER.md §9.5 item 1's own wording describes the
// LATTER mechanism, not the former, despite naming the former by name).
//
// Unlike privacy-taint, lineage analysis has NO degraded/non-IR-backed mode:
// `buildGraphWithCoverage(callGraph, opts)` requires a real callGraph with
// real CFGs, and there is nothing meaningful to fall back to. A missing or
// malformed callGraph is reported as `not_available`, never attempted as a
// degraded run.

import { buildGraphWithCoverage } from './coverage.js';

/**
 * @param {{functions: Map}} callGraph a real callGraph — the same shape
 *   `buildProjectIR`/`buildProjectIRAsync` produce (`_sharedIR.callGraph`
 *   in `runFullScan`).
 * @param {object} [opts]
 * @param {string} [opts.repository] threaded straight to `buildGraphWithCoverage`.
 * @param {boolean} [opts.deterministic] when true, `generatedAt` is left
 *   `undefined` so `buildDataFlowGraph`'s own fixed-literal default applies
 *   — the literal itself lives in exactly one place, `graph-builder.js`.
 * @param {Record<string,object>} [opts.perFile] threaded to the coverage
 *   ledger's `languages[]` computation.
 * @param {Array<object>} [opts.parseFailures] threaded to the coverage
 *   ledger's `parseFailures`/`languages[].filesExpected` computation.
 * @returns {{status: 'not_available'|'complete'|'failed', graph: object|null, failure: string|null, elapsedMs: number}}
 *   `status` is never `'not_requested'` — that decision belongs to the
 *   CALLER (whether to call this function at all), not to this function's
 *   own return value.
 */
export function buildLineageGraph(callGraph, opts = {}) {
  const t0 = Date.now();
  if (!callGraph || typeof callGraph.functions?.values !== 'function') {
    return { status: 'not_available', graph: null, failure: null, elapsedMs: Date.now() - t0 };
  }
  try {
    const built = buildGraphWithCoverage(callGraph, {
      repository: opts.repository,
      generatedAt: opts.deterministic ? undefined : new Date().toISOString(),
      perFile: opts.perFile,
      parseFailures: opts.parseFailures,
    });
    return { status: 'complete', graph: built.graph, failure: null, elapsedMs: Date.now() - t0 };
  } catch (e) {
    // Best-effort (DESIGN_GRAPH_BUILDER.md §9.5 item 1): recorded, never
    // swallowed. The caller (runFullScan) folds `failure` into scanHealth.
    return { status: 'failed', graph: null, failure: String((e && e.message) || e), elapsedMs: Date.now() - t0 };
  }
}
