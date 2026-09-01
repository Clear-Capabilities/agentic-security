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

import * as fs from 'node:fs';
import { buildGraphWithCoverage } from './coverage.js';
import { scanTransitEvidence } from './transit-protection.js';
// Milestone 2, Sub-project G, increment 1 (FR-408/AC-09): loaded ONCE, here
// — mirroring `scanTransitEvidence`'s own single-computation discipline one
// line above — never re-loaded at a lower layer (`coverage.js`/
// `graph-builder.js` both only ever consume the already-loaded object).
import { loadPrivacySinkPolicy } from '../dataflow/privacy-sink-policy.js';
import { statePath } from '../posture/state-dir.js';

/**
 * @param {{functions: Map}} callGraph a real callGraph — the same shape
 *   `buildProjectIR`/`buildProjectIRAsync` produce (`_sharedIR.callGraph`
 *   in `runFullScan`).
 * @param {object} [opts]
 * @param {string} [opts.repository] threaded straight to `buildGraphWithCoverage`.
 * @param {string} [opts.scanRoot] the real scan root path — distinct from
 *   `opts.repository`, which by the time it reaches this function is only a
 *   basename (see `engine.js`'s own call site). Used ONLY to load the
 *   operator's privacy sink policy (Milestone 2, Sub-project G, increment
 *   1, FR-408/AC-09) — never threaded to `buildGraphWithCoverage` itself,
 *   which never reads the filesystem. See the function body for why
 *   existence is checked explicitly rather than inferred from
 *   `loadPrivacySinkPolicy`'s own return value.
 * @param {string} [opts.environment] optional deployment-environment
 *   override for policy evaluation's environment-scoped rules; threaded to
 *   `buildGraphWithCoverage`'s `opts.environment`, which falls back to
 *   `AGENTIC_SECURITY_ENVIRONMENT` at the point the verdict is computed
 *   (`graph-builder.js`), mirroring `dataflow/privacy-taint.js`'s own
 *   precedent.
 * @param {boolean} [opts.deterministic] when true, `generatedAt` is left
 *   `undefined` so `buildDataFlowGraph`'s own fixed-literal default applies
 *   — the literal itself lives in exactly one place, `graph-builder.js`.
 * @param {Record<string,object>} [opts.perFile] threaded to the coverage
 *   ledger's `languages[]` computation.
 * @param {Array<object>} [opts.parseFailures] threaded to the coverage
 *   ledger's `parseFailures`/`languages[].filesExpected` computation.
 * @param {Record<string,string>} [opts.fileContents] `{path: rawSourceString}`
 *   — threaded to `transit-protection.js`'s `scanTransitEvidence` (Milestone 2,
 *   Sub-project B, increment 1). As of increment 2, `scanTransitEvidence` is
 *   called EXACTLY ONCE, here, per `buildLineageGraph` call — its result
 *   (a `Map<file, findings[]>`) feeds BOTH the returned `transitEvidence`
 *   field below AND `buildGraphWithCoverage`'s own `opts.transitEvidenceByFile`
 *   (the same `Map` reference, never recomputed), which is what actually
 *   drives `edge.protection.transit` verdicts inside `graph-builder.js`. See
 *   `DESIGN_TRANSIT_PROTECTION.md` §6 for why this single-computation
 *   discipline is load-bearing (a second call inside `coverage.js`'s own
 *   default hook would double-scan every file). `graph` is NOT
 *   byte-identical to omitting `opts.fileContents` anymore — a network
 *   sink's `edge.protection.transit` can now genuinely change with the
 *   evidence supplied.
 * @returns {{status: 'not_available'|'complete'|'failed', graph: object|null, transitEvidence: Map<string,object[]>, failure: string|null, elapsedMs: number}}
 *   `status` is never `'not_requested'` — that decision belongs to the
 *   CALLER (whether to call this function at all), not to this function's
 *   own return value. `transitEvidence` is a `Map<file, findings[]>` — see
 *   `DESIGN_TRANSIT_PROTECTION.md` §3 for why a `Map`, not a plain object.
 *   It is a real, populated result of running `scanCryptoProtocol` over
 *   `opts.fileContents` (empty when omitted). As of increment 2, this same
 *   `Map` IS also joined to specific graph edges — via
 *   `buildGraphWithCoverage`'s `opts.transitEvidenceByFile`, consulted by
 *   `resolveTransitProtectionForSite` for `external-api` sink sites — but
 *   this returned field itself stays the raw, ungrouped `Map<file,
 *   findings[]>`, not a per-edge join result.
 */
export function buildLineageGraph(callGraph, opts = {}) {
  const t0 = Date.now();
  if (!callGraph || typeof callGraph.functions?.values !== 'function') {
    return { status: 'not_available', graph: null, transitEvidence: new Map(), failure: null, elapsedMs: Date.now() - t0 };
  }
  try {
    // Milestone 2, Sub-project B, increment 2 (DESIGN_TRANSIT_PROTECTION.md
    // §6, item 4): `scanTransitEvidence` runs EXACTLY ONCE per
    // `buildLineageGraph` call, here — the same `Map` reference feeds both
    // this function's own `transitEvidence` return field AND
    // `buildGraphWithCoverage`'s `opts.transitEvidenceByFile`, which is what
    // `coverage.js`'s default `resolveTransitProtection` hook actually
    // consults. `coverage.js` never calls `scanTransitEvidence`/
    // `scanCryptoProtocol` itself — it only reads this pre-computed Map —
    // so no file is ever scanned twice.
    const transitEvidence = scanTransitEvidence(opts.fileContents ?? {});
    // Milestone 2, Sub-project G, increment 1 (FR-408/AC-09): load the
    // operator's privacy sink policy exactly once, here. Existence is
    // checked EXPLICITLY (never inferred from `loadPrivacySinkPolicy`'s own
    // return value alone) because that function deliberately returns the
    // SAME empty `{allow: []}` shape whether the policy file is missing,
    // malformed, or genuinely present with an empty `allow` array —
    // collapsing three states `graph-builder.js`'s own policy-verdict logic
    // needs to keep apart. A MISSING policy must read
    // `flow.policyVerdict: 'not_evaluated'` (nothing was actually
    // evaluated — privacy-sink-policy.js's own header: "nothing changes for
    // a repo with no policy file"); a PRESENT-but-empty policy (an
    // operator's deliberate "nothing is permitted yet" `{"allow": []}`)
    // must read `'prohibited'` — the deny-by-default stance that same
    // header establishes once a policy is genuinely in play.
    // `privacySinkPolicy` therefore stays `undefined` (never coerced to
    // `{allow: []}`) unless the file genuinely exists on disk — this is
    // what lets `graph-builder.js`'s `opts.privacySinkPolicy != null` gate
    // make that distinction at all.
    const _policyFile = opts.scanRoot ? statePath(opts.scanRoot, 'privacy-policy.json') : null;
    const privacySinkPolicy = _policyFile && fs.existsSync(_policyFile)
      ? loadPrivacySinkPolicy(opts.scanRoot)
      : undefined;
    const built = buildGraphWithCoverage(callGraph, {
      repository: opts.repository,
      generatedAt: opts.deterministic ? undefined : new Date().toISOString(),
      perFile: opts.perFile,
      parseFailures: opts.parseFailures,
      transitEvidenceByFile: transitEvidence,
      privacySinkPolicy,
      environment: opts.environment,
    });
    return { status: 'complete', graph: built.graph, transitEvidence, failure: null, elapsedMs: Date.now() - t0 };
  } catch (e) {
    // Best-effort (DESIGN_GRAPH_BUILDER.md §9.5 item 1): recorded, never
    // swallowed. The caller (runFullScan) folds `failure` into scanHealth.
    return { status: 'failed', graph: null, transitEvidence: new Map(), failure: String((e && e.message) || e), elapsedMs: Date.now() - t0 };
  }
}
