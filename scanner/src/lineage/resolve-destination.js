//
// resolve-destination.js — Milestone 2, Sub-project A ("external destination
// resolver"), increment 1.
//
// Implements DESIGN_DESTINATION_RESOLVER.md's `destination` object shape and
// its two real resolution rules (literal, dynamic) — see that file for the
// full field contract and the explicit list of what is deferred to later
// increments (constant-folding, config-chain resolution, schema
// correlation, runtime corroboration, AI-provider/model resolution).
//
// Reuse boundary: this module adds NO new detection of its own. It composes
// three primitives `coverage.js` already shipped for FR-203 (Sub-project E,
// increment 4) — `detectUnresolvedDestination`, `renderExpr`, and the
// `FR203_ARG0_DESTINATION_CATEGORIES` eligibility set — rather than
// re-deriving a second, potentially-drifting notion of "is this call site's
// destination statically nameable". Importing `coverage.js` here and having
// `coverage.js` import `resolveDestination` back (Task 4, wiring this as
// `buildGraphWithCoverage`'s default `opts.resolveDestination`) makes the
// two files mutually dependent — a real ES module cycle, not an accident.
// It is safe here specifically because neither module's own top-level body
// ever READS a value imported from the other; every cross-module reference
// below is inside a function body, resolved only once `resolveDestination`
// is actually CALLED, by which point module evaluation (both files) has
// long finished. `detectUnresolvedDestination`/`renderExpr` are function
// declarations (hoisted with a real value before either file's top-level
// body runs at all); `FR203_ARG0_DESTINATION_CATEGORIES` is a `const`, only
// ever referenced inside `resolveDestination`'s own body, never at this
// file's top level.

import { detectUnresolvedDestination, renderExpr, FR203_ARG0_DESTINATION_CATEGORIES } from './coverage.js';

function isLiteral(e) {
  return Boolean(e) && typeof e === 'object' && e.kind === 'literal';
}

const UNKNOWN = Object.freeze({ resolutionStatus: 'unknown', raw: null, literalValue: null, blockingExpression: null });

/**
 * `resolveDestination(site)` — the `opts.resolveDestination` hook
 * `graph-builder.js` (Task 3) and `coverage.js`'s `buildGraphWithCoverage`
 * (Task 4) wire in. `site` is the same shape `detectUnresolvedDestination`/
 * `resolveSiteDecision` already consume: `site.calleeExpr`, `site.args`,
 * and (when available) `site.decision.category` — the registry category
 * `FR203_ARG0_DESTINATION_CATEGORIES` gates against. Never throws, even on
 * a malformed/missing `site` (mirrors `detectUnresolvedDestination`'s own
 * defensiveness).
 *
 * Exactly three outcomes (DESIGN_DESTINATION_RESOLVER.md §2):
 *
 * 1. `'literal'` — the destination-bearing argument (arg0, but ONLY when
 *    `site.decision.category` is one of `FR203_ARG0_DESTINATION_CATEGORIES`
 *    — everywhere else arg0 is a PAYLOAD, not a destination, exactly the
 *    distinction MUST-FIX 1 already drew for FR-203) or the call's receiver
 *    (a member callee's `object`) is a `literal`-kind expression.
 * 2. `'dynamic'` — anything `detectUnresolvedDestination(site)` already
 *    flags as unresolvable, respecting the SAME arg0 category gate: a
 *    `via: 'arg0'` result only counts when the category is eligible, or it
 *    would reintroduce the exact false-positive MUST-FIX 1 fixed (a
 *    non-literal SQL/HTML payload argument on a database/client-storage
 *    call site is not a "dynamic destination", it's an ordinary payload).
 *    A `via: 'receiver'` result always counts — the receiver signal has no
 *    narrower gate in FR-203 either.
 * 3. `'unknown'` — everything else: a plain identifier or plain member
 *    chain FR-203 itself doesn't flag, or a non-eligible-category literal
 *    argument. Deliberately the same answer Milestone 1 always gave.
 */
export function resolveDestination(site) {
  if (!site || typeof site !== 'object') return UNKNOWN;

  const category = site.decision && typeof site.decision === 'object' ? site.decision.category : null;
  const argEligible = typeof category === 'string' && FR203_ARG0_DESTINATION_CATEGORIES.includes(category);

  const args = Array.isArray(site.args) ? site.args : [];
  const arg0 = args[0];
  if (argEligible && isLiteral(arg0)) {
    return { resolutionStatus: 'literal', raw: renderExpr(arg0), literalValue: String(arg0.value), blockingExpression: null };
  }

  const callee = site.calleeExpr;
  const receiver = callee && typeof callee === 'object' && callee.kind === 'member' ? callee.object : null;
  if (isLiteral(receiver)) {
    return { resolutionStatus: 'literal', raw: renderExpr(receiver), literalValue: String(receiver.value), blockingExpression: null };
  }

  const unresolved = detectUnresolvedDestination(site);
  if (unresolved && (unresolved.via !== 'arg0' || argEligible)) {
    return { resolutionStatus: 'dynamic', raw: unresolved.blockingExpression, literalValue: null, blockingExpression: unresolved.blockingExpression };
  }

  return UNKNOWN;
}
