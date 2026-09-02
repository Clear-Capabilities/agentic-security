// drift-policy.js — M4 deliverable #8, sub-project 8b, Task 2: a
// before/after drift-policy DSL evaluated against a GraphDiff (Task 1's
// own output, see graph-diff.js).
//
// Mirrors dataflow/privacy-sink-policy.js's fail-closed axis-matching
// STYLE exactly — the `_matchesEnvironment`/`_matchesDestination`
// precedent (an unset rule field is unconstrained; a set field the
// current context has no comparable value for does NOT match) — never
// its literal single-graph-state shape. That module evaluates a static
// state ("is this (class, sink) pair permitted right now"); this module
// evaluates a TRANSITION ("did this (class, sink) pair newly start
// flowing, or did this flow's own verdict regress"), which is why its
// rule shape is `{trigger, ...}`-keyed rather than `{allow: [...]}`.
//
// ── Design judgment calls made in this file (disclosed, not hidden) ──
//
// 1. `loadDriftPolicies(policyFilePath)` takes a literal file path, not
//    a scanRoot — a deliberate, task-brief-directed divergence from
//    `loadPrivacySinkPolicy(scanRoot)`'s own scanRoot-relative
//    convention (`statePath(scanRoot, 'privacy-policy.json')`). Drift
//    policies are a new artifact with no established scanRoot-relative
//    home yet (Task 3's CLI wiring is the only real caller, and it can
//    resolve whatever path convention it wants — e.g. a `--policy`
//    flag, or a default under `.agentic-security/` — without this
//    module forcing that choice). Keeping the signature a plain path
//    keeps this module honest about being a pure evaluator with no
//    opinion on where its config file lives.
//
// 2. The rule vocabulary generalizes `fromPolicyVerdict`/
//    `toPolicyVerdict` to a second, structurally identical pair,
//    `fromProtectionSummary`/`toProtectionSummary`, rather than adding a
//    generic `field`/`from`/`to` triple. The task brief's own worked
//    examples name `protectionSummary`'s "protected -> unknown/
//    unprotected" transition as "an equivalent from/to pair for
//    protectionSummary, generalizing" the policyVerdict pair — read
//    literally, that is an instruction to add the SAME shape for a
//    second watched field, not to invent a fully generic DSL over every
//    WATCHED_FLOW_FIELDS entry. A generic `field`/`from`/`to` triple was
//    considered and rejected: nothing in the brief's worked examples
//    needs a THIRD field's transition, and a generic form would need its
//    own validation against `WATCHED_FLOW_FIELDS` this task's tests
//    don't exercise. Extending to a fully generic form remains easy
//    later (both matchers already share one small helper,
//    `_matchesVerdictTransition`) without a rule-shape migration for
//    what's shipped today.
//
// 3. `dataClass`/`sinkCategory` are read as ADDITIONAL, optional
//    constraints on a `changed_flow` rule too, not just `new_flow`
//    rules — the brief's own rule shape lists them as top-level fields
//    (not scoped textually to `new_flow` alone), and a changed flow's
//    id is guaranteed present in `graphAfter` by construction (a
//    `changed.flows` entry only exists when the SAME flow id survived
//    into the after-graph — see graph-diff.js's own `computeGraphDiff`
//    header), so the same `_resolveFlowContext` resolution that
//    `new_flow` rules use applies unchanged. This lets an operator write
//    "a PHI flow that regresses from protected" as one rule instead of
//    two, and costs nothing when a rule doesn't set either field (both
//    stay unconstrained, per the fail-closed style above).
//
// 4. A `changed_flow` rule that sets none of
//    dataClass/sinkCategory/fromPolicyVerdict/toPolicyVerdict/
//    fromProtectionSummary/toProtectionSummary matches EVERY
//    `changed.flows` entry — every axis is independently unconstrained,
//    so a rule with no axes set is the fully unconstrained case, exactly
//    as an `allow` rule with neither `class` nor `sink` would be in
//    `privacy-sink-policy.js` (it doesn't have that case in practice
//    because `sink` is required there; this module has no required axis
//    besides `trigger`, so the maximally-open rule is reachable and
//    intentional — "alert on ANY change to a flow matching these
//    constraints" is a real, useful policy shape).
//
// 5. The task brief's PRD-quoted worked examples also name "PII -> AI"
//    ,"PCI -> log" (both plain `new_flow` shapes, already covered by
//    dataClass/sinkCategory matching — no separate mechanism needed) and
//    "new unresolved recipient" (a `governanceRefs.recipient`-shaped
//    transition). The brief's own "Tests to write" section does not
//    require a test for the recipient example, and it does not reduce
//    cleanly to either matcher this task implements (a "new unresolved
//    recipient" is a value becoming a specific sentinel, not a flow
//    newly existing or an already-modeled verdict field transitioning)
//    — left out rather than guessed at. Judgment call #2's rejected
//    generic `field`/`from`/`to` form is the natural place to add it
//    later, against a real governanceRefs.recipient fixture.
//
// 6. Fix round 1, Important 1 (see graph-diff.js's own judgment call #4):
//    a `new_flow` rule must skip an added flow entry whose
//    `causeClassification === 'reidentified'` — that flow isn't actually
//    new, it's the SAME real-world (source, sink, dataElementIds) flow as
//    a flow that existed before, just minted under a new flowId because
//    the engine's own confidence/shape (evidenceGrade/transformationIds)
//    changed. Firing `new_flow` on it would false-fire `--fail-on-drift`
//    on a non-event, exactly what this fix round exists to close.

import * as fs from 'node:fs';

const POLICY_TRIGGERS = Object.freeze(['new_flow', 'changed_flow']);

function _isValidRuleShape(p) {
  return !!p && typeof p === 'object' && !Array.isArray(p) && POLICY_TRIGGERS.includes(p.trigger);
}

/**
 * Load an operator's drift-policy rules from a literal JSON file path
 * (see judgment call #1 above — never a scanRoot). Never throws — a
 * missing file (ENOENT) is "no policies configured," matching
 * `loadPrivacySinkPolicy`'s own precedent; a malformed file logs a
 * warning and degrades to no policies. Each entry is validated loosely:
 * an entry that isn't a plain object with a recognized `trigger` is
 * skipped (with a warning naming how many were dropped), never crashing
 * the whole load over one bad rule.
 */
export function loadDriftPolicies(policyFilePath) {
  const EMPTY = { policies: [] };
  if (!policyFilePath) return EMPTY;

  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(policyFilePath, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`agentic-security: bad JSON in drift policy file (${policyFilePath}) — falling back to no policies (${e.message})`);
    }
    return EMPTY;
  }

  if (!Array.isArray(raw?.policies)) {
    console.error(`agentic-security: drift policy file ${policyFilePath} has no "policies" array — falling back to no policies (expected {"policies":[...]})`);
  }
  const rawPolicies = Array.isArray(raw?.policies) ? raw.policies : [];
  const policies = rawPolicies.filter(_isValidRuleShape);
  const skipped = rawPolicies.length - policies.length;
  if (skipped > 0) {
    console.error(`agentic-security: skipped ${skipped} malformed drift-policy rule(s) in ${policyFilePath} (each must be an object with trigger: 'new_flow' | 'changed_flow')`);
  }
  return { policies };
}

// Fail-closed, matching privacy-sink-policy.js's own
// _matchesEnvironment/_matchesDestination precedent exactly: an unset
// rule value is unconstrained (matches anything); a set rule value with
// no comparable current value does NOT match.
function _matchesDataClass(ruleDataClass, dataClasses) {
  if (ruleDataClass == null) return true;
  if (!Array.isArray(dataClasses) || !dataClasses.length) return false;
  return dataClasses.includes(ruleDataClass);
}

function _matchesSinkCategory(ruleSinkCategory, sinkCategory) {
  if (ruleSinkCategory == null) return true;
  if (!sinkCategory) return false;
  return ruleSinkCategory === sinkCategory;
}

// Matches a rule's {fromX, toX} pair against the {before, after} of the
// changes[] entry for field X (or undefined, when that field didn't
// change on this flow). Unset fromX/toX is unconstrained. A set fromX/
// toX with no changes[] entry for that field at all (the flow changed,
// but not on this axis) does NOT match — fails closed, same as an
// environment-scoped rule against a caller who supplied no environment.
function _matchesVerdictTransition(ruleFrom, ruleTo, changeEntry) {
  if (ruleFrom == null && ruleTo == null) return true;
  if (!changeEntry) return false;
  if (ruleFrom != null && changeEntry.before !== ruleFrom) return false;
  if (ruleTo != null && changeEntry.after !== ruleTo) return false;
  return true;
}

// Resolves the real dataClasses/sinkCategory/sinkNode/flow for a flow id
// against graphAfter — shared by both new_flow (added.flows entries) and
// changed_flow (changed.flows entries) matching, since a changed.flows
// entry's id is, by construction, present in graphAfter too (see
// graph-diff.js's own computeGraphDiff: a changed entry only exists for
// a flow id surviving into the after-graph). Returns null when the id
// can't be resolved (should not happen for a well-formed GraphDiff
// produced by computeGraphDiff against its own graphAfter, but a rule
// must never crash the whole evaluation over a caller-supplied
// diff/graph pairing that doesn't actually match).
function _resolveFlowContext(flowId, graphAfter) {
  const flow = (graphAfter?.flows ?? []).find((f) => f.id === flowId);
  if (!flow) return null;

  const dataClasses = [];
  const seen = new Set();
  for (const deId of flow.dataElementIds ?? []) {
    const de = (graphAfter.dataElements ?? []).find((d) => d.id === deId);
    if (!de) continue;
    for (const cls of de.dataClasses ?? []) {
      if (!seen.has(cls)) { seen.add(cls); dataClasses.push(cls); }
    }
  }
  const dataElementNames = (flow.dataElementIds ?? [])
    .map((id) => (graphAfter.dataElements ?? []).find((d) => d.id === id)?.name)
    .filter((n) => typeof n === 'string' && n.length > 0);

  const sinkNode = (graphAfter.nodes ?? []).find((n) => n.id === flow.sink) ?? null;
  const sinkCategory = sinkNode?.subtype ?? sinkNode?.kind ?? null;

  return { flow, dataClasses, dataElementNames, sinkNode, sinkCategory };
}

function _describeTransition(changeEntry) {
  if (!changeEntry) return null;
  return `${changeEntry.field} ${changeEntry.before} -> ${changeEntry.after}`;
}

function _buildViolation(rule, trigger, ctx, transitionDescriptions) {
  const base = trigger === 'new_flow'
    ? `New flow ${ctx.flow.id} (${ctx.dataClasses.join('/') || 'unclassified data'}) newly reaches sink ${ctx.sinkCategory ?? ctx.sinkNode?.id ?? 'unknown'}`
    : `Flow ${ctx.flow.id} changed: ${transitionDescriptions.length ? transitionDescriptions.join(', ') : 'matched changed_flow rule (no policyVerdict/protectionSummary transition named by this rule)'}`;
  const reason = rule.reason ? `${base} (${rule.reason})` : base;

  return {
    flowId: ctx.flow.id,
    dataElementNames: ctx.dataElementNames,
    sinkCategory: ctx.sinkCategory,
    sinkNodeId: ctx.sinkNode?.id ?? ctx.flow.sink,
    trigger,
    rule,
    reason,
  };
}

/**
 * Evaluates operator-configured drift policies against a GraphDiff.
 * `policies` is `{policies: [...]}` (loadDriftPolicies' own return
 * shape). `graphAfter` is the AFTER graph the diff was computed against
 * — needed because an `added.flows`/`changed.flows` entry carries only
 * `{id, causeClassification, ...}` (see graph-diff.js's own header),
 * never dataElement/sink info directly.
 *
 * Returns `{violations: [...]}` — never a bare boolean per flow; every
 * violation names the real triggering flow (id, data element names,
 * sink), the rule that fired, and a human-readable `reason` string.
 */
export function evaluateDriftPolicies(diff, policies, graphAfter) {
  const violations = [];
  const rules = Array.isArray(policies?.policies) ? policies.policies : [];
  if (!rules.length) return { violations };

  for (const rule of rules) {
    if (rule.trigger === 'new_flow') {
      for (const addedEntry of diff?.added?.flows ?? []) {
        // See judgment call #6 above / graph-diff.js's own judgment call
        // #4: a reidentified added flow is not actually new.
        if (addedEntry.causeClassification === 'reidentified') continue;
        const ctx = _resolveFlowContext(addedEntry.id, graphAfter);
        if (!ctx) continue;
        if (!_matchesDataClass(rule.dataClass, ctx.dataClasses)) continue;
        if (!_matchesSinkCategory(rule.sinkCategory, ctx.sinkCategory)) continue;
        violations.push(_buildViolation(rule, 'new_flow', ctx, []));
      }
    } else if (rule.trigger === 'changed_flow') {
      for (const changedEntry of diff?.changed?.flows ?? []) {
        const ctx = _resolveFlowContext(changedEntry.id, graphAfter);
        if (!ctx) continue;
        if (!_matchesDataClass(rule.dataClass, ctx.dataClasses)) continue;
        if (!_matchesSinkCategory(rule.sinkCategory, ctx.sinkCategory)) continue;

        const changes = Array.isArray(changedEntry.changes) ? changedEntry.changes : [];
        const policyChange = changes.find((c) => c.field === 'policyVerdict');
        if (!_matchesVerdictTransition(rule.fromPolicyVerdict, rule.toPolicyVerdict, policyChange)) continue;

        const protectionChange = changes.find((c) => c.field === 'protectionSummary');
        if (!_matchesVerdictTransition(rule.fromProtectionSummary, rule.toProtectionSummary, protectionChange)) continue;

        const transitionDescriptions = [policyChange, protectionChange].map(_describeTransition).filter(Boolean);
        violations.push(_buildViolation(rule, 'changed_flow', ctx, transitionDescriptions));
      }
    }
    // An unrecognized trigger was already filtered out by
    // loadDriftPolicies' own _isValidRuleShape when loaded from disk; a
    // directly hand-built `policies` object (as tests do) with an
    // unrecognized trigger simply matches nothing, silently — the same
    // "match nothing rather than throw" discipline as every other
    // unresolvable axis in this file.
  }

  return { violations };
}
