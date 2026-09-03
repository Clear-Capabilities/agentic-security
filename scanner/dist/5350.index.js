export const id = 5350;
export const ids = [5350];
export const modules = {

/***/ 5350:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  AUDIENCE_MODES: () => (/* binding */ AUDIENCE_MODES),
  emitDecisionStory: () => (/* binding */ emitDecisionStory)
});

// EXTERNAL MODULE: ./src/dataflow/privacy-taxonomy.js
var privacy_taxonomy = __webpack_require__(7451);
;// CONCATENATED MODULE: ./src/lineage/decision-story.js
// decision-story.js — M4 deliverable #7 (FR-501 §14, DFG-035): the
// DecisionStory extension contract (§10.10) + a transparent 9-factor
// ranking engine over real flows.
//
// Mirrors obligation-mapping.js's own shape exactly: a record is
// explicitly NOT a DataFlowGraph v1 entity (§10.10 — "associated with,
// but not required inside, the immutable base graph"), never added to
// dataflow-graph.schema.json, never routed through validate.js.
//
// Ranking-factor availability, grounded in real investigation (see this
// sub-project's own scoping doc): 7 of 9 factors are direct reads off
// the graph, 1 (breadth) is a small new aggregation defined here, and 2
// (recipientJurisdiction, changeRecency) are honestly `available: false`
// on every flow — never fabricated, never silently dropped from the
// factor list. recipientJurisdiction needs a RecipientProfile extension
// (capability #6, not yet built); changeRecency needs GraphSnapshot/
// GraphDiff (capability #3, Data-Flow Time Machine, not yet built).
//
// PRD's own binding constraint: "never represents an uncalibrated score
// as expected financial loss or breach probability." This module NEVER
// blends factors into a single opaque float — rankFlows performs a
// documented, transparent, CONFIGURABLE (opts.factorOrder) multi-key
// sort over each factor's own ordinal tier. Every factor stays
// individually inspectable on the returned record.



// The sink-registry categories (sink-registry.js's own CATEGORY_NODE_KIND
// vocabulary) that count as an AI destination for the aiUse factor.
// Exported so export-briefing.js's own "AI providers" chapter-3 listing
// reads the SAME vocabulary rather than keeping a second, independently
// drifting copy (Task 2 review finding, fixed).
const AI_SINK_SUBTYPES = Object.freeze(['ai-model-provider', 'ai-agent', 'ai-tool']);

const RANKING_FACTORS = Object.freeze([
  'sensitivity', 'externality', 'controlVerdict', 'recipientJurisdiction',
  'aiUse', 'breadth', 'evidenceConfidence', 'policyState', 'changeRecency',
]);

// Ordinal tier ranks, worst-first, used both to score a flow's own
// factor and to compare two flows during rankFlows's own sort. Every
// factor uses a SMALL, real, disclosed vocabulary — never a blended
// number.
const _TIER_RANK = {
  sensitivity: { critical: 4, high: 3, medium: 2, low: 1, none: 0 },
  externality: { external: 2, unknown: 1, internal: 0 },
  controlVerdict: { unprotected: 4, mixed: 3, unknown: 2, not_assessed: 1, protected: 0, not_applicable: 0 },
  recipientJurisdiction: { unknown: 0 },
  aiUse: { ai_destination: 1, none: 0 },
  breadth: { high: 2, medium: 1, low: 0 },
  // Lower confidence is MORE attention-worthy (an uncertain flow needs
  // review), so the tier rank is inverted relative to the raw score —
  // disclosed here, not left implicit.
  evidenceConfidence: { low: 2, medium: 1, high: 0 },
  policyState: { prohibited: 4, manual_review_required: 3, conditionally_permitted: 2, not_evaluated: 1, permitted: 0 },
  changeRecency: { unknown: 0 },
};

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isArray(v) { return Array.isArray(v); }

/**
 * Structural validation only — mirrors
 * obligation-mapping.js#validateObligationMapping's own {valid, errors}
 * shape and "never throws" contract.
 */
function validateDecisionStory(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'DecisionStory record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('story:')) {
    err('$.id', 'id is required and must start with "story:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.audienceMode)) err('$.audienceMode', 'audienceMode is required');
  if (!_isPlainObject(record.scopeQuery)) err('$.scopeQuery', 'scopeQuery is required and must be an object');
  if (!_isArray(record.chapters)) err('$.chapters', 'chapters must be an array');
  if (!_isArray(record.contributingGraphIds)) err('$.contributingGraphIds', 'contributingGraphIds must be an array');
  if (!_isArray(record.rankingFactors)) err('$.rankingFactors', 'rankingFactors must be an array');
  if (!_isNonEmptyString(record.evidenceGrade)) err('$.evidenceGrade', 'evidenceGrade is required');
  if (!_isPlainObject(record.coverage)) err('$.coverage', 'coverage is required and must be an object');
  if (!_isArray(record.decisions)) err('$.decisions', 'decisions must be an array');
  if (!_isNonEmptyString(record.generatedAt)) err('$.generatedAt', 'generatedAt is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');

  return { valid: errors.length === 0, errors };
}

function _sensitivityFactor(flow, graph) {
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const classes = de?.dataClasses ?? [];
  if (classes.length === 0) return { available: true, tier: 'none', evidence: [] };
  let worst = 'low';
  for (const cls of classes) {
    const sev = privacy_taxonomy/* DEFAULT_TAXONOMY */.Qb[cls]?.severity ?? 'medium';
    if ((privacy_taxonomy/* SEVERITY_RANK */.f3[sev] ?? 0) > (privacy_taxonomy/* SEVERITY_RANK */.f3[worst] ?? 0)) worst = sev;
  }
  return { available: true, tier: worst, evidence: [de.id] };
}

function _externalityFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const value = sink?.externality?.value ?? 'unknown';
  return { available: true, tier: value, evidence: [flow.sink] };
}

function _controlVerdictFactor(flow) {
  return { available: true, tier: flow.protectionSummary ?? 'not_assessed', evidence: flow.edgeIds ?? [] };
}

function _recipientJurisdictionFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'RecipientProfile extension not yet built (capability #6, Third-Party/Cross-Border Intelligence)' };
}

function _aiUseFactor(flow, nodesById) {
  const sink = nodesById.get(flow.sink);
  const isAi = AI_SINK_SUBTYPES.includes(sink?.subtype);
  return { available: true, tier: isAi ? 'ai_destination' : 'none', evidence: isAi ? [flow.sink] : [] };
}

/**
 * New small aggregation (the scoping doc's own "smallest real addition"
 * for breadth/blast-radius): how many OTHER flows in the same graph
 * share this flow's own sink node or dataElement. A crude but real,
 * non-fabricated proxy for "how widely does this exposure reach" —
 * never presented as a calibrated blast-radius count, just an ordinal
 * tier over a real, disclosed count.
 */
function _breadthFactor(flow, graph) {
  let sharedCount = 0;
  for (const other of graph.flows) {
    if (other.id === flow.id) continue;
    const sharesSink = other.sink === flow.sink;
    const sharesData = other.dataElementIds.some((id) => flow.dataElementIds.includes(id));
    if (sharesSink || sharesData) sharedCount++;
  }
  const tier = sharedCount >= 5 ? 'high' : sharedCount >= 1 ? 'medium' : 'low';
  return { available: true, tier, evidence: [], sharedFlowCount: sharedCount };
}

function _evidenceConfidenceFactor(flow) {
  const tier = flow.confidence?.tier ?? 'medium';
  return { available: true, tier, evidence: [] };
}

function _policyStateFactor(flow) {
  return { available: true, tier: flow.policyVerdict ?? 'not_evaluated', evidence: flow.evidenceRefs ?? [] };
}

function _changeRecencyFactor() {
  // Honest gap — see this file's own header. Never fabricated.
  return { available: false, tier: 'unknown', evidence: [], unavailableReason: 'GraphSnapshot/GraphDiff not yet built (capability #3, Data-Flow Time Machine)' };
}

/** Score ONE flow on all 9 factors. Never throws on a well-formed graph. */
function scoreFlow(flow, graph, nodesById) {
  return {
    flowId: flow.id,
    factors: {
      sensitivity: _sensitivityFactor(flow, graph),
      externality: _externalityFactor(flow, nodesById),
      controlVerdict: _controlVerdictFactor(flow),
      recipientJurisdiction: _recipientJurisdictionFactor(),
      aiUse: _aiUseFactor(flow, nodesById),
      breadth: _breadthFactor(flow, graph),
      evidenceConfidence: _evidenceConfidenceFactor(flow),
      policyState: _policyStateFactor(flow),
      changeRecency: _changeRecencyFactor(),
    },
  };
}

/**
 * Score and rank every flow in the graph. opts.factorOrder (default
 * RANKING_FACTORS) is the PRD's own "transparent configurable factors"
 * requirement, made real: a lexicographic multi-key sort over each
 * factor's own ordinal tier rank, in the given priority order — NEVER a
 * blended single score. Ties within all factors preserve original flow
 * order (stable sort).
 */
function rankFlows(graph, opts = {}) {
  const factorOrder = opts.factorOrder ?? RANKING_FACTORS;
  const nodesById = new Map(graph.nodes.map((n) => [n.id, n]));
  const scored = graph.flows.map((flow) => ({
    flow,
    ...scoreFlow(flow, graph, nodesById),
    factorOrderUsed: factorOrder,
  }));
  const rankOf = (scoredFlow, factor) => {
    const f = scoredFlow.factors[factor];
    return _TIER_RANK[factor]?.[f.tier] ?? 0;
  };
  return scored.sort((a, b) => {
    for (const factor of factorOrder) {
      const diff = rankOf(b, factor) - rankOf(a, factor);
      if (diff !== 0) return diff;
    }
    return 0;
  });
}

// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(859);
// EXTERNAL MODULE: ./src/lineage/ids.js
var ids = __webpack_require__(5034);
// EXTERNAL MODULE: ./src/lineage/protection.js
var protection = __webpack_require__(965);
// EXTERNAL MODULE: ./src/dataflow/privacy-governance.js
var privacy_governance = __webpack_require__(3308);
;// CONCATENATED MODULE: ./src/lineage/export-briefing.js
// export-briefing.js — M4 deliverable #7 (FR-501 §14, DFG-035): Executive
// Risk Story Mode. Turns Task 1's decision-story.js#rankFlows output into a
// 5-chapter Markdown narrative (`emitDecisionStory`), covering 6 audience
// modes that change wording/verbosity only — never the underlying ranking,
// facts, or chapter order (decision-story.js's own binding constraint:
// "never represents an uncalibrated score as expected financial loss or
// breach probability" extends here to "never represents a re-worded fact
// as a different fact").
//
// Chapter design (grounded in decision-story.js's real factor vocabulary
// and the DataFlowGraph v1 schema's real top-level fields — see this
// file's own review notes below for exactly which fields each chapter
// reads):
//   1. Scope & Confidence     — graph.scope/scanHealth/coverage/limitations
//   2. Sensitive-Data Footprint — rankFlows grouped by sensitivity tier
//   3. External Exposure      — externality.tier === 'external' flows
//   4. Control & Governance Gaps — controlVerdict.tier !== 'protected' flows
//   5. Change & Decisions Needed — NO new/worsened-flow claims (changeRecency
//      is always unavailable per decision-story.js); an explicit "no
//      historical baseline" disclosure instead, plus every flow whose
//      policyState is manual_review_required/prohibited as a real,
//      currently-decision-relevant fact.
//
// Markdown-escaping discipline (BLOCKING-1 precedent, export-privacy.js):
// chapter 4 interpolates the exact same flow.governanceRefs operator prose
// DPIA/RoPA does, so the exact same injection risk applies. _mdInline/
// _mdCell/_mdCode are reimplemented LOCALLY here (not imported from
// export-privacy.js, which does not export them either) per this
// codebase's established per-module-owns-its-own-escaping-helpers
// precedent, and are applied to every governance value and every
// graph-derived label/name this file interpolates.







const DECISION_STORY_VERSION = '1.0.0';

const AUDIENCE_MODES = Object.freeze(['board', 'ciso', 'privacy', 'compliance', 'regulator', 'technical']);

// --- Local Markdown-escaping helpers (mirror export-privacy.js's own
// _mdInline/_mdCell/_mdCode verbatim — see this file's header for why they
// are not imported across modules). ---

/** Collapse embedded newlines to spaces — an unescaped newline in an
 * interpolated value (operator-supplied governance prose, or a
 * source-derived label) would otherwise break out of its Markdown line and
 * inject arbitrary content (e.g. a fake heading) mid-document. */
function _mdInline(value) {
  return String(value).replace(/\r\n|\r|\n/g, ' ');
}

/** _mdInline, plus pipe-escaping for a Markdown table cell — an unescaped
 * `|` in a cell value shifts every later column in that row. Backslashes
 * are escaped FIRST: a value already containing a literal `\|` would
 * otherwise become `\\|` — an escaped backslash followed by a still-live
 * `|` column delimiter. */
function _mdCell(value) {
  return _mdInline(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Wrap a value in a Markdown inline-code span, safe even when the value
 * itself contains backticks — CommonMark's rule: the fence must be one
 * backtick longer than the longest run of consecutive backticks anywhere
 * in the content, padded with a space on each side. */
function _mdCode(value) {
  const s = _mdInline(value);
  const runs = s.match(/`+/g);
  const maxRun = runs ? Math.max(...runs.map((r) => r.length)) : 0;
  if (maxRun === 0) return `\`${s}\``;
  const fence = '`'.repeat(maxRun + 1);
  return `${fence} ${s} ${fence}`;
}

// --- Audience-mode wording table. Controls prose register and verbosity
// ONLY — see this file's own header. `chapter2Cap` is FR-501's own "maximum
// of seven primary observations" requirement, scoped to Chapter 2's
// per-flow observation list (never to the chapter's own aggregate
// summaries, which always report the full group). ---
const _AUDIENCE_WORDING = Object.freeze({
  board: {
    label: 'Board Briefing',
    registerNote: 'Written for board-level review: plain language, decision-focused, capped at the primary observations that matter most.',
    chapter2Cap: 7,
    verbose: false,
  },
  ciso: {
    label: 'CISO Briefing',
    registerNote: 'Written for security leadership: risk-prioritized, control- and evidence-focused.',
    chapter2Cap: null,
    verbose: true,
  },
  privacy: {
    label: 'Privacy Officer Briefing',
    registerNote: 'Written for privacy/DPO review: data-class, AI-processing-context, and governance-gap focused.',
    chapter2Cap: null,
    verbose: true,
  },
  compliance: {
    label: 'Compliance Briefing',
    registerNote: 'Written for compliance review: policy-state and control-gap focused.',
    chapter2Cap: null,
    verbose: true,
  },
  regulator: {
    label: 'Regulator-Facing Briefing',
    registerNote: 'Written for external regulatory review: formal register, full evidentiary caveats preserved throughout.',
    chapter2Cap: null,
    verbose: true,
  },
  technical: {
    label: 'Technical Briefing',
    // Review finding (RECOMMENDED, fixed): the previous wording ("every
    // factor tier shown") was false — only sensitivity/externality/
    // controlVerdict are ever rendered per-flow; aiUse/breadth/
    // evidenceConfidence affect ranking ORDER only and are never shown
    // per item in any mode. Reworded to describe what is actually true.
    registerNote: 'Full technical detail: no observation cap, verbose tables shown. Sensitivity, externality, and control-verdict tiers are shown per flow; all nine ranking factors (see the list at the end of this report) are considered when ordering flows, whether or not each is individually displayed.',
    chapter2Cap: null,
    verbose: true,
  },
});

const SENSITIVITY_TIER_ORDER = ['critical', 'high', 'medium', 'low', 'none'];
const SENSITIVITY_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None / unclassified' };

const POLICY_LABELS = {
  prohibited: 'prohibited by policy',
  permitted: 'permitted',
  conditionally_permitted: 'conditionally permitted',
  manual_review_required: 'needs manual review',
  not_evaluated: 'not yet evaluated against policy',
};

function _primaryDataElement(flow, graph) {
  return (graph.dataElements ?? []).find((d) => (flow.dataElementIds ?? []).includes(d.id)) ?? null;
}

function _policyLabel(verdict, wording) {
  return wording.verbose ? `\`${verdict}\`` : (POLICY_LABELS[verdict] ?? verdict);
}

function _flowHasUnencryptedTransit(flow, edgesById) {
  return (flow.edgeIds ?? []).some((id) => edgesById.get(id)?.protection?.transit?.verdict === 'unprotected');
}

function _flowHasAtRestUnknown(flow, edgesById) {
  return (flow.edgeIds ?? []).some((id) => {
    const v = edgesById.get(id)?.protection?.atRest?.verdict;
    return v === 'not_assessed' || v === 'unknown';
  });
}

// --- Chapter 1: Scope & Confidence — direct reads off the graph's own
// required top-level envelope fields (scope/scanHealth/coverage/
// limitations; dataflow-graph.schema.json's own top-level `required` list).
function _chapter1ScopeConfidence(graph, wording, hasFilter) {
  const lines = [];
  lines.push('## Chapter 1: Scope & Confidence');
  lines.push('');
  const scope = graph.scope ?? {};
  const scanHealth = graph.scanHealth ?? {};
  const coverage = graph.coverage ?? {};
  const limitations = graph.limitations ?? [];

  lines.push(`This report is derived from a **${_mdInline(scope.source ?? 'unknown')}**-sourced data flow graph${scope.source === 'fixture' ? ' — illustrative demo data, not a real scan.' : '.'}`);
  lines.push('');
  lines.push(`Scan health: **${_mdInline(scanHealth.status ?? 'unknown')}**${scanHealth.reason ? ` (${_mdInline(scanHealth.reason)})` : ''}.`);
  lines.push('');
  if (graph.graphId) { lines.push(`Graph identity: \`${_mdInline(graph.graphId)}\`.`); lines.push(''); }

  // Review finding (RECOMMENDED, fixed): --filter narrows every chapter's
  // own flow content (via _filterGraph), but the coverage NUMBERS below
  // still come from the SOURCE graph's own coverage ledger, which
  // _filterGraph never touches (narrowing coverage counts to "how much of
  // a filtered subgraph was covered" is not a well-defined question — the
  // ledger is a whole-scan artifact). Left unlabeled, this read as an
  // unscoped whole-scan ledger sitting beside a scoped, filtered chapter
  // set with no indication either way — AC-25's own "coverage limitations
  // remain prominent" requirement.
  if (hasFilter) {
    lines.push('**This report is scoped to a filtered subset of the graph** (`--filter`). The coverage figures below describe the WHOLE underlying scan, not just this filtered scope — Chapters 2 through 5 report only the filtered flows.');
    lines.push('');
  }

  const sources = coverage.sources ?? {};
  const sinks = coverage.sinks ?? {};
  lines.push('**Coverage at a glance:**');
  lines.push('');
  lines.push(`- Sources matched: ${sources.matched ?? 0} (${sources.unseedable ?? 0} unseedable)`);
  lines.push(`- Sink call sites: ${sinks.callStatementSites ?? 0} (${sinks.connected ?? 0} connected, ${sinks.disconnected ?? 0} disconnected, ${sinks.unsupportedSites ?? 0} unsupported)`);
  if (coverage.degradedTerminals) lines.push(`- Degraded analysis terminals: ${coverage.degradedTerminals}`);
  if (coverage.unresolvedDestinations) lines.push(`- Unresolved destinations: ${coverage.unresolvedDestinations}`);
  if (coverage.pathBudgetTruncation) lines.push('- One or more path reconstructions hit a budget limit — treat affected flows as a lower bound, not a complete picture.');
  lines.push('');

  if (wording.verbose && Array.isArray(coverage.languages) && coverage.languages.length) {
    lines.push('**Languages analyzed:**');
    lines.push('');
    for (const l of coverage.languages) lines.push(`- ${_mdInline(l.language)}: ${l.filesAnalyzed ?? 0}/${l.filesExpected ?? 0} file(s) analyzed`);
    lines.push('');
  }

  if (limitations.length) {
    lines.push('**Known limitations of this analysis:**');
    lines.push('');
    for (const l of limitations) lines.push(`- ${_mdInline(l)}`);
    lines.push('');
  }

  lines.push('**Ranking factors honestly unavailable in this milestone:** `recipientJurisdiction` (needs a recipient-profile registry, not yet built) and `changeRecency` (needs the Data-Flow Time Machine, not yet built) are disclosed as unavailable on every flow scored below — never fabricated, never silently dropped from the factor list.');
  lines.push('');

  return { id: 'scope-confidence', number: 1, title: 'Scope & Confidence', itemCount: limitations.length, markdown: lines.join('\n') };
}

// --- Chapter 2: Sensitive-Data Footprint — rankFlows grouped by the
// sensitivity factor's own tier. Every ranked flow is pushed into ITS OWN
// tier's bucket unconditionally, including 'none' — mirrors
// export-privacy.js#_groupRowsByClass's own never-silently-drop-a-flow
// discipline (a bare `if (tier !== 'none') continue` would make an
// unclassified flow genuinely invisible from the whole chapter, not merely
// ungrouped).
function _chapter2SensitiveFootprint(ranked, graph, nodesById, wording) {
  const lines = [];
  lines.push('## Chapter 2: Sensitive-Data Footprint');
  lines.push('');
  if (ranked.length === 0) {
    lines.push('No flows were identified in this graph scope — nothing to report.');
    return { id: 'sensitive-footprint', number: 2, title: 'Sensitive-Data Footprint', itemCount: 0, markdown: lines.join('\n') };
  }

  const grouped = new Map();
  for (const rf of ranked) {
    const tier = rf.factors.sensitivity.tier;
    if (!grouped.has(tier)) grouped.set(tier, []);
    grouped.get(tier).push(rf);
  }

  const cap = wording.chapter2Cap;
  let shown = 0;
  let truncated = false;

  for (const tier of SENSITIVITY_TIER_ORDER) {
    const group = grouped.get(tier);
    if (!group || group.length === 0) continue;
    if (cap != null && shown >= cap) { truncated = true; break; }

    lines.push(`### ${SENSITIVITY_LABELS[tier] ?? tier} (${group.length} flow(s))`);
    lines.push('');

    // Group-level aggregates always reflect the FULL group, regardless of
    // the per-item cap below — the cap narrows the observation LIST, never
    // the honest summary counts.
    const dataClasses = new Set();
    const destinations = new Set();
    const aiContexts = new Set();
    for (const rf of group) {
      const de = _primaryDataElement(rf.flow, graph);
      for (const c of de?.dataClasses ?? []) dataClasses.add(c);
      for (const c of de?.aiContexts ?? []) aiContexts.add(c);
      const snk = nodesById.get(rf.flow.sink);
      if (snk) destinations.add(snk.label || snk.id);
    }
    if (dataClasses.size) lines.push(`- Data classes: ${[...dataClasses].sort().map(_mdCode).join(', ')}`);
    if (destinations.size) lines.push(`- Destinations reached: ${[...destinations].sort().map(_mdCode).join(', ')}`);
    if (wording.verbose && aiContexts.size) lines.push(`- AI processing contexts: ${[...aiContexts].sort().map(_mdCode).join(', ')}`);
    lines.push('');

    for (const rf of group) {
      if (cap != null && shown >= cap) { truncated = true; break; }
      const de = _primaryDataElement(rf.flow, graph);
      const snk = nodesById.get(rf.flow.sink);
      const controlNote = wording.verbose ? ` (control: \`${rf.factors.controlVerdict.tier}\`)` : '';
      lines.push(`- ${_mdCode(de?.name ?? '(unnamed field)')} -> ${_mdCode(snk?.label ?? snk?.id ?? 'unknown destination')}${controlNote}`);
      shown++;
    }
    lines.push('');
    if (truncated) break;
  }

  if (truncated) {
    lines.push(`_${ranked.length - shown} additional flow(s) not shown — capped at ${cap} primary observations for this audience mode._`);
    lines.push('');
  }

  return { id: 'sensitive-footprint', number: 2, title: 'Sensitive-Data Footprint', itemCount: shown, markdown: lines.join('\n') };
}

// --- Chapter 3: External Exposure — externality.tier === 'external' flows,
// PLUS any flow whose sink node is genuinely FR-203-unresolved
// (node.kind === 'unresolved'). Final whole-branch review finding
// (BLOCKING, fixed): this chapter originally filtered on 'external' alone,
// but FR-203's unresolved-destination path (sink-registry.js) sets
// externality:'unknown' on the SAME return object as kind:'unresolved' —
// never 'external' — so EVERY unresolved-destination flow (including
// every real AI-provider flow in this JS catalog, since every AI SDK entry
// is a member-chain receiver that always triggers FR-203) was silently
// dropped from the whole chapter, and the chapter's own "unresolved
// destinations"/"AI providers" bullets were unreachable dead code.
//
// Deliberately narrower than "any externality:'unknown' flow": a plain
// resolved store-kind sink (a local database write) ALSO carries
// externality:'unknown' by category design (sink-registry.js's
// CATEGORY_EXTERNALITY — "could be local or third-party-managed, the
// registry can't tell"), which is a genuinely different, non-security
// concept from FR-203's "the destination itself could not be statically
// determined." Gating on node.kind === 'unresolved' targets the real
// FR-203 gap the review found without also pulling in every ordinary
// database/file/object-storage write in the graph.
function _chapter3ExternalExposure(ranked, graph, nodesById, wording) {
  const lines = [];
  lines.push('## Chapter 3: External Exposure');
  lines.push('');
  const exposureFlows = ranked.filter((rf) => {
    if (rf.factors.externality.tier === 'external') return true;
    return nodesById.get(rf.flow.sink)?.kind === 'unresolved';
  });
  if (exposureFlows.length === 0) {
    lines.push('No flows in this graph scope reach an external or unresolved destination.');
    return { id: 'external-exposure', number: 3, title: 'External Exposure', itemCount: 0, markdown: lines.join('\n') };
  }

  const resolvedExternal = exposureFlows.filter((rf) => rf.factors.externality.tier === 'external');
  const unresolvedTier = exposureFlows.filter((rf) => nodesById.get(rf.flow.sink)?.kind === 'unresolved');

  const destinations = new Set();
  const aiProviders = new Set();
  const unresolved = new Set();
  for (const rf of exposureFlows) {
    const snk = nodesById.get(rf.flow.sink);
    if (!snk) continue;
    destinations.add(snk.label || snk.id);
    if (AI_SINK_SUBTYPES.includes(snk.subtype)) aiProviders.add(snk.label || snk.id);
    if (snk.kind === 'unresolved') unresolved.add(snk.label || snk.id);
  }

  lines.push(`${exposureFlows.length} flow(s) reach an external or unresolved destination — ${resolvedExternal.length} resolved external, ${unresolvedTier.length} destination not statically resolved.`);
  lines.push('');
  if (destinations.size) { lines.push(`**Destinations:** ${[...destinations].sort().map(_mdCode).join(', ')}`); lines.push(''); }
  if (aiProviders.size) { lines.push(`**AI providers/agents/tools among them:** ${[...aiProviders].sort().map(_mdCode).join(', ')}`); lines.push(''); }
  if (unresolved.size) { lines.push(`**Destination not statically resolved (could not be determined by analysis):** ${[...unresolved].sort().map(_mdCode).join(', ')}`); lines.push(''); }

  if (wording.verbose) {
    lines.push('| Data element | Destination | Externality | Sensitivity | Control |');
    lines.push('|---|---|---|---|---|');
    for (const rf of exposureFlows) {
      const de = _primaryDataElement(rf.flow, graph);
      const snk = nodesById.get(rf.flow.sink);
      const cells = [de?.name ?? '(unnamed field)', snk?.label ?? snk?.id ?? 'unknown', rf.factors.externality.tier, rf.factors.sensitivity.tier, rf.factors.controlVerdict.tier];
      lines.push(`| ${cells.map(_mdCell).join(' | ')} |`);
    }
    lines.push('');
  }

  return { id: 'external-exposure', number: 3, title: 'External Exposure', itemCount: exposureFlows.length, markdown: lines.join('\n') };
}

// --- Chapter 4: Control & Governance Gaps — controlVerdict.tier !==
// 'protected' flows, sub-categorized into raw-logging / unencrypted-
// transit / at-rest-unknown / governance-field gaps / policy conflicts.
function _chapter4ControlGovernanceGaps(ranked, graph, nodesById, edgesById, wording) {
  const lines = [];
  lines.push('## Chapter 4: Control & Governance Gaps');
  lines.push('');
  const gaps = ranked.filter((rf) => rf.factors.controlVerdict.tier !== 'protected');
  if (gaps.length === 0) {
    lines.push('No control or governance gaps were identified in this graph scope.');
    return { id: 'control-governance-gaps', number: 4, title: 'Control & Governance Gaps', itemCount: 0, markdown: lines.join('\n') };
  }

  const rawLogging = [];
  const unencryptedTransit = [];
  const atRestUnknown = [];
  const governanceGapFlows = [];
  // Final whole-branch review finding (BLOCKING, fixed): this used to be
  // ONE bucket, `flow.policyVerdict !== 'permitted'`, rendered under
  // "policy conflict (not permitted)". With no
  // .agentic-security/privacy-policy.json on disk — the default for
  // essentially every user — every flow reads `not_evaluated`, so every
  // flow was reported as being in policy conflict: an unsupported
  // compliance claim (AC-25's own "no unsupported ... compliance claim
  // appears") about a flow no policy was ever applied to, AND a direct
  // contradiction of Chapter 5, which correctly treats not_evaluated as
  // "no decision needed" (decision-story.js's own _TIER_RANK already
  // distinguishes these 4 states; this chapter was the one place that
  // collapsed them). Split into three honestly-labeled buckets.
  // manualReviewNeeded and conditionally_permitted have no real producer
  // in the current pipeline (confirmed directly against
  // graph-builder.js's own policyVerdict assignment site, Task 2's own
  // disclosed finding) — only not_evaluated/permitted/prohibited are
  // ever emitted from real code today. This branch's own correctness
  // rests on the hand-traced symmetry with policyConflicts/notEvaluated
  // below, not a real-graph regression test, for the same reason Task 2
  // never fabricated a hand-built graph carrying an
  // unreachable-in-practice verdict just to exercise this one branch
  // (scoped re-review of the final-review fix round, noted but
  // deliberately not "fixed" with a fake fixture).
  const policyConflicts = [];
  const manualReviewNeeded = [];
  const notEvaluated = [];

  for (const rf of gaps) {
    const { flow } = rf;
    const snk = nodesById.get(flow.sink);
    if (flow.handling === 'raw' && snk?.kind === 'log') rawLogging.push(rf);
    if (_flowHasUnencryptedTransit(flow, edgesById)) unencryptedTransit.push(rf);
    if (_flowHasAtRestUnknown(flow, edgesById)) atRestUnknown.push(rf);
    const gapFields = privacy_governance/* GOVERNANCE_FIELDS */.n4.filter((f) => (flow.governanceRefs?.[f]?.source ?? 'manual_required') === 'manual_required');
    if (gapFields.length) governanceGapFlows.push({ rf, gapFields });
    if (flow.policyVerdict === 'prohibited' || flow.policyVerdict === 'conditionally_permitted') policyConflicts.push(rf);
    else if (flow.policyVerdict === 'manual_review_required') manualReviewNeeded.push(rf);
    else if (flow.policyVerdict === 'not_evaluated') notEvaluated.push(rf);
  }

  lines.push(`${gaps.length} flow(s) do not carry a fully protected control verdict.`);
  lines.push('');

  const section = (title, items, render) => {
    if (!items.length) return;
    lines.push(`**${title} (${items.length}):**`);
    lines.push('');
    for (const item of items) lines.push(`- ${render(item)}`);
    lines.push('');
  };

  // Every bullet includes its destination (N-3, review finding): the same
  // field reaching two different sinks previously rendered two
  // byte-identical bullets in a list, indistinguishable from a
  // duplication bug.
  const withDestination = (rf) => {
    const de = _primaryDataElement(rf.flow, graph);
    const snk = nodesById.get(rf.flow.sink);
    return `${_mdCode(de?.name ?? '(unnamed field)')} -> ${_mdCode(snk?.label ?? snk?.id ?? 'unknown destination')}`;
  };

  section('Raw data reaching a log sink', rawLogging, withDestination);
  section('Flows with unencrypted transit', unencryptedTransit, withDestination);
  section('Flows with at-rest protection unknown', atRestUnknown, withDestination);

  // A real Markdown TABLE (not a bullet list), deliberately — this is the
  // one place in this chapter that interpolates the operator-supplied
  // governance PROSE VALUES DPIA/RoPA read from flow.governanceRefs
  // (export-privacy.js's own BLOCKING-1 precedent: an unescaped `|` or
  // embedded newline in one of these values corrupts a table's column
  // alignment or injects a fake heading). Every cell goes through _mdCell.
  if (governanceGapFlows.length) {
    lines.push(`**Flows with governance fields requiring manual input (${governanceGapFlows.length}):**`);
    lines.push('');
    const header = ['Data element', 'Destination', 'Missing fields', 'Provided values'];
    lines.push(`| ${header.join(' | ')} |`);
    lines.push(`|${header.map(() => '---').join('|')}|`);
    for (const { rf, gapFields } of governanceGapFlows) {
      const de = _primaryDataElement(rf.flow, graph);
      const snk = nodesById.get(rf.flow.sink);
      const provided = privacy_governance/* GOVERNANCE_FIELDS */.n4
        .filter((f) => rf.flow.governanceRefs?.[f]?.source === 'operator_provided')
        .map((f) => `${f}: ${rf.flow.governanceRefs[f].value}`)
        .join('; ');
      const cells = [de?.name ?? '(unnamed field)', snk?.label ?? snk?.id ?? 'unknown destination', gapFields.join(', '), provided || '(none)'];
      lines.push(`| ${cells.map(_mdCell).join(' | ')} |`);
    }
    lines.push('');
  }

  const withPolicyLabel = (rf) => `${withDestination(rf)} — ${_mdInline(_policyLabel(rf.flow.policyVerdict, wording))}`;
  section('Flows prohibited or conditionally permitted by policy', policyConflicts, withPolicyLabel);
  section('Flows requiring manual policy review', manualReviewNeeded, withPolicyLabel);
  section('Flows not yet evaluated against policy (no policy configured for this scan)', notEvaluated, withPolicyLabel);

  return { id: 'control-governance-gaps', number: 4, title: 'Control & Governance Gaps', itemCount: gaps.length, markdown: lines.join('\n') };
}

// --- Chapter 5: Change & Decisions Needed — NO new/worsened-flow claims
// (changeRecency is always unavailable, decision-story.js's own header).
// A prominent disclosure instead (AC-25's "coverage limitations remain
// prominent"), plus every flow whose policyState is manual_review_required
// or prohibited, presented as a real, currently-decision-relevant fact.
function _chapter5ChangeAndDecisions(ranked, graph, wording) {
  const lines = [];
  lines.push('## Chapter 5: Change & Decisions Needed');
  lines.push('');
  lines.push('**No historical baseline is available in this milestone.** Change-over-time claims (a flow being new or having gotten worse since a prior scan) require the Data-Flow Time Machine, which has not shipped yet — nothing below claims a flow is new or has regressed. Every item is a real, currently-decision-relevant fact about the graph as it stands today.');
  lines.push('');

  const decisions = ranked.filter((rf) => rf.factors.policyState.tier === 'manual_review_required' || rf.factors.policyState.tier === 'prohibited');
  if (decisions.length === 0) {
    lines.push('No flows currently require a manual policy decision.');
    lines.push('');
  } else {
    lines.push(`**Decisions needed now (${decisions.length}):**`);
    lines.push('');
    for (const rf of decisions) {
      const de = _primaryDataElement(rf.flow, graph);
      lines.push(`- ${_mdCode(de?.name ?? '(unnamed field)')} — ${_mdInline(_policyLabel(rf.flow.policyVerdict, wording))}`);
    }
    lines.push('');
  }

  return {
    id: 'change-and-decisions', number: 5, title: 'Change & Decisions Needed', itemCount: decisions.length,
    markdown: lines.join('\n'), decisions,
  };
}

function _renderMarkdown(record, wording, chapters) {
  const lines = [];
  lines.push(`# Executive Risk Story — ${wording.label}`);
  lines.push('');
  // Full digest, never truncated (review finding, RECOMMENDED, fixed) —
  // AC-25's own "preserves graph digest and reproducibility metadata"
  // requirement; a truncated digest is a weaker reproducibility claim
  // than the graph itself makes.
  lines.push(`Generated ${_mdInline(record.generatedAt)} · graph digest \`${_mdInline(record.graphDigest)}\` · audience mode \`${record.audienceMode}\`.`);
  lines.push('');
  lines.push(wording.registerNote);
  lines.push('');
  lines.push('This report is generated from real, code-derived data flow analysis. It is a decision-support artifact, not a compliance certification — see Chapter 1 for scope and coverage limitations.');
  lines.push('');
  lines.push('---');
  lines.push('');
  for (const ch of chapters) {
    lines.push(ch.markdown);
    lines.push('');
  }
  lines.push('---');
  lines.push('');
  lines.push(`Ranking factors considered, in priority order: ${record.rankingFactors.map((f) => `\`${f}\``).join(', ')}.`);
  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`;
}

/**
 * Emit the 5-chapter Executive Risk Story (FR-501 §14). Returns
 * {record, markdown} — `record` is a DecisionStory (§10.10 extension
 * contract, validated before return, never a DataFlowGraph v1 entity),
 * `markdown` is the human-readable narrative.
 *
 * @param {object} graph a real DataFlowGraph v1 document.
 * @param {object} [opts]
 * @param {{nodeIds:string[], edgeIds:string[]}} [opts.filter] the same
 *   {nodeIds, edgeIds} shape export-json.js/export-csv.js/export-privacy.js
 *   all use — narrows the GRAPH (via export-json.js's own _filterGraph)
 *   before flows are ranked. The graph DIGEST always identifies the
 *   SOURCE graph, never the filtered view — export-json.js's own
 *   established precedent (two different filters of one scan must report
 *   the same digest).
 * @param {string} [opts.generatedAt] falls back to `graph.generatedAt` —
 *   NEVER wall-clock, so the record's own generatedAt/id stay deterministic
 *   under AGENTIC_SECURITY_DETERMINISTIC=1 test fixtures the same way
 *   every other M4 exporter's regression tests already rely on.
 * @param {string} [opts.audienceMode] one of AUDIENCE_MODES, default
 *   'technical'. Controls prose register/verbosity only — see this file's
 *   own header for the binding "never change facts" constraint.
 * @param {string[]} [opts.factorOrder] overrides decision-story.js's own
 *   default RANKING_FACTORS priority sequence for THIS story — threaded
 *   straight through to rankFlows, satisfying the PRD's own "transparent
 *   CONFIGURABLE factors" requirement at the API level (review finding,
 *   RECOMMENDED, fixed — this was previously never threaded, so nothing
 *   external could reach rankFlows's own opts.factorOrder at all). Not yet
 *   exposed as its own `dataflow export` CLI flag — see commands/
 *   dataflow.md's own disclosure of that narrower, still-open gap.
 */
function emitDecisionStory(graph, opts = {}) {
  const audienceMode = opts.audienceMode ?? 'technical';
  if (!AUDIENCE_MODES.includes(audienceMode)) {
    throw new Error(`emitDecisionStory: unrecognized audienceMode "${audienceMode}" — must be one of ${AUDIENCE_MODES.join('|')}`);
  }
  const wording = _AUDIENCE_WORDING[audienceMode];

  const scopedGraph = opts.filter ? (0,export_json/* _filterGraph */.e)(graph, opts.filter) : graph;
  const generatedAt = opts.generatedAt ?? graph.generatedAt;
  const nodesById = new Map((scopedGraph.nodes ?? []).map((n) => [n.id, n]));
  const edgesById = new Map((scopedGraph.edges ?? []).map((e) => [e.id, e]));
  const ranked = rankFlows(scopedGraph, opts.factorOrder ? { factorOrder: opts.factorOrder } : undefined);

  const ch1 = _chapter1ScopeConfidence(scopedGraph, wording, Boolean(opts.filter));
  const ch2 = _chapter2SensitiveFootprint(ranked, scopedGraph, nodesById, wording);
  const ch3 = _chapter3ExternalExposure(ranked, scopedGraph, nodesById, wording);
  const ch4 = _chapter4ControlGovernanceGaps(ranked, scopedGraph, nodesById, edgesById, wording);
  const ch5 = _chapter5ChangeAndDecisions(ranked, scopedGraph, wording);
  const chapters = [ch1, ch2, ch3, ch4, ch5];

  // Deliberate: the digest always identifies the SOURCE graph this story
  // was taken from, never the filtered `scopedGraph` — mirrors
  // export-json.js#exportGraphJSON's own established rule (AC-25's
  // "preserves graph digest" requirement, satisfied against the graph the
  // caller actually handed in, not a view of it).
  const graphDigest = (0,export_json.computeGraphDigest)(graph);

  const evidenceGrade = ranked.length === 0 ? 'none' : 'code';
  if (!protection/* EVIDENCE_GRADES */.xE.includes(evidenceGrade)) {
    throw new Error(`emitDecisionStory: internal error — evidenceGrade "${evidenceGrade}" is not a member of EVIDENCE_GRADES`);
  }

  const scopeQuery = { filter: opts.filter ?? null };

  const record = {
    id: (0,ids/* storyId */.xj)({ graphDigest, audienceMode, scopeQuery }),
    version: DECISION_STORY_VERSION,
    audienceMode,
    scopeQuery,
    // Strip ch5's internal-only `decisions` array (used below to build
    // record.decisions) before it lands twice on the public record.
    chapters: chapters.map(({ decisions: _decisions, ...c }) => c),
    contributingGraphIds: graph.graphId ? [graph.graphId] : [],
    rankingFactors: RANKING_FACTORS,
    evidenceGrade,
    coverage: scopedGraph.coverage ?? {},
    decisions: ch5.decisions.map((rf) => ({
      flowId: rf.flow.id,
      policyVerdict: rf.flow.policyVerdict,
      dataElementName: _primaryDataElement(rf.flow, scopedGraph)?.name ?? null,
      sinkLabel: nodesById.get(rf.flow.sink)?.label ?? null,
    })),
    generatedAt,
    graphDigest,
  };

  const { valid, errors } = validateDecisionStory(record);
  if (!valid) {
    throw new Error(`emitDecisionStory: internal error — produced an invalid DecisionStory record: ${JSON.stringify(errors)}`);
  }

  const markdown = _renderMarkdown(record, wording, chapters);
  return { record, markdown };
}


/***/ })

};
