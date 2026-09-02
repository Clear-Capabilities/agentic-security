export const id = 379;
export const ids = [379];
export const modules = {

/***/ 1379:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  emitGraphDpiaArtifact: () => (/* binding */ emitGraphDpiaArtifact),
  emitGraphRopaArtifact: () => (/* binding */ emitGraphRopaArtifact)
});

;// CONCATENATED MODULE: ../frontend/src/lib/flow-path.js
// Shared per-flow path/topology helpers, used by every view that needs to
// know "which nodes does this flow actually touch" — extracted here after
// Architecture View independently reimplemented the same node-collection
// logic inline in computeFlowSummary, to avoid a third divergent copy when
// Privacy View needed it too.

function flowPathNodeIds(graph, flow) {
  const ids = new Set([flow.source, flow.sink]);
  for (const edgeId of flow.edgeIds) {
    const edge = graph.edges.find((e) => e.id === edgeId);
    if (edge) {
      ids.add(edge.from);
      ids.add(edge.to);
    }
  }
  return ids;
}

// Backend AI node-subtype vocabulary (scanner/src/lineage/schema.js's
// SOURCE_CATEGORIES/SINK_CATEGORIES, AI-flavored entries only). This list
// must be hand-kept in sync with that schema file — the frontend never
// imports scanner/src/lineage/ at runtime (see frontend/CLAUDE.md).
// Corrected this increment: the previous set ('ai-assistant',
// 'vector-store') matched neither real enum and silently never matched
// any real node.
const AI_SUBTYPES = new Set([
  'ai-model-provider', 'ai-local-model', 'ai-agent', 'ai-tool',
  'ai-vector-store', 'ai-memory', 'ai-training', 'ai-evaluation', 'ai-telemetry',
  'ai-model-output', 'ai-tool-result', 'ai-retrieved-document',
]);

// AI relevance is computed from flow/node TOPOLOGY (does the path touch an
// AI-kind node), never from dataElement.aiContexts — that field is never
// populated by name-only classification (see scanner/src/lineage's
// classification.js), so an aiContexts-based filter would show zero AI
// relevance despite real AI-processing flows existing in the graph.
function isAiRelevantFlow(graph, flow) {
  const pathNodeIds = flowPathNodeIds(graph, flow);
  return graph.nodes.some((n) => pathNodeIds.has(n.id) && AI_SUBTYPES.has(n.subtype));
}

;// CONCATENATED MODULE: ../frontend/src/lib/protection-visual.js
// The single source of truth for how a protection verdict renders — every
// view/component must call protectionVisual() rather than hardcoding a
// color or glyph, so AC-20 (verdicts distinguishable without color) holds
// everywhere by construction, not by convention.
//
// These verdict strings are NOT imported from scanner/src/lineage/protection.js
// — the browser bundle never imports anything under scanner/src/lineage/ at
// runtime (see frontend/CLAUDE.md). Keep this list in sync by hand if the
// backend's PROTECTION_VERDICTS/FLOW_SUMMARY_VALUES enums ever change.

// PRD §8.4, exact quoted precedence: "unprotected/prohibited → mixed →
// unknown/manual_required → protected/permitted → not_assessed". Read as
// display priority when aggregating multiple verdicts into one, not a raw
// severity order: not_assessed is LOWEST priority because it means "no
// information," and any real signal (even a protected one) should be shown
// instead of "not assessed." not_applicable isn't named in the PRD list;
// treated at the same lowest priority as not_assessed (both mean "nothing
// to prioritize").
const VERDICT_PRECEDENCE = Object.freeze([
  'unprotected',
  'mixed',
  'unknown',
  'protected',
  'not_assessed',
  'not_applicable',
]);

const VISUALS = Object.freeze({
  protected: { verdict: 'protected', label: 'Protected', glyph: '✓', lineStyle: 'solid', colorVar: '--status-protected' },
  unprotected: { verdict: 'unprotected', label: 'Unprotected', glyph: '✗', lineStyle: 'solid', colorVar: '--status-unprotected' },
  mixed: { verdict: 'mixed', label: 'Mixed', glyph: '±', lineStyle: 'solid', colorVar: '--status-unprotected' },
  unknown: { verdict: 'unknown', label: 'Unknown', glyph: '?', lineStyle: 'dashed', colorVar: '--status-unknown' },
  not_applicable: { verdict: 'not_applicable', label: 'Not applicable', glyph: '·', lineStyle: 'dotted', colorVar: '--text-secondary' },
  not_assessed: { verdict: 'not_assessed', label: 'Not assessed', glyph: '–', lineStyle: 'dotted', colorVar: '--status-unknown' },
});

function protection_visual_protectionVisual(verdict) {
  return VISUALS[verdict] ?? VISUALS.not_assessed;
}

function worstVerdict(verdicts) {
  for (const tier of VERDICT_PRECEDENCE) {
    if (verdicts.includes(tier)) return tier;
  }
  return 'not_assessed';
}

;// CONCATENATED MODULE: ../frontend/src/lib/row-filters.js
// Shared, deduplicated row-vs-active-filters matcher — was previously two
// near-identical private copies (privacy-view.js's and inventory-view.js's
// own rowMatchesFilters). Every check here reads a PRE-ATTACHED row
// property (never the graph directly) — the caller's own row-computation
// step is responsible for attaching whichever of these properties make
// sense for that row's own shape (see lib/filter-rail.js's own facet list
// and each view's own row-building code). A facet whose property the row
// does not carry AT ALL is skipped (never a hide) — this is what makes it
// safe for a single shared function to serve row shapes as different as a
// Privacy flow-row and an Inventory dataElement-row.
const LIST_FACETS = [
  ['dataClass', 'dataClasses', true], // true = row property is itself an array (dataClasses), match if ANY overlaps
  ['protection', 'protectionSummary', false], // false = row property is a single value, match if included in the filter's list
  ['transitVerdict', 'transitVerdict', false],
  ['atRestVerdict', 'atRestVerdict', false],
  ['handlingVerdict', 'handlingVerdict', false],
  ['sourceCategory', 'sourceCategory', false],
  ['sinkCategory', 'sinkCategory', false],
  ['destinationExternality', 'destinationExternality', false],
  ['policyVerdict', 'policyVerdict', false],
];

function matchesFilters(row, filters) {
  for (const [filterKey, rowProp, rowIsArray] of LIST_FACETS) {
    const activeValues = filters[filterKey];
    if (!activeValues?.length) continue; // this facet isn't active at all
    if (!(rowProp in row)) continue; // row doesn't carry this property — unaffected, not hidden
    if (rowIsArray) {
      if (!(row[rowProp] ?? []).some((v) => activeValues.includes(v))) return false;
    } else {
      if (row[rowProp] !== undefined && !activeValues.includes(row[rowProp])) return false;
    }
  }
  // Unlike the 9 facets above (list-of-selected-values), `ai` is a single
  // boolean toggle, matching its existing shape in both views — kept as
  // its own explicit check, not folded into LIST_FACETS's generic loop,
  // since it's structurally different (a boolean flag, not a multi-select).
  // Checked for ANY row carrying `isAiRelevant` — this is the real fix for
  // Inventory's own previously-missing AI check (its private
  // rowMatchesFilters never checked `ai` at all; Privacy's did).
  if (filters.ai && 'isAiRelevant' in row && !row.isAiRelevant) return false;
  return true;
}

;// CONCATENATED MODULE: ../frontend/src/views/privacy-view.js





const LIFECYCLE_STAGES = Object.freeze(['collection', 'processing', 'storage', 'sharing', 'retention', 'deletion']);

function stageForNode(node) {
  return LIFECYCLE_STAGES.includes(node.lifecycleStages?.[0]) ? node.lifecycleStages[0] : 'processing';
}

function computePrivacyRow(graph, flow) {
  const dataElement = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  const pathNodeIds = flowPathNodeIds(graph, flow);
  const pathNodes = graph.nodes.filter((n) => pathNodeIds.has(n.id));
  // This flow's own resolved edges — the same per-edgeId lookup
  // flowPathNodeIds() already performs internally, applied here to keep the
  // edge objects (rather than just the node ids) so the three protection
  // dimensions below can be aggregated per-flow via worstVerdict().
  const pathEdges = flow.edgeIds.map((edgeId) => graph.edges.find((e) => e.id === edgeId)).filter(Boolean);

  const stageCells = LIFECYCLE_STAGES.map((stage) => ({
    stage,
    nodeLabels: pathNodes.filter((n) => stageForNode(n) === stage).map((n) => n.label),
  }));

  const sourceNode = graph.nodes.find((n) => n.id === flow.source);
  const sinkNode = graph.nodes.find((n) => n.id === flow.sink);

  return {
    flowId: flow.id,
    dataElementName: dataElement?.name ?? 'unknown field',
    dataClasses: dataElement?.dataClasses ?? [],
    stageCells,
    governanceRefs: flow.governanceRefs ?? {},
    protectionSummary: flow.protectionSummary,
    policyVerdict: flow.policyVerdict,
    isAiRelevant: isAiRelevantFlow(graph, flow),
    // worstVerdict() always returns a real verdict string (falling back to
    // 'not_assessed', never null/undefined) even for an empty edge list, so
    // these three are always set unconditionally — unlike sourceCategory/
    // sinkCategory/destinationExternality below, there is no genuinely-absent
    // case to guard against.
    transitVerdict: worstVerdict(pathEdges.map((e) => e.protection.transit.verdict)),
    atRestVerdict: worstVerdict(pathEdges.map((e) => e.protection.atRest.verdict)),
    handlingVerdict: worstVerdict(pathEdges.map((e) => e.protection.handling.verdict)),
    // Only set when a real, non-null value exists — keeps matchesFilters's
    // own "property absent = unaffected, never a hide" semantics clean
    // rather than introducing a third (present-but-null) state.
    ...(sourceNode?.subtype ? { sourceCategory: sourceNode.subtype } : {}),
    ...(sinkNode?.subtype ? { sinkCategory: sinkNode.subtype } : {}),
    ...(sinkNode?.externality?.value ? { destinationExternality: sinkNode.externality.value } : {}),
  };
}

/**
 * @param {object} graph
 * @param {object} state
 * @param {((flow: object) => boolean) | null} [queryPredicate] - Milestone 3,
 *   sub-project M3-UX-Query, Task 4: the query language's compiled predicate
 *   (lib/query-language.js's `compileQuery`), applied here as an ADDITIONAL
 *   condition alongside the existing dataClass/protection/ai filters — a row
 *   must pass BOTH to stay visible. Omitted/null (every pre-existing
 *   caller/test) means "no query active," matching every row, so behavior
 *   is unchanged for anyone not passing it.
 */
function computePrivacyViewModel(graph, state, queryPredicate = null) {
  const matchesQuery = queryPredicate ?? (() => true);
  const rows = graph.flows.map((flow) => {
    const row = computePrivacyRow(graph, flow);
    return {
      ...row,
      selected: row.flowId === state.selectedId,
      visible: matchesFilters(row, state.filters ?? {}) && matchesQuery(flow),
    };
  });
  return { stages: LIFECYCLE_STAGES, rows };
}

const CLASS_BADGE_COLOR_VAR = { PII: '--class-pii', PHI: '--class-phi', PCI: '--class-pci' };

/**
 * @param {ReturnType<typeof computePrivacyViewModel>} viewModel
 * @param {HTMLElement} canvasEl
 * @param {(flowId: string) => void} onSelectFlow
 */
function renderPrivacyView(viewModel, canvasEl, onSelectFlow) {
  clear(canvasEl);

  const headerRow = el('tr', {}, [
    el('th', {}, 'Field'),
    el('th', {}, 'Protection'),
    ...viewModel.stages.map((stage) => el('th', {}, stage.charAt(0).toUpperCase() + stage.slice(1))),
  ]);

  const bodyRows = viewModel.rows.map((row) => renderPrivacyRow(row, onSelectFlow));

  const table = el('table', { class: 'privacy-table' }, [el('thead', {}, headerRow), el('tbody', {}, bodyRows)]);

  canvasEl.appendChild(el('div', { class: 'privacy-view' }, table));
}

function renderPrivacyRow(row, onSelectFlow) {
  const classBadges = row.dataClasses.map((cls) =>
    el('span', { class: 'privacy-class-badge', style: `color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--text-secondary'}); border-color: var(${CLASS_BADGE_COLOR_VAR[cls] ?? '--border-default'})` }, cls),
  );

  const fieldCell = el('td', { class: 'privacy-field-cell' }, [
    el('div', {}, row.dataElementName),
    el('div', {}, classBadges),
    row.isAiRelevant ? el('span', { class: 'privacy-governance-badge', style: 'border-color: var(--context-ai); color: var(--context-ai)' }, 'AI processing') : null,
  ]);

  const visual = protectionVisual(row.protectionSummary);
  const protectionCell = el(
    'td',
    { class: 'privacy-protection-cell' },
    el('span', { style: `border-color: var(${visual.colorVar}); color: var(${visual.colorVar})` }, `${visual.glyph} ${visual.label}`),
  );

  const stageCells = row.stageCells.map((cell) => renderStageCell(cell, row));

  return el(
    'tr',
    {
      class: 'privacy-row',
      'data-selected': String(row.selected),
      'data-visible': String(row.visible),
      tabindex: '0',
      role: 'button',
      'aria-label': `${row.dataElementName} lifecycle, ${row.protectionSummary}${row.selected ? ', selected' : ''}`,
      onClick: () => onSelectFlow(row.flowId),
      onKeydown: (evt) => {
        if (evt.key === 'Enter' || evt.key === ' ') {
          evt.preventDefault();
          onSelectFlow(row.flowId);
        }
      },
    },
    [fieldCell, protectionCell, ...stageCells],
  );
}

function renderStageCell(cell, row) {
  const children = [];
  if (cell.nodeLabels.length > 0) {
    children.push(el('div', {}, cell.nodeLabels.join(', ')));
  } else {
    children.push(el('div', { class: 'privacy-stage-cell-empty-label' }, '—'));
  }

  // Governance facts are shown once, on whichever stage cell is the most
  // relevant home for them — sharing (recipient/purpose/lawfulBasis/transfer)
  // or retention/deletion — rather than repeating them on every cell. This
  // loop runs unconditionally (independent of whether nodeLabels is empty)
  // so a fact like deletion:not_found is never structurally unreachable just
  // because a flow's path happens not to touch a deletion-stage node.
  const governanceKeysForStage = {
    sharing: ['recipient', 'purpose', 'lawfulBasis', 'transfer'],
    retention: ['retention'],
    deletion: ['deletion'],
  };
  const relevantKeys = governanceKeysForStage[cell.stage] ?? [];
  for (const key of relevantKeys) {
    if (key in row.governanceRefs) {
      const value = row.governanceRefs[key];
      children.push(el('div', { class: 'privacy-governance-badge' }, `${key}: ${value}`));
    }
  }

  return el('td', { class: cell.nodeLabels.length === 0 ? 'privacy-stage-cell privacy-stage-cell-empty' : 'privacy-stage-cell' }, children);
}

// EXTERNAL MODULE: ./src/dataflow/privacy-governance.js
var privacy_governance = __webpack_require__(3308);
// EXTERNAL MODULE: ./src/lineage/export-json.js
var export_json = __webpack_require__(859);
;// CONCATENATED MODULE: ./src/lineage/export-privacy.js
// export-privacy.js — Milestone 4 deliverable #10 (DFG-020): graph-derived
// DPIA/RoPA export, migrating off the Layer-2 taint engine's
// dataflow/privacy-taint.js#emitDpiaArtifact / privacy-governance.js#emitRopaArtifact
// (which derive from piiFields, name-in-argument classification with no
// path/alias/field-mapping precision) onto the real DataFlowGraph v1's
// field-identity-tracked flows.
//
// Reuses frontend/src/views/privacy-view.js#computePrivacyViewModel
// DIRECTLY (the first live scanner/ -> frontend/ module import in this
// codebase, confirmed safe: that module only touches document/window
// inside renderPrivacyView's own function body, never at module top
// level, so importing it from plain Node never executes any DOM code)
// rather than re-deriving lifecycle-stage/dataClass/protection-verdict
// row computation a second time. This mirrors this package's own
// established discipline of reusing an already-correct, already-tested
// computation rather than a parallel copy that can drift.
//
// Both emit functions mirror their taint-engine-era predecessors'
// structure/wording (GDPR Art. 35 framing for the DPIA, the
// register-not-narrative RoPA table) but are populated from real graph
// rows.
//
// Filter wiring: opts.filter is the SAME {nodeIds, edgeIds} shape every
// other `dataflow export` format uses (export-json.js's own convention).
// It filters the GRAPH itself, via export-json.js's _filterGraph, BEFORE
// computePrivacyViewModel ever runs — never threaded into
// computePrivacyViewModel's own state.filters parameter, which expects a
// completely different shape (per-facet selected-value arrays, e.g.
// {dataClass: [...]}) and would silently no-op if handed {nodeIds, edgeIds}.





function _emptyState() {
  return { selectedId: null };
}

/**
 * Collapse embedded newlines to spaces. Every value interpolated into a
 * Markdown line below can originate from operator-supplied prose (a
 * governance field from .agentic-security/privacy-governance.json) or
 * from source-derived identifiers — neither is trusted not to contain a
 * literal newline, which would otherwise let the value break out of its
 * line and inject arbitrary Markdown (e.g. a fake heading) mid-document.
 */
function _mdInline(value) {
  return String(value).replace(/\r\n|\r|\n/g, ' ');
}

/** _mdInline, plus pipe-escaping for a Markdown table cell — an
 * unescaped `|` in a cell value shifts every later column in that row.
 * Backslashes are escaped FIRST: a value already containing a literal
 * `\|` (e.g. a Windows path fragment, a regex snippet) would otherwise
 * become `\\|` — in Markdown that reads as an escaped backslash followed
 * by a still-live, still-unescaped `|` column delimiter. */
function _mdCell(value) {
  return _mdInline(value).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Wrap a value in a Markdown inline-code span, safe even when the value
 * itself contains backticks. CommonMark's own general rule: the fence
 * must be one backtick longer than the longest run of consecutive
 * backticks anywhere in the content, padded with a space on each side —
 * a fixed double-backtick fence (this function's own earlier version)
 * is not safe against a value containing 2+ CONSECUTIVE backticks, since
 * the value's own run would then close the span early. */
function _mdCode(value) {
  const s = _mdInline(value);
  const runs = s.match(/`+/g);
  const maxRun = runs ? Math.max(...runs.map((r) => r.length)) : 0;
  if (maxRun === 0) return `\`${s}\``;
  const fence = '`'.repeat(maxRun + 1);
  return `${fence} ${s} ${fence}`;
}

function _scopedViewModel(graph, filter) {
  const scopedGraph = filter ? (0,export_json/* _filterGraph */.e)(graph, filter) : graph;
  return computePrivacyViewModel(scopedGraph, _emptyState(), null);
}

/**
 * Group computePrivacyViewModel's rows by data class, mirroring
 * emitDpiaArtifact's own grouping.
 *
 * Task-2 review finding (non-blocking, fixed): the old taint-engine
 * emitDpiaArtifact's identical grouping code was safe only because its
 * input (piiFields) was pre-filtered to classified fields by
 * construction — it never saw an unclassified field at all. This
 * function draws from EVERY graph flow via computePrivacyViewModel, so a
 * bare `for (const cls of row.dataClasses)` silently drops any flow
 * whose dataClasses is [] from the whole document — not merely
 * ungrouped, genuinely INVISIBLE, with no count, no mention, nothing —
 * for a document whose entire purpose is a complete inventory. RoPA's
 * own sibling loop already falls back to a '(unclassified)' bucket
 * (mirroring the same sentinel resolveGovernanceRefs's default hook
 * uses in coverage.js, Task 1's own fix round); mirrored here so the two
 * artifacts never disagree about how many real flows exist in scope.
 */
function _groupRowsByClass(rows) {
  const grouped = new Map();
  for (const row of rows) {
    const classes = row.dataClasses.length ? row.dataClasses : ['(unclassified)'];
    for (const cls of classes) {
      let g = grouped.get(cls);
      if (!g) { g = []; grouped.set(cls, g); }
      g.push(row);
    }
  }
  return grouped;
}

/**
 * Graph-derived DPIA (Data Protection Impact Assessment) — narrative
 * Markdown, mirroring dataflow/privacy-taint.js#emitDpiaArtifact's own
 * structure. opts.filter scopes to a subset of the graph (the "filtered
 * ... from the selected graph scope" requirement, PRD 7.4).
 */
function emitGraphDpiaArtifact(graph, opts = {}) {
  const viewModel = _scopedViewModel(graph, opts.filter);
  const visibleRows = viewModel.rows.filter((r) => r.visible !== false);
  const grouped = _groupRowsByClass(visibleRows);

  const lines = [];
  lines.push('# Data Protection Impact Assessment (DPIA)');
  lines.push('');
  lines.push(`Generated by agentic-security scanner (graph-derived) on ${(opts.generatedAt ?? new Date().toISOString()).slice(0, 10)}.`);
  lines.push('');
  lines.push('This is an automated DPIA scaffold derived from real data-flow analysis');
  lines.push('(field identity, path provenance, and protection verdicts). It must be');
  lines.push('reviewed and completed by a privacy officer before use.');
  lines.push('');
  lines.push('Governance fields reflect .agentic-security/privacy-governance.json as');
  lines.push('of the scan that produced this graph, not as of the moment this document');
  lines.push('was exported — re-scan (with lineage deep mode enabled) after editing');
  lines.push('that config, then re-export, to pick up the change.');
  lines.push('');
  if (grouped.size === 0) {
    lines.push('No regulated data classes were identified in this graph scope.');
    return lines.join('\n');
  }
  lines.push('## Data classes identified');
  lines.push('');
  for (const [cls, rows] of grouped) {
    lines.push(`### ${_mdInline(cls)} (${rows.length} flow(s))`);
    lines.push('');
    for (const row of rows.slice(0, 20)) {
      const crossClassNote = row.dataClasses.length > 1 ? ` (also: ${row.dataClasses.filter((c) => c !== cls).map(_mdInline).join(', ')})` : '';
      lines.push(`- ${_mdCode(row.dataElementName)} — ${_mdInline(row.sourceCategory ?? 'unknown source')} -> ${_mdInline(row.sinkCategory ?? 'unknown sink')} (protection: ${_mdInline(row.protectionSummary)})${crossClassNote}`);
    }
    if (rows.length > 20) lines.push(`- ... and ${rows.length - 20} more`);
    lines.push('');
    lines.push(`**Governance fields for ${_mdInline(cls)}:**`);
    lines.push('');
    // Worst-case-wins across this class's own rows, the same tie-break
    // Task 1's resolveGovernanceRefs default uses — never silently pick
    // whichever row happened to be iterated last.
    const merged = {};
    for (const row of rows) {
      for (const field of privacy_governance/* GOVERNANCE_FIELDS */.n4) {
        const r = row.governanceRefs?.[field];
        if (!r) continue;
        if (!merged[field] || merged[field].source === 'manual_required') merged[field] = r;
      }
    }
    // A flow with >1 dataClasses already carries a single governanceRefs
    // record merged (worst-case-wins) across ALL of its own classes back
    // at mint time (coverage.js#resolveGovernanceRefs) — this section can
    // only re-merge that already-merged record across rows, never recover
    // per-class distinctness that was lost earlier. Disclose it rather
    // than silently presenting a cross-class value as if it were specific
    // to this one class.
    if (rows.some((row) => row.dataClasses.length > 1)) {
      lines.push(`_Note: some flows in this section also belong to other data classes; the governance values below are each flow's own record merged across ALL of its classes, not verified as specific to ${_mdInline(cls)} alone._`);
      lines.push('');
    }
    for (const field of privacy_governance/* GOVERNANCE_FIELDS */.n4) {
      const r = merged[field] ?? { value: privacy_governance/* MANUAL_REQUIRED */.Dh, source: 'manual_required' };
      lines.push(`- ${field}: ${_mdCode(r.value)}${r.source === 'operator_provided' ? ' (operator-provided)' : ''}`);
    }
    lines.push('');
  }
  lines.push('## Regulatory framework mapping');
  lines.push('');
  lines.push('- **GDPR Art. 35** — DPIA required when processing is likely to result in high risk to data subjects.');
  lines.push('- **CCPA 1798.130** — Notice + access rights for collected personal information.');
  if (grouped.has('PHI')) lines.push('- **HIPAA 164.308** — Administrative safeguards for ePHI access.');
  if (grouped.has('PCI')) lines.push('- **PCI DSS Req. 3** — Protect stored cardholder data.');
  lines.push('');
  lines.push('This document organizes automated technical assessment evidence. It does');
  lines.push("not certify compliance and is not a legal determination — see the graph's");
  lines.push('own `disclaimer`/`limitations` fields for the full caveat.');
  return lines.join('\n');
}

/**
 * Graph-derived RoPA (Record of Processing Activities, GDPR Art. 30) —
 * tabular Markdown register, mirroring
 * dataflow/privacy-governance.js#emitRopaArtifact's own format, but ONE
 * ROW PER (dataClass x flow) rather than per dataClass alone — a real,
 * disclosed precision improvement the graph's own per-flow sink/
 * destination resolution makes possible (the taint-engine version has no
 * per-flow destination-resolution concept at all).
 */
function emitGraphRopaArtifact(graph, opts = {}) {
  const viewModel = _scopedViewModel(graph, opts.filter);
  const visibleRows = viewModel.rows.filter((r) => r.visible !== false);

  const lines = [];
  lines.push('# Record of Processing Activities (RoPA) — GDPR Art. 30, graph-derived');
  lines.push('');
  lines.push(`Generated by agentic-security scanner (graph-derived) on ${(opts.generatedAt ?? new Date().toISOString()).slice(0, 10)}. Every governance`);
  lines.push('field below is either supplied by an operator');
  lines.push('(.agentic-security/privacy-governance.json) or marked');
  lines.push(`\`${privacy_governance/* MANUAL_REQUIRED */.Dh}\` — none are inferable from source code, and none are`);
  lines.push(`guessed. A privacy officer must fill in every \`${privacy_governance/* MANUAL_REQUIRED */.Dh}\` cell`);
  lines.push('before this document is usable as a real RoPA.');
  lines.push('');
  lines.push('Governance fields reflect .agentic-security/privacy-governance.json as');
  lines.push('of the scan that produced this graph, not as of the moment this document');
  lines.push('was exported — re-scan (with lineage deep mode enabled) after editing');
  lines.push('that config, then re-export, to pick up the change.');
  lines.push('');
  if (visibleRows.length === 0) {
    lines.push('No regulated data flows were identified in this graph scope.');
    return lines.join('\n');
  }
  const header = ['Data class', 'Field', 'Source', 'Destination', 'Protection', ...privacy_governance/* GOVERNANCE_FIELDS */.n4];
  lines.push(`| ${header.join(' | ')} |`);
  lines.push(`|${header.map(() => '---').join('|')}|`);
  let gapCount = 0;
  let rowCount = 0;
  let crossClassRows = false;
  for (const row of visibleRows) {
    for (const cls of row.dataClasses.length ? row.dataClasses : ['(unclassified)']) {
      rowCount++;
      const fieldValues = privacy_governance/* GOVERNANCE_FIELDS */.n4.map((f) => {
        const r = row.governanceRefs?.[f] ?? { value: privacy_governance/* MANUAL_REQUIRED */.Dh, source: 'manual_required' };
        if (r.source === 'manual_required') gapCount++;
        return r.value;
      });
      const isCrossClass = row.dataClasses.length > 1;
      if (isCrossClass) crossClassRows = true;
      const clsCell = isCrossClass ? `${cls}*` : cls;
      const cells = [clsCell, row.dataElementName, row.sourceCategory ?? 'unknown source', row.sinkCategory ?? 'unknown destination', row.protectionSummary, ...fieldValues];
      lines.push(`| ${cells.map(_mdCell).join(' | ')} |`);
    }
  }
  lines.push('');
  if (crossClassRows) {
    lines.push('\\* This flow also belongs to other data classes; governance fields are');
    lines.push("this flow's own record merged across ALL of its classes, not verified as");
    lines.push('specific to the data class shown in this row alone.');
    lines.push('');
  }
  lines.push(`${gapCount} field(s) across ${rowCount} row(s) (${visibleRows.length} flow(s)) require manual input.`);
  return lines.join('\n');
}


/***/ })

};
