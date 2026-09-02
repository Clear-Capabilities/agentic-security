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

import { computePrivacyViewModel } from '../../../frontend/src/views/privacy-view.js';
import { GOVERNANCE_FIELDS, MANUAL_REQUIRED } from '../dataflow/privacy-governance.js';
import { _filterGraph } from './export-json.js';

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
  const scopedGraph = filter ? _filterGraph(graph, filter) : graph;
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
export function emitGraphDpiaArtifact(graph, opts = {}) {
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
      for (const field of GOVERNANCE_FIELDS) {
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
    for (const field of GOVERNANCE_FIELDS) {
      const r = merged[field] ?? { value: MANUAL_REQUIRED, source: 'manual_required' };
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
export function emitGraphRopaArtifact(graph, opts = {}) {
  const viewModel = _scopedViewModel(graph, opts.filter);
  const visibleRows = viewModel.rows.filter((r) => r.visible !== false);

  const lines = [];
  lines.push('# Record of Processing Activities (RoPA) — GDPR Art. 30, graph-derived');
  lines.push('');
  lines.push(`Generated by agentic-security scanner (graph-derived) on ${(opts.generatedAt ?? new Date().toISOString()).slice(0, 10)}. Every governance`);
  lines.push('field below is either supplied by an operator');
  lines.push('(.agentic-security/privacy-governance.json) or marked');
  lines.push(`\`${MANUAL_REQUIRED}\` — none are inferable from source code, and none are`);
  lines.push(`guessed. A privacy officer must fill in every \`${MANUAL_REQUIRED}\` cell`);
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
  const header = ['Data class', 'Field', 'Source', 'Destination', 'Protection', ...GOVERNANCE_FIELDS];
  lines.push(`| ${header.join(' | ')} |`);
  lines.push(`|${header.map(() => '---').join('|')}|`);
  let gapCount = 0;
  let rowCount = 0;
  let crossClassRows = false;
  for (const row of visibleRows) {
    for (const cls of row.dataClasses.length ? row.dataClasses : ['(unclassified)']) {
      rowCount++;
      const fieldValues = GOVERNANCE_FIELDS.map((f) => {
        const r = row.governanceRefs?.[f] ?? { value: MANUAL_REQUIRED, source: 'manual_required' };
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
