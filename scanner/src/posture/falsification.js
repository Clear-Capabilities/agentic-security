// Addition #1 — Default falsification pass ("prove it can't be blocked, or demote").
//
// For each taint-style finding we actively try to DISPROVE it: locate a
// context-matched control (a sanitizer whose shape actually neutralizes THIS
// CWE family) on the path between source and sink. A finding that is blocked by
// such a control is "falsified" — demoted and quarantined. A finding with no
// blocking control "survives" and stands.
//
// This is recall-preserving, exactly like `dataflow/proof-gate.js`: a falsified
// finding is DEMOTED (confidence + tiers) and flagged `quarantined`, never
// removed and never severity-touched. Genuine vulnerabilities have no valid
// control on the path, so they survive — the corpus `pre:TP` fixtures stay TP.
//
// An OPTIONAL LLM tier (`opts.llmReview`, wired only when an LLM endpoint is
// configured) argues the opposing case over survivors; it is never required and
// the deterministic core runs fully offline.

import { isValidSanitizerFor } from '../dataflow/sanitizer-proof.js';

const DEMOTE_FACTOR = 0.4;               // mirror proof-gate.js
const TIERS = ['low', 'medium', 'high']; // confidence / exploitability tier order

function _dropTier(tier) {
  const i = TIERS.indexOf(tier);
  if (i <= 0) return tier;               // unknown or already lowest → unchanged
  return TIERS[i - 1];
}

function _fileText(fileContents, file) {
  if (!fileContents || !file) return '';
  if (fileContents instanceof Map) return fileContents.get(file) || '';
  return fileContents[file] || '';
}

// Reconstruct the path window: the source line, the sink line, and the lines
// between/around the sink, plus whatever snippets the finding already carries.
function _pathWindow(finding, fileContents) {
  const parts = [];
  if (finding.source?.snippet) parts.push(String(finding.source.snippet));
  if (finding.sink?.snippet) parts.push(String(finding.sink.snippet));
  const text = _fileText(fileContents, finding.file);
  if (text) {
    const lines = text.split('\n');
    const sinkLine = Number(finding.sink?.line) || 0;
    const srcLine = Number(finding.source?.line) || 0;
    const lo = Math.max(0, Math.min(sinkLine, srcLine) - 3);
    const hi = Math.min(lines.length, Math.max(sinkLine, srcLine) + 3);
    for (let i = lo; i < hi; i++) parts.push(lines[i]);
  }
  return parts.join('\n');
}

/**
 * Pure classifier. Returns `{ verdict, reasons }` with verdict ∈
 *   'blocked'  — a context-matched control for this CWE family sits on the path
 *   'survived' — no blocking control found; the finding stands
 *   'unproven' — not enough context to attempt falsification
 */
export function classifyFinding(finding, fileContents) {
  if (!finding || !finding.cwe || !finding.source || !finding.sink) {
    return { verdict: 'unproven', reasons: ['not a taint-style finding'] };
  }
  // A sanitizer that doesn't match the sink context does NOT block the flow —
  // the finding survives (this is a real bug, not a mitigation).
  if (finding.sanitizerMismatch === true) {
    return { verdict: 'survived', reasons: ['wrong-context sanitizer does not neutralize this sink'] };
  }
  const window = _pathWindow(finding, fileContents);
  if (!window || !window.trim()) {
    return { verdict: 'unproven', reasons: ['no source context available to attempt falsification'] };
  }
  const v = isValidSanitizerFor(window, finding.cwe);
  if (v.trusted) {
    return { verdict: 'blocked', reasons: [`context-matched control on path — ${v.reason}`] };
  }
  return { verdict: 'survived', reasons: ['no context-matched control found between source and sink'] };
}

/**
 * Default-on annotator. Adds `finding.falsification = { verdict, reasons }` to
 * every taint-style finding; demotes + quarantines the ones falsified as blocked.
 * NEVER removes a finding and NEVER mutates severity (recall-preserving).
 *
 * @param opts.llmReview  optional (survivor) => { verdict, reason } — the LLM tier.
 *                        Wired only when an LLM endpoint is configured; run over
 *                        survivors, and its result is attached at .falsification.llm.
 */
export function annotateFalsification(findings, fileContents, opts = {}) {
  if (!Array.isArray(findings)) return findings;
  const survivors = [];
  for (const f of findings) {
    if (!f || !f.source || !f.sink || !f.cwe) continue; // only taint-style findings
    let res;
    try { res = classifyFinding(f, fileContents); }
    catch { res = { verdict: 'unproven', reasons: ['classification error'] }; }
    f.falsification = { verdict: res.verdict, reasons: res.reasons };

    if (res.verdict === 'blocked') {
      f.quarantined = true;
      if (typeof f.confidence === 'number') {
        f.confidence = Math.max(0, Math.round(f.confidence * DEMOTE_FACTOR * 1000) / 1000);
      }
      if (f.confidenceTier) f.confidenceTier = _dropTier(f.confidenceTier);
      if (f.exploitabilityTier) f.exploitabilityTier = _dropTier(f.exploitabilityTier);
      // severity intentionally untouched.
    } else if (res.verdict === 'survived') {
      survivors.push(f);
    }
  }

  // Optional LLM tier — only over survivors, only when a reviewer is supplied.
  if (typeof opts.llmReview === 'function') {
    for (const f of survivors) {
      try {
        const llm = opts.llmReview(f);
        if (llm) f.falsification.llm = llm;
      } catch { /* the LLM tier is advisory; never let it break the scan */ }
    }
  }
  return findings;
}
