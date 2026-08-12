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
import {
  recordProducer, assertSeparation, recordVerdict, consensusOf, producerIdOf,
  VERIFIER_FALSIFICATION, VERIFIER_LLM_REVIEW,
} from './verification-separation.js';

const DEMOTE_FACTOR = 0.4;               // mirror proof-gate.js
// Stage 3 correctness audit (detection depth): this ladder was missing
// 'critical' — exploitability.js sets f.exploitabilityTier = 'critical' at
// score >= 0.80 (the tier falsification most needs to demote, since it's
// exactly the findings a false "survives" verdict would most overstate).
// _dropTier('critical') hit the `i <= 0` "unknown tier, leave unchanged"
// branch (indexOf returns -1 for an unrecognized value), so a falsified
// finding at the critical exploitability tier kept its full tier — the
// demotion silently no-op'd for the highest tier in the system. 'very-low'
// (confidence.js's own floor tier) is included too, for the same reason
// confidenceTier is demoted by this same function — it was already
// unchanged-at-floor by the same `i <= 0` fallback, so this is a
// completeness fix there, not a behavior change.
const TIERS = ['very-low', 'low', 'medium', 'high', 'critical']; // confidence / exploitability tier order

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
  //
  // Stage 3 correctness audit (detection depth): this was `=== true`, but
  // the field's real producer (engine.js's applySanitizerEffectiveness)
  // sets `f.sanitizerMismatch = f.sanitizerType` — a STRING sanitizer-type
  // label ("Type Guard", "JWT Algo Pinning", ...), never the literal
  // boolean `true`. Every OTHER consumer of this field (confidence.js,
  // exploitability.js, engine.js's own scoring) checks it via plain
  // truthiness; this strict-equality check could never match a real
  // finding, making the whole branch dead code.
  if (finding.sanitizerMismatch) {
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

// Map a falsification-style verdict onto the verification vocabulary.
// 'blocked'/'refuted' = the finding was disproved on this lens; 'survived' =
// the attempt to disprove it failed, so the finding stands on this lens.
function _verdictFor(v) {
  if (v === 'blocked' || v === 'refuted' || v === 'false-positive') return 'refuted';
  if (v === 'survived' || v === 'upheld' || v === 'true-positive') return 'upheld';
  return 'undecided';
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

    // R7 — enforced separation. The detector produced this finding; the
    // falsification pass is a *different* party, and records its verdict only
    // after the separation check passes. Recall-preserving: a 'refuted'
    // verdict is recorded, never acted on by deletion or severity change.
    try {
      recordProducer(f, producerIdOf(f));
      if (assertSeparation(f, VERIFIER_FALSIFICATION).ok) {
        recordVerdict(f, {
          verifierId: VERIFIER_FALSIFICATION,
          lens: 'control-flow',
          verdict: _verdictFor(res.verdict),
          reason: res.reasons && res.reasons[0],
        });
      }
      f.verification.consensus = consensusOf(f);
    } catch { /* verification bookkeeping is advisory; never break the scan */ }

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
        if (llm) {
          f.falsification.llm = llm;
          // A second, independently-identified verifier arguing the opposing
          // case — this is what makes a contested finding visible as contested
          // rather than resolved by whoever spoke last.
          if (assertSeparation(f, VERIFIER_LLM_REVIEW).ok) {
            recordVerdict(f, {
              verifierId: VERIFIER_LLM_REVIEW,
              lens: 'llm-review',
              verdict: _verdictFor(llm.verdict),
              reason: llm.reason,
            });
            f.verification.consensus = consensusOf(f);
          }
        }
      } catch { /* the LLM tier is advisory; never let it break the scan */ }
    }
  }
  return findings;
}
