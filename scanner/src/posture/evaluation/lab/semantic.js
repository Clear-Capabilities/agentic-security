// The semantic secondary view of a frozen run (contract-driven verification, Epic C-03). Evaluator-only: it runs after the hunt is
// frozen, reads references the arms never saw, and NEVER changes the localized score (`score.js`), which stays the headline.
//
// A reference defect may carry a semantic description: the attacker capability, the violated boundary or invariant, the root cause
// (a file and a line span) and the exploitable path's entry point. A finding matches SEMANTICALLY only when it is anchored in source
// (file and line) inside the reference's root-cause span or on its path's entry file, AND an adjudication record says it describes
// the same defect. A CWE match or similar prose alone never matches. A model judge may PROPOSE a match (`proposedBy: 'model'`); a
// proposal alone is `ambiguous`, never a match. A reference counts once however many findings describe it; extra findings on an
// already-matched reference are `duplicate-description`, not extra true positives. A finding that matches no reference is
// `unlabelled-needs-review`, never automatically a false positive.
import { normalizeCwe } from './dataset.js';

const SEMANTIC_OUTCOMES = Object.freeze(['exact-localized', 'semantic-adjudicated', 'ambiguous', 'unmatched']);
// adjudication kinds: `independent-human` (can establish a match) and `model-proposal` (cannot)

const inSpan = (f, span, slack = 0) => span && f.file === span.file && Number.isInteger(f.line) && f.line >= span.startLine - slack && f.line <= span.endLine + slack;

/**
 * @param {object} o
 * @param {object[]} o.references   [{ id, cwe, expectedSpan:{file,startLine,endLine}, semantic?: { capability, boundary, rootCause:{file,startLine,endLine}, entryFile } }]
 * @param {object[]} o.findings     [{ id, file, line, cwe }] the frozen findings of one attempt (staged paths mapped back by the caller)
 * @param {object[]} [o.adjudications] [{ referenceId, findingId, verdict: 'same-defect'|'different-defect', kind, reviewer }]
 * @param {number}   [o.tolerance]  the localized tolerance, for the exact tier only
 */
export function semanticView({ references, findings, adjudications = [], tolerance = 3 }) {
  const out = { references: [], unlabelled: [], counts: Object.fromEntries(SEMANTIC_OUTCOMES.map((k) => [k, 0])), duplicateDescriptions: 0 };
  const claimed = new Set();
  for (const ref of references) {
    const exact = findings.filter((f) => inSpan(f, ref.expectedSpan, tolerance) && normalizeCwe(f.cwe) === normalizeCwe(ref.cwe));
    let outcome; let matched = [];
    if (exact.length) { outcome = 'exact-localized'; matched = exact; }
    else {
      const anchored = findings.filter((f) => (ref.semantic?.rootCause && inSpan(f, ref.semantic.rootCause)) || (ref.semantic?.entryFile && f.file === ref.semantic.entryFile && Number.isInteger(f.line)));
      const adj = (f) => adjudications.filter((a) => a.referenceId === ref.id && a.findingId === f.id);
      const confirmed = anchored.filter((f) => adj(f).some((a) => a.verdict === 'same-defect' && a.kind === 'independent-human'));
      const proposed = anchored.filter((f) => !confirmed.includes(f) && adj(f).some((a) => a.verdict === 'same-defect'));
      if (confirmed.length) { outcome = 'semantic-adjudicated'; matched = confirmed; }
      else if (proposed.length || anchored.length) { outcome = 'ambiguous'; matched = [...proposed, ...anchored.filter((f) => !proposed.includes(f))]; }
      else outcome = 'unmatched';
    }
    out.counts[outcome] += 1;
    if (matched.length > 1 && (outcome === 'exact-localized' || outcome === 'semantic-adjudicated')) out.duplicateDescriptions += matched.length - 1;
    for (const f of matched) claimed.add(f.id);
    out.references.push({ referenceId: ref.id, outcome, findings: matched.map((f) => f.id), reason: outcome === 'ambiguous' ? 'anchored near the root cause or entry, but no independent adjudication says it is the same defect' : null });
  }
  for (const f of findings) if (!claimed.has(f.id)) out.unlabelled.push({ findingId: f.id, status: 'unlabelled-needs-review' });
  // A view that only an independent adjudication can raise; the localized figure is the exact tier and is reported unchanged.
  out.semanticRecall = references.length ? (out.counts['exact-localized'] + out.counts['semantic-adjudicated']) / references.length : null;
  out.localizedRecall = references.length ? out.counts['exact-localized'] / references.length : null;
  return out;
}
