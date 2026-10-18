// Automatic corpus creation and scoring for ONE candidate rule.
//
// Positive corpus: the original vulnerable snippet plus its generated sibling variants (mutation.js).
// Negative corpus: an explicit patched/clean variant the caller supplies, nearby clean patterns, protected
// (sanitizer/guard) variants, and the NEGATIVE mutations of those (same mutators, applied to the safe side) — a
// candidate rule must decline on ALL of them, not just the one hand-picked negative.
//
// Scoring reuses the exact runtime matcher (`runRule` in `../custom-rules.js`), never a second implementation —
// the score a rule gets here is the score it will actually produce once promoted.
import { generateVariants } from './mutation.js';
import { compileToCustomRule } from './ir.js';
import { runRule } from '../custom-rules.js';

function toRuntimeRule(ir) {
  const { ok, doc, errs } = compileToCustomRule(ir);
  if (!ok) throw new Error(`cannot build corpus for an invalid rule IR: ${errs.join('; ')}`);
  const regexes = doc.match.allOf ? doc.match.allOf.map((p) => new RegExp(p, 'g')) : [new RegExp(doc.match.pattern, 'g')];
  return {
    id: doc.id, title: doc.title, severity: doc.severity, cwe: doc.cwe, languages: doc.languages, message: doc.message,
    regexes, requireAll: !!doc.match.allOf, windowLines: doc.match.window ?? 5,
    notMatch: doc.match.notMatch ? new RegExp(doc.match.notMatch) : null,
  };
}

const EXT = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

export function buildCorpus(ir, { originalCode, patchedCode = null, nearbyCleanCode = [], protectedVariantsCode = [] } = {}) {
  const positives = [{ label: 'original', code: originalCode }];
  for (const v of generateVariants(originalCode)) positives.push({ label: `sibling:${v.mutator}`, code: v.code });

  const negatives = [];
  if (patchedCode) {
    negatives.push({ label: 'patched', code: patchedCode });
    for (const v of generateVariants(patchedCode)) negatives.push({ label: `patched-sibling:${v.mutator}`, code: v.code });
  }
  // The safe side is mutated too (rename, wrapper, equivalent API, ALTERNATE SANITIZER, framework variant, ...): a rule keyed to one
  // sanitizer's name or one framework's accessor fires on the sibling that uses another, and that is a protected-negative failure.
  nearbyCleanCode.forEach((code, i) => {
    negatives.push({ label: `nearby-clean-${i}`, code });
    for (const v of generateVariants(code)) negatives.push({ label: `nearby-clean-${i}-sibling:${v.mutator}`, code: v.code });
  });
  protectedVariantsCode.forEach((code, i) => {
    negatives.push({ label: `protected-${i}`, code });
    for (const v of generateVariants(code)) negatives.push({ label: `protected-${i}-sibling:${v.mutator}`, code: v.code });
  });

  return { positives, negatives };
}

export function scoreRule(ir, corpus) {
  const rule = toRuntimeRule(ir);
  const lang = ir.languages[0] || 'javascript';
  const file = EXT[lang] || 'x.txt';
  const run = (code) => runRule(rule, file, code).length > 0;

  const posResults = corpus.positives.map((p) => ({ ...p, fired: run(p.code) }));
  const negResults = corpus.negatives.map((n) => ({ ...n, fired: run(n.code) }));

  const tp = posResults.filter((p) => p.fired).length;
  const fn = posResults.length - tp;
  const fp = negResults.filter((n) => n.fired).length;
  const tn = negResults.length - fp;
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = corpus.positives.length === 0 ? null : tp / corpus.positives.length;
  // "Protected negative failures" per PRD 3: a rule firing on a sanitizer/guard-carrying variant specifically.
  const protectedFailures = negResults.filter((n) => n.label.startsWith('protected-') && n.fired).length;

  return { precision, recall, tp, fp, tn, fn, protectedFailures, positives: posResults, negatives: negResults };
}
