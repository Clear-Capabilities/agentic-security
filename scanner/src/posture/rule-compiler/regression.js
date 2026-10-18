// Regression integration for promoted rules (PRD 3, requirement 8): a promoted rule joins a corpus every later rule and every later
// run is held to, instead of being checked once at promotion and forgotten.
//
//   shared false-positive corpus   the SAFE code of every promoted rule (its patched, nearby-clean and protected variants) plus any file
//                                  the operator drops in `.agentic-security/rule-compiler/fp-corpus/`. A new candidate must not fire
//                                  on any of it, so rule N+1 cannot reintroduce the false positive rule N was built to avoid.
//   regression run                 `rules regress` re-scores every PROMOTED rule against its own corpus, then against the shared false
//                                  positive corpus, and reports any rule that no longer clears its gate (the matcher, the loader or
//                                  another rule changed underneath it).
// The rule-specific unit tests are the fixtures written at evaluation (the existing `rule test` convention); this module adds the cross-rule
// part, which a per-rule check cannot see.
import fs from 'node:fs';
import path from 'node:path';
import { statePath } from '../state-dir.js';
import { buildCorpus, scoreRule } from './corpus.js';
import { evaluateRule } from './promotion.js';
import { runRule, normalizeCustomRule } from '../custom-rules.js';
import { compileToCustomRule } from './ir.js';
import { loadIR, loadCorpus, loadProvenance } from './store.js';
import { stateOf } from './lifecycle.js';

const FP_DIR = 'rule-compiler/fp-corpus';
const MAX_FP_FILE = 256 * 1024;
const MAX_FP_FILES = 500;
const EXT_OF = { '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.py': 'python', '.go': 'go', '.rb': 'ruby', '.java': 'java', '.rs': 'rust', '.cs': 'csharp', '.php': 'php' };

/** Operator-supplied false positives (real code a rule should never flag). Plain files; symlinks and oversized files are ignored. */
function operatorFalsePositives(root) {
  const dir = statePath(root, ...FP_DIR.split('/'));
  const out = [];
  let names = [];
  try { names = fs.readdirSync(dir).sort(); } catch { return out; }
  for (const n of names.slice(0, MAX_FP_FILES)) {
    const f = path.join(dir, n);
    try {
      const st = fs.lstatSync(f);
      if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_FP_FILE) continue;
      out.push({ label: `operator-fp:${n}`, file: n, language: EXT_OF[path.extname(n).toLowerCase()] ?? 'any', code: fs.readFileSync(f, 'utf8') });
    } catch { /* unreadable: skipped */ }
  }
  return out;
}

function promotedRuleIds(ledger) {
  return [...new Set(ledger.entries.map((e) => e.ruleId))].filter((id) => stateOf(ledger, id) === 'PROMOTED');
}

/** The shared false-positive corpus as seen by `exceptId`: the safe code of every OTHER promoted rule, plus the operator's files. */
export function sharedFalsePositiveCorpus(root, ledger, exceptId = null) {
  const items = [];
  for (const id of promotedRuleIds(ledger)) {
    if (id === exceptId) continue;
    const ir = loadIR(root, id); const spec = loadCorpus(root, id);
    if (!ir || !spec || typeof spec.originalCode !== 'string') continue;
    let corpus; try { corpus = buildCorpus(ir, spec); } catch { continue; }
    for (const n of corpus.negatives) items.push({ label: `rule:${id}:${n.label}`, language: ir.languages[0] ?? 'any', code: n.code });
  }
  return [...items, ...operatorFalsePositives(root)];
}

const FILE_FOR_LANG = { javascript: 'x.js', typescript: 'x.ts', python: 'x.py', go: 'x.go', ruby: 'x.rb', java: 'x.java', rust: 'x.rs', csharp: 'x.cs', php: 'x.php', any: 'x.txt' };

/** Which shared false-positive items does this rule fire on? A rule is only run against items written in a language it applies to. */
export function falsePositiveHits(ir, items) {
  const { ok, doc } = compileToCustomRule(ir);
  if (!ok) return [{ label: '(rule does not compile)' }];
  const rule = normalizeCustomRule(doc);
  if (!rule) return [{ label: '(rule would be rejected by the loader)' }];
  const hits = [];
  for (const it of items) {
    const lang = it.language && it.language !== 'any' ? it.language : (ir.languages[0] ?? 'any');
    if (!ir.languages.includes('any') && !ir.languages.includes(lang)) continue;
    if (runRule(rule, FILE_FOR_LANG[lang] ?? 'x.txt', it.code).length > 0) hits.push({ label: it.label });
  }
  return hits;
}

/** Re-score every promoted rule (or one) against its own corpus and the shared false-positive corpus. */
export function regressRules(root, ledger, { only = null, thresholds } = {}) {
  const results = [];
  for (const id of promotedRuleIds(ledger)) {
    if (only && id !== only) continue;
    const ir = loadIR(root, id); const spec = loadCorpus(root, id);
    if (!ir || !spec || typeof spec.originalCode !== 'string') { results.push({ id, status: 'unverifiable', reasons: [!ir ? 'the rule IR is missing' : 'no evaluated corpus was kept for this rule (run rules evaluate --corpus again)'] }); continue; }
    let ev; let corpus;
    try { corpus = buildCorpus(ir, spec); ev = evaluateRule(ir, corpus, thresholds); } catch (e) { results.push({ id, status: 'broken', reasons: [`cannot be scored: ${String(e.message).slice(0, 120)}`] }); continue; }
    const fp = falsePositiveHits(ir, sharedFalsePositiveCorpus(root, ledger, id));
    const baseline = loadProvenance(root, id)?.benchmarkResults ?? null;
    const reasons = [...ev.reasons];
    if (fp.length) reasons.push(`fires on ${fp.length} item(s) of the shared false-positive corpus: ${fp.slice(0, 3).map((h) => h.label).join(', ')}${fp.length > 3 ? ', ...' : ''}`);
    if (baseline && ev.score.recall != null && baseline.recall != null && ev.score.recall < baseline.recall) reasons.push(`recall fell from ${(baseline.recall * 100).toFixed(1)}% to ${(ev.score.recall * 100).toFixed(1)}% since promotion`);
    results.push({ id, status: reasons.length ? 'regressed' : 'ok', reasons, precision: ev.score.precision, recall: ev.score.recall, protectedFailures: ev.score.protectedFailures, fpCorpusHits: fp.length });
  }
  return results;
}
