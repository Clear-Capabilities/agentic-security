// The synthesis loop for the rule compiler (PRD 3, requirement 5): propose, compile, test positives, test negatives, mutation test,
// score, revise, repeat with bounded attempts, emit a candidate.
//
// "Models propose rules. Evidence promotes rules." A model's proposal (a `match` in the spec) is tried first when there is one.
// When there is none, or it fails, this module proposes deterministically from the two pieces of evidence it has: the vulnerable
// code and its patched twin. The lines that exist only in the vulnerable version say what the flaw looks like; the calls that exist
// only in the patched version say what a safe version looks like (and become the `notMatch` that keeps the rule quiet on safe files).
// No model is consulted here and nothing here promotes a rule: the loop returns attempts and a best candidate, and promotion stays
// with the gate and the lifecycle ledger.
//
// Every attempt is scored against the real corpus (positives with their mutations, negatives with theirs) by the same matcher the
// rule will run on once promoted. An attempt that does not clear the gate is revised from WHY it failed: low recall generalizes,
// a negative that fires adds the safe version's names to `notMatch`.
import { draftRuleIR, validateRuleIR } from './ir.js';
import { buildCorpus } from './corpus.js';
import { evaluateRule } from './promotion.js';

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
const KEYWORDS = new Set(['if', 'else', 'for', 'while', 'return', 'function', 'const', 'let', 'var', 'new', 'await', 'async', 'try', 'catch', 'throw', 'typeof', 'def', 'class', 'import', 'from', 'with', 'in', 'of', 'and', 'or', 'not', 'is', 'func', 'fn', 'public', 'private', 'static', 'void', 'int', 'string']);
const SOURCES = [
  String.raw`req(?:uest)?\.(?:body|query|params|headers|cookies)\b`, String.raw`ctx\.(?:query|params|request\.body)\b`, String.raw`request\.(?:args|form|values|json|GET|POST)\b`,
  String.raw`\$_(?:GET|POST|REQUEST|COOKIE)\b`, String.raw`process\.argv\b`, String.raw`os\.Args\b`, String.raw`\bgetParameter\s*\(`, String.raw`r\.(?:URL\.Query\(\)|FormValue)\b`,
];

const meaningful = (l) => { const t = l.trim(); return t.length >= 8 && !/^(?:\/\/|#|\/\*|\*|[{}()\];,]+$)/.test(t); };

/** Lines (trimmed) present only in `a`. */
function onlyIn(a, b) {
  const bs = new Set(String(b ?? '').split('\n').map((l) => l.trim()));
  return String(a ?? '').split('\n').filter((l) => meaningful(l) && !bs.has(l.trim())).map((l) => l.trim());
}

/** Call names (a.b.c) in some code, in order of appearance, without keywords. */
function callNames(code) {
  const out = [];
  for (const m of String(code).matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g)) if (!KEYWORDS.has(m[1]) && !out.includes(m[1])) out.push(m[1]);
  return out;
}

/** A regular expression for one source line: the call names stay, strings and the other identifiers become classes. */
export function generalizeLine(line) {
  const keep = new Set(callNames(line));
  let out = ''; let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (/\s/.test(c)) { const before = line[i - 1] ?? ''; while (/\s/.test(line[i] ?? '')) i++; out += /[\w$]/.test(before) && /[\w$]/.test(line[i] ?? '') ? String.raw`\s+` : String.raw`\s*`; continue; }
    if (c === '"' || c === "'" || c === '`') { const q = c; let j = i + 1; while (j < line.length && line[j] !== q) j += line[j] === '\\' ? 2 : 1; out += q === '`' ? '`[^`]*`' : `(?:'[^']*'|"[^"]*")`; i = j + 1; continue; }
    const id = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*/.exec(line.slice(i));
    if (id) { const tok = id[0]; const isCall = line[i + tok.length] === '(' || keep.has(tok); out += isCall || KEYWORDS.has(tok) ? esc(tok) : String.raw`[A-Za-z_$][\w$.]*`; i += tok.length; continue; }
    const num = /^\d+(?:\.\d+)?/.exec(line.slice(i));
    if (num) { out += String.raw`\d+(?:\.\d+)?`; i += num[0].length; continue; }
    out += esc(c); i++;
  }
  return out;
}

const sinkOf = (line) => callNames(line).filter((n) => !/^(?:console|logger|log)\b/.test(n))[0] ?? null;
const interpolation = String.raw`(?:\+|\$\{|%s|%d|\.format\s*\(|\bf["']|\|\|)`;

/** Ordered proposals, most specific first. Each is {strategy, match}; `match.notMatch` is added by `withSafeNames`. */
export function proposeCandidates({ vulnerableCode, patchedCode = null }) {
  const vuln = onlyIn(vulnerableCode, patchedCode);
  const lines = vuln.length ? vuln : String(vulnerableCode).split('\n').filter(meaningful).map((l) => l.trim()).filter((l) => callNames(l).length);
  const out = []; const seen = new Set();
  const add = (strategy, match, structure = null) => { const k = JSON.stringify([match, structure]); if (!seen.has(k)) { seen.add(k); out.push({ strategy, ...(match ? { match } : {}), ...(structure ? { structure } : {}) }); } };
  for (const l of lines.slice(0, 3)) add('line-shape', { pattern: generalizeLine(l) });
  for (const l of lines.slice(0, 3)) {
    const sink = sinkOf(l);
    if (sink) add('sink-with-interpolation', { pattern: `${esc(sink)}\\s*\\([^)\\n]*${interpolation}` });
  }
  const sink = lines.map(sinkOf).find(Boolean);
  const src = SOURCES.find((s) => new RegExp(s).test(vulnerableCode));
  if (sink && src) add('source-and-sink', { allOf: [`${esc(sink)}\\s*\\(`, src], window: 6 });
  // the same evidence as an explicit structure: a source and a sink the matcher enforces, so a sanitizer found in the patched code can
  // later be added as a LOCAL guard (dropping one hit) instead of a file-level exclusion (silencing the whole file)
  if (sink && src) add('structural', null, { source: src, sink: `${esc(sink)}\\s*\\(`, window: 6 });
  if (sink) add('sink-call', { pattern: `${esc(sink)}\\s*\\(` });
  return out;
}

/** Names that appear in the patched code and not in the vulnerable code: the safe version's vocabulary. */
export function safeNames({ vulnerableCode, patchedCode }) {
  if (!patchedCode) return [];
  const v = new Set(callNames(vulnerableCode));
  const names = callNames(patchedCode).filter((n) => !v.has(n));
  if (/\?['"`]?\s*[,)]/.test(patchedCode) && !/\?['"`]?\s*[,)]/.test(vulnerableCode)) names.push('?');
  return names;
}

const PLACEHOLDER_RE = '\\?[\'"`]?\\s*[,)]';
const safeRegex = (names) => (names.length ? names.map((n) => (n === '?' ? PLACEHOLDER_RE : esc(n))).join('|') : null);

const summary = (score) => ({ precision: score.precision, recall: score.recall, tp: score.tp, fp: score.fp, fn: score.fn, tn: score.tn, protectedFailures: score.protectedFailures });
const quality = (e) => (e.pass ? 10 : 0) + (e.score.precision ?? 0) * (e.score.recall ?? 0) - e.score.protectedFailures * 0.5;

/**
 * @param {object} o
 * @param {object} o.base      the IR fields that are not the match: id, title, severity, cwe, family, languages, remediation, evidence
 * @param {object} o.corpusSpec  { originalCode, patchedCode?, nearbyCleanCode?, protectedVariantsCode? }
 * @param {object|null} o.proposed  a match supplied by a model or a person, tried first
 * @returns {{attempts: object[], best: object|null, exhausted: boolean}}
 */
export function synthesizeCandidate({ base, corpusSpec, proposed = null, maxAttempts = 6, thresholds, leakageOk = true }) {
  const cap = Math.max(1, Math.min(12, maxAttempts));
  const queue = [];
  if (proposed) queue.push({ strategy: 'proposed', match: proposed });
  for (const p of proposeCandidates({ vulnerableCode: corpusSpec.originalCode, patchedCode: corpusSpec.patchedCode })) queue.push(p);
  const names = safeNames({ vulnerableCode: corpusSpec.originalCode, patchedCode: corpusSpec.patchedCode });
  const attempts = []; const tried = new Set();
  const tryOne = (strategy, match, structure = null) => {
    const key = JSON.stringify([match, structure]);
    if (tried.has(key) || attempts.length >= cap) return null;
    tried.add(key);
    const ir = draftRuleIR({ ...base, ...(match ? { match } : {}), ...(structure ?? {}) });
    const errs = validateRuleIR(ir);
    if (errs.length) { attempts.push({ n: attempts.length + 1, strategy, match: match ?? null, structure, valid: false, errors: errs, pass: false, reasons: errs }); return null; }
    const corpus = buildCorpus(ir, corpusSpec);
    const ev = evaluateRule(ir, corpus, thresholds);
    const rec = { n: attempts.length + 1, strategy, match: match ?? null, structure, valid: true, pass: ev.pass && leakageOk, reasons: ev.reasons, score: summary(ev.score), ir, corpusSizes: { positives: corpus.positives.length, negatives: corpus.negatives.length } };
    attempts.push(rec);
    return { rec, ev };
  };
  for (let qi = 0; qi < queue.length && attempts.length < cap; qi++) {
    const q = queue[qi];
    const first = tryOne(q.strategy, q.match, q.structure);
    if (!first) continue;
    if (first.rec.pass) break;
    // revise from the failure: a negative that fired means the safe version is not excluded yet
    const fired = first.ev.score.negatives.filter((n) => n.fired);
    const rx = safeRegex(names);
    if (fired.length && rx && q.structure && !q.structure.sanitizer) { const r = tryOne(`${q.strategy}+sanitizer`, null, { ...q.structure, sanitizer: rx }); if (r?.rec.pass) break; }
    else if (fired.length && rx && q.match && !q.match.notMatch) { const r = tryOne(`${q.strategy}+exclude-safe`, { ...q.match, notMatch: rx }); if (r?.rec.pass) break; }
  }
  const valid = attempts.filter((a) => a.valid);
  const best = valid.length ? [...valid].sort((a, b) => quality({ pass: b.pass, score: b.score }) - quality({ pass: a.pass, score: a.score }))[0] : null;
  return { attempts: attempts.map(({ ir, ...rest }) => rest), best: best ? { strategy: best.strategy, match: best.match, structure: best.structure, pass: best.pass, score: best.score, reasons: best.reasons } : null, exhausted: !attempts.some((a) => a.pass) };
}
