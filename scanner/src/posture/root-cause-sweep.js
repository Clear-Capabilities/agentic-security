// Addition #3 — Root-cause sweep with total-count accounting.
//
// A detector fires on the instance it can prove. But the same root cause is
// usually copy-pasted across the codebase, and most of those siblings never
// trip a rule (different variable names, an assignment wrapper, a file the
// scanner didn't reach with taint). This module takes CONFIRMED findings and
// sweeps every source line for structural siblings of the same sink, then
// accounts for every match honestly:
//
//     found === candidates + mitigated        (per sweep, always)
//
// where `found` is every structural match across the repo EXCLUDING the
// finding's own origin site, `mitigated` is the subset a detector already
// covered (a finding exists at that file:line), and `candidates` is the
// remainder — new instances nobody has looked at yet. Nothing is dropped.
//
// Matching reuses semantic-clone's normalized token-shape hashing (`shapeHash`)
// so that `db.query(a)` and `db.query(b)` collapse to one shape. Pure shape is
// too loose on its own (`db.query(x)` and `console.log(x)` both normalize to
// `ID.ID(ID)`), so we anchor on the LITERAL callee (`db.query`) and use the
// shape only to confirm the argument arity/structure. Anchor + shape = precise.
//
// Like semantic-clone this is a coarse structural approximation, not a proof of
// semantic equivalence. It catches the common "same call, cloned around" case.

import { shapeHash } from './semantic-clone.js';

// shapeHash defaults to minTokens:8 (tuned to avoid trivial clone collisions on
// whole functions). A single call expression is short — `foo(a)` is 4 tokens,
// `db.query(a)` is 6 — so we lower the floor for call-granular matching.
const MIN_SHAPE_TOKENS = 3;

// A callee whose final segment is one of these is control flow, not a sink call.
const CONTROL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'with', 'do', 'await',
]);

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Accept both a Map and a plain { path: source } object.
function toMap(fileContents) {
  if (fileContents instanceof Map) return fileContents;
  const m = new Map();
  if (fileContents && typeof fileContents === 'object') {
    for (const k of Object.keys(fileContents)) m.set(k, fileContents[k]);
  }
  return m;
}

// A finding qualifies for a sweep when it is confirmed. With confirmedOnly
// disabled we sweep everything (the caller has opted out of the gate).
function qualifies(finding, confirmedOnly) {
  if (!confirmedOnly) return true;
  return finding.confirmed === true || finding.confidenceTier === 'high';
}

// The origin site is the finding's own location; siblings must exclude it.
function originSite(finding) {
  if (finding.sink && finding.sink.file && finding.sink.line != null) {
    return { file: finding.sink.file, line: finding.sink.line };
  }
  return { file: finding.file ?? null, line: finding.line ?? null };
}

// Every file:line that already carries a finding — used to classify a match as
// 'mitigated-or-known' vs. a fresh 'candidate'.
function buildKnownLocations(findings) {
  const set = new Set();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || typeof f !== 'object') continue;
    if (f.file != null && f.line != null) set.add(`${f.file}:${f.line}`);
    if (f.sink && f.sink.file != null && f.sink.line != null) set.add(`${f.sink.file}:${f.sink.line}`);
  }
  return set;
}

// Pull the leading callee path out of a call snippet: `db.query(x)` → `db.query`.
function extractCallee(snippet) {
  if (!snippet || typeof snippet !== 'string') return null;
  const m = snippet.match(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/);
  if (!m) return null;
  const callee = m[1];
  const last = callee.split('.').pop();
  if (CONTROL_KEYWORDS.has(last)) return null;
  return callee;
}

// Extract the full balanced call expression for `callee` from `text`:
// `const r = db.query(f(1), g);` → `db.query(f(1), g)`. Null if absent/unbalanced.
function extractCall(text, callee) {
  if (!text || typeof text !== 'string') return null;
  const re = new RegExp('(?:^|[^\\w$.])' + escapeRegex(callee) + '\\s*\\(');
  const m = re.exec(text);
  if (!m) return null;
  const calleeStart = m.index + m[0].indexOf(callee); // callee offset within the match

  const open = text.indexOf('(', calleeStart);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(calleeStart, i + 1);
    }
  }
  return null; // unbalanced on this line
}

// Structural shape of a sink snippet: hash of the normalized call expression
// (callee + args reduced to token kinds), reusing semantic-clone's hasher.
function sinkShapeOf(snippet) {
  if (!snippet || typeof snippet !== 'string') return null;
  const callee = extractCallee(snippet);
  const call = callee ? (extractCall(snippet, callee) || snippet) : snippet;
  return shapeHash(call, { minTokens: MIN_SHAPE_TOKENS });
}

// Build a searchable pattern from a finding's sink (preferred) or fall back to
// vuln/cwe keywords when no snippet is available.
function deriveSinkPattern(finding) {
  const snippet = finding?.sink?.snippet || finding?.snippet || '';
  const callee = extractCallee(snippet);
  if (callee) {
    return {
      kind: 'call',
      callee,
      shape: sinkShapeOf(snippet),
      regex: new RegExp('(?:^|[^\\w$.])' + escapeRegex(callee) + '\\s*\\('),
      display: `${callee}(…)`,
    };
  }
  const kw = keywordFor(finding);
  if (kw) {
    return { kind: 'keyword', keyword: kw, shape: null, regex: new RegExp(escapeRegex(kw), 'i'), display: kw };
  }
  return null;
}

// Source pattern is reported for context; the sweep itself is sink-driven.
function deriveSourcePattern(finding) {
  const s = finding?.source?.snippet;
  if (s && typeof s === 'string' && s.trim()) return { display: s.trim() };
  const kw = keywordFor(finding);
  if (kw) return { display: kw };
  return null;
}

function keywordFor(finding) {
  const v = (finding?.vuln ?? '').toString().trim();
  if (v) return v;
  const cwe = (finding?.cwe ?? '').toString().trim();
  if (cwe) return cwe;
  return null;
}

// Does a single source line structurally match the sink pattern?
function matchLine(pattern, line) {
  if (!pattern || typeof line !== 'string') return false;
  if (pattern.kind === 'call') {
    if (!pattern.regex.test(line)) return false;      // literal callee anchor
    if (pattern.shape == null) return true;           // anchor-only (snippet too short to shape)
    const call = extractCall(line, pattern.callee);
    if (!call) return false;
    return shapeHash(call, { minTokens: MIN_SHAPE_TOKENS }) === pattern.shape;
  }
  if (pattern.kind === 'keyword') {
    return pattern.regex.test(line);
  }
  return false;
}

/**
 * Sweep confirmed findings for sibling instances of the same root cause.
 *
 * @param {Array<object>} findings   scan findings (confirmed ones drive sweeps)
 * @param {Map|object}    fileContents  { path: source } — Map or plain object
 * @param {object}        opts       { confirmedOnly = true }
 * @returns {{ sweeps: Array<object>, totals: {found,candidates,mitigated} }}
 */
export function sweepRootCauses(findings, fileContents, opts = {}) {
  const confirmedOnly = opts?.confirmedOnly !== false;
  const list = Array.isArray(findings) ? findings : [];
  const files = toMap(fileContents);
  const knownLocations = buildKnownLocations(list);

  const sweeps = [];
  const totals = { found: 0, candidates: 0, mitigated: 0 };

  for (const finding of list) {
    if (!finding || typeof finding !== 'object') continue;
    if (!qualifies(finding, confirmedOnly)) continue;

    const sinkPattern = deriveSinkPattern(finding);
    if (!sinkPattern) continue; // nothing searchable — skip rather than fabricate
    const sourcePattern = deriveSourcePattern(finding);
    const origin = originSite(finding);

    const instances = [];
    for (const [path, source] of files) {
      if (source == null) continue;
      const lines = String(source).split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!matchLine(sinkPattern, line)) continue;
        const lineNo = i + 1;
        if (path === origin.file && lineNo === origin.line) continue; // exclude the finding's own site
        const status = knownLocations.has(`${path}:${lineNo}`) ? 'mitigated-or-known' : 'candidate';
        instances.push({ file: path, line: lineNo, snippet: line.trim(), status });
      }
    }

    const candidates = instances.filter((x) => x.status === 'candidate').length;
    const mitigated = instances.filter((x) => x.status === 'mitigated-or-known').length;
    const found = instances.length; // every match is exactly one status → invariant holds by construction

    sweeps.push({
      fromFindingId: finding.id ?? finding.stableId ?? null,
      sourcePattern: sourcePattern ? sourcePattern.display : null,
      sinkPattern: sinkPattern.display,
      found,
      candidates,
      mitigated,
      remaining: candidates, // unaccounted instances that still need triage
      instances,
    });

    totals.found += found;
    totals.candidates += candidates;
    totals.mitigated += mitigated;
  }

  return { sweeps, totals };
}

/**
 * One short human line per sweep, e.g.:
 *   "root-cause sweep: 20 found, 3 candidate, 17 mitigated"
 */
export function formatSweepLedger(result) {
  if (!result || !Array.isArray(result.sweeps)) return '';
  return result.sweeps
    .map((s) => `root-cause sweep: ${s.found} found, ${s.candidates} candidate, ${s.mitigated} mitigated`)
    .join('\n');
}

export const _internals = {
  MIN_SHAPE_TOKENS,
  sinkShapeOf,
  deriveSinkPattern,
  deriveSourcePattern,
  extractCallee,
  extractCall,
  matchLine,
  qualifies,
  originSite,
  buildKnownLocations,
  toMap,
};
