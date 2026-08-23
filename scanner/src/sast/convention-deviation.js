// PRD Theme 6 — repo-internal convention deviation.
//
// THE IDEA, AND WHY IT IS DIFFERENT FROM EVERY OTHER DETECTOR HERE.
// Every other rule in this directory asks "does this match a known-bad
// pattern?" — which requires someone to have enumerated the pattern first.
// This one asks the inverse: "does this site deviate from what THIS codebase
// has already established as its own correct handling?"
//
// That inversion matters because 10 of the 96 real-world misses root-caused in
// docs/INDEPENDENT_POPULATION_ROOT_CAUSE.md share exactly one shape: the
// correct guard already exists elsewhere in the same file, and one site forgot
// it. No catalog can express that — the guard is the project's own invention.
//
// Worked example (GHSA-9rj7-rf2p-w77r, GitPython CVE, argument injection):
//   Repo.blame / blame_incremental / _clone / archive   →  call
//        Git.check_unsafe_options(...) before forwarding **kwargs to git.*
//   Repo.init                                            →  forwards **kwargs
//        straight to git.init(**kwargs) with no such call
// A `--template=<path>` kwarg becomes a git CLI flag that installs an
// attacker-controlled hook. The fix added exactly the missing guard call.
//
// WHAT THIS DOES NOT CLAIM. A deviation is not a proof of exploitability — it
// is evidence that this site is inconsistent with its own neighbours, which is
// why findings carry the supporting siblings and sit at medium severity. That
// is the honest strength of the signal, and it is deliberately not inflated.
//
// PRECISION CONTROLS (all required before anything is reported):
//   - a real population: at least MIN_GUARDED_SIBLINGS guarded neighbours
//   - a real majority:   guarded / (guarded + unguarded) >= MIN_GUARDED_RATIO
//   - structural similarity: siblings are only compared when they forward
//     caller-controlled options into the SAME primitive receiver, so
//     `TagReference.create(**kwargs)` is never weighed against `git.init(...)`
import { blankComments } from './_comment-strip.js';

const PY_RE = /\.py$/i;
const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;

/** Guard-shaped callee: an action verb applied to a checkable concern. */
// The dotted qualifier is an OPTIONAL single-quantifier group rather than a
// repeated one: `(?:\w+\.)*` is a nested quantifier, which this project's own
// redos-nfa.js flags — correctly, since this scanner runs over untrusted code.
// Accepts both snake_case (`check_unsafe_options`) and camelCase
// (`assertWorkspaceAccess`) so the same comparator works across Python and
// JS/TS. The verb must be followed by `_` or an uppercase letter, so a bare
// `check(x)` or an unrelated `requirement(x)` does not qualify.
const GUARD_CALL_RE = /\b((?:[\w.]{0,120}\.)?(?:check|verify|validate|assert|require|ensure|guard|sanitiz[e]?|authoriz[e]?)(?:_\w{1,64}|[A-Z]\w{0,63}))\s{0,8}\(/;

/** A call that forwards caller-controlled options onward: f(..., **kwargs). */
const FORWARD_INTO_RE = /\b(\w{1,64})\s{0,8}\.\s{0,8}(\w{1,64})\s{0,8}\([^)]{0,400}(?:\*\*|\.{3})\w{1,64}/g;

/** At least this many neighbours must already guard before absence means anything. */
export const MIN_GUARDED_SIBLINGS = 3;
/** And they must be the majority, not a vocal minority. */
export const MIN_GUARDED_RATIO = 0.5;

/**
 * Split Python source into function units: name, signature, body, line.
 * Indentation-based, matching the language; a unit ends at the next `def` at
 * any indent, which is sufficient for the sibling comparison this makes.
 */
export function pythonUnits(code) {
  const lines = code.split('\n');
  const units = [];
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(\s{0,200})(?:async\s{1,8})?def\s{1,8}(\w{1,80})\s{0,8}\(/);
    if (m) {
      if (cur) units.push(cur);
      // Capture the signature across continuation lines by paren balance.
      let j = i, depth = 0, sig = '';
      do {
        sig += lines[j];
        depth += (lines[j].match(/\(/g) || []).length - (lines[j].match(/\)/g) || []).length;
        j++;
      } while (depth > 0 && j < lines.length && j < i + 40);
      // bodyStartLine: `body` collects from the line AFTER the decl, so an
      // offset inside it maps to an absolute line through this.
      // sigSpan: how many SOURCE lines the signature occupies. The loop above
      // appends continuation lines to `body`, so without this the "first body
      // line" is really still part of the parameter list.
      cur = { name: m[2], indent: m[1].length, line: i + 1, bodyStartLine: i + 2, sigSpan: j - i, sig, body: [] };
    } else if (cur) {
      cur.body.push(lines[i]);
    }
  }
  if (cur) units.push(cur);
  return units.map(u => ({ ...u, body: u.body.join('\n') }));
}

/**
 * Split brace-language source into function units.
 *
 * Recognises the four shapes that carry a guard-then-forward convention in
 * JS/TS: `function name(...)`, `name(...) {` class methods, `name = (...) =>`,
 * and `async` variants of each. The body is taken by brace matching from the
 * opening `{`, which is sufficient for the sibling comparison this makes —
 * this is a convention comparator, not a parser.
 *
 * 6 of the 10 known sibling-omission entries are TypeScript, and were
 * unreachable while this module was Python-only.
 */
export function jsUnits(code) {
  const units = [];
  const lines = code.split('\n');
  const DECL = /(?:^|\s)(?:(?:async\s{1,4})?function\s{1,4}(\w{1,80})\s{0,4}\(|(?:public|private|protected|static|async)\s{1,4}(\w{1,80})\s{0,4}\(|(?:const|let|var)\s{1,4}(\w{1,80})\s{0,4}=\s{0,4}(?:async\s{1,4})?\(|^\s{0,80}(\w{1,80})\s{0,4}\([^)]{0,400}\)\s{0,4}\{)/;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DECL);
    if (!m) continue;
    const name = m[1] || m[2] || m[3] || m[4];
    if (!name || /^(?:if|for|while|switch|catch|return|typeof|new)$/.test(name)) continue;
    // Signature: from the decl to the first `{` (may span lines).
    let sig = '', j = i, open = -1;
    for (; j < lines.length && j < i + 20; j++) {
      sig += lines[j];
      const k = lines[j].indexOf('{', j === i ? m.index : 0);
      if (k !== -1) { open = j; break; }
    }
    if (open === -1) continue;
    // Body by brace matching from `open`.
    let depth = 0, body = [], done = false;
    for (let b = open; b < lines.length && !done; b++) {
      const text = lines[b];
      for (const ch of text) { if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth === 0) { done = true; break; } } }
      body.push(text);
    }
    units.push({ name, line: i + 1, bodyStartLine: open + 1, sig, body: body.join('\n') });
    i = open;
  }
  return units;
}

/**
 * The core, pure analysis. Takes units from the WHOLE PROJECT — each tagged
 * with its file — and reports sites that skip the guard their peers apply.
 *
 * WHY PROJECT-SCOPED, NOT PER-FILE. The first version analysed one file at a
 * time and measured 1 of 10 against its own exit gate. Diagnosis: the
 * convention is a property of the CODEBASE, not of a file.
 * `Git.check_unsafe_options` is called from git/repo/base.py (5 sites),
 * git/index/base.py (2) and git/objects/commit.py (1) — project-wide an
 * unambiguous 8-site convention, but per-file it fragments into populations of
 * 5, 2 and 1, and only the first clears MIN_GUARDED_SIBLINGS. Lowering the
 * threshold would have been the wrong fix: it weakens the precision control
 * everywhere instead of restoring the population that genuinely exists.
 */

// Where the missing guard BELONGS: the first executable statement of the body.
//
// A "this function omits the guard its peers apply" finding is function-scoped,
// and the three candidate lines it could carry are not equivalent:
//
//   the `def` line        — not actionable, and furthest from the fix
//   the forwarding call   — actionable, but the guard goes ABOVE it
//   the first statement   — exactly where a remediation inserts the guard
//
// Measured on this detector's own source advisory (GHSA-9rj7-rf2p-w77r): the
// upstream fix inserts `Git.check_unsafe_options(...)` as the first statement
// of `init()`, at pre-line 1431. The `def` is at 1395 and the forwarding call
// at 1439 — both far outside the ±3 localization window, while the insertion
// point is inside it. The detector was never wrong about WHICH function; it was
// pointing at the wrong line within it.
//
// Skips the docstring, because nobody inserts a guard above one.
function guardInsertionLine(u) {
  if (!Number.isInteger(u.bodyStartLine)) return u.line;
  const lines = String(u.body || '').split('\n');
  let i = 0;
  // Python signature continuation lines land in the body; skip until the
  // signature's parentheses have closed.
  i = Math.max(0, (u.sigSpan || 1) - 1);
  while (i < lines.length && !lines[i].trim()) i++;
  const DOC = new RegExp('^[rubf]{0,2}(' + '"'.repeat(3) + "|'''" + ')');
  const head = (lines[i] || '').trim();
  const doc = head.match(DOC);
  if (doc) {
    const q = doc[1];
    if (!head.slice(doc[0].length).includes(q)) {   // multi-line docstring
      i++;
      while (i < lines.length && !lines[i].includes(q)) i++;
    }
    i++;
    while (i < lines.length && !lines[i].trim()) i++;
  }
  return u.bodyStartLine + Math.min(i, Math.max(lines.length - 1, 0));
}

export function analyseUnits(units) {
  // receiver -> { guarded: [...], unguarded: [...] }
  const groups = new Map();
  for (const u of units) {
    // Python `**kwargs` / JS `...opts` — the option bag this compares on.
    if (!/\*\*\w+|\.{3}\w/.test(u.sig)) continue;
    const forwards = [...u.body.matchAll(FORWARD_INTO_RE)];
    if (!forwards.length) continue;                          // never forwards it on
    const guard = u.body.match(GUARD_CALL_RE);
    for (const f of forwards) {
      const receiver = f[1];
      // `self.<method>` delegates to a sibling; the guard, if any, belongs to
      // that sibling. Grouping on it would compare a method against itself
      // one hop away.
      if (receiver === 'self' || receiver === 'cls' || receiver === 'this') continue;
      if (!groups.has(receiver)) groups.set(receiver, { guarded: [], unguarded: [] });
      const g = groups.get(receiver);
      const key = `${u.file}::${u.name}`;
      // Report the FORWARDING CALL, not the `def` line.
      //
      // Two reasons, and the second is why it changed. (1) The call is where a
      // reader has to look and where the guard has to go; a function signature
      // is not actionable. (2) Measured against bench/independent, this
      // detector fired on the right file with the right CWE on its own source
      // advisory (GHSA-9rj7-rf2p-w77r) and still scored zero, because the
      // finding sat on `def init(` at line 1395 while the fix landed at 1400 —
      // five lines away, against a ±3 localization window. It was never a
      // detection gap. Widening the window would have been benchmark gaming;
      // pointing at the line the remediation actually touches is just correct.
      const callLine = Number.isInteger(u.bodyStartLine)
        ? u.bodyStartLine + u.body.slice(0, f.index).split('\n').length - 1
        : u.line;
      const row = {
        name: u.name, line: guardInsertionLine(u), defLine: u.line, callLine,
        file: u.file, into: `${f[1]}.${f[2]}`,
      };
      if (guard) { if (!g.guarded.some(x => `${x.file}::${x.name}` === key)) g.guarded.push({ ...row, guard: guard[1] }); }
      else if (!g.unguarded.some(x => `${x.file}::${x.name}` === key)) g.unguarded.push(row);
    }
  }

  const out = [];
  for (const [receiver, g] of groups) {
    if (g.guarded.length < MIN_GUARDED_SIBLINGS) continue;
    const total = g.guarded.length + g.unguarded.length;
    if (g.guarded.length / total < MIN_GUARDED_RATIO) continue;
    const tally = new Map();
    for (const x of g.guarded) tally.set(x.guard, (tally.get(x.guard) || 0) + 1);
    const consensusGuard = [...tally.entries()].sort((a, b) => b[1] - a[1])[0][0];
    for (const u of g.unguarded) {
      out.push({
        ...u, receiver, consensusGuard,
        guardedSiblings: g.guarded.map(x => (x.file === u.file ? x.name : `${x.file}:${x.name}`)),
        ratio: g.guarded.length / total,
      });
    }
  }
  return out;
}

function _finding(d) {
  return {
    id: `convention-deviation:guard-omitted:${d.file}:${d.line}:${d.name}`,
    file: d.file, line: d.line,
    vuln: `Convention deviation — ${d.name}() forwards caller-controlled options to ${d.into} without the ${d.consensusGuard}() guard its peers apply`,
    severity: 'medium',
    cwe: 'CWE-88',
    family: 'convention-deviation',
    parser: 'CONVENTION',
    confidence: 0.55,
    description:
      `${d.guardedSiblings.length} other method(s) in this project — ${d.guardedSiblings.slice(0, 6).join(', ')} — call ` +
      `${d.consensusGuard}() before forwarding an option bag to ${d.receiver}.*, and ${d.name}() does not. ` +
      'Where those options become command-line flags, an unvalidated option bag lets a caller inject flags the ' +
      'author never intended (arbitrary file read/write, or code execution via a hook-installing flag).',
    remediation:
      `Apply the same guard the neighbouring methods use — ${d.consensusGuard}() — to ${d.name}()'s options before ` +
      'forwarding them, or document why this call site is exempt.',
    checkedFor: `${d.consensusGuard}() call in ${d.name}(); compared against ${d.guardedSiblings.length} peer(s) forwarding into ${d.receiver}.*`,
    evidenceSiblings: d.guardedSiblings,
  };
}

/**
 * Project-level entry point. `fileContents` is the engine's `fc` map
 * (path -> source), so the convention population spans the whole codebase.
 */
export function scanConventionDeviationProject(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const units = [];
  for (const [file, raw] of Object.entries(fileContents)) {
    if (!raw || typeof raw !== 'string' || raw.length > 500_000) continue;
    const isPy = PY_RE.test(file), isJs = JS_RE.test(file);
    if (!isPy && !isJs) continue;
    // Cheap relevance gate: the option-bag spread this detector compares on.
    if (isPy && !/\*\*\w+/.test(raw)) continue;
    if (isJs && !/\.{3}\w/.test(raw)) continue;
    try {
      const us = isPy ? pythonUnits(blankComments(raw, 'py')) : jsUnits(blankComments(raw));
      for (const u of us) units.push({ ...u, file, lang: isPy ? 'py' : 'js' });
    } catch { /* per-file best-effort, same as every other detector here */ }
  }
  if (!units.length) return [];
  try { return analyseUnits(units).map(_finding); } catch { return []; }
}

/** Single-file convenience wrapper — the project view of one file. */
export function scanConventionDeviation(file, raw) {
  return scanConventionDeviationProject({ [file]: raw });
}

export const _internals = { GUARD_CALL_RE, FORWARD_INTO_RE, pythonUnits, jsUnits, analyseUnits };
