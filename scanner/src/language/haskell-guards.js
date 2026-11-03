// Dominating-guard recognition for Haskell taint findings (HS-003.AC03).
//
// A finding is only refuted by a control that (a) is a real condition in the code, (b) actually
// DOMINATES the sink (the sink is reachable only through the branch on which the condition makes the
// value safe), and (c) is the RIGHT KIND of control for the finding's vulnerability family. All three
// are judged on the IR, never on adjacent text:
//
//   - structural branches  `if c then A else B` and guards: the IR records which condition selects
//     which branch (`hs.branchConds`), so a sink inside branch i inherits that fact;
//   - exit guards          `unless safe (throwIO e)` / `when unsafe (die m)` earlier in a `do` block,
//     counted only when the call node dominates the sink node in the CFG (removing it makes the sink
//     unreachable from entry).
//
// Context matters. A `..` check or a containment check is a PATH control and says nothing about SQL or
// a URL; an allow-list membership or a character-class check holds for any family. A containment
// check (`isPrefixOf base v`) counts only when `v` was canonicalised, because `base ++ "/../x"` also
// has the prefix. A weak guard is reported as a note on the finding and does not refute it.

const CANON_CALLS = new Set(['System.Directory.canonicalizePath', 'System.Directory.makeAbsolute', 'System.FilePath.normalise']);
import { HS_SANITIZERS } from './haskell-models.js';
// the catalog's HTML escapers (blaze, lucid): the same list the taint catalog is generated from
const CATALOG_HTML_ESCAPERS = new Set(HS_SANITIZERS.filter((s) => (s.appliesTo || []).includes('xss')).map((s) => `${s.module}.${s.name}`));
const EXIT_CALLS = new Set(['Control.Exception.throwIO', 'Control.Exception.throw', 'System.Exit.die', 'System.Exit.exitFailure', 'System.Exit.exitWith', 'throwIO', 'throw', 'die', 'exitFailure', 'exitWith', 'error', 'fail', 'ioError', 'Control.Monad.Fail.fail']);
const WHEN = new Set(['Control.Monad.when', 'when']);
const UNLESS = new Set(['Control.Monad.unless', 'unless']);
const IS_ELEM = new Set(['Data.List.elem', 'Prelude.elem', 'elem', 'Data.Foldable.elem']);
const NOT_ELEM = new Set(['Data.List.notElem', 'Prelude.notElem', 'notElem', 'Data.Foldable.notElem']);
const IS_MEMBER = /^Data\.(?:Set|HashSet|Map|Map\.Strict|HashMap\.Strict)\.member$/;
const NOT_MEMBER = /^Data\.(?:Set|HashSet|Map|Map\.Strict|HashMap\.Strict)\.notMember$/;
const CHARCLASS = new Set(['Data.Char.isAlphaNum', 'Data.Char.isAlpha', 'Data.Char.isDigit', 'Data.Char.isAscii', 'isAlphaNum', 'isAlpha', 'isDigit']);

const FAMILY_BY_CWE = { 'CWE-22': 'path', 'CWE-918': 'url', 'CWE-78': 'cmd', 'CWE-88': 'cmd', 'CWE-89': 'sql', 'CWE-79': 'xss', 'CWE-601': 'redirect', 'CWE-94': 'code', 'CWE-1427': 'prompt' };

const isStr = (e) => e && e.kind === 'literal' && typeof e.value === 'string';

export function identNames(e, out = new Set(), depth = 0) {
  if (!e || typeof e !== 'object' || depth > 30) return out;
  if (e.kind === 'ident' && e.name && !(e.hs && e.hs.functionRef)) out.add(e.name);
  for (const k of ['left', 'right', 'object', 'value', 'callee']) if (e[k] && typeof e[k] === 'object') identNames(e[k], out, depth + 1);
  for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) for (const x of e[k]) identNames(x, out, depth + 1);
  if (Array.isArray(e.props)) for (const p of e.props) identNames(p && p.value, out, depth + 1);
  return out;
}

const mentions = (e, vars) => { for (const n of identNames(e)) if (vars.has(n)) return true; return false; };

/** Classify a condition over the value `vars`. -> {safeWhen, kind, families, needsCanon?, subject} | null */
export function classifyCondition(c, vars, derived = new Set()) {
  if (!c || typeof c !== 'object') return null;
  // The IR lowers `&&` / `||` to a `logical` node (`and` / `or`); a `binary` node is kept for the same operators from other lowerings.
  if (c.kind === 'logical' && (c.op === 'and' || c.op === 'or')) return classifyCondition({ kind: 'binary', op: c.op === 'and' ? '&&' : '||', left: c.left, right: c.right }, vars, derived);
  if (c.kind === 'binary') {
    if (c.op === '&&') { const a = classifyCondition(c.left, vars, derived); const b = classifyCondition(c.right, vars, derived); return [a, b].find((x) => x && x.safeWhen === true) || null; }
    if (c.op === '||') { const a = classifyCondition(c.left, vars, derived); const b = classifyCondition(c.right, vars, derived); return [a, b].find((x) => x && x.safeWhen === false) || null; }
    if (c.op === '==' || c.op === '===') {
      const pair = (l, r) => l && l.kind === 'call' && /(?:^|\.)takeFileName$/.test(l.callee || '') && l.args && l.args[0] && r && r.kind === 'ident' && l.args[0].kind === 'ident' && l.args[0].name === r.name && vars.has(r.name);
      if (pair(c.left, c.right) || pair(c.right, c.left)) return { safeWhen: true, kind: 'bare-filename', families: ['path'], subject: (c.left.kind === 'ident' ? c.left : c.right).name };
    }
    return null;
  }
  if (c.kind !== 'call') return null;
  const name = c.callee || '';
  const a = c.args || [];
  if (name === 'not' || name === 'Prelude.not') { const inner = classifyCondition(a[0], vars, derived); return inner ? { ...inner, safeWhen: !inner.safeWhen } : null; }
  if (name === 'Data.List.isInfixOf' && isStr(a[0]) && a[0].value.includes('..') && a[1] && a[1].kind === 'ident' && vars.has(a[1].name)) {
    return { safeWhen: false, kind: 'traversal-check', families: ['path'], subject: a[1].name };
  }
  if (name === 'Data.List.isPrefixOf' && a[1] && a[1].kind === 'ident' && vars.has(a[1].name)) {
    // A URL that must start with a scheme-and-host literal ending in "/" cannot name another host: an allow-list for the
    // URL family. A path prefix is only a weak check unless canonicalised (a "/../" survives it).
    if (isStr(a[0]) && /^[a-z][a-z0-9+.-]*:\/\/[^/@?#\s]+\/(?:[^\s]*)$/i.test(a[0].value)) return { safeWhen: true, kind: 'host-anchored-prefix', families: ['url'], subject: a[1].name };
    return { safeWhen: true, kind: 'containment', families: ['path'], needsCanon: true, subject: a[1].name };
  }
  // `".." `elem` splitDirectories v`: the path has a parent-directory component (and `notElem` is the opposite)
  if ((IS_ELEM.has(name) || NOT_ELEM.has(name)) && isStr(a[0]) && a[0].value === '..' && a[1] && a[1].kind === 'call' && /(?:^|\.)(?:splitDirectories|splitPath)$/.test(a[1].callee || '') && a[1].args && a[1].args[0] && a[1].args[0].kind === 'ident' && vars.has(a[1].args[0].name)) {
    return { safeWhen: NOT_ELEM.has(name), kind: 'traversal-check', families: ['path'], subject: a[1].args[0].name };
  }
  // `uriRegName a `elem` ["api.example.com"]` where `a` was parsed from the checked URL: the host is on an allow-list, which is the
  // URL family's control. Only a HOST accessor over a value derived from the checked one counts (a path or query allow-list does not).
  // The list may be written inline (a literal list of strings) or be a named constant (`allowedHosts`): either way it must not be built from the
  // checked value, or the check would compare the value with itself.
  const fixedList = (l) => l && ((l.kind === 'array' && l.elements.length && l.elements.every((x) => isStr(x) || (x && x.kind === 'call' && /(?:^|\.)(?:pack|fromString)$/.test(x.callee || '') && x.args && x.args.length === 1 && isStr(x.args[0]))))
    || (l.kind === 'ident' && !mentions(l, vars) && !mentions(l, derived)));
  if ((IS_ELEM.has(name) || NOT_ELEM.has(name)) && a[0] && a[0].kind === 'call' && /(?:^|\.)(?:uriRegName|uriAuthority|getHost|host|hostName)$/.test(a[0].callee || '') && a[0].args && a[0].args[0] && a[0].args[0].kind === 'ident'
      && (vars.has(a[0].args[0].name) || derived.has(a[0].args[0].name)) && fixedList(a[1])) {
    return { safeWhen: IS_ELEM.has(name), kind: 'host-allow-list', families: ['url'], subject: a[0].args[0].name };
  }
  if ((IS_ELEM.has(name) || NOT_ELEM.has(name)) && a[0] && a[0].kind === 'ident' && vars.has(a[0].name) && !mentions(a[1], vars)) {
    return { safeWhen: IS_ELEM.has(name), kind: 'allow-list', families: ['*'], subject: a[0].name };
  }
  if ((IS_MEMBER.test(name) || NOT_MEMBER.test(name)) && a[0] && a[0].kind === 'ident' && vars.has(a[0].name) && !mentions(a[1], vars)) {
    return { safeWhen: IS_MEMBER.test(name), kind: 'allow-list', families: ['*'], subject: a[0].name };
  }
  if ((name === 'all' || name === 'Prelude.all' || name === 'Data.List.all') && a[0] && a[0].kind === 'ident' && CHARCLASS.has(a[0].name) && a[1] && a[1].kind === 'ident' && vars.has(a[1].name)) {
    return { safeWhen: true, kind: 'character-class', families: ['*'], subject: a[1].name };
  }
  return null;
}

function nodeList(fn) { return Object.entries(fn.cfg.nodes).map(([id, n]) => ({ id, ...n })); }

function reachableWithout(fn, skipId, targetId) {
  const seen = new Set();
  const stack = [fn.cfg.entry];
  while (stack.length) {
    const id = stack.pop();
    if (id === skipId || seen.has(id)) continue;
    if (id === targetId) return true;
    seen.add(id);
    for (const s of fn.cfg.nodes[id].succ || []) stack.push(s);
  }
  return false;
}

const exprChildren = (e) => {
  const out = [];
  for (const k of ['left', 'right', 'object', 'value', 'callee']) if (e[k] && typeof e[k] === 'object') out.push([k, e[k]]);
  for (const k of ['args', 'elements', 'parts']) if (Array.isArray(e[k])) e[k].forEach((x, i) => out.push([`${k}${i}`, x]));
  if (Array.isArray(e.props)) e.props.forEach((p, i) => p && p.value && out.push([`props${i}`, p.value]));
  return out;
};

// Find the sink call at `line` with callee `callee`; returns [{ nodeId, facts, call }].
export function findSites(fn, callee, line) {
  const sites = [];
  // `callee` is a name, or a pattern when several spellings of one operation are wanted (`readFile`, `T.readFile`, `B.readFile`)
  const named = typeof callee === 'string' ? (c) => c === callee : (c) => typeof c === 'string' && callee.test(c);
  const visit = (e, nodeId, facts, depth) => {
    if (!e || typeof e !== 'object' || depth > 60) return;
    if (e.kind === 'call' && named(e.callee) && (e.line === line || nodeLine(nodeId) === line)) sites.push({ nodeId, facts, call: e });
    if (e.kind === 'union') {
      const bc = e.hs && e.hs.branchConds;
      e.branches.forEach((b, i) => visit(b, nodeId, bc && bc[i] ? [...facts, bc[i]] : facts, depth + 1));
      return;
    }
    for (const [, c] of exprChildren(e)) visit(c, nodeId, facts, depth + 1);
  };
  const nodeLine = (id) => (fn.cfg.nodes[id] ? fn.cfg.nodes[id].line : -1);
  for (const n of nodeList(fn)) {
    if (n.kind === 'call' && named(n.callee) && n.line === line) sites.push({ nodeId: n.id, facts: [], call: { kind: 'call', callee: n.callee, args: n.args || [] } });
    for (const k of ['source', 'value', 'cond']) if (n[k]) visit(n[k], n.id, [], 0);
    if (Array.isArray(n.args) && n.kind === 'call') for (const a of n.args) visit(a, n.id, [], 0);
  }
  return sites;
}

function reachableWithoutEdge(fn, from, to, target) {
  const seen = new Set();
  const stack = [fn.cfg.entry];
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    if (id === target) return true;
    seen.add(id);
    for (const s of fn.cfg.nodes[id].succ || []) { if (id === from && s === to) continue; stack.push(s); }
  }
  return false;
}

// Facts from the CFG's own `if` structure: a node reachable only through ONE outgoing edge of an `if`
// node runs only when that branch's condition holds (then) or fails (else).
function cfgBranchFacts(fn, siteNodeId) {
  const facts = [];
  for (const n of nodeList(fn)) {
    if (n.kind !== 'if' || !n.cond || (n.thenEntry === undefined && (n.succ || []).length !== 2) || n.thenEntry === n.elseEntry) continue;
    // `thenEntry`/`elseEntry` are recorded by the IR: the successor order alone is not then/else.
    const thenEntry = n.thenEntry ?? n.succ[0];
    const elseEntry = n.elseEntry ?? n.succ[1];
    const viaThen = reachableWithoutEdge(fn, n.id, elseEntry, siteNodeId);   // reachable with the else edge removed
    const viaElse = reachableWithoutEdge(fn, n.id, thenEntry, siteNodeId);
    if (viaThen && !viaElse) facts.push({ cond: n.cond, when: true, line: n.line });
    else if (viaElse && !viaThen) facts.push({ cond: n.cond, when: false, line: n.line });
  }
  return facts;
}

// `unless C (exit)` / `when C (exit)` call nodes that dominate `siteNodeId`.
function exitGuardFacts(fn, siteNodeId) {
  const facts = [];
  for (const n of nodeList(fn)) {
    if (n.kind !== 'call' || n.id === siteNodeId) continue;
    const isWhen = WHEN.has(n.callee), isUnless = UNLESS.has(n.callee);
    if (!isWhen && !isUnless) continue;
    const [cond, action] = n.args || [];
    if (!cond || !action || !containsExit(action)) continue;
    if (reachableWithout(fn, n.id, siteNodeId)) continue;           // does not dominate
    // continuing past `unless C exit` means C held; past `when C exit` means C did not
    facts.push({ cond, when: isUnless, line: n.line, via: isUnless ? 'unless' : 'when' });
  }
  return facts;
}

function containsExit(e, depth = 0) {
  if (!e || typeof e !== 'object' || depth > 20) return false;
  if (e.kind === 'call' && EXIT_CALLS.has(e.callee)) return true;
  for (const [, c] of exprChildren(e)) if (containsExit(c, depth + 1)) return true;
  return false;
}

// The variables a value was built from: for `req <- parse target`, the origins of `req` include `target` (transitively).
function originsOf(fn, seed) {
  const out = new Set(seed);
  const assigns = nodeList(fn).filter((n) => n.kind === 'assign' && n.target && n.source);
  for (let round = 0; round < 8; round++) {
    let grew = false;
    for (const n of assigns) if (out.has(n.target)) for (const v of identNames(n.source)) if (!out.has(v)) { out.add(v); grew = true; }
    if (!grew) break;
  }
  for (const v of seed) out.delete(v);
  return out;
}

// Variables assigned from an expression that mentions one of `seed` (transitively, bounded): the values derived from it.
function derivedFrom(fn, seed) {
  const out = new Set(seed);
  const assigns = nodeList(fn).filter((n) => n.kind === 'assign' && n.target && n.source);
  for (let round = 0; round < 8; round++) {
    let grew = false;
    for (const n of assigns) if (!out.has(n.target) && mentions(n.source, out)) { out.add(n.target); grew = true; }
    if (!grew) break;
  }
  for (const v of seed) out.delete(v);
  return out;
}

/**
 * One flow reaching several sinks of one family in one function (`req <- parseRequest u; httpLbs req m`) is ONE finding:
 * the later sink's argument is derived from the earlier sink's argument. The earliest sink is kept, the others are listed
 * on it as `relatedSinks`, and the highest severity wins. Independent flows (a different tainted value) stay separate.
 * Mutates `findings` in place; returns the number merged.
 */
export function consolidateFlowSinks(findings, perFile) {
  const live = (findings || []).filter((f) => f && f.parser === 'IR-TAINT' && /\.(?:l?hs|hsc)$/i.test(String(f.file || '')) && f._funcQid && f.callee && !f._provenUnreachable);
  const groups = new Map();
  for (const f of live) { const k = `${f.file}|${f._funcQid}|${f.cwe}`; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(f); }
  const drop = new Set();
  const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  for (const list of groups.values()) {
    if (list.length < 2) continue;
    list.sort((a, b) => a.line - b.line);
    const ir = perFile && perFile[list[0].file];
    const fn = ir && ir.functions.find((x) => x.qid === list[0]._funcQid);
    if (!fn) continue;
    const argVars = (f) => { const site = findSites(fn, f.callee, f.line)[0]; const e = site && (site.call.args || [])[Number.isInteger(f.argIndex) ? f.argIndex : 0]; return e ? identNames(e) : new Set(); };
    for (let i = 0; i < list.length; i++) {
      const head = list[i];
      if (drop.has(head)) continue;
      const headVars = argVars(head);
      if (!headVars.size) continue;
      const derived = derivedFrom(fn, headVars);
      for (let j = i + 1; j < list.length; j++) {
        const later = list[j];
        if (drop.has(later)) continue;
        // the later sink must be handed a bare variable BUILT from the earlier sink's argument, not the same value again:
        // `readIt (takeFileName l)` and `readIt l` are two separate flows with their own sanitizer verdicts.
        const lv = argVars(later);
        const site = findSites(fn, later.callee, later.line)[0];
        const lateArg = site && (site.call.args || [])[Number.isInteger(later.argIndex) ? later.argIndex : 0];
        if (!lateArg || lateArg.kind !== 'ident' || lv.size !== 1 || !derived.has([...lv][0])) continue;
        drop.add(later);
        head.relatedSinks = [...(head.relatedSinks || []), { line: later.line, callee: later.callee }];
        if ((SEV[later.severity] || 0) > (SEV[head.severity] || 0)) head.severity = later.severity;
      }
    }
  }
  if (!drop.size) return 0;
  for (let i = findings.length - 1; i >= 0; i--) if (drop.has(findings[i])) findings.splice(i, 1);
  return drop.size;
}

function isCanonical(fn, name) {
  for (const n of nodeList(fn)) {
    if (n.kind === 'assign' && n.target === name && n.source && n.source.kind === 'call' && CANON_CALLS.has(n.source.callee)) return true;
  }
  return false;
}

// A hand-written HTML escaper: a project function (or one of its local helpers) that spells out the entities for `<`, `>` and `&`. Recognised by
// what the code does (it produces those entity strings), never by its name. Kept per IR build.
const ESCAPERS = new WeakMap();
const ENTITY = { lt: /&lt;|&#0*60;|&#x0*3c;/i, gt: /&gt;|&#0*62;|&#x0*3e;/i, amp: /&amp;|&#0*38;|&#x0*26;/i };
function stringLiteralsOf(fn) {
  const out = [];
  const visit = (e, depth) => {
    if (!e || typeof e !== 'object' || depth > 60) return;
    if (e.kind === 'literal' && typeof e.value === 'string') out.push(e.value);
    for (const [, c] of exprChildren(e)) visit(c, depth + 1);
    if (Array.isArray(e.branches)) for (const b of e.branches) visit(b, depth + 1);   // the arms of a conditional or a multi-clause function
  };
  for (const n of nodeList(fn)) { for (const k of ['source', 'value', 'cond']) visit(n[k], 0); if (Array.isArray(n.args)) for (const a of n.args) visit(a, 0); }
  return out;
}
export function htmlEscapers(perFile) {
  if (!perFile || typeof perFile !== 'object') return new Set();
  let hit = ESCAPERS.get(perFile);
  if (hit) return hit;
  hit = new Set();
  for (const ir of Object.values(perFile)) {
    const fns = ir.functions || [];
    // local helpers and lambdas record their parent's qid: one pass groups them, so the whole file costs one visit per function
    const children = new Map();
    for (const fn of fns) { const par = fn.hs && fn.hs.parent; if (par) { if (!children.has(par)) children.set(par, []); children.get(par).push(fn); } }
    const lits = new Map();
    const litsOf = (fn, depth = 0) => {
      if (lits.has(fn.qid)) return lits.get(fn.qid);
      let out = stringLiteralsOf(fn);
      if (depth < 8) for (const c of children.get(fn.qid) || []) out = out.concat(litsOf(c, depth + 1));
      lits.set(fn.qid, out);
      return out;
    };
    for (const fn of fns) {
      if (!fn.name || fn.name.endsWith('.<module>') || (fn.hs && (fn.hs.kind === 'closure' || fn.hs.kind === 'local-function'))) continue;
      const all = litsOf(fn);
      if (all.some((l) => ENTITY.lt.test(l)) && all.some((l) => ENTITY.gt.test(l)) && all.some((l) => ENTITY.amp.test(l))) hit.add(fn.name);
    }
  }
  ESCAPERS.set(perFile, hit);
  return hit;
}

/** Every occurrence of a variable inside `e` is an argument of an escaper (or a value an escaper call produced): nothing raw reaches the sink. */
function allUsesEscaped(fn, e, escapers, depth = 0) {
  if (!e || typeof e !== 'object' || depth > 40) return true;
  if (e.kind === 'call' && escapers.has(e.callee)) return true;     // whatever it receives is escaped
  if (e.kind === 'ident') {
    if (e.hs && e.hs.functionRef) return true;
    // a name bound in this function stands for its definition (`page = "<p>" ++ path ++ "</p>"` with `path = escape (...)`): every use inside it must be escaped too
    // A definition built from other values is judged by them; a definition with no value in it (`w <- param "w"`, a read) is the raw origin.
    const defs = nodeList(fn).filter((n) => n.kind === 'assign' && n.target === e.name && n.source);
    return defs.length > 0 && defs.every((n) => (n.source.kind === 'call' && escapers.has(n.source.callee)) || (identNames(n.source).size > 0 && allUsesEscaped(fn, n.source, escapers, depth + 1)));
  }
  for (const [, c] of exprChildren(e)) if (!allUsesEscaped(fn, c, escapers, depth + 1)) return false;
  return true;
}

/**
 * Judge one finding. Mutates it when a dominating, family-appropriate guard refutes the flow.
 * @returns {{status:'refuted'|'weak-guard'|'none', guard?:object}}
 */
export function judgeFinding(f, perFile) {
  const fam = FAMILY_BY_CWE[f.cwe];
  const ir = perFile && perFile[f.file];
  if (!fam || !ir || !f._funcQid || !f.callee) return { status: 'none' };
  // A finding found while analysing a CALLER (`_funcQid`) is located at the callee's line: the sink function is the one in the
  // finding's file that has the call at that line (the caller first, then the others), the way haskell-trust.js locates it.
  const direct = ir.functions.find((x) => x.qid === f._funcQid);
  let fn = null; let sites = [];
  for (const cand of [direct, ...ir.functions.filter((x) => x !== direct)].filter(Boolean)) {
    const s = findSites(cand, f.callee, f.line);
    if (s.length) { fn = cand; sites = s; break; }
  }
  if (!fn || !sites.length) return { status: 'none' };
  let weak = null;
  let first = null;
  for (const site of sites) {
    const argIdx = Number.isInteger(f.argIndex) ? f.argIndex : 0;
    const argExpr = (site.call.args || [])[argIdx];
    const vars = identNames(argExpr);
    if (!vars.size) return { status: 'none' };
    // The sink argument may be a value BUILT from the checked one (`req <- parseUrlThrow target; httpLbs req m`): the
    // guard names the original, so the origins of the argument count as its subject too.
    for (const v of originsOf(fn, vars)) vars.add(v);
    const derived = derivedFrom(fn, vars);   // values built FROM the checked one (`a` in `Just a <- parseURI url`)
    const facts = [...site.facts, ...cfgBranchFacts(fn, site.nodeId), ...exitGuardFacts(fn, site.nodeId)];
    let refuted = null;
    if (fam === 'xss') {
      // the project's own escapers plus the catalog's HTML escapers (blaze/lucid `toHtml`, `text`, ...): the taint walk records the latter on
      // the path for the proof gate, but a sink argument built by a HELPER (`html (renderHtml (greeting name))`) is judged here, where the
      // helper's body can be read: a helper that uses the parameter receiving the tainted value only under an escaper escapes it
      const escapers = new Set([...htmlEscapers(perFile), ...CATALOG_HTML_ESCAPERS]);
      const helperByName = (callee) => ir.functions.find((x) => x.name === callee || x.qid === callee || (x.qid || '').endsWith(`::${callee}`)) || null;
      const paramEscaped = (helper, param, depth) => {
        if (depth > 2) return false;
        const under = (e, inEsc, d) => {
          if (!e || typeof e !== 'object' || d > 40) return true;
          if (e.kind === 'ident' && e.name === param) return inEsc;
          if (e.kind === 'call' && typeof e.callee === 'string') {
            if (escapers.has(e.callee)) return true;
            const h = helperByName(e.callee);
            if (h && Array.isArray(h.params)) {
              // a nested helper: each argument that mentions the parameter must land on a parameter the nested helper escapes
              return (e.args || []).every((a, i) => !identNames(a).has(param) || (h.params[i] && paramEscaped(h, h.params[i], depth + 1) && under(a, true, d + 1)));
            }
          }
          for (const [, c] of exprChildren(e)) if (!under(c, inEsc, d + 1)) return false;
          return true;
        };
        for (const n of nodeList(helper)) {
          for (const k of ['source', 'value', 'cond']) if (n[k] && !under(n[k], false, 0)) return false;
          if (Array.isArray(n.args)) for (const a of n.args) if (!under(a, false, 0)) return false;
        }
        return true;
      };
      const addHelperEscapers = (e, d) => {
        if (!e || typeof e !== 'object' || d > 40) return;
        if (e.kind === 'call' && typeof e.callee === 'string' && !escapers.has(e.callee)) {
          const h = helperByName(e.callee);
          if (h && Array.isArray(h.params) && (e.args || []).length) {
            const taintedPositions = (e.args || []).map((a, i) => ([...identNames(a)].some((v) => vars.has(v) || derived.has(v)) ? i : -1)).filter((i) => i >= 0);
            if (taintedPositions.length && taintedPositions.every((i) => h.params[i] && paramEscaped(h, h.params[i], 0))) escapers.add(e.callee);
          }
        }
        for (const [, c] of exprChildren(e)) addHelperEscapers(c, d + 1);
      };
      addHelperEscapers(argExpr, 0);
      for (const v of identNames(argExpr)) for (const n of nodeList(fn)) if (n.kind === 'assign' && n.target === v && n.source) addHelperEscapers(n.source, 0);
      const calls = [];
      const find = (e, d) => { if (!e || typeof e !== 'object' || d > 40) return; if (e.kind === 'call' && escapers.has(e.callee)) calls.push(e); for (const [, c] of exprChildren(e)) find(c, d + 1); };
      // the escaper may sit behind one or more local bindings (`page = ... path ...`, `path = escape (...)`): follow them, each once
      const followed = new Set();
      const findIn = (e, d) => { if (!e || d > 40) return; find(e, d); for (const v of identNames(e)) { if (followed.has(v)) continue; followed.add(v); for (const n of nodeList(fn)) if (n.kind === 'assign' && n.source && n.target === v) findIn(n.source, d + 1); } };
      findIn(argExpr, 0);
      if (calls.length && allUsesEscaped(fn, argExpr, escapers)) refuted = { kind: 'html-escaper', line: calls[0].line || fn.line, subject: calls[0].callee };
    }
    for (const fact of facts) {
      if (refuted) break;
      const cls = classifyCondition(fact.cond, vars, derived);
      if (!cls || cls.safeWhen !== fact.when) continue;
      if (!(cls.families.includes('*') || cls.families.includes(fam))) continue;          // wrong-context control
      if (cls.needsCanon && !isCanonical(fn, cls.subject)) { weak = { kind: cls.kind, line: fact.line || fn.line, reason: 'containment check on a path that was not canonicalised' }; continue; }
      refuted = { kind: cls.kind, line: fact.line || (fact.cond && fact.cond.line) || fn.line, subject: cls.subject };
      break;
    }
    if (!refuted) return weak ? { status: 'weak-guard', guard: weak } : { status: 'none' };
    if (!first) first = refuted;
  }
  return { status: 'refuted', guard: first };
}

/**
 * CWE-88 (argument injection) into a process argv: a literal "--" element BEFORE every tainted element ends
 * option parsing for programs that follow that convention. It is a convention, not a guarantee, so the finding
 * is lowered to `low` with the assumption stated; it is never refuted or dropped.
 */
export function optionTerminator(f, perFile) {
  if (f.cwe !== 'CWE-88') return null;
  const ir = perFile && perFile[f.file];
  const fn = ir && f._funcQid && ir.functions.find((x) => x.qid === f._funcQid);
  if (!fn || !f.callee) return null;
  const sites = findSites(fn, f.callee, f.line);
  if (!sites.length) return null;
  for (const site of sites) {
    const list = (site.call.args || [])[Number.isInteger(f.argIndex) ? f.argIndex : 1];
    if (!list || list.kind !== 'array') return null;
    const idx = list.elements.findIndex((e) => e && e.kind === 'literal' && e.value === '--');
    if (idx < 0) return null;
    const tainted = list.elements.some((e, i) => i < idx && e && e.kind !== 'literal');
    if (tainted) return null;
  }
  return { kind: 'option-terminator' };
}

const SHELLS = /^(?:\/(?:usr\/)?(?:local\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|ash|fish|csh|tcsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i;
const SHELL_C = /^(?:-[a-z]*c[a-z]*|\/[ck]|-command|-encodedcommand)$/i;
const PROCESS_FNS = new Set(['System.Process.callProcess', 'System.Process.spawnProcess', 'System.Process.readProcess', 'System.Process.readProcessWithExitCode', 'System.Process.proc']);

/**
 * `callProcess "sh" ["-c", script]` runs `script` through a shell: tainted text in the script is command injection (CWE-78),
 * not an argument-injection into a fixed program. Only a literal shell program followed by a command flag qualifies, and the
 * tainted element must come AFTER the flag (a tainted argument before `-c` is just an argument).
 * Mutates the finding; returns true when it was promoted.
 */
export function promoteShellInterpreter(f, perFile) {
  if (!f || f.cwe !== 'CWE-88' || !PROCESS_FNS.has(f.callee)) return false;
  const ir = perFile && perFile[f.file];
  const fn = ir && f._funcQid && ir.functions.find((x) => x.qid === f._funcQid);
  if (!fn) return false;
  for (const site of findSites(fn, f.callee, f.line)) {
    const [prog, list] = site.call.args || [];
    if (!isStr(prog) || !SHELLS.test(prog.value) || !list || list.kind !== 'array') continue;
    const flag = list.elements.findIndex((e) => isStr(e) && SHELL_C.test(e.value));
    if (flag < 0) continue;
    // `sh -c SCRIPT arg0 arg1 ..`: only the SCRIPT is parsed by the shell. The elements after it are the positional parameters ($0, $1, ...), plain
    // data to a script that does not interpolate them into code; a tainted script is injection, tainted positionals are judged by `quotedPositionals`.
    const script = list.elements[flag + 1];
    if (script && script.kind !== 'literal') {
      f.cwe = 'CWE-78'; f.severity = 'critical'; f.vuln = 'OS Command Injection (shell interpreter -c)';
      f.id = String(f.id).replace('cwe-88', 'cwe-78'); f.shellInterpreter = prog.value;
      return true;
    }
  }
  return false;
}

/**
 * `callProcess "sh" ["-c", "gzip -9 -- \"$1\"", "sh", target]`: the script is a constant and the tainted value is a positional parameter the
 * script expands INSIDE DOUBLE QUOTES after `--`. The shell does not re-parse a quoted expansion, and `--` ends the program's option parsing, so
 * neither shell nor option injection is possible through it. A reference that is unquoted, quoted with single quotes, or not preceded by `--` is not
 * covered: the finding stays. Returns the control or null.
 */
export function quotedPositionals(f, perFile) {
  if (!f || f.cwe !== 'CWE-88' || !PROCESS_FNS.has(f.callee)) return null;
  const ir = perFile && perFile[f.file];
  const fn = ir && f._funcQid && ir.functions.find((x) => x.qid === f._funcQid);
  if (!fn) return null;
  const sites = findSites(fn, f.callee, f.line);
  if (!sites.length) return null;
  for (const site of sites) {
    const [prog, list] = site.call.args || [];
    if (!isStr(prog) || !SHELLS.test(prog.value) || !list || list.kind !== 'array') return null;
    const flag = list.elements.findIndex((e) => isStr(e) && SHELL_C.test(e.value));
    const script = flag >= 0 ? list.elements[flag + 1] : null;
    if (!isStr(script)) return null;
    // a tainted element BEFORE the script (or the script itself) is not a positional parameter
    if (list.elements.slice(0, flag + 2).some((e) => e && e.kind !== 'literal')) return null;
    // the literal keeps the Haskell string's own escapes (`\"`, `\\`, `\n`): decode them to get the text the shell receives
    const text = script.value.replace(/\\(["'\\ntr])/g, (m, c) => ({ n: '\n', t: '\t', r: '\r' }[c] || c));
    let dq = false; let sq = false; let seenDashes = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === '\\' && !sq) { i++; continue; }
      if (ch === "'" && !dq) { sq = !sq; continue; }
      if (ch === '"' && !sq) { dq = !dq; continue; }
      if (!dq && !sq && ch === '-' && text[i + 1] === '-' && /\s/.test(text[i + 2] || ' ') && (i === 0 || /\s/.test(text[i - 1]))) { seenDashes = true; continue; }
      if (ch === '$' && !sq) {
        const rest = text.slice(i + 1);
        if (/^(?:[0-9]|\{[0-9]+\}|[@*]|\{[@*]\})/.test(rest)) {
          if (!dq || !seenDashes) return null;
        } else if (/^[A-Za-z_(`{]/.test(rest)) { return null; }   // another expansion or a command substitution: not judged here
      }
      if (ch === '`' && !sq) return null;
    }
    return { kind: 'quoted-positional-parameters' };
  }
  return null;
}

/** Applies judgeFinding to every Haskell taint finding. Returns counts. */
/**
 * A raw WAI response (`responseLBS status headers body`) is an HTML context only when its headers say so. Returns `html` (a `text/html`
 * content type is written in the header list), `other` (another content type is written there), or `unknown` (the headers are not literal
 * text the walk can read). Read from the call's own header argument; nothing else decides it.
 */
export function waiHtmlContext(f, perFile) {
  if (!f || f.cwe !== 'CWE-79' || !/^Network\.Wai\.response(?:LBS|Builder)$/.test(f.callee || '')) return null;
  const ir = perFile && perFile[f.file];
  if (!ir) return 'unknown';
  const fns = [ir.functions.find((x) => x.qid === f._funcQid), ...ir.functions].filter(Boolean);
  for (const fn of fns) {
    const sites = findSites(fn, f.callee, f.line);
    if (!sites.length) continue;
    const texts = [];
    const resolveLocal = (name) => { for (const n of nodeList(fn)) if (n.kind === 'assign' && n.target === name && n.source) return n.source; return null; };
    const visit = (e, d) => {
      if (!e || typeof e !== 'object' || d > 40) return;
      if (e.kind === 'literal' && typeof e.value === 'string') texts.push(e.value);
      if (e.kind === 'ident' && d < 2) { const src = resolveLocal(e.name); if (src) visit(src, d + 1); }
      for (const [, c] of exprChildren(e)) visit(c, d + 1);
    };
    for (const site of sites) visit((site.call.args || [])[1], 0);
    const types = texts.filter((t) => /^(?:text|application|image|audio|video|multipart)\/[\w.+-]+/i.test(t.trim()));
    if (types.some((t) => /^text\/html/i.test(t.trim()))) return 'html';
    if (types.length) return 'other';
    // A `Location` header and no content type: a redirect, whose body a browser never renders (keter's redirect helper echoes the target
    // URL as the body of its 3xx response; that is a redirect finding's business, not an HTML injection).
    if (texts.some((t) => /^location$/i.test(t.trim()))) return 'redirect';
    return 'unknown';
  }
  return 'unknown';
}

// ── a request whose host is fixed ────────────────────────────────────────────
// SSRF is the client choosing the HOST. A URL built as `fixedBase <> clientText` where the fixed part is a literal (or a constant bound to
// one) that already names a scheme, a host and a "/" cannot reach another host: the client text lands in the path, query or fragment.
// Likewise a request value built by http-conduit's modifiers (`setRequestQueryString q base`, `setRequestPath p base`, ...) over a fixed
// base request keeps that base's host; the modifiers take the base as their LAST argument. A record update of such a value is judged by
// its base unless it sets a field that names the host.
const HOST_ANCHORED = /^[a-z][a-z0-9+.-]*:\/\/[^/@?#\s]+\/[^\s]*$/i;
const REQUEST_BUILDERS = /(?:^|\.)(?:parseRequest|parseRequest_|parseUrlThrow|parseUrl|requestFromURI|requestFromURI_)$/;
const REQUEST_MODIFIERS = /(?:^|\.)(?:setRequestQueryString|setRequestQuery|setQueryString|setRequestPath|setRequestBody|setRequestBodyLBS|setRequestBodyJSON|setRequestBodyURLEncoded|setRequestBodyFile|setRequestBodySource|setRequestHeader|setRequestHeaders|addRequestHeader|setRequestMethod|setRequestBasicAuth|setRequestBearerAuth|setRequestIgnoreStatus|setRequestResponseTimeout|setRequestCheckStatus|setRequestManager|urlEncodedBody|applyBasicAuth|applyBearerAuth)$/;
const PEEL_WRAPPERS = /(?:^|\.)(?:liftIO|pure|return|unpack|pack|fromString|toStrict|fromStrict|encodeUtf8|decodeUtf8|toText|fromText)$/;
const HOST_FIELD = /^(?:host|port|secure|url|uri|requestHost)$/i;

function fixedHostRequest(f, perFile) {
  if (!f || f.cwe !== 'CWE-918') return null;
  const ir = perFile && perFile[f.file];
  if (!ir || !f.callee) return null;
  const direct = ir.functions.find((x) => x.qid === f._funcQid);
  let fn = null; let sites = [];
  for (const cand of [direct, ...ir.functions.filter((x) => x !== direct)].filter(Boolean)) {
    const s = findSites(cand, f.callee, f.line);
    if (s.length) { fn = cand; sites = s; break; }
  }
  if (!fn || !sites.length) return null;
  const argIdx = Number.isInteger(f.argIndex) ? f.argIndex : 0;
  // a local name bound once stands for its definition; a zero-parameter function of the module whose body is one literal is a constant
  const localDef = (name) => { const defs = []; for (const n of nodeList(fn)) if (n.kind === 'assign' && n.target === name && n.source) defs.push(n.source); return defs.length === 1 ? defs[0] : null; };
  const constDef = (name) => {
    const bare = name.replace(/^.*\./, '');
    const c = ir.functions.find((x) => (x.name === name || x.qid === name || (x.name || '').replace(/^.*\./, '') === bare) && (!Array.isArray(x.params) || x.params.length === 0));
    if (!c) return null;
    const rets = Object.values(c.cfg.nodes).filter((n) => n.kind === 'return' && n.value);
    return rets.length === 1 ? rets[0].value : null;
  };
  let evidence = null;
  const fixed = (e, seen, depth) => {
    if (!e || typeof e !== 'object' || depth > 24) return false;
    if (e.kind === 'literal') { const ok = typeof e.value === 'string' && HOST_ANCHORED.test(e.value); if (ok) evidence = e.value.replace(/^([a-z][a-z0-9+.-]*:\/\/[^/@?#\s]+\/).*$/i, '$1'); return ok; }
    if (e.kind === 'ident') {
      if (seen.has(e.name)) return false;
      seen.add(e.name);
      const d = localDef(e.name) || constDef(e.name);
      return d ? fixed(d, seen, depth + 1) : false;
    }
    if (e.kind === 'union') return Array.isArray(e.branches) && e.branches.length > 0 && e.branches.every((b) => fixed(b, new Set(seen), depth + 1));
    if (e.kind === 'object' && Array.isArray(e.props)) {
      // a record update: `{ method = "POST" }` joined (as a union) with its base; a field that names the host makes it unknown
      if (e.props.some((p) => HOST_FIELD.test(String(p.key || p.name || '')))) return false;
      return e.object ? fixed(e.object, seen, depth + 1) : true;
    }
    if (e.kind === 'binary' && (e.op === '<>' || e.op === '++' || (e.hs && e.hs.concat))) return fixed(e.left, seen, depth + 1);
    if (e.kind === 'call' && typeof e.callee === 'string') {
      const args = e.args || [];
      if (PEEL_WRAPPERS.test(e.callee) && args.length === 1) return fixed(args[0], seen, depth + 1);
      if (REQUEST_BUILDERS.test(e.callee) && args.length >= 1) return fixed(args[args.length - 1], seen, depth + 1);
      if (REQUEST_MODIFIERS.test(e.callee) && args.length >= 1) return fixed(args[args.length - 1], seen, depth + 1);
      if (/(?:^|\.)(?:<\/>|combine|joinPath)$/.test(e.callee) && args.length === 2) return fixed(args[0], seen, depth + 1);
    }
    return false;
  };
  for (const site of sites) {
    const arg = (site.call.args || [])[argIdx];
    if (!arg) return null;
    // a record update is a union of the base and the update: a union judged branch by branch above; an `object` branch with no base is the
    // update alone, which is fixed when it names no host field, so the base branch decides
    if (!fixed(arg, new Set(), 0)) return null;
  }
  return { kind: 'fixed-host-request', base: evidence };
}

export function applyHaskellGuards(findings, perFile) {
  const stats = { refuted: 0, weak: 0 };
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT') continue;
    try {
      const ctx = waiHtmlContext(f, perFile);
      if (ctx === 'other' && !f._notHtmlContext) {
        f._notHtmlContext = true; f.severity = 'info';
        f.controls = [...(f.controls || []), { kind: 'non-html-content-type', evidenceKind: 'source' }];
        f.guardNote = { kind: 'non-html-content-type', reason: 'the response headers written at this call name a content type other than text/html; the body is not parsed as HTML by a browser that honours them' };
        stats.weak++;
        continue;
      }
      if (ctx === 'redirect' && !f._notHtmlContext) {
        f._notHtmlContext = true; f.severity = 'info';
        f.controls = [...(f.controls || []), { kind: 'redirect-response-body', evidenceKind: 'source' }];
        f.guardNote = { kind: 'redirect-response-body', reason: 'the response headers written at this call set Location and no content type: a redirect, whose body a browser does not render' };
        stats.weak++;
        continue;
      }
      if (ctx === 'unknown' && !f._htmlContextUnknown) { f._htmlContextUnknown = true; f.uncertainty = [...(f.uncertainty || []), { kind: 'unread-content-type', detail: 'the response headers at this call are not literal text, so whether the body is served as HTML was not read' }]; }
    } catch { /* judged below */ }
    try {
      const fh = fixedHostRequest(f, perFile);
      if (fh && !f._fixedHost) {
        f._fixedHost = true; f.severity = 'info';
        f.controls = [...(f.controls || []), { kind: 'fixed-host-request', evidenceKind: 'source' }];
        f.guardNote = { kind: 'fixed-host-request', reason: `the request's host is fixed by the literal${fh.base ? ` "${fh.base}"` : ''} the URL or base request starts from; the client's text can only choose the path, query or fragment, which is not a server-side request forgery (a path it chooses on that host is still worth a look)` };
        stats.weak++;
        continue;
      }
    } catch { /* judged below */ }
    try { promoteShellInterpreter(f, perFile); } catch { /* judged as an argument-injection below */ }
    try {
      const qp = quotedPositionals(f, perFile);
      if (qp && !f._quotedPositionals) {
        f._quotedPositionals = true; f.severity = 'info';
        f.controls = [...(f.controls || []), { kind: 'quoted-positional-parameters', evidenceKind: 'source' }];
        f.guardNote = { kind: 'quoted-positional-parameters', reason: 'the script is a constant and expands the tainted value only inside double quotes after "--"; the shell does not re-parse it and the program stops reading options' };
        stats.weak++;
        continue;
      }
    } catch { /* judged below */ }
    try {
      const ot = optionTerminator(f, perFile);
      if (ot && !f._optionTerminated) {
        f._optionTerminated = true; f.severity = 'info';
        f.controls = [...(f.controls || []), { kind: 'option-terminator', evidenceKind: 'source' }];
        f.guardNote = { kind: 'option-terminator', reason: 'a literal "--" precedes the tainted argument; this assumes the program treats "--" as the end of options (a convention, not a guarantee)' };
        stats.weak++;
        continue;
      }
    } catch { /* judged below */ }
    let r;
    try { r = judgeFinding(f, perFile); } catch { continue; }
    if (r.status === 'refuted') {
      // Same channel the proof gate already reads: a flow a dominating control makes infeasible is
      // demoted (never dropped), so the auditor still sees it and severity gates are unaffected.
      f._provenUnreachable = true;
      f._provenUnreachableReason = `dominating ${r.guard.kind} guard`;
      f.controls = [...(f.controls || []), { kind: 'dominating-guard', evidenceKind: 'source' }];
      stats.refuted++;
    } else if (r.status === 'weak-guard') {
      f.guardNote = r.guard;
      stats.weak++;
    }
  }
  return stats;
}
