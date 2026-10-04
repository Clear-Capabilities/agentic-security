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
const EXIT_CALLS = new Set(['Control.Exception.throwIO', 'Control.Exception.throw', 'System.Exit.die', 'System.Exit.exitFailure', 'System.Exit.exitWith', 'throwIO', 'throw', 'die', 'exitFailure', 'exitWith', 'error', 'fail', 'ioError', 'Control.Monad.Fail.fail']);
const WHEN = new Set(['Control.Monad.when', 'when']);
const UNLESS = new Set(['Control.Monad.unless', 'unless']);
const IS_ELEM = new Set(['Data.List.elem', 'Prelude.elem', 'elem', 'Data.Foldable.elem']);
const NOT_ELEM = new Set(['Data.List.notElem', 'Prelude.notElem', 'notElem', 'Data.Foldable.notElem']);
const IS_MEMBER = /^Data\.(?:Set|HashSet|Map|Map\.Strict|HashMap\.Strict)\.member$/;
const NOT_MEMBER = /^Data\.(?:Set|HashSet|Map|Map\.Strict|HashMap\.Strict)\.notMember$/;
const CHARCLASS = new Set(['Data.Char.isAlphaNum', 'Data.Char.isAlpha', 'Data.Char.isDigit', 'Data.Char.isAscii', 'isAlphaNum', 'isAlpha', 'isDigit']);

const FAMILY_BY_CWE = { 'CWE-22': 'path', 'CWE-918': 'url', 'CWE-78': 'cmd', 'CWE-88': 'cmd', 'CWE-89': 'sql', 'CWE-79': 'xss', 'CWE-1427': 'prompt' };

const isStr = (e) => e && e.kind === 'literal' && typeof e.value === 'string';

function identNames(e, out = new Set(), depth = 0) {
  if (!e || typeof e !== 'object' || depth > 30) return out;
  if (e.kind === 'ident' && e.name && !(e.hs && e.hs.functionRef)) out.add(e.name);
  for (const k of ['left', 'right', 'object', 'value', 'callee']) if (e[k] && typeof e[k] === 'object') identNames(e[k], out, depth + 1);
  for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) for (const x of e[k]) identNames(x, out, depth + 1);
  if (Array.isArray(e.props)) for (const p of e.props) identNames(p && p.value, out, depth + 1);
  return out;
}

const mentions = (e, vars) => { for (const n of identNames(e)) if (vars.has(n)) return true; return false; };

/** Classify a condition over the value `vars`. -> {safeWhen, kind, families, needsCanon?, subject} | null */
export function classifyCondition(c, vars) {
  if (!c || typeof c !== 'object') return null;
  if (c.kind === 'binary') {
    if (c.op === '&&') { const a = classifyCondition(c.left, vars); const b = classifyCondition(c.right, vars); return [a, b].find((x) => x && x.safeWhen === true) || null; }
    if (c.op === '||') { const a = classifyCondition(c.left, vars); const b = classifyCondition(c.right, vars); return [a, b].find((x) => x && x.safeWhen === false) || null; }
    if (c.op === '==' || c.op === '===') {
      const pair = (l, r) => l && l.kind === 'call' && /(?:^|\.)takeFileName$/.test(l.callee || '') && l.args && l.args[0] && r && r.kind === 'ident' && l.args[0].kind === 'ident' && l.args[0].name === r.name && vars.has(r.name);
      if (pair(c.left, c.right) || pair(c.right, c.left)) return { safeWhen: true, kind: 'bare-filename', families: ['path'], subject: (c.left.kind === 'ident' ? c.left : c.right).name };
    }
    return null;
  }
  if (c.kind !== 'call') return null;
  const name = c.callee || '';
  const a = c.args || [];
  if (name === 'not' || name === 'Prelude.not') { const inner = classifyCondition(a[0], vars); return inner ? { ...inner, safeWhen: !inner.safeWhen } : null; }
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
function findSites(fn, callee, line) {
  const sites = [];
  const visit = (e, nodeId, facts, depth) => {
    if (!e || typeof e !== 'object' || depth > 60) return;
    if (e.kind === 'call' && e.callee === callee && (e.line === line || nodeLine(nodeId) === line)) sites.push({ nodeId, facts, call: e });
    if (e.kind === 'union') {
      const bc = e.hs && e.hs.branchConds;
      e.branches.forEach((b, i) => visit(b, nodeId, bc && bc[i] ? [...facts, bc[i]] : facts, depth + 1));
      return;
    }
    for (const [, c] of exprChildren(e)) visit(c, nodeId, facts, depth + 1);
  };
  const nodeLine = (id) => (fn.cfg.nodes[id] ? fn.cfg.nodes[id].line : -1);
  for (const n of nodeList(fn)) {
    if (n.kind === 'call' && n.callee === callee && n.line === line) sites.push({ nodeId: n.id, facts: [], call: { kind: 'call', callee: n.callee, args: n.args || [] } });
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

/**
 * Judge one finding. Mutates it when a dominating, family-appropriate guard refutes the flow.
 * @returns {{status:'refuted'|'weak-guard'|'none', guard?:object}}
 */
export function judgeFinding(f, perFile) {
  const fam = FAMILY_BY_CWE[f.cwe];
  const ir = perFile && perFile[f.file];
  if (!fam || !ir || !f._funcQid || !f.callee) return { status: 'none' };
  const fn = ir.functions.find((x) => x.qid === f._funcQid);
  if (!fn) return { status: 'none' };
  const sites = findSites(fn, f.callee, f.line);
  if (!sites.length) return { status: 'none' };
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
    const facts = [...site.facts, ...cfgBranchFacts(fn, site.nodeId), ...exitGuardFacts(fn, site.nodeId)];
    let refuted = null;
    for (const fact of facts) {
      const cls = classifyCondition(fact.cond, vars);
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
    if (list.elements.slice(flag + 1).some((e) => e && e.kind !== 'literal')) {
      f.cwe = 'CWE-78'; f.severity = 'critical'; f.vuln = 'OS Command Injection (shell interpreter -c)';
      f.id = String(f.id).replace('cwe-88', 'cwe-78'); f.shellInterpreter = prog.value;
      return true;
    }
  }
  return false;
}

/** Applies judgeFinding to every Haskell taint finding. Returns counts. */
export function applyHaskellGuards(findings, perFile) {
  const stats = { refuted: 0, weak: 0 };
  for (const f of findings || []) {
    if (!f || f.parser !== 'IR-TAINT') continue;
    try { promoteShellInterpreter(f, perFile); } catch { /* judged as an argument-injection below */ }
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
