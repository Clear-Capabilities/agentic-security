// Dynamic features the static analysis cannot resolve, reported instead of silently approximated (E2-03).
//
// Where the engine meets one of these it takes the sound direction (a write through an unknown key taints the whole container, a read through
// an unknown key reads the whole container) and loses precision. That is the right trade, but it must be visible: a result that depended on it is
// less precise than one that did not, and a reviewer should be able to see which functions contain such constructs.
//
// Pure: reads the Layer-1 IR only.
const LIMIT_KINDS = Object.freeze({
  'computed-write': 'a write through a key that is not a literal (`o[k] = v`): the engine taints the whole container `o`, so clean sibling fields read afterwards are over-approximated as tainted',
  'computed-read': 'a read through a key that is not a literal (`o[k]`): the engine cannot tell which field is read, so any tainted field of `o` reaches it',
  'eval-like': 'code built at run time (`eval`, `new Function`, `setTimeout` with a string): its content is not analysed',
  'dynamic-require': 'a module name computed at run time (`require(name)`, `import(name)`): the callee is unknown, so the call stays unresolved',
  'reflective-call': 'a call through reflection (`Reflect.apply`, `fn.call/apply` on a computed target, `obj[name]()`): the callee is unknown',
  'getter-or-proxy': 'property access that may run user code (`Proxy`, `Object.defineProperty` accessors): reads and writes may have effects the engine does not model',
});

const expressions = (e, acc = []) => {
  if (!e || typeof e !== 'object') return acc;
  acc.push(e);
  for (const k of ['object', 'callee', 'left', 'right', 'value']) if (e[k] && typeof e[k] === 'object') expressions(e[k], acc);
  for (const k of ['args', 'parts', 'elements', 'props', 'branches']) if (Array.isArray(e[k])) for (const x of e[k]) expressions(x && x.value && !x.kind ? x.value : x, acc);
  return acc;
};
const nameOf = (c) => (typeof c === 'string' ? c : c && c.kind === 'ident' ? c.name : c && c.kind === 'member' ? `${nameOf(c.object)}.${c.prop}` : '');

/** @returns {{kind:string, line:number, detail:string, effect:string}[]} */
function limitsOfFunction(fn) {
  const out = [];
  const add = (kind, line, detail) => out.push({ kind, line: Number.isInteger(line) ? line : (fn.line || 0), detail, effect: LIMIT_KINDS[kind] });
  for (const n of Object.values(fn.cfg?.nodes || {})) {
    if (n.kind === 'assign') {
      if (typeof n.target === 'string' && /\.\*$/.test(n.target)) add('computed-write', n.line, n.target);
      for (const x of expressions(n.source)) inspect(x, n.line, add);
    } else if (n.kind === 'call') {
      inspect({ kind: 'call', callee: n.callee, args: n.args }, n.line, add);
      for (const a of n.args || []) for (const x of expressions(a)) inspect(x, n.line, add);
    } else if (n.kind === 'return' && n.value) for (const x of expressions(n.value)) inspect(x, n.line, add);
  }
  return out;
}

function inspect(x, line, add) {
  if (x.kind === 'member' && x.prop === '*') add('computed-read', line, `${nameOf(x.object)}[…]`);
  if (x.kind === 'call') {
    const c = nameOf(x.callee);
    if (/^(?:eval|Function|new Function|setTimeout|setInterval)$/.test(c)) { if (c === 'eval' || c === 'Function' || c === 'new Function' || (x.args && x.args[0] && x.args[0].kind !== 'function-value' && x.args[0].kind !== 'ident' && x.args[0].kind !== 'literal')) add('eval-like', line, c); else if ((c === 'setTimeout' || c === 'setInterval') && x.args && x.args[0] && x.args[0].kind === 'literal' && typeof x.args[0].value === 'string') add('eval-like', line, `${c}(string)`); }
    if (c === 'require' && x.args && x.args[0] && x.args[0].kind !== 'literal') add('dynamic-require', line, 'require(<expression>)');
    if (/^Reflect\.(?:apply|construct|get|set)$/.test(c)) add('reflective-call', line, c);
    if (x.callee && x.callee.kind === 'member' && x.callee.prop === '*') add('reflective-call', line, `${nameOf(x.callee.object)}[…](…)`);
    if (/^(?:Object\.defineProperty|Object\.defineProperties|Object\.setPrototypeOf)$/.test(c) || c === 'Proxy' || c === 'new Proxy') add('getter-or-proxy', line, c);
  }
}

/**
 * @param {{perFile:Record<string,{functions:object[]}>}} projectIR
 * @returns {{file:string, qid:string, function:string, kind:string, line:number, detail:string, effect:string}[]} sorted, stable
 */
export function analysisLimits(projectIR) {
  const out = [];
  for (const file of Object.keys(projectIR?.perFile || {}).sort()) {
    for (const fn of projectIR.perFile[file].functions || []) {
      for (const l of limitsOfFunction(fn)) out.push({ file, qid: String(fn.qid).replace(/@\d+$/, ''), function: fn.name, ...l });
    }
  }
  return out.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.kind < b.kind ? -1 : 1)));
}
