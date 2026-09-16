// C# IR — a CST-ish intermediate representation produced from the token
// stream, sufficient for security detectors without requiring a full
// parse (no overload resolution, no generics inference, no semantic model).
//
// Why hand-rolled rather than tree-sitter-c-sharp? The scanner's design
// principle is "no runtime cloud calls / no new runtime deps unless lazy."
// tree-sitter native bindings drag in node-gyp; WASM is bundlable but adds
// a 1.5 MB blob. For Juliet C# + idiomatic ASP.NET code, a focused
// hand-rolled CST gets us most of the way at zero dependency cost.
//
// IR shape (what each node carries):
//
//   File:    { usings: string[], namespaces: Namespace[], classes: ClassDecl[],
//              methods: MethodDecl[],   // top-level (rare; usually inside class)
//              calls: CallExpr[],       // every method call site
//              ctors: NewExpr[],        // every `new TypeName(...)` site
//              assignments: Assign[],   // every `x = ...` or `x.Member = ...`
//              decls: VarDecl[],        // every typed local + field
//              attrs: AttributeUse[],   // every [Foo(...)] use
//              strings: StringLit[],    // every string/verbatim/interp literal
//            }
//
//   ClassDecl: { name, attrs: AttributeUse[], line, endLine, methods: [], fields: [] }
//   MethodDecl: { name, returnType, params: [{name,type}], attrs: [], line, endLine,
//                 bodyTokens, calls: [], decls: [], assignments: [], strings: [] }
//   CallExpr: { receiver: string|null, method: string, args: ArgExpr[],
//               line, scope: MethodDecl|null }
//   NewExpr:  { type: string, args: ArgExpr[], line, scope }
//   Assign:   { target: string, isMember: bool, memberPath: string|null,
//               rhsTokens, line, scope }
//   VarDecl:  { name, type, rhsTokens|null, line, scope, isVar: bool }
//   AttributeUse: { name, argsRaw: string, line, attachedTo: 'class'|'method'|'param'|'field' }
//
//   ArgExpr:  { tokens, // raw tokens between commas
//               text,   // simple textual concatenation for matching
//               idents  // identifier names referenced }
//
// The IR is intentionally shallow: a method's body is a flat list of CallExpr /
// Assign / VarDecl, not a tree. Detectors that need control-flow analysis
// (the existing taint engine) consume IR.calls / IR.assignments and rebuild
// their own data structures.

import { tokenize, identsIn } from '../sast/csharp-tokenizer.js';

// Type modifiers that appear before a type name in a declaration.
const TYPE_MODIFIERS = new Set(['readonly', 'const', 'static', 'public', 'private', 'protected', 'internal', 'override', 'virtual', 'abstract', 'sealed', 'partial', 'async', 'new', 'unsafe', 'extern', 'ref', 'out', 'in', 'params']);

const BUILTIN_TYPES = new Set(['void', 'bool', 'byte', 'sbyte', 'char', 'short', 'ushort', 'int', 'uint', 'long', 'ulong', 'float', 'double', 'decimal', 'string', 'object', 'var', 'dynamic']);

// SARD_80_F1 W4.C11 — compound assignment operators, tokenized as single
// 'op' tokens by csharp-tokenizer.js but previously never checked for here.
const CS_COMPOUND_ASSIGN_OPS = new Set(['+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '??=']);

function isType(tok) {
  if (!tok) return false;
  if (tok.kind === 'kw' && BUILTIN_TYPES.has(tok.value)) return true;
  if (tok.kind === 'ident') return /^[A-Z]/.test(tok.value) || tok.value === 'var';
  return false;
}

function readType(tokens, i) {
  // Greedy type reader: handles `Foo`, `Foo.Bar.Baz`, `List<int>`, `Foo[]`,
  // `Foo?`, `Foo.Bar<X,Y>`, `Span<byte>[]`. Returns { type, next } or null.
  const start = i;
  if (!isType(tokens[i])) return null;
  let buf = tokens[i].value;
  i++;
  // Dotted-namespace qualified name
  while (tokens[i] && tokens[i].kind === 'dot' && tokens[i + 1] && tokens[i + 1].kind === 'ident') {
    buf += '.' + tokens[i + 1].value;
    i += 2;
  }
  // Generic <X[,Y]>
  if (tokens[i] && tokens[i].kind === 'op' && tokens[i].value === '<') {
    let depth = 1;
    let g = '<';
    i++;
    while (tokens[i] && depth > 0) {
      const t = tokens[i];
      if (t.kind === 'op' && t.value === '<') depth++;
      if (t.kind === 'op' && t.value === '>') depth--;
      if (t.kind === 'op' && t.value === '>>') { depth -= 2; g += '>>'; i++; continue; }
      g += (t.value || '');
      i++;
      if (depth === 0) break;
    }
    buf += g;
  }
  // Array brackets [] or [,]
  while (tokens[i] && tokens[i].kind === 'lbracket') {
    let j = i + 1, ok = true, depth = 1;
    while (tokens[j] && depth > 0) {
      if (tokens[j].kind === 'lbracket') depth++;
      else if (tokens[j].kind === 'rbracket') depth--;
      else if (tokens[j].kind !== 'comma' && tokens[j].kind !== 'op') { ok = false; break; }
      j++;
    }
    if (!ok) break;
    buf += tokens.slice(i, j).map(t => t.value || '').join('');
    i = j;
  }
  // Nullable ?
  if (tokens[i] && tokens[i].kind === 'op' && tokens[i].value === '?') {
    buf += '?'; i++;
  }
  return { type: buf, next: i, startIdx: start };
}

function tokenText(tokens) {
  // Re-render a token slice into a plain string for `text` matching.
  // String literal contents become their literal value; interpolations are
  // expanded as `"…{expr}…"` so detectors can grep for `${var}` shapes.
  // Inserts a space between adjacent "word" tokens (idents + keywords) so
  // `new SqlCommand` doesn't render as `newSqlCommand` and break downstream
  // regex matching.
  const parts = [];
  let prevWasWord = false;
  for (const t of tokens || []) {
    if (!t || t.kind === 'eof') continue;
    const isWord = (t.kind === 'ident' || t.kind === 'kw');
    if (isWord && prevWasWord) parts.push(' ');
    if (t.kind === 'string')   parts.push(`"${t.value}"`);
    else if (t.kind === 'verbatim') parts.push(`@"${t.value}"`);
    else if (t.kind === 'interp') {
      parts.push('"');
      for (const p of t.parts || []) {
        if (p.kind === 'lit') parts.push(p.text);
        else if (p.kind === 'expr') parts.push('{' + p.text + '}');
      }
      parts.push('"');
    }
    else if (t.kind === 'char') parts.push(`'${t.value}'`);
    else parts.push(t.value || '');
    prevWasWord = isWord;
  }
  return parts.join('');
}

function splitArgsByComma(tokens) {
  // Split a token slice on top-level commas (depth-aware on (), [], <>, {}).
  const out = []; let cur = []; let depth = 0;
  for (const t of tokens) {
    if (t.kind === 'lparen' || t.kind === 'lbrace' || t.kind === 'lbracket' || (t.kind === 'op' && t.value === '<')) depth++;
    if (t.kind === 'rparen' || t.kind === 'rbrace' || t.kind === 'rbracket' || (t.kind === 'op' && t.value === '>')) depth--;
    if (depth === 0 && t.kind === 'comma') { out.push(cur); cur = []; continue; }
    cur.push(t);
  }
  if (cur.length) out.push(cur);
  return out;
}

function makeArgExpr(tokens) {
  return { tokens, text: tokenText(tokens), idents: identsIn(tokens) };
}

// Walk balanced delimiters and return the index of the matching close.
function matchClose(tokens, openIdx, openKind, closeKind) {
  let depth = 0;
  for (let i = openIdx; i < tokens.length; i++) {
    if (tokens[i].kind === openKind) depth++;
    else if (tokens[i].kind === closeKind) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Read an attribute use `[Name(args)]` starting at attr-open.
function readAttribute(tokens, i, attachedTo) {
  const open = i;
  const close = matchClose(tokens, i, 'attr-open', 'attr-close');
  if (close === -1) return null;
  // Inside: ident(.ident)* (args)? — possibly multiple attributes comma-separated
  // e.g. [HttpGet("/x"), Authorize] — we record only the first for simplicity.
  let j = open + 1;
  const nameTokens = [];
  while (j < close && (tokens[j].kind === 'ident' || tokens[j].kind === 'dot')) {
    nameTokens.push(tokens[j].value);
    j++;
  }
  const name = nameTokens.join('');
  let argsRaw = '';
  if (tokens[j] && tokens[j].kind === 'lparen') {
    const aClose = matchClose(tokens, j, 'lparen', 'rparen');
    if (aClose !== -1) {
      argsRaw = tokenText(tokens.slice(j + 1, aClose));
      j = aClose + 1;
    }
  }
  return { attr: { name, argsRaw, line: tokens[open].line, attachedTo }, next: close + 1 };
}

// Read a method header: `[attrs]* modifiers* returnType Name(params) (`{`|`;`|`=>`)
// Returns { method, bodyStart, bodyEnd, next } or null.
function readMethodHeader(tokens, i, attachedAttrs) {
  // Skip modifiers
  let j = i;
  const modifiers = [];
  while (tokens[j] && tokens[j].kind === 'kw' && TYPE_MODIFIERS.has(tokens[j].value)) {
    modifiers.push(tokens[j].value);
    j++;
  }
  // Return type
  const tr = readType(tokens, j);
  if (!tr) return null;
  j = tr.next;
  // Method name
  if (!tokens[j] || tokens[j].kind !== 'ident') return null;
  const name = tokens[j].value;
  j++;
  // Generic <T> on method
  if (tokens[j] && tokens[j].kind === 'op' && tokens[j].value === '<') {
    const close = (function findGenericClose(){
      let d = 1, k = j + 1;
      while (tokens[k] && d > 0) {
        if (tokens[k].kind === 'op' && tokens[k].value === '<') d++;
        if (tokens[k].kind === 'op' && tokens[k].value === '>') d--;
        if (tokens[k].kind === 'op' && tokens[k].value === '>>') d -= 2;
        k++; if (d === 0) return k - 1;
      }
      return -1;
    })();
    if (close !== -1) j = close + 1;
  }
  // Params
  if (!tokens[j] || tokens[j].kind !== 'lparen') return null;
  const paramOpen = j;
  const paramClose = matchClose(tokens, j, 'lparen', 'rparen');
  if (paramClose === -1) return null;
  const paramTokens = tokens.slice(paramOpen + 1, paramClose);
  const params = [];
  for (const argTokens of splitArgsByComma(paramTokens)) {
    let k = 0;
    while (argTokens[k] && argTokens[k].kind === 'attr-open') {
      const ac = matchClose(argTokens, k, 'attr-open', 'attr-close');
      k = ac === -1 ? argTokens.length : ac + 1;
    }
    while (argTokens[k] && argTokens[k].kind === 'kw' && TYPE_MODIFIERS.has(argTokens[k].value)) k++;
    const tr2 = readType(argTokens, k);
    if (!tr2) continue;
    k = tr2.next;
    if (argTokens[k] && argTokens[k].kind === 'ident') {
      params.push({ type: tr2.type, name: argTokens[k].value });
    }
  }
  j = paramClose + 1;
  // Optional: where T : ...
  while (tokens[j] && tokens[j].kind === 'kw' && tokens[j].value === 'where') {
    while (tokens[j] && tokens[j].kind !== 'lbrace' && tokens[j].kind !== 'arrow' && tokens[j].kind !== 'semi') j++;
  }
  // Body
  if (!tokens[j]) return null;
  if (tokens[j].kind === 'semi') {
    // Abstract / interface method — no body to walk.
    return { method: { name, returnType: tr.type, params, attrs: attachedAttrs, line: tokens[i].line, endLine: tokens[j].line, modifiers, bodyTokens: [] }, next: j + 1 };
  }
  if (tokens[j].kind === 'arrow') {
    // Expression-bodied member: => expr;
    let k = j + 1;
    while (tokens[k] && tokens[k].kind !== 'semi') k++;
    const body = tokens.slice(j + 1, k);
    return { method: { name, returnType: tr.type, params, attrs: attachedAttrs, line: tokens[i].line, endLine: tokens[k]?.line || tokens[j].line, modifiers, bodyTokens: body }, next: k + 1 };
  }
  if (tokens[j].kind === 'lbrace') {
    const bClose = matchClose(tokens, j, 'lbrace', 'rbrace');
    if (bClose === -1) return null;
    const body = tokens.slice(j + 1, bClose);
    return { method: { name, returnType: tr.type, params, attrs: attachedAttrs, line: tokens[i].line, endLine: tokens[bClose].line, modifiers, bodyTokens: body }, next: bClose + 1 };
  }
  return null;
}

function walkMethodBody(method) {
  const out = { calls: [], ctors: [], assignments: [], decls: [], strings: [] };
  const tokens = method.bodyTokens;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    // String literals
    if (t.kind === 'string' || t.kind === 'verbatim' || t.kind === 'interp') {
      out.strings.push({ kind: t.kind, value: t.value || tokenText([t]), line: t.line, parts: t.parts || null });
      continue;
    }
    // new Type(args)
    if (t.kind === 'kw' && t.value === 'new') {
      const tr = readType(tokens, i + 1);
      if (tr && tokens[tr.next] && tokens[tr.next].kind === 'lparen') {
        const open = tr.next;
        const close = matchClose(tokens, open, 'lparen', 'rparen');
        if (close !== -1) {
          const args = splitArgsByComma(tokens.slice(open + 1, close)).map(makeArgExpr);
          out.ctors.push({ type: tr.type, args, line: t.line });
          i = close;
          continue;
        }
      }
    }
    // Variable declaration: TypeOrVar identifier (= ...)? ;
    if (isType(t)) {
      const tr = readType(tokens, i);
      if (tr && tokens[tr.next] && tokens[tr.next].kind === 'ident' && tokens[tr.next + 1]) {
        const after = tokens[tr.next + 1];
        if (after.kind === 'op' && after.value === '=') {
          // typed init
          let j = tr.next + 2;
          let depth = 0;
          while (j < tokens.length && (depth > 0 || tokens[j].kind !== 'semi')) {
            if (tokens[j].kind === 'lparen' || tokens[j].kind === 'lbrace' || tokens[j].kind === 'lbracket') depth++;
            if (tokens[j].kind === 'rparen' || tokens[j].kind === 'rbrace' || tokens[j].kind === 'rbracket') depth--;
            j++;
          }
          const rhs = tokens.slice(tr.next + 2, j);
          out.decls.push({ name: tokens[tr.next].value, type: tr.type, rhsTokens: rhs, rhsText: tokenText(rhs), line: t.line, isVar: tr.type === 'var' });
          i = j;
          continue;
        }
        if (after.kind === 'semi' || after.kind === 'comma') {
          out.decls.push({ name: tokens[tr.next].value, type: tr.type, rhsTokens: null, rhsText: '', line: t.line, isVar: tr.type === 'var' });
          i = tr.next + 1;
          continue;
        }
      }
    }
    // Assignment / call: <ident-or-builtin-type-kw>(.member)* (= ...)? ( ( … ) )?
    // Built-in type keywords like `string` are valid receivers for static
    // methods (`string.Format`, `int.TryParse`, etc.), so we accept them here.
    if (t.kind === 'ident' || (t.kind === 'kw' && BUILTIN_TYPES.has(t.value) && t.value !== 'void' && t.value !== 'var' && t.value !== 'dynamic')) {
      // Collect dotted target
      let j = i;
      const targetParts = [tokens[j].value];
      j++;
      while (tokens[j] && tokens[j].kind === 'dot' && tokens[j + 1] && tokens[j + 1].kind === 'ident') {
        targetParts.push(tokens[j + 1].value);
        j += 2;
      }
      // SARD_80_F1 W4.C11 — compound assignment (`+=`, `-=`, …) was
      // previously invisible here (only bare `=` matched), so a statement
      // like `cmd.CommandText += "..." + tainted + "...";` — Juliet's own
      // universal convention for building CommandText — produced NO
      // assignment record at all, silently dropping it from this
      // detector's taint model. This model (`analyzeMethodFlow`, see
      // csharp-analysis.js) has no un-taint step — a taintMap entry is
      // only ever set true, never cleared — so treating the compound RHS
      // exactly like a plain assign's RHS is already correct: if the
      // target was tainted before, that status is never touched (no
      // clearing branch exists); if this RHS is tainted, it becomes
      // tainted now, same as a `+=` should.
      if (tokens[j] && tokens[j].kind === 'op' &&
          (tokens[j].value === '=' || CS_COMPOUND_ASSIGN_OPS.has(tokens[j].value))) {
        let k = j + 1;
        let depth = 0;
        while (k < tokens.length && (depth > 0 || tokens[k].kind !== 'semi')) {
          if (tokens[k].kind === 'lparen' || tokens[k].kind === 'lbrace' || tokens[k].kind === 'lbracket') depth++;
          if (tokens[k].kind === 'rparen' || tokens[k].kind === 'rbrace' || tokens[k].kind === 'rbracket') depth--;
          k++;
        }
        const rhs = tokens.slice(j + 1, k);
        out.assignments.push({
          target: targetParts[0],
          isMember: targetParts.length > 1,
          memberPath: targetParts.length > 1 ? targetParts.slice(1).join('.') : null,
          fullTarget: targetParts.join('.'),
          rhsTokens: rhs, rhsText: tokenText(rhs),
          line: t.line,
        });
        i = k;
        continue;
      }
      // Call: ident(.ident)* ( args )
      if (tokens[j] && tokens[j].kind === 'lparen') {
        const open = j;
        const close = matchClose(tokens, open, 'lparen', 'rparen');
        if (close !== -1) {
          const args = splitArgsByComma(tokens.slice(open + 1, close)).map(makeArgExpr);
          out.calls.push({
            receiver: targetParts.length > 1 ? targetParts.slice(0, -1).join('.') : null,
            method: targetParts[targetParts.length - 1],
            args, line: t.line,
            fullPath: targetParts.join('.'),
          });
          i = close;
          continue;
        }
      }
    }
  }
  // Second pass: walk inside the rhs of every decl and assignment, looking
  // for embedded calls and ctors. C# expressions can carry calls anywhere
  // (`var x = Foo(Bar() + Baz())`), and the first pass only collected
  // top-level statement-level calls. We don't try to track receiver
  // typing for these nested calls — detectors that need that look up the
  // receiver in flow.typeMap separately.
  function _scanNested(tokens, line) {
    for (let k = 0; k < tokens.length; k++) {
      const tk = tokens[k];
      if (tk.kind === 'kw' && tk.value === 'new') {
        const tr = readType(tokens, k + 1);
        if (tr && tokens[tr.next] && tokens[tr.next].kind === 'lparen') {
          const open = tr.next;
          const close = matchClose(tokens, open, 'lparen', 'rparen');
          if (close !== -1) {
            out.ctors.push({ type: tr.type, args: splitArgsByComma(tokens.slice(open + 1, close)).map(makeArgExpr), line: tk.line || line });
          }
        }
        continue;
      }
      if (tk.kind === 'ident' || (tk.kind === 'kw' && BUILTIN_TYPES.has(tk.value) && tk.value !== 'void' && tk.value !== 'var' && tk.value !== 'dynamic')) {
        let j = k;
        const parts = [tk.value];
        j++;
        while (tokens[j] && tokens[j].kind === 'dot' && tokens[j + 1] && tokens[j + 1].kind === 'ident') {
          parts.push(tokens[j + 1].value);
          j += 2;
        }
        if (tokens[j] && tokens[j].kind === 'lparen') {
          const open = j;
          const close = matchClose(tokens, open, 'lparen', 'rparen');
          if (close !== -1) {
            out.calls.push({
              receiver: parts.length > 1 ? parts.slice(0, -1).join('.') : null,
              method: parts[parts.length - 1],
              args: splitArgsByComma(tokens.slice(open + 1, close)).map(makeArgExpr),
              line: tk.line || line,
              fullPath: parts.join('.'),
            });
            // Recurse into args so nested calls inside arguments are also caught.
            _scanNested(tokens.slice(open + 1, close), tk.line || line);
          }
        }
      }
    }
  }
  for (const d of out.decls) if (d.rhsTokens) _scanNested(d.rhsTokens, d.line);
  for (const a of out.assignments) if (a.rhsTokens) _scanNested(a.rhsTokens, a.line);
  method.calls = out.calls;
  method.ctors = out.ctors;
  method.assignments = out.assignments;
  method.decls = out.decls;
  method.strings = out.strings;
  return out;
}

// Build the full IR for a C# source file.
export function buildCSharpIR(source) {
  const tokens = tokenize(source);
  const ir = {
    tokens,
    usings: [], namespaces: [], classes: [], methods: [],
    calls: [], ctors: [], assignments: [], decls: [], attrs: [], strings: [],
  };
  let pendingAttrs = [];

  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (!t || t.kind === 'eof') break;

    // using directive
    if (t.kind === 'kw' && t.value === 'using') {
      let j = i + 1;
      while (tokens[j] && tokens[j].kind !== 'semi' && tokens[j].kind !== 'lparen') j++;
      const parts = tokens.slice(i + 1, j).map(t => t.value).filter(Boolean).join('');
      if (parts) ir.usings.push(parts);
      i = j + 1;
      continue;
    }

    // namespace declaration
    if (t.kind === 'kw' && t.value === 'namespace') {
      let j = i + 1;
      const nameParts = [];
      while (tokens[j] && (tokens[j].kind === 'ident' || tokens[j].kind === 'dot')) {
        nameParts.push(tokens[j].value); j++;
      }
      ir.namespaces.push({ name: nameParts.join(''), line: t.line });
      i = j;
      continue;
    }

    // Attribute
    if (t.kind === 'attr-open') {
      const a = readAttribute(tokens, i, 'unknown');
      if (a) {
        pendingAttrs.push(a.attr);
        ir.attrs.push(a.attr);
        i = a.next;
        continue;
      }
    }

    // class / struct / interface / record
    if (t.kind === 'kw' && (t.value === 'class' || t.value === 'struct' || t.value === 'interface' || t.value === 'record')) {
      const nameTok = tokens[i + 1];
      const cls = { name: nameTok && nameTok.kind === 'ident' ? nameTok.value : '<anon>', attrs: pendingAttrs, line: t.line, methods: [], baseTypes: [] };
      pendingAttrs = [];
      // Extract base types: `class X : Foo, Bar<int> { … }`. Walk after the
      // class name to a ':' and then collect comma-separated type tokens
      // until '{'. We don't model `where T : …` constraint clauses here;
      // they're stripped during method-body skipping.
      let nameEnd = i + 2;
      // Skip generic on class
      if (tokens[nameEnd] && tokens[nameEnd].kind === 'op' && tokens[nameEnd].value === '<') {
        let d = 1; let k = nameEnd + 1;
        while (tokens[k] && d > 0) {
          if (tokens[k].kind === 'op' && tokens[k].value === '<') d++;
          if (tokens[k].kind === 'op' && tokens[k].value === '>') d--;
          if (tokens[k].kind === 'op' && tokens[k].value === '>>') d -= 2;
          k++; if (d === 0) break;
        }
        nameEnd = k;
      }
      if (tokens[nameEnd] && tokens[nameEnd].kind === 'op' && tokens[nameEnd].value === ':') {
        let k = nameEnd + 1;
        let curBase = '';
        while (tokens[k] && tokens[k].kind !== 'lbrace' && !(tokens[k].kind === 'kw' && tokens[k].value === 'where')) {
          if (tokens[k].kind === 'comma') { if (curBase.trim()) cls.baseTypes.push(curBase.trim()); curBase = ''; k++; continue; }
          if (tokens[k].kind === 'ident' || tokens[k].kind === 'dot' || tokens[k].kind === 'kw' || tokens[k].kind === 'op') curBase += tokens[k].value;
          k++;
        }
        if (curBase.trim()) cls.baseTypes.push(curBase.trim());
      }
      // Find class body
      let j = i + 2;
      while (tokens[j] && tokens[j].kind !== 'lbrace' && tokens[j].kind !== 'semi') j++;
      if (!tokens[j] || tokens[j].kind !== 'lbrace') { ir.classes.push(cls); i = j + 1; continue; }
      const classClose = matchClose(tokens, j, 'lbrace', 'rbrace');
      cls.endLine = (classClose !== -1) ? tokens[classClose].line : t.line;
      // Walk members
      let k = j + 1;
      let memberAttrs = [];
      while (k < classClose) {
        const tk = tokens[k];
        if (!tk) break;
        if (tk.kind === 'attr-open') {
          const a = readAttribute(tokens, k, 'unknown');
          if (a) { memberAttrs.push(a.attr); ir.attrs.push(a.attr); k = a.next; continue; }
        }
        // Skip nested classes/structs — they get their own pass via the outer loop pattern.
        if (tk.kind === 'kw' && (tk.value === 'class' || tk.value === 'struct' || tk.value === 'interface' || tk.value === 'record')) {
          // Find the nested type's closing brace and skip it.
          let nb = k + 1;
          while (tokens[nb] && tokens[nb].kind !== 'lbrace' && tokens[nb].kind !== 'semi') nb++;
          if (tokens[nb]?.kind === 'lbrace') {
            const ncClose = matchClose(tokens, nb, 'lbrace', 'rbrace');
            k = ncClose === -1 ? classClose : ncClose + 1;
          } else { k = nb + 1; }
          memberAttrs = [];
          continue;
        }
        const mh = readMethodHeader(tokens, k, memberAttrs);
        if (mh) {
          memberAttrs.forEach(a => { a.attachedTo = 'method'; });
          // Walk the method body to fill calls / decls / assignments / strings.
          walkMethodBody(mh.method);
          cls.methods.push(mh.method);
          ir.methods.push(mh.method);
          ir.calls.push(...mh.method.calls);
          ir.ctors.push(...mh.method.ctors);
          ir.assignments.push(...mh.method.assignments);
          ir.decls.push(...mh.method.decls);
          ir.strings.push(...mh.method.strings);
          memberAttrs = [];
          k = mh.next;
          continue;
        }
        // Field declaration at class level: TypeOrVar Name (=expr)?;
        if (isType(tk)) {
          const tr = readType(tokens, k);
          if (tr && tokens[tr.next] && tokens[tr.next].kind === 'ident') {
            let f = tr.next + 1;
            // optional = init
            if (tokens[f] && tokens[f].kind === 'op' && tokens[f].value === '=') {
              let fj = f + 1, depth = 0;
              while (fj < tokens.length && (depth > 0 || tokens[fj].kind !== 'semi')) {
                if (tokens[fj].kind === 'lparen' || tokens[fj].kind === 'lbrace' || tokens[fj].kind === 'lbracket') depth++;
                if (tokens[fj].kind === 'rparen' || tokens[fj].kind === 'rbrace' || tokens[fj].kind === 'rbracket') depth--;
                fj++;
              }
              ir.decls.push({ name: tokens[tr.next].value, type: tr.type, rhsTokens: tokens.slice(f + 1, fj), rhsText: tokenText(tokens.slice(f + 1, fj)), line: tk.line, isVar: false, isField: true });
              k = fj + 1;
              memberAttrs = [];
              continue;
            }
            if (tokens[f] && tokens[f].kind === 'semi') {
              ir.decls.push({ name: tokens[tr.next].value, type: tr.type, rhsTokens: null, rhsText: '', line: tk.line, isVar: false, isField: true });
              k = f + 1;
              memberAttrs = [];
              continue;
            }
            // Property: TypeName Name { get; set; } — skip the body.
            if (tokens[f] && tokens[f].kind === 'lbrace') {
              const pClose = matchClose(tokens, f, 'lbrace', 'rbrace');
              ir.decls.push({ name: tokens[tr.next].value, type: tr.type, rhsTokens: null, rhsText: '', line: tk.line, isVar: false, isField: true, isProperty: true });
              k = pClose === -1 ? classClose : pClose + 1;
              memberAttrs = [];
              continue;
            }
          }
        }
        k++;
      }
      ir.classes.push(cls);
      i = classClose === -1 ? tokens.length : classClose + 1;
      pendingAttrs = [];
      continue;
    }

    i++;
  }

  // Cross-reference: which class/method does each call live in?
  for (const cls of ir.classes) {
    for (const m of cls.methods) {
      for (const c of m.calls) c.scope = m;
      for (const a of m.assignments) a.scope = m;
      for (const d of m.decls) d.scope = m;
      for (const x of m.ctors) x.scope = m;
    }
  }
  return ir;
}
