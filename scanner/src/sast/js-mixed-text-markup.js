// JavaScript/TypeScript: DOM content serialised by mixing decoded text with markup (CWE-79).
//
// Code that turns a list of DOM child nodes back into an HTML string often walks the nodes and, per node, takes the element's markup
// (`outerHTML`, `innerHTML`, `.html()`) or the text node's text (`textContent`, `nodeValue`, `data`, `innerText`, jQuery `.text()`).
// The two are not the same kind of string. Markup is escaped (`&lt;` stays `&lt;`); text is DECODED (`&lt;img onerror=..&gt;` in the
// page reads back as `<img onerror=..>`). Joining them into one string and later using it as HTML turns text the page showed as
// harmless characters into live elements: a stored XSS whenever that text came from a user.
//
// The rule reports a node-type branch (`nodeType === 3`, `Node.TEXT_NODE`, `nodeName === '#text'`, `instanceof Text`) whose one arm
// reads decoded text and whose other arm reads markup, as a conditional expression, or as an if/else whose arms both append to the same
// string or list. It is silent when the text arm passes the text through any call (an escaper), or when the serialisation goes through
// markup only (cloning the nodes into a wrapper and reading the wrapper's `innerHTML`). It does not check where the joined string is
// used; the finding says so.
import { parseSync } from '@babel/core';
import presetReact from '@babel/preset-react';
import presetTypescript from '@babel/preset-typescript';

const FILE_RE = /\.(?:[cm]?[jt]sx?)$/i;
const MARKUP_PROPS = new Set(['outerHTML', 'innerHTML']);
const TEXT_PROPS = new Set(['textContent', 'nodeValue', 'innerText', 'data', 'wholeText']);
const NODE_TYPE_TEST = /\bnodeType\s*[!=]==?\s*(?:3|Node\.TEXT_NODE)\b|\b(?:3|Node\.TEXT_NODE)\s*[!=]==?\s*[\w$.()\s]*nodeType\b|\bnodeName\s*[!=]==?\s*['"]#text['"]|\binstanceof\s+Text\b/;

function parse(file, code) {
  try {
    return parseSync(code, {
      filename: file, sourceType: 'unambiguous', babelrc: false, configFile: false,
      presets: [presetReact, [presetTypescript, { ignoreExtensions: true }]],
      parserOpts: { plugins: ['decorators-legacy'], errorRecovery: true },
    });
  } catch { return null; }
}

function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const n of node) walk(n, visit); return; }
  if (typeof node.type !== 'string') return;
  visit(node);
  for (const k of Object.keys(node)) {
    if (k === 'loc' || k === 'start' || k === 'end' || k.endsWith('Comments') || k === 'extra') continue;
    const v = node[k];
    if (v && typeof v === 'object') walk(v, visit);
  }
}

const isMember = (m) => m?.type === 'MemberExpression' || m?.type === 'OptionalMemberExpression';
const propName = (m) => (isMember(m) && !m.computed ? m.property?.name : null);
const isCallNode = (c) => c?.type === 'CallExpression' || c?.type === 'OptionalCallExpression';
// a zero-argument method call (a getter such as jQuery `.html()` / `.text()`)
const getterName = (c) => (isCallNode(c) && c.arguments.length === 0 ? propName(c.callee) : null);
const unwrap = (e) => (e && (e.type === 'TSAsExpression' || e.type === 'ParenthesizedExpression') ? unwrap(e.expression) : e);

/** markup read: x.outerHTML, x.innerHTML, $(x).html() */
const isMarkupRead = (e) => { const u = unwrap(e); return MARKUP_PROPS.has(propName(u)) || getterName(u) === 'html'; };
/** decoded text read, not passed through any call: x.textContent, x.nodeValue, $(x).text() */
const isTextRead = (e) => {
  const u = unwrap(e);
  if (!u) return false;
  if (u.type === 'LogicalExpression') return isTextRead(u.left) || isTextRead(u.right);
  return TEXT_PROPS.has(propName(u)) || getterName(u) === 'text';
};
const mixes = (a, b) => (isTextRead(a) && isMarkupRead(b)) || (isMarkupRead(a) && isTextRead(b));

/** the single expression an if/else arm appends: `s += e` or `parts.push(e)`, with the target's source text */
function appended(stmt, code) {
  let s = stmt;
  if (s?.type === 'BlockStatement') { if (s.body.length !== 1) return null; s = s.body[0]; }
  if (s?.type !== 'ExpressionStatement') return null;
  const e = s.expression;
  if (e.type === 'AssignmentExpression' && e.operator === '+=') return { target: code.slice(e.left.start, e.left.end), value: e.right };
  if (isCallNode(e) && propName(e.callee) === 'push' && e.arguments.length === 1) return { target: `${code.slice(e.callee.object.start, e.callee.object.end)}.push`, value: e.arguments[0] };
  return null;
}

export function scanJsMixedTextMarkup(file, code) {
  if (!FILE_RE.test(file) || !code || code.length > 400_000) return [];
  if (!/outerHTML|innerHTML|\.html\(\s*\)/.test(code)) return [];
  if (!/textContent|nodeValue|innerText|\.text\(\s*\)|\.data\b|wholeText/.test(code)) return [];
  if (!/nodeType|TEXT_NODE|#text|instanceof\s+Text\b/.test(code)) return [];
  const ast = parse(file, code);
  if (!ast) return [];
  const out = []; const seen = new Set();
  const report = (node) => {
    const line = node.loc?.start?.line || 1;
    if (seen.has(line)) return;
    seen.add(line);
    out.push({
      id: `js-mixed-text-markup:${file}:${line}`,
      file, line,
      vuln: 'XSS: decoded DOM text joined with markup',
      severity: 'medium',
      cwe: 'CWE-79',
      family: 'xss',
      stride: 'Tampering',
      description: 'A node-type branch serialises DOM content by taking markup (outerHTML/innerHTML/.html()) for elements and DECODED text (textContent/nodeValue/.text()) for text nodes, and joins them into one string. Text the page displayed as `&lt;img onerror=..&gt;` reads back as `<img onerror=..>`, so when the joined string is used as HTML that text becomes a live element. Where the string is used is not checked here.',
      remediation: 'Serialise through markup only (clone the nodes into a wrapper element and read its innerHTML), or escape the text arm (`escapeHtml(node.textContent)`) before joining it with markup.',
      snippet: (code.split('\n')[line - 1] || '').trim().slice(0, 200),
      parser: 'MIXED-TEXT-MARKUP',
      confidence: 0.6,
    });
  };
  walk(ast.program, (n) => {
    if (n.type === 'ConditionalExpression' && NODE_TYPE_TEST.test(code.slice(n.test.start, n.test.end)) && mixes(n.consequent, n.alternate)) report(n);
    if (n.type === 'IfStatement' && n.alternate && NODE_TYPE_TEST.test(code.slice(n.test.start, n.test.end))) {
      const a = appended(n.consequent, code); const b = appended(n.alternate, code);
      if (a && b && a.target === b.target && mixes(a.value, b.value)) report(n);
    }
  });
  return out;
}
