// Per-item permission used to FILTER a listing but not to ENFORCE the matching write: CWE-266 / CWE-285.
//
// THE SHAPE. A resource lists what the caller may pick from by filtering with a per-item permission predicate, and the handler that
// applies the caller's picks loops over the request-supplied items and acts on each without asking the same predicate:
//
//     @GET  available()  { return roles.stream().filter(auth::canAssignRole) ... }      // the UI only offers permitted items
//     @POST add(List<RoleRep> picked) {
//         manage.require();                                                             // a check on the container, not the item
//         for (RoleRep r : picked) container.addRole(lookup(r));                        // any item the caller names is applied
//     }
//
// The listing is a user-interface convenience; the request is under the caller's control, so a hand-written request names an item the
// listing would have hidden. The fix enforces the predicate (`requireAssignRole(item)` or `if (!canAssignRole(item)) throw`) inside the
// loop.
//
// WHAT MUST BE TRUE TO REPORT. The file filters with a predicate named `can<Something>` (a method reference `::canX` or a lambda calling
// `canX(`); a write handler (POST/PUT/DELETE/PATCH annotation, or a write-shaped name) takes a collection parameter and loops over it;
// the loop body calls a mutating method; and neither `can<Something>` nor `require<Something>` with the same Something appears in the
// handler. CWE-266 when the mutation assigns or removes a role, scope, permission or privilege (that is a privilege assignment), else
// CWE-285.

const FILE_RE = /\.(?:java|kt|ts|tsx|js|mjs|cjs)$/i;

const FILTER_PRED = /\.filter\s*\(\s*(?:[\w.()]+?::\s*(can[A-Z]\w*)|\(?\s*\w+\s*\)?\s*->\s*[^)\n]*?\b(can[A-Z]\w*)\s*\(|\(?\s*\w+\s*\)?\s*=>\s*[^)\n]*?\b(can[A-Z]\w*)\s*\()/g;
const WRITE_ANNOTATION = /@(?:POST|PUT|DELETE|PATCH|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b/;
const WRITE_NAME = /^(?:add|delete|remove|update|create|set|grant|revoke|assign|unassign|put|post|patch|save|map|unmap|link|unlink)(?:[A-Z_]|$)/;
const MUTATION = /\.\s*((?:add|delete|remove|grant|revoke|assign|unassign|set|update|insert|save|put|map|unmap|link|unlink|attach|detach)\w*)\s*\(/;
const PRIVILEGE = /role|scope|permission|privilege|grant|authorit|policy|group|membership/i;

const isTest = (f) => /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(f) || /(?:Test|Tests|IT)\.(?:java|kt)$/.test(f) || /\.(?:test|spec)\.\w+$/.test(f);

function matchBrace(code, open) {
  let depth = 0; let q = null;
  for (let i = open; i < code.length; i++) {
    const ch = code[i];
    if (q) { if (ch === '\\') { i++; continue; } if (ch === q || (ch === '\n' && q !== '`')) q = null; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { q = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i;
  }
  return -1;
}
const lineAt = (code, idx) => code.slice(0, idx).split('\n').length;
function matchParen(code, open) {
  let depth = 0;
  for (let i = open; i < code.length && i - open < 4000; i++) {
    if (code[i] === '(') depth++;
    else if (code[i] === ')' && --depth === 0) return i;
  }
  return -1;
}

const NOT_A_METHOD = /^(?:if|for|while|switch|catch|return|new|else|synchronized|using|foreach|throw|do|try)$/;
/**
 * Method headers, found line by line rather than with one regex (a repeated modifier group followed by a type and a name backtracks
 * badly on long lines): the identifier right before the line's first `(`, preceded only by annotations, modifiers and a type.
 */
function methodHeads(code) {
  const out = [];
  let at = 0;
  for (const text of code.split('\n')) {
    const paren = text.indexOf('(');
    if (paren > 0) {
      const toks = text.slice(0, paren).trim().split(/\s+/);
      const name = toks[toks.length - 1];
      if (/^[A-Za-z_]\w*$/.test(name) && !NOT_A_METHOD.test(name) && toks.slice(0, -1).every((t) => /^@?[\w<>[\],.?]+$/.test(t) && !NOT_A_METHOD.test(t))) {
        out.push({ index: at, name, paren: at + paren });
      }
    }
    at += text.length + 1;
  }
  return out;
}


export function scanFilterEnforceAsymmetry(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || code.length > 1_000_000 || !/\.filter\s*\(/.test(code) || isTest(file)) return [];
  const preds = new Set();
  for (const m of code.matchAll(FILTER_PRED)) preds.add(m[1] || m[2] || m[3]);
  if (!preds.size) return [];
  const stems = [...preds].map((p) => p.replace(/^can/, ''));
  const lines = code.split('\n');
  const out = [];
  for (const m of methodHeads(code)) {
    const name = m.name;
    if (!/^[a-z_]/.test(name)) continue;
    const pClose = matchParen(code, m.paren);
    if (pClose < 0) continue;
    const after = code.slice(pClose + 1, pClose + 300);
    const b = after.search(/[{;]|=>/);
    if (b < 0 || after[b] !== '{') continue;
    const paramText = code.slice(m.paren + 1, pClose);
    const headLine = lineAt(code, m.index);
    const prelude = lines.slice(Math.max(0, headLine - 8), headLine - 1).join('\n');
    if (!WRITE_ANNOTATION.test(prelude) && !WRITE_NAME.test(name)) continue;
    // A collection parameter: `List<X> items`, `Set<X> items`, `X[] items`, `items: X[]`, `items: List<X>`.
    const params = [...paramText.matchAll(/(?:(?:List|Set|Collection|Iterable)<[^>]+>|\w+\[\])\s+(\w+)|(\w+)\s*:\s*(?:\w+\[\]|(?:List|Set|Array|Collection)<[^>]+>)/g)]
      .map((x) => x[1] || x[2]);
    if (!params.length) continue;
    const open = pClose + 1 + b;
    const close = matchBrace(code, open);
    if (close < 0) continue;
    const body = code.slice(open + 1, close);
    if (stems.some((s) => new RegExp(`\\b(?:can|require|check|ensure|assert)${s}\\b`).test(body))) continue;
    const bodyLine0 = lineAt(code, open);
    for (const p of params) {
      const loop = body.match(new RegExp(`for\\s*\\(\\s*(?:final\\s+)?[\\w<>.]+\\s+\\w+\\s*:\\s*${p}\\s*\\)\\s*\\{|for\\s*\\(\\s*(?:const|let|var)\\s+\\w+\\s+of\\s+${p}\\s*\\)\\s*\\{|\\b${p}\\s*\\.\\s*forEach\\s*\\(`));
      if (!loop) continue;
      const lOpen = body.indexOf('{', loop.index);
      const lClose = lOpen >= 0 ? matchBrace(body, lOpen) : -1;
      const loopBody = lClose > 0 ? body.slice(lOpen, lClose) : body.slice(loop.index, loop.index + 800);
      const mut = loopBody.match(MUTATION);
      if (!mut) continue;
      const at = bodyLine0 + lineAt(body, (lOpen >= 0 ? lOpen : loop.index) + mut.index) - 1;
      const priv = PRIVILEGE.test(mut[1]) || PRIVILEGE.test(name);
      const pred = [...preds][0];
      out.push({
        id: `filter-enforce-asymmetry:${file}:${at}`,
        file, line: at,
        vuln: `${name} applies request-supplied items without the per-item check (${pred}) the file uses to filter them`,
        severity: 'high',
        cwe: priv ? 'CWE-266' : 'CWE-285',
        family: 'broken-access-control',
        stride: 'Elevation of Privilege',
        description: `This file filters what the caller may choose with \`${pred}\`, but \`${name}\` loops over the items in the request (\`${p}\`) and calls \`${mut[1]}\` on each without asking \`${pred}\` or its require form. Filtering a listing only hides items in the user interface; a hand-written request can name an item the filter would have removed${priv ? ', which here assigns a privilege the caller was not allowed to grant' : ''}.`,
        remediation: `Enforce the same per-item predicate inside the loop, before \`${mut[1]}\`: call the require form of \`${pred}\` or reject the request when \`${pred}(item)\` is false.`,
        snippet: (lines[at - 1] || '').trim().slice(0, 200),
        parser: 'FILTER-ENFORCE',
        confidence: 0.6,
      });
    }
  }
  return out;
}
