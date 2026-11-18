// A write handler gated only by READ permissions: CWE-285.
//
// THE SHAPE. A handler that changes state checks the caller's permissions, but every permission it names is a READ permission:
//
//     public void writeReadings(String deviceId, Reading[] values) {
//         if (!loggedIn() && !device.isPublicRead()) throw new WebApplicationException(FORBIDDEN);
//         if (loggedIn() && !hasRole(Role.READ_DEVICES)) throw new WebApplicationException(FORBIDDEN);
//         readingService.store(deviceId, values);           // a writer only needed read access
//     }
//
// It is the classic copy of a read handler into a write handler: the checks came along unchanged, so anyone allowed to look can now
// change. The fix swaps the read permissions for their write counterparts.
//
// WHAT MUST BE TRUE TO REPORT. The handler's name (or HTTP annotation) says it writes; its body denies access somewhere (403, FORBIDDEN,
// AccessDenied, PermissionDenied, abort(403)); at least one guard condition names a READ permission (`READ_ASSETS`,
// `ACCESS_PUBLIC_READ`, `isAccessPublicRead()`, `canRead`); and nothing in the body names a write, edit, manage or admin permission.
// CWE-285: the check exists but authorizes the wrong operation; the rule cannot tell a missing write check (862) from a wrong one (863).

const FILE_RE = /\.(?:java|kt|cs|ts|tsx|js|mjs|cjs|php)$/i;
const PREFILTER = /READ|Read|read/;

const WRITE_NAME = /^(?:write|update|create|delete|remove|set|save|put|post|patch|insert|upsert|modify|edit|store|upload|import|replace|append|add)(?:[A-Z_]|$)/;
const WRITE_VERB_ANNOTATION = /@(?:PUT|POST|DELETE|PATCH|PutMapping|PostMapping|DeleteMapping|PatchMapping)\b/;
const READ_ANNOTATION = /@(?:GET|GetMapping)\b/;

const READ_TOKEN = /\b(?:READ_[A-Z][A-Z0-9_]*|[A-Z][A-Z0-9_]*_READ(?:_[A-Z0-9_]+)?|\w*PublicRead\w*|canRead\w*|can_read\w*|hasReadAccess\w*|has_read_access)\b/;
const WRITE_TOKEN = /\b(?:WRITE_[A-Z][A-Z0-9_]*|[A-Z][A-Z0-9_]*_WRITE(?:_[A-Z0-9_]+)?|\w*PublicWrite\w*|canWrite\w*|can_write\w*|canEdit\w*|can_edit\w*|hasWriteAccess\w*|(?:EDIT|UPDATE|MANAGE|MODIFY|DELETE|CREATE|ADMIN)_[A-Z][A-Z0-9_]*|[A-Z][A-Z0-9_]*_(?:EDIT|UPDATE|MANAGE|MODIFY|ADMIN))\b/;
const DENY = /\b(?:FORBIDDEN|Forbidden\w*|AccessDenied\w*|PermissionDenied\w*|UnauthorizedAccess\w*|NotAllowed\w*)\b|\b403\b/;

const isTest = (f) => /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(f) || /(?:Test|Tests|IT)\.(?:java|kt|cs)$/.test(f) || /\.(?:test|spec)\.\w+$/.test(f);

/** Index of the `}` closing the `{` at `open`, skipping strings; -1 if unbalanced. */
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


export function scanReadPermissionWrite(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || code.length > 1_000_000 || !PREFILTER.test(code) || isTest(file)) return [];
  if (!READ_TOKEN.test(code) || !DENY.test(code)) return [];
  const out = [];
  const lines = code.split('\n');
  for (const m of methodHeads(code)) {
    const name = m.name;
    // Body: the first `{` after the parameter list, unless a `;` (declaration only) or `=>` expression comes first.
    const after = m.paren;
    let depth = 0; let pClose = -1;
    for (let i = after; i < code.length && i - after < 2000; i++) {
      if (code[i] === '(') depth++;
      else if (code[i] === ')' && --depth === 0) { pClose = i; break; }
    }
    if (pClose < 0) continue;
    const rest = code.slice(pClose, pClose + 400);
    const b = rest.search(/[{;]|=>/);
    if (b < 0 || rest[b] !== '{') continue;
    const open = pClose + b;
    const close = matchBrace(code, open);
    if (close < 0) continue;
    const body = code.slice(open + 1, close);
    const headLine = lineAt(code, m.index);
    const prelude = lines.slice(Math.max(0, headLine - 6), headLine).join('\n');
    const writes = (WRITE_NAME.test(name) || WRITE_VERB_ANNOTATION.test(prelude)) && !READ_ANNOTATION.test(prelude);
    if (!writes) continue;
    if (!DENY.test(body) || WRITE_TOKEN.test(body)) continue;
    // A guard line: a condition naming a read permission, with a denial on it or within the next three lines.
    const bodyLines = body.split('\n');
    const bodyLine0 = lineAt(code, open);
    let hit = -1; let token = '';
    for (let k = 0; k < bodyLines.length; k++) {
      const t = bodyLines[k];
      const tok = t.match(READ_TOKEN);
      if (!tok || !/\bif\s*\(|&&|\|\||ifPresentOrElse|orElseThrow|\bunless\b|\brequire|\bassert/.test(t)) continue;
      if (!DENY.test(bodyLines.slice(k, k + 4).join('\n'))) continue;
      hit = bodyLine0 + k; token = tok[0];
      break;
    }
    if (hit < 0) continue;
    out.push({
      id: `read-permission-write:${file}:${hit}`,
      file, line: hit,
      vuln: `Write handler ${name} is authorized with a read permission (${token})`,
      severity: 'high',
      cwe: 'CWE-285',
      family: 'broken-access-control',
      stride: 'Elevation of Privilege',
      description: `\`${name}\` changes state, but the only permissions it checks are read permissions (\`${token}\` at line ${hit}), and it names no write permission. A caller who may only read can call it and modify data. This is the usual result of copying a read handler's checks into a write handler.`,
      remediation: `Check the write counterpart of each permission in \`${name}\` (for example the WRITE role instead of the READ role, and public-write instead of public-read access flags).`,
      snippet: (lines[hit - 1] || '').trim().slice(0, 200),
      parser: 'READ-GUARDS-WRITE',
      confidence: 0.6,
    });
  }
  return out;
}
