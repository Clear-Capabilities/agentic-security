// Database-aware taint (v0.70 #10).
//
// When `user.bio = req.body.bio` writes tainted text to a DB column, then
// later `display(getUser(id).bio)` reads it and feeds it to an HTML
// renderer, that's stored-XSS — but our forward-taint analysis loses the
// flow at the DB boundary because the engine doesn't model storage as a
// memory channel.
//
// This module fills the gap as a SAST detector. It walks file content
// looking for two patterns in the same file (v1 scope; cross-file in v2):
//   1. WRITE:  ORM write/create/update of a model field FROM a user source
//   2. READ:   ORM read of the SAME model field, used in a render/HTML sink
//
// When both patterns match, emit a stored-XSS-class finding with the
// trace pointing to both sites.
//
// ORM frameworks recognized (v1):
//   - Sequelize:    Model.create({ field: x })            / .save()
//   - Prisma:       prisma.<model>.create({ data: { field: x } })
//   - TypeORM:      repo.save({ field: x })               / repo.update(...)
//   - Mongoose:     new Model({ field: x }).save()
//   - SQLAlchemy:   model.field = x; session.add; session.commit
//   - Django ORM:   Model.objects.create(field=x)         / Model(field=x).save()
//
// Render sinks recognized: res.send / res.render / res.write / res.json,
// ctx.body, template helpers (template literals, dangerouslySetInnerHTML).

import { blankComments } from './_comment-strip.js';

const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|query\.|body\.|ctx\.query|ctx\.request|c\.Query|r\.URL\.Query|_GET|_POST|_REQUEST|getParameter)\b/;

// Patterns that capture (model, field, value) where value is a user source.
const WRITE_PATTERNS_JS = [
  // Sequelize Model.create({ field: req.body.x })
  // We capture: model, then any field initializer with a user source.
  /\b([A-Z][\w]*)\s*\.\s*create\s*\(\s*\{[^}]*?\b([a-z_][\w]*)\s*:\s*([^,}]+)/g,
  // Prisma prisma.<model>.create({ data: { field: req.body.x }})
  /\bprisma\s*\.\s*([a-z][\w]*)\s*\.\s*(?:create|update)\s*\(\s*\{[^}]*?data\s*:\s*\{[^}]*?\b([a-z_][\w]*)\s*:\s*([^,}]+)/g,
  // TypeORM repo.save({ field: req.body.x })
  /\b([a-zA-Z_][\w]*)\s*\.\s*save\s*\(\s*\{[^}]*?\b([a-z_][\w]*)\s*:\s*([^,}]+)/g,
];

const WRITE_PATTERNS_PY = [
  // Django Model.objects.create(field=req.POST['x'])
  /\b([A-Z][\w]*)\s*\.\s*objects\s*\.\s*create\s*\(([^)]*?)\b([a-z_]\w*)\s*=\s*([^,)]+)/g,
  // SQLAlchemy: instance.field = request.x; followed by session.commit()
  /\b([a-z_]\w*)\s*\.\s*([a-z_]\w*)\s*=\s*([^\n;]*?(?:request|req|params|query|body|_GET|_POST)[^\n;]*)/g,
];

// Read sites: any `.find / findOne / findByPk / findById / query / get`
// call. We collect those + the captured-variable name (when `const x = ...`)
// + the model name. Then in a separate pass we look for `<var>.<field>`
// access AND for direct `.find(...).<field>` chains.
const READ_CALL_RE_JS =
  /(?:(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:await\s+)?)?\b([A-Z][\w]*|[a-z_][\w]*|prisma\s*\.\s*[a-z][\w]*)\s*\.\s*(?:find|findOne|findByPk|findById|findUnique|findFirst|get|query)\s*\(/g;

const READ_CALL_RE_PY =
  /(?:([a-z_]\w*)\s*=\s*)?\b([A-Z][\w]*)\s*\.\s*objects\s*\.\s*(?:get|filter|first|all)\s*\(/g;

const RENDER_SINK_RE_JS =
  /\b(?:res\.send|res\.write|res\.render|res\.json|ctx\.body\s*=|dangerouslySetInnerHTML|innerHTML\s*=)\b/;

const RENDER_SINK_RE_PY =
  /\b(?:render_template_string|HttpResponse\s*\(|response\.write|HttpResponseHtml)\b/;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}

/**
 * Walk the file once collecting WRITE pairs (model, field, line) where the
 * written value is a user source.
 */
function _findTaintedWrites(code, lang) {
  const writes = [];
  const patterns = lang === 'js' ? WRITE_PATTERNS_JS : WRITE_PATTERNS_PY;
  for (const pat of patterns) {
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      // The capture indices vary by pattern. Inspect groups 1..4.
      // For JS Sequelize: m[1]=model, m[2]=field, m[3]=value
      // For Prisma: m[1]=model, m[2]=field, m[3]=value
      // For Python: m[1]=model, m[3]=field, m[4]=value (Django) or
      //            m[1]=instance, m[2]=field, m[3]=value (SQLA assign)
      let model, field, value;
      if (lang === 'js') {
        model = m[1]; field = m[2]; value = m[3];
      } else {
        // Django: 4 groups; SQLA-style assign: 3 groups
        if (m.length >= 5 && m[4] !== undefined) {
          model = m[1]; field = m[3]; value = m[4];
        } else {
          model = m[1]; field = m[2]; value = m[3];
        }
      }
      if (!value || !TAINT_HINT_RE.test(value)) continue;
      writes.push({ model, field, line: _lineOf(code, m.index) });
    }
  }
  return writes;
}

/**
 * Walk the file collecting READ sites: any ORM read call, optionally
 * captured into a local variable, where THAT variable's `.field` is
 * accessed within a render-sink window in the following ~20 lines.
 *
 * Handles two indirection levels:
 *   (1) `const x = await Model.findOne({...}); res.send('<p>' + x.bio + '</p>')`
 *   (2) `res.send(Model.findOne({...}).bio)`  (direct chain)
 */
function _findRendersOfReads(code, lang) {
  const reads = [];
  const callRe = lang === 'js' ? new RegExp(READ_CALL_RE_JS.source, READ_CALL_RE_JS.flags)
                                : new RegExp(READ_CALL_RE_PY.source, READ_CALL_RE_PY.flags);
  const sinkRe = lang === 'js' ? RENDER_SINK_RE_JS : RENDER_SINK_RE_PY;
  const lines = code.split('\n');
  let m;
  while ((m = callRe.exec(code))) {
    // JS groups: 1=varName (maybe undefined), 2=model.  PY: 1=varName, 2=model.
    const varName = m[1] || null;
    const modelToken = (m[2] || '').trim();
    // Pull a clean model name out of `prisma.user` → `user` style.
    const model = modelToken.includes('.') ? modelToken.split('.').pop() : modelToken;
    const line = _lineOf(code, m.index);
    // Look ahead up to 25 lines for any field access + a render sink in the
    // same window.
    const lo = line - 1;
    const hi = Math.min(lines.length, line + 25);
    const window = lines.slice(lo, hi).join('\n');
    if (!sinkRe.test(window)) continue;
    // Collect every `.<field>` access in the window — they're the read
    // candidates. We try BOTH shapes:
    //   (a) <varName>.<field>  when the call was assigned
    //   (b) .find(...).<field> inline-chain
    const FRAMEWORK_NOISE = new Set(['then', 'catch', 'finally', 'where',
      'select', 'data', 'create', 'update', 'delete', 'save', 'find',
      'findOne', 'findFirst', 'findUnique', 'findByPk', 'findById', 'all',
      'first', 'get', 'query', 'count', 'objects']);
    const fieldRegexes = [];
    if (varName) {
      fieldRegexes.push(new RegExp(`\\b${_escapeRegex(varName)}\\.([a-zA-Z_]\\w*)`, 'g'));
    }
    fieldRegexes.push(new RegExp(
      `\\.\\s*(?:find|findOne|findByPk|findById|findUnique|findFirst|get|query|first|all)\\s*\\([^)]*\\)\\s*\\.\\s*([a-zA-Z_]\\w*)`, 'g'));
    for (const fieldRe of fieldRegexes) {
      let fm;
      while ((fm = fieldRe.exec(window))) {
        const field = fm[1];
        if (FRAMEWORK_NOISE.has(field)) continue;
        const fieldLineLocal = window.slice(0, fm.index).split('\n').length;
        reads.push({ model, field, line: line + fieldLineLocal - 1 });
      }
    }
  }
  return reads;
}

function _escapeRegex(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

export function scanDbTaint(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  // Pre-filter: file must mention both an ORM-write and a render sink.
  if (!/\bcreate\s*\(|\.\s*save\s*\(|\.\s*objects\s*\.|prisma\s*\./.test(code)) return [];
  const writes = _findTaintedWrites(code, lang);
  if (writes.length === 0) return [];
  const reads = _findRendersOfReads(code, lang);
  if (reads.length === 0) return [];

  const findings = [];
  const seen = new Set();
  for (const w of writes) {
    for (const r of reads) {
      // Match on field name (column). Model-name matching is best-effort —
      // many codebases pass model classes around through variables.
      if (w.field !== r.field) continue;
      const id = `db-taint:${fp}:${w.line}->${r.line}:${w.model}.${w.field}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line: r.line,
        vuln: `Stored XSS via DB round-trip (${w.model}.${w.field})`,
        severity: 'high',
        cwe: 'CWE-79',
        family: 'stored-xss',
        stride: 'Tampering',
        snippet: (raw.split('\n')[r.line - 1] || '').trim().slice(0, 200),
        remediation:
          `User content written to ${w.model}.${w.field} at line ${w.line} is later read at line ${r.line} and fed to a render sink. ` +
          'Mitigations: ' +
          '(1) sanitize at WRITE time (HTML-escape before storage) and tag the column as "html-safe stored", OR ' +
          '(2) escape at READ time inside the render (use the framework\'s auto-escape), OR ' +
          '(3) use a content-security-policy that blocks inline scripts on rendered pages. ' +
          'Defense in depth: do BOTH (1) and (2).',
        parser: 'DB-TAINT',
        confidence: 0.7,
        trace: [
          { line: w.line, kind: 'db-write', sourceLabel: `${w.model}.${w.field} ← user source` },
          { line: r.line, kind: 'db-read',  sourceLabel: `${w.model}.${w.field} → render` },
        ],
      });
    }
  }
  return findings;
}
