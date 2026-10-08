export const id = 9227;
export const ids = [9227];
export const modules = {

/***/ 89227:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   analyzePolyglotBridges: () => (/* binding */ analyzePolyglotBridges)
/* harmony export */ });
/* unused harmony exports BRIDGES_VERSION, blastRadius */
/* harmony import */ var _secrets_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(55812);
/* harmony import */ var _nix_ir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(91548);
// Polyglot and deployment/configuration bridges (X-006).
//
// Links an application written in Haskell to the other services it talks to, and Nix service declarations to the
// application that reads their environment. A link is made ONLY from an exact, independently evidenced protocol fact:
//
//   http   a literal client URL (method + path) equals a server route, AND the target service is identified by a
//          matching listener port or a host equal to the service root. A path match alone is a candidate.
//   queue  a literal queue/topic name written by a producer equals the name read by a consumer in another root over
//          the SAME broker technology. Different technology with one name is a gap, not a link.
//   store  a table and column set written by one root and read by another, over the same literal database name.
//   env    a Nix service environment variable is read by the application that service LAUNCHES (the executable or
//          package named in ExecStart equals the application's own name). A matching variable name alone is a candidate.
//
// Field paths are only attached to a LINKED bridge, and only where the two sides name the same field. A similar field
// name never creates a link. Anything dynamic, ambiguous, mismatched or on an unsupported protocol is returned as a
// candidate or gap with its reason, never as a proven flow.
//
// Source roots: the first path segment of a file is its service root ('.' for top-level files). Locations are the
// original file and line. Nothing is executed or fetched; this is static source evidence ("scope": "static-source").
//
// Inclusion (a service's package contains an application) and data propagation are separate lists: a blast-radius or
// reverse query over data links never follows an inclusion edge unless the caller asks for it.




const BRIDGES_VERSION = 'language-bridges/1';
const SCOPE = 'static-source';
const MAX_FILE = 600_000;

const langOf = (f) => (/\.l?hs$/i.test(f) ? 'haskell' : /\.(?:mjs|cjs|js|jsx|ts|tsx)$/i.test(f) ? 'javascript' : /\.py$/i.test(f) ? 'python' : /\.nix$/i.test(f) ? 'nix' : null);
const rootOf = (f) => { const parts = f.split('/'); return parts.length > 1 ? parts[0] : '.'; };
const lineAt = (text, idx) => { let l = 1; for (let i = 0; i < idx && i < text.length; i++) if (text.charCodeAt(i) === 10) l++; return l; };
const uniq = (a) => [...new Set(a)];
const METHODS = new Set(['get', 'post', 'put', 'delete', 'patch']);

// ── comment stripping for C-like and Python sources (keeps offsets and newlines) ──
function stripComments(text, lang) {
  const out = text.split('');
  const n = text.length;
  let i = 0; let str = null;
  while (i < n) {
    const c = text[i]; const d = text[i + 1];
    if (str) { if (c === '\\') { i += 2; continue; } if (c === str) str = null; i++; continue; }
    if (c === '"' || c === "'" || (c === '`' && lang === 'javascript')) { str = c; i++; continue; }
    if (lang === 'javascript' && c === '/' && d === '/') { while (i < n && text[i] !== '\n') { out[i] = ' '; i++; } continue; }
    if (lang === 'javascript' && c === '/' && d === '*') { while (i < n && !(text[i] === '*' && text[i + 1] === '/')) { if (text[i] !== '\n') out[i] = ' '; i++; } if (i < n) { out[i] = ' '; out[i + 1] = ' '; } i += 2; continue; }
    if (lang === 'python' && c === '#') { while (i < n && text[i] !== '\n') { out[i] = ' '; i++; } continue; }
    i++;
  }
  return out.join('');
}

// ── URL and SQL helpers ───────────────────────────────────────────────────────
function parseUrl(literal) {
  const m = /^(?:([A-Z]+)\s+)?([a-z][a-z0-9+.-]*):\/\/([^/?#\s:]+)(?::(\d+))?(\/[^?#\s]*)?/i.exec(String(literal).trim());
  if (!m) return null;
  return { method: (m[1] || 'GET').toUpperCase(), scheme: m[2].toLowerCase(), host: m[3].toLowerCase(), port: m[4] ? Number(m[4]) : null, path: m[5] || '/' };
}
const SEG_PARAM = /^(?::[\w-]+|\{[\w-]+\}|<[\w:]+>|\$[\w]+)$/;
function pathKey(p) { return String(p).split('/').map((s) => (SEG_PARAM.test(s) ? '*' : s)).join('/').replace(/\/+$/, '') || '/'; }

const SQL_WRITE = /^\s*(?:insert\s+into|update|replace\s+into)\s+["`]?([\w.]+)["`]?/i;
const SQL_READ = /^\s*select\s+([\s\S]+?)\s+from\s+["`]?([\w.]+)["`]?/i;
function sqlFacts(sql) {
  const w = SQL_WRITE.exec(sql);
  if (w) {
    let cols = [];
    const ins = /^\s*(?:insert|replace)\s+into\s+["`]?[\w.]+["`]?\s*\(([^)]*)\)/i.exec(sql);
    if (ins) cols = ins[1].split(',').map((s) => s.trim().replace(/["`]/g, '')).filter((s) => /^\w+$/.test(s));
    else { const set = /\bset\s+([\s\S]+?)(?:\bwhere\b|$)/i.exec(sql); if (set) cols = [...set[1].matchAll(/["`]?(\w+)["`]?\s*=/g)].map((m) => m[1]); }
    return { mode: 'write', table: w[1].toLowerCase(), columns: uniq(cols.map((c) => c.toLowerCase())) };
  }
  const r = SQL_READ.exec(sql);
  if (r) {
    const raw = r[1].trim();
    const cols = raw === '*' ? ['*'] : raw.split(',').map((s) => s.trim().replace(/^.*\./, '').replace(/\s+as\s+.*$/i, '').replace(/["`]/g, '')).filter((s) => /^[\w*]+$/.test(s));
    return { mode: 'read', table: r[2].toLowerCase(), columns: uniq(cols.map((c) => c.toLowerCase())) };
  }
  return null;
}
const dbNameOf = (s) => { const m = /(?:dbname|database)\s*=\s*['"]?([\w-]+)/i.exec(s) || /\/\/[^/\s]+\/([\w-]+)/.exec(s); return m ? m[1].toLowerCase() : null; };
const dbHostOf = (s) => { const m = /host\s*=\s*['"]?([\w.-]+)/i.exec(s) || /\/\/(?:[^@/\s]*@)?([\w.-]+)/.exec(s); return m ? m[1].toLowerCase() : null; };

// ── per-language extraction ──────────────────────────────────────────────────
function emptyFacts() { return { clients: [], routes: [], listeners: [], producers: [], consumers: [], sql: [], dbConns: [], envReads: [], dynamic: [], names: [] }; }

function haskellFacts(file, text) {
  const f = emptyFacts();
  const toks = (0,_secrets_js__WEBPACK_IMPORTED_MODULE_0__/* .tokenizeHaskell */ .cH)(text);
  const imports = new Set([...text.matchAll(/^import\s+(?:qualified\s+)?([\w.]+)/gm)].map((m) => m[1]));
  const amqp = [...imports].some((m) => /^Network\.AMQP/.test(m));
  const kafka = [...imports].some((m) => /^Kafka\./.test(m));
  const lineOfTok = (t) => lineAt(text, t.start);
  const windowEnd = (i, max) => { let j = i + 1; while (j < toks.length && j - i <= max) { if (text[toks[j].start - 1] === '\n' && /\S/.test(text[toks[j].start]) && j > i + 1) break; j++; } return j; };
  const keysIn = (a, b, op) => { const out = []; for (let k = a; k < b - 1; k++) if (toks[k].k === 's' && toks[k + 1].k === 'o' && toks[k + 1].v === op) out.push(toks[k].v); return out; };
  const readsIn = (a, b) => { const out = []; for (let k = a; k < b - 1; k++) if (toks[k].k === 'o' && /^\.:\??$/.test(toks[k].v) && toks[k + 1].k === 's') out.push(toks[k + 1].v); return out; };
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.k !== 'i') continue;
    const base = t.v.replace(/^.*\./, '');
    const next = toks[i + 1];
    if (/^(?:parseRequest|parseRequest_|parseUrlThrow|parseUrlThrow_)$/.test(base)) {
      if (next && next.k === 's') {
        const u = parseUrl(next.v);
        const end = windowEnd(i, 80);
        if (u) f.clients.push({ file, line: lineOfTok(t), language: 'haskell', ...u, fields: uniq(keysIn(i, end, '.=')) });
        else f.dynamic.push({ file, line: lineOfTok(t), language: 'haskell', kind: 'http', reason: `request literal "${next.v.slice(0, 40)}" is not an absolute URL` });
      } else f.dynamic.push({ file, line: lineOfTok(t), language: 'haskell', kind: 'http', reason: 'dynamic endpoint: the request target is not a string literal' });
    } else if (METHODS.has(base) && next && next.k === 's' && next.v.startsWith('/') && /^(?:get|post|put|delete|patch)$/.test(t.v)) {
      const end = windowEnd(i, 120);
      f.routes.push({ file, line: lineOfTok(t), language: 'haskell', method: base.toUpperCase(), path: next.v, fields: uniq(readsIn(i, end)) });
    } else if (/^publishMsg'?$/.test(base)) {
      const strs = []; for (let k = i + 1; k < Math.min(toks.length, i + 8); k++) if (toks[k].k === 's') strs.push(toks[k].v);
      const end = windowEnd(i, 60);
      if (strs.length) f.producers.push({ file, line: lineOfTok(t), language: 'haskell', tech: amqp ? 'amqp' : null, name: strs.length > 1 ? strs[1] : strs[0], fields: uniq(keysIn(i - 30 < 0 ? 0 : i - 30, end, '.=')) });
      else f.dynamic.push({ file, line: lineOfTok(t), language: 'haskell', kind: 'queue', reason: 'dynamic queue name' });
    } else if (/^(?:consumeMsgs'?|getMsg|declareQueue)$/.test(base)) {
      const s = toks.slice(i + 1, i + 5).find((x) => x.k === 's');
      const end = windowEnd(i, 120);
      if (s) f.consumers.push({ file, line: lineOfTok(t), language: 'haskell', tech: amqp ? 'amqp' : null, name: s.v, fields: uniq(readsIn(i, end)) });
    } else if (base === 'TopicName' && next && next.k === 's') {
      const end = windowEnd(i, 60);
      const role = /Producer|produceMessage|ProducerRecord/.test(text) ? 'producers' : 'consumers';
      f[role].push({ file, line: lineOfTok(t), language: 'haskell', tech: kafka ? 'kafka' : null, name: next.v, fields: uniq(role === 'producers' ? keysIn(i - 20 < 0 ? 0 : i - 20, end, '.=') : readsIn(i, end)) });
    } else if (/^(?:execute|execute_|query|query_|executeMany)$/.test(base)) {
      const s = toks.slice(i + 1, i + 6).find((x) => x.k === 's');
      const facts = s ? sqlFacts(s.v) : null;
      if (facts) f.sql.push({ file, line: lineOfTok(t), language: 'haskell', ...facts, connection: null });
    } else if (/^connectPostgreSQL'?$/.test(base) && next && next.k === 's') {
      f.dbConns.push({ file, line: lineOfTok(t), language: 'haskell', db: dbNameOf(next.v), host: dbHostOf(next.v) });
    } else if (/^(?:lookupEnv|getEnv|getEnvDefault)$/.test(base) && next && next.k === 's') {
      f.envReads.push({ file, line: lineOfTok(t), language: 'haskell', name: next.v });
    }
  }
  for (const m of text.matchAll(/(?:^|[\s(])(?:run|scotty|runEnv|Warp\.run)\s+(\d{2,5})\b/gm)) f.listeners.push({ file, line: lineAt(text, m.index), language: 'haskell', port: Number(m[1]) });
  return f;
}

function jsFacts(file, raw) {
  const f = emptyFacts();
  const text = stripComments(raw, 'javascript');
  const amqp = /['"]amqplib['"]/.test(text); const kafka = /['"]kafkajs['"]/.test(text);
  const routeRe = /\b(?:app|router|server)\.(get|post|put|delete|patch)\(\s*(['"`])([^'"`]+)\2/g;
  const routes = [...text.matchAll(routeRe)];
  routes.forEach((m, idx) => {
    const seg = text.slice(m.index, idx + 1 < routes.length ? routes[idx + 1].index : text.length);
    const fields = [];
    for (const r of seg.matchAll(/\breq\.body\.(\w+)/g)) fields.push(r[1]);
    for (const r of seg.matchAll(/\breq\.body\[\s*['"](\w+)['"]\s*\]/g)) fields.push(r[1]);
    for (const r of seg.matchAll(/\{([^{}]*)\}\s*=\s*req\.body/g)) for (const x of r[1].split(',')) { const n = x.trim().split(/[:=\s]/)[0]; if (/^\w+$/.test(n)) fields.push(n); }
    f.routes.push({ file, line: lineAt(text, m.index), language: 'javascript', method: m[1].toUpperCase(), path: m[3], fields: uniq(fields) });
  });
  for (const m of text.matchAll(/\.listen\(\s*(\d{2,5})\b/g)) f.listeners.push({ file, line: lineAt(text, m.index), language: 'javascript', port: Number(m[1]) });
  for (const m of text.matchAll(/\b(?:fetch|axios\.(?:get|post|put|delete|patch))\(\s*(['"`])((?:https?):\/\/[^'"`]+)\1(?:\s*,\s*\{([^}]*)\})?/g)) {
    const u = parseUrl(m[2]); if (!u) continue;
    const verb = /axios\.(\w+)/.exec(m[0]); const meth = /method\s*:\s*['"](\w+)['"]/i.exec(m[3] || '');
    const body = (m[3] || '').match(/JSON\.stringify\(\{([^}]*)\}\)/);
    const seg = body ? [...body[1].matchAll(/(\w+)\s*[:,]/g)].map((x) => x[1]) : [];
    f.clients.push({ file, line: lineAt(text, m.index), language: 'javascript', ...u, method: (verb ? verb[1] : meth ? meth[1] : 'GET').toUpperCase(), fields: uniq(seg) });
  }
  const queueTechs = amqp ? 'amqp' : kafka ? 'kafka' : null;
  for (const m of text.matchAll(/\.(consume|sendToQueue)\(\s*(['"`])([^'"`]+)\2/g)) {
    (m[1] === 'consume' ? f.consumers : f.producers).push({ file, line: lineAt(text, m.index), language: 'javascript', tech: queueTechs, name: m[3], fields: [] });
  }
  for (const m of text.matchAll(/\.publish\(\s*(['"`])[^'"`]*\1\s*,\s*(['"`])([^'"`]+)\2/g)) f.producers.push({ file, line: lineAt(text, m.index), language: 'javascript', tech: queueTechs, name: m[3], fields: [] });
  for (const m of text.matchAll(/topic\s*:\s*(['"`])([^'"`]+)\1/g)) {
    const before = text.slice(Math.max(0, m.index - 140), m.index);
    (/\bsubscribe\b/.test(before) ? f.consumers : f.producers).push({ file, line: lineAt(text, m.index), language: 'javascript', tech: kafka ? 'kafka' : null, name: m[2], fields: [] });
  }
  // fields: attach message field names seen in a JSON.stringify({...}) / JSON.parse(...) variable within the call window
  for (const p of f.producers) { const seg = text.slice(Math.max(0, text.indexOf(p.name) - 200), text.indexOf(p.name) + 300); const o = /JSON\.stringify\(\{([^}]*)\}\)/.exec(seg); if (o) p.fields = uniq([...o[1].matchAll(/(\w+)\s*[:,]/g)].map((x) => x[1])); }
  for (const c of f.consumers) { const seg = text; const v = /(?:const|let|var)\s+(\w+)\s*=\s*JSON\.parse/.exec(seg); if (v) c.fields = uniq([...seg.matchAll(new RegExp(`\\b${v[1]}\\.(\\w+)`, 'g'))].map((x) => x[1])); }
  for (const m of text.matchAll(/\.(?:query|execute)\(\s*(['"`])([\s\S]*?)\1/g)) { const s = sqlFacts(m[2]); if (s) f.sql.push({ file, line: lineAt(text, m.index), language: 'javascript', ...s }); }
  for (const m of text.matchAll(/new\s+(?:Pool|Client)\(\s*\{([^}]*)\}/g)) f.dbConns.push({ file, line: lineAt(text, m.index), language: 'javascript', db: dbNameOf(`database=${(/database\s*:\s*['"]([\w-]+)/.exec(m[1]) || [])[1] || ''}`), host: ((/host\s*:\s*['"]([\w.-]+)/.exec(m[1]) || [])[1] || null) });
  for (const m of text.matchAll(/process\.env\.([A-Z_][A-Z0-9_]*)|process\.env\[\s*['"]([^'"]+)['"]\s*\]/g)) f.envReads.push({ file, line: lineAt(text, m.index), language: 'javascript', name: m[1] || m[2] });
  return f;
}

function pyFacts(file, raw) {
  const f = emptyFacts();
  const text = stripComments(raw, 'python');
  const pika = /\bimport pika\b|\bfrom pika\b/.test(text);
  const decos = [...text.matchAll(/@\w+\.(?:route\(\s*(['"])([^'"]+)\1(?:\s*,\s*methods\s*=\s*\[([^\]]*)\])?|(get|post|put|delete|patch)\(\s*(['"])([^'"]+)\5)/g)];
  decos.forEach((m, idx) => {
    const seg = text.slice(m.index, idx + 1 < decos.length ? decos[idx + 1].index : text.length);
    const fields = [];
    for (const r of seg.matchAll(/(?:request\.(?:json|get_json\(\))|data|payload|body)\s*\[\s*['"](\w+)['"]\s*\]/g)) fields.push(r[1]);
    for (const r of seg.matchAll(/(?:request\.(?:json|get_json\(\))|data|payload|body)\.get\(\s*['"](\w+)['"]/g)) fields.push(r[1]);
    const path = m[2] || m[6];
    const methods = m[4] ? [m[4].toUpperCase()] : (m[3] ? [...m[3].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : ['GET']);
    for (const method of methods) f.routes.push({ file, line: lineAt(text, m.index), language: 'python', method, path, fields: uniq(fields) });
  });
  for (const m of text.matchAll(/\b(?:app|uvicorn)\.run\([^)]*?\bport\s*=\s*(\d{2,5})/g)) f.listeners.push({ file, line: lineAt(text, m.index), language: 'python', port: Number(m[1]) });
  for (const m of text.matchAll(/requests\.(get|post|put|delete|patch)\(\s*(['"])(https?:\/\/[^'"]+)\2([^)]*)\)/g)) {
    const u = parseUrl(m[3]); if (!u) continue;
    const js = /json\s*=\s*\{([^}]*)\}/.exec(m[4] || '');
    f.clients.push({ file, line: lineAt(text, m.index), language: 'python', ...u, method: m[1].toUpperCase(), fields: js ? uniq([...js[1].matchAll(/['"](\w+)['"]\s*:/g)].map((x) => x[1])) : [] });
  }
  for (const m of text.matchAll(/basic_consume\([^)]*?queue\s*=\s*(['"])([^'"]+)\1/g)) f.consumers.push({ file, line: lineAt(text, m.index), language: 'python', tech: pika ? 'amqp' : null, name: m[2], fields: [] });
  for (const m of text.matchAll(/basic_publish\([^)]*?routing_key\s*=\s*(['"])([^'"]+)\1/g)) f.producers.push({ file, line: lineAt(text, m.index), language: 'python', tech: pika ? 'amqp' : null, name: m[2], fields: [] });
  for (const c of f.consumers) { const seg = text; const v = /(\w+)\s*=\s*json\.loads/.exec(seg); if (v) c.fields = uniq([...seg.matchAll(new RegExp(`\\b${v[1]}\\[\\s*['"](\\w+)['"]\\s*\\]|\\b${v[1]}\\.get\\(\\s*['"](\\w+)['"]`, 'g'))].map((x) => x[1] || x[2])); }
  for (const m of text.matchAll(/\.execute\(\s*(['"]{1,3})([\s\S]*?)\1/g)) { const s = sqlFacts(m[2]); if (s) f.sql.push({ file, line: lineAt(text, m.index), language: 'python', ...s }); }
  for (const m of text.matchAll(/\.connect\(([^)]*)\)/g)) { if (!/dbname|database/.test(m[1])) continue; f.dbConns.push({ file, line: lineAt(text, m.index), language: 'python', db: dbNameOf(m[1].replace(/['"]/g, '').replace(/,\s*/g, ' ').replace(/\bdatabase\s*=/, 'database=')), host: dbHostOf(m[1].replace(/['"]/g, '').replace(/,\s*/g, ' ')) }); }
  for (const m of text.matchAll(/os\.environ\[\s*['"]([^'"]+)['"]\s*\]|os\.environ\.get\(\s*['"]([^'"]+)['"]|os\.getenv\(\s*['"]([^'"]+)['"]/g)) f.envReads.push({ file, line: lineAt(text, m.index), language: 'python', name: m[1] || m[2] || m[3] });
  return f;
}

/** Application identity per root, from manifests only (never from directory guesswork alone beyond the root name). */
function appNames(files) {
  const out = new Map();
  const add = (root, name) => { if (!name) return; if (!out.has(root)) out.set(root, new Set()); out.get(root).add(String(name).toLowerCase()); };
  for (const [file, text] of Object.entries(files)) {
    const root = rootOf(file);
    if (/\.cabal$/i.test(file)) { for (const m of String(text).matchAll(/^\s*(?:executable|name)\s*:?\s+([\w-]+)/gim)) add(root, m[1]); }
    else if (/(?:^|\/)package\.ya?ml$/i.test(file)) { for (const m of String(text).matchAll(/^name:\s*([\w-]+)/gm)) add(root, m[1]); const ex = /^executables:\s*\n((?:[ \t]+.*\n?)*)/m.exec(text); if (ex) for (const m of ex[1].matchAll(/^[ \t]{2}([\w-]+):/gm)) add(root, m[1]); }
    else if (/(?:^|\/)package\.json$/i.test(file)) { try { add(root, JSON.parse(text).name); } catch { /* malformed manifest: no identity */ } }
    else if (/(?:^|\/)pyproject\.toml$/i.test(file)) { const m = /^name\s*=\s*['"]([\w-]+)['"]/m.exec(text); if (m) add(root, m[1]); }
  }
  return out;
}

function nixServices(files) {
  const services = [];
  for (const [file, text] of Object.entries(files)) {
    if (!/\.nix$/i.test(file)) continue;
    let ir; try { ir = (0,_nix_ir_js__WEBPACK_IMPORTED_MODULE_1__/* .analyzeNix */ .KL)(text, { file }).ir; } catch { continue; }
    const by = new Map();
    for (const b of ir.bindings || []) {
      const p = b.path || [];
      const si = p.indexOf('services');
      if (p[0] !== 'systemd' || si !== 1 || !p[2]) continue;
      const name = p[2];
      if (!by.has(name)) by.set(name, { name, file, line: b.span.startLine, env: {}, environmentFile: false, exec: null, pkg: null, exe: null, port: null, dynamic: false });
      const s = by.get(name); const rest = p.slice(3).join('.');
      if (/^environment\.[A-Za-z_][\w]*$/.test(rest)) s.env[p[4]] = { line: b.span.startLine, value: b.value && b.value.literal != null ? b.value.literal : null };
      else if (/EnvironmentFile$/.test(rest)) s.environmentFile = true;
      else if (/(?:^|\.)ExecStart$/.test(rest) || rest === 'script') {
        s.exec = text.slice(b.valueSpan.startOffset, b.valueSpan.endOffset);
        const interp = (b.value && b.value.interpolations || []).map((x) => x.text);
        const pk = interp.map((t) => /^pkgs\.([\w-]+)/.exec(t)).find(Boolean); if (pk) s.pkg = pk[1].toLowerCase();
        const exe = /\/bin\/([\w.-]+)/.exec(s.exec); if (exe) s.exe = exe[1].toLowerCase();
        const port = /--port[ =](\d{2,5})/.exec(s.exec); if (port) s.port = Number(port[1]);
        if (rest === 'script') { s.dynamic = true; }
      }
      if (b.dynamic) s.dynamic = true;
    }
    services.push(...by.values());
  }
  for (const s of services) if (s.port == null && s.env.PORT && /^\d+$/.test(String(s.env.PORT.value))) s.port = Number(s.env.PORT.value);
  return services;
}

const loc = (x) => ({ file: x.file, line: x.line, language: x.language, root: rootOf(x.file) });

/**
 * @param {Record<string,string>} files every source/manifest/Nix file handed to the scan
 * @returns {{version, scope, services, inclusions, bridges, candidates, gaps, limits}}
 */
function analyzePolyglotBridges(files) {
  const all = {};
  for (const [f, t] of Object.entries(files || {})) if (typeof t === 'string' && t.length <= MAX_FILE) all[f] = t;
  const facts = emptyFacts();
  const merge = (x) => { for (const k of Object.keys(facts)) facts[k].push(...x[k]); };
  for (const [file, text] of Object.entries(all)) {
    const lang = langOf(file);
    try { if (lang === 'haskell') merge(haskellFacts(file, text)); else if (lang === 'javascript') merge(jsFacts(file, text)); else if (lang === 'python') merge(pyFacts(file, text)); } catch { /* one file's failure never hides the others */ }
  }
  const names = appNames(all);
  const services = nixServices(all);
  const bridges = []; const candidates = []; const gaps = [];
  const push = (list, o) => list.push({ scope: SCOPE, ...o });

  // listener ports per root
  const portsByRoot = new Map();
  for (const l of facts.listeners) { const r = rootOf(l.file); if (!portsByRoot.has(r)) portsByRoot.set(r, new Set()); portsByRoot.get(r).add(l.port); }
  const rootsOnPort = (port) => [...portsByRoot.entries()].filter(([, s]) => s.has(port)).map(([r]) => r);
  const allRoots = new Set(Object.keys(all).map(rootOf));

  // ── http ────────────────────────────────────────────────────────────────────
  for (const d of facts.dynamic) push(gaps, { kind: d.kind, status: 'gap', reason: d.reason, from: loc(d), evidence: [] });
  for (const c of facts.clients) {
    const from = loc(c);
    if (!/^https?$/.test(c.scheme)) { push(gaps, { kind: 'http', status: 'gap', reason: `unsupported protocol "${c.scheme}"`, from, evidence: [] }); continue; }
    const key = pathKey(c.path);
    const sameRoute = facts.routes.filter((r) => rootOf(r.file) !== from.root && pathKey(r.path) === key);
    const matching = sameRoute.filter((r) => r.method === c.method);
    if (!matching.length) {
      if (sameRoute.length) push(gaps, { kind: 'http', status: 'gap', reason: `method mismatch: client ${c.method} ${c.path}, server offers ${sameRoute.map((r) => r.method).join('/')}`, from, evidence: [] });
      else if (c.port != null && rootsOnPort(c.port).filter((r) => r !== from.root).length) push(gaps, { kind: 'http', status: 'gap', reason: `schema mismatch: a service listens on port ${c.port} but declares no ${c.method} ${c.path}`, from, evidence: [`listener port ${c.port}`] });
      else push(gaps, { kind: 'http', status: 'gap', reason: 'unknown endpoint: no server in the provided roots declares this route', from, evidence: [] });
      continue;
    }
    const identified = matching.filter((r) => { const root = rootOf(r.file); return (c.port != null && (portsByRoot.get(root) || new Set()).has(c.port)) || c.host === root.toLowerCase(); });
    const targetRoots = uniq(matching.map((r) => rootOf(r.file)));
    if (identified.length === 1 && uniq(identified.map((r) => rootOf(r.file))).length === 1) {
      const s = identified[0];
      const clientFields = c.fields; const serverFields = s.fields;
      const shared = clientFields.filter((x) => serverFields.includes(x));
      const root = rootOf(s.file);
      const evidence = [`literal route ${c.method} ${c.path} matches ${s.method} ${s.path}`, c.port != null && (portsByRoot.get(root) || new Set()).has(c.port) ? `client port ${c.port} equals the listener port of root "${root}"` : `client host "${c.host}" names root "${root}"`];
      push(bridges, { kind: 'http', status: 'linked', protocol: 'http', confidence: 'high', from, to: loc(s), fields: shared.map((name) => ({ name, label: 'same field name on a linked endpoint', from: { file: c.file, line: c.line }, to: { file: s.file, line: s.line } })), clientOnlyFields: clientFields.filter((x) => !serverFields.includes(x)), serverOnlyFields: serverFields.filter((x) => !clientFields.includes(x)), evidence });
    } else if (identified.length > 1) {
      push(candidates, { kind: 'http', status: 'candidate', reason: 'ambiguous service mapping: more than one service matches the route and port', from, to: identified.map(loc), evidence: [`literal route ${c.method} ${c.path}`] });
    } else {
      push(candidates, { kind: 'http', status: 'candidate', reason: targetRoots.length > 1 ? 'ambiguous service mapping: several roots declare this route and none is identified by port or host' : 'the route matches but the service is not identified by a listener port or host name', from, to: matching.map(loc), evidence: [`literal route ${c.method} ${c.path}`] });
    }
  }

  // ── queues ──────────────────────────────────────────────────────────────────
  for (const p of facts.producers) {
    const from = loc(p);
    const sameName = facts.consumers.filter((c) => c.name === p.name && rootOf(c.file) !== from.root);
    if (!sameName.length) { push(gaps, { kind: 'queue', status: 'gap', reason: `no consumer of "${p.name}" in another root`, from, evidence: [] }); continue; }
    const sameTech = sameName.filter((c) => c.tech && p.tech && c.tech === p.tech);
    if (!sameTech.length) { push(gaps, { kind: 'queue', status: 'gap', reason: `a consumer reads "${p.name}" over ${sameName[0].tech || 'an unrecognised broker'} but this producer uses ${p.tech || 'an unrecognised broker'}: different or unsupported protocol`, from, to: sameName.map(loc), evidence: [] }); continue; }
    if (uniq(sameTech.map((c) => rootOf(c.file))).length > 1) { push(candidates, { kind: 'queue', status: 'candidate', reason: 'ambiguous: several roots consume this queue name', from, to: sameTech.map(loc), evidence: [`queue "${p.name}" over ${p.tech}`] }); continue; }
    const c = sameTech[0];
    const shared = p.fields.filter((x) => c.fields.includes(x));
    push(bridges, { kind: 'queue', status: 'linked', protocol: p.tech, confidence: 'medium', from, to: loc(c), queue: p.name, fields: shared.map((name) => ({ name, label: 'same field name on a linked queue', from: { file: p.file, line: p.line }, to: { file: c.file, line: c.line } })), producerOnlyFields: p.fields.filter((x) => !c.fields.includes(x)), consumerOnlyFields: c.fields.filter((x) => !p.fields.includes(x)), evidence: [`literal queue "${p.name}" over ${p.tech}`], limitations: ['broker host identity is not verified from source'] });
  }

  // ── stores ──────────────────────────────────────────────────────────────────
  const connOf = (rootName) => facts.dbConns.filter((d) => rootOf(d.file) === rootName);
  for (const w of facts.sql.filter((s) => s.mode === 'write')) {
    const wr = rootOf(w.file);
    const readers = facts.sql.filter((s) => s.mode === 'read' && s.table === w.table && rootOf(s.file) !== wr);
    if (!readers.length) continue;
    for (const r of readers) {
      const cols = r.columns.includes('*') ? w.columns : r.columns.filter((c) => w.columns.includes(c));
      const wc = connOf(wr); const rc = connOf(rootOf(r.file));
      const wdb = uniq(wc.map((d) => d.db).filter(Boolean)); const rdb = uniq(rc.map((d) => d.db).filter(Boolean));
      const from = loc(w); const to = loc(r);
      if (!cols.length) { push(gaps, { kind: 'store', status: 'gap', reason: `table "${w.table}" is shared but the written and read column sets do not intersect`, from, to, evidence: [] }); continue; }
      if (wdb.length === 1 && rdb.length === 1 && wdb[0] === rdb[0]) {
        push(bridges, { kind: 'store', status: 'linked', protocol: 'sql', confidence: 'medium', from, to, table: w.table, database: wdb[0], fields: cols.map((name) => ({ name: `${w.table}.${name}`, label: 'same table and column in the same literal database', from: { file: w.file, line: w.line }, to: { file: r.file, line: r.line } })), evidence: [`both roots connect to database "${wdb[0]}"`, `table "${w.table}" written then read`], limitations: ['database host identity is not verified from source'] });
      } else {
        push(candidates, { kind: 'store', status: 'candidate', reason: wdb.length && rdb.length && wdb[0] !== rdb[0] ? `different databases ("${wdb[0]}" and "${rdb[0]}")` : 'database identity is not stated by both sides', from, to, table: w.table, evidence: [`table "${w.table}" with columns ${cols.join(', ')}`] });
      }
    }
  }

  // ── Nix env/launch -> application read, plus inclusion ───────────────────────
  const inclusions = [];
  for (const s of services) {
    const owners = [...names.entries()].filter(([, set]) => (s.exe && set.has(s.exe)) || (s.pkg && set.has(s.pkg))).map(([r]) => r);
    for (const r of owners) inclusions.push({ kind: 'service-includes-application', service: s.name, root: r, via: s.exe ? `ExecStart executable ${s.exe}` : `package ${s.pkg}`, from: { file: s.file, line: s.line, language: 'nix', root: rootOf(s.file) } });
    if (s.environmentFile) push(gaps, { kind: 'env', status: 'gap', reason: `service "${s.name}" uses EnvironmentFile: its contents are not read`, from: { file: s.file, line: s.line, language: 'nix', root: rootOf(s.file) }, evidence: [] });
    if (s.dynamic && !s.exe) push(gaps, { kind: 'env', status: 'gap', reason: `service "${s.name}" launches through a generated script: the executable is not resolved statically`, from: { file: s.file, line: s.line, language: 'nix', root: rootOf(s.file) }, evidence: [] });
    for (const [varName, info] of Object.entries(s.env)) {
      const readers = facts.envReads.filter((e) => e.name === varName);
      if (!readers.length) continue;
      const from = { file: s.file, line: info.line, language: 'nix', root: rootOf(s.file) };
      const owned = readers.filter((e) => owners.includes(rootOf(e.file)));
      if (owned.length) {
        for (const e of owned) push(bridges, { kind: 'env', status: 'linked', protocol: 'environment', confidence: 'high', from, to: loc(e), service: s.name, fields: [{ name: varName, label: 'service environment variable read by the application it launches', from: { file: s.file, line: info.line }, to: { file: e.file, line: e.line } }], valueKnown: info.value !== null, evidence: [`service "${s.name}" launches ${s.exe ? `executable "${s.exe}"` : `package "${s.pkg}"`}, the application of root "${rootOf(e.file)}"`] });
      } else {
        for (const e of readers) push(candidates, { kind: 'env', status: 'candidate', reason: owners.length ? `the service launches a different application than root "${rootOf(e.file)}"` : 'the variable name matches but the service does not identify the application it launches', from, to: loc(e), service: s.name, evidence: [`environment variable ${varName}`] });
      }
    }
  }

  const bySort = (a, b) => (a.from.file + a.from.line).localeCompare(b.from.file + b.from.line) || a.kind.localeCompare(b.kind);
  bridges.sort(bySort); candidates.sort(bySort); gaps.sort(bySort);
  return {
    version: BRIDGES_VERSION, scope: SCOPE,
    services: services.map((s) => ({ name: s.name, file: s.file, line: s.line, executable: s.exe, package: s.pkg, port: s.port })),
    inclusions, bridges, candidates, gaps,
    limits: ['source roots are the first path segment; a service with no distinct root cannot be linked', 'schema documents (OpenAPI, GraphQL, gRPC) are not required: links come from literal routes, queue names, tables and launch declarations', `${allRoots.size} root(s) considered`],
  };
}

/**
 * Roots reachable from `root` over EVIDENCED data links only. `direction`: 'downstream' follows data written by the
 * root, 'upstream' follows who sends data to it. Candidates, gaps and inclusions are never followed unless
 * `includeInclusions` is true, and then they are reported separately from the data roots.
 */
function blastRadius(result, root, { direction = 'downstream', includeInclusions = false } = {}) {
  const seen = new Set([root]); const queue = [root]; const edges = [];
  while (queue.length) {
    const cur = queue.shift();
    for (const b of result.bridges) {
      const a = b.from.root; const z = b.to.root;
      const [src, dst] = direction === 'downstream' ? [a, z] : [z, a];
      if (src !== cur || seen.has(dst)) continue;
      seen.add(dst); queue.push(dst); edges.push({ from: src, to: dst, kind: b.kind });
    }
  }
  const out = { roots: [...seen].filter((r) => r !== root).sort(), edges, inclusions: [] };
  if (includeInclusions) out.inclusions = result.inclusions.filter((i) => seen.has(i.root));
  return out;
}


/***/ })

};
