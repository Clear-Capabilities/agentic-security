// Bounded context for model-assisted validation (PRD FR 05 "required validation flow").
//
// The model is shown numbered spans, each with an id (S1, S2, ...), a role and exact file and line bounds: the code around the
// finding, the source and sink when they lie outside it, each traced path step, and the related files on a Haskell/Nix evidence
// chain. It is asked to cite the span lines its verdict rests on. A citation is checked against the spans actually sent:
//
//   valid    every citation names a span and a line inside it
//   none     the reply cited nothing (recorded; the verdict is kept, and the disposition lists the missing citation)
//   invalid  a citation names a span or a line that was not sent: the model reasoned about code it was not shown, so the reply
//            is not used (the caller turns it into `escalate`)
//
// Callers and configuration are collected by name, and the prompt says so:
//
//   callers        the nearest function definition above the finding, then call sites of that name in scanned files of the same
//                  language. Matched by name, not resolved through imports or dispatch: a same-named function can appear, and
//                  calls through aliases, callbacks or dynamic dispatch are missed.
//   configuration  environment keys read in the finding's span, then the scanned configuration files that set them. Dotenv files
//                  other than examples are never read, and the value of a secret-like key is masked before redaction.
//
// What is not collected is stated in `gaps`, never implied.

import { languagePromptExtras } from '../language/context.js';

const lineOf = (x) => (x && Number.isInteger(x.line) && x.line > 0 ? x.line : null);

/**
 * @returns {{spans:{id:string, role:string, file:string, start:number, end:number, text:string}[], gaps:string[]}}
 */
export function collectBoundedContext(finding, fileContents, { window = 20, stepWindow = 3, maxSpans = 10, maxCallers = 3, maxConfig = 2 } = {}) {
  const raw = [];
  const gaps = [];
  const add = (role, file, line, w, mask = null) => {
    const code = fileContents && typeof fileContents[file] === 'string' ? fileContents[file] : null;
    if (code === null) { gaps.push(`${role} file ${file} was not available`); return; }
    const lines = mask ? code.split('\n').map(mask) : code.split('\n');
    const start = Math.max(1, line - w);
    const end = Math.min(lines.length, line + w);
    if (start > end) return;
    raw.push({ role, file, start, end, lines });
  };
  if (finding && finding.file && lineOf(finding)) add('finding', finding.file, finding.line, window);
  const src = finding && finding.source; const snk = finding && finding.sink;
  if (lineOf(src)) add('source', src.file || finding.file, src.line, stepWindow);
  if (lineOf(snk)) add('sink', snk.file || finding.file, snk.line, stepWindow);
  for (const step of Array.isArray(finding && finding.path) ? finding.path : []) {
    if (lineOf(step)) add('path-step', step.file || finding.file, step.line, stepWindow);
  }
  if (finding && finding.file && lineOf(finding) && typeof (fileContents || {})[finding.file] === 'string') {
    collectCallers(finding, fileContents, { maxCallers, stepWindow, add, gaps });
    collectConfiguration(finding, fileContents, { window, maxConfig, add, gaps });
  } else {
    gaps.push('the finding has no readable source line, so callers and configuration were not collected');
  }
  // Merge spans that overlap or touch in the same file; the first role stays, the others are kept as `alsoRoles`.
  const merged = [];
  for (const s of raw) {
    const hit = merged.find((m) => m.file === s.file && s.start <= m.end + 1 && s.end >= m.start - 1);
    if (hit) { hit.start = Math.min(hit.start, s.start); hit.end = Math.max(hit.end, s.end); if (hit.role !== s.role && !hit.alsoRoles.includes(s.role)) hit.alsoRoles.push(s.role); continue; }
    merged.push({ ...s, alsoRoles: [] });
  }
  const spans = merged.slice(0, maxSpans).map((m, i) => ({
    id: `S${i + 1}`, role: m.role, ...(m.alsoRoles.length ? { alsoRoles: m.alsoRoles } : {}), file: m.file, start: m.start, end: m.end,
    text: m.lines.slice(m.start - 1, m.end).map((l, k) => `${m.start + k}: ${l}`).join('\n'),
  }));
  if (merged.length > maxSpans) gaps.push(`${merged.length - maxSpans} span(s) beyond the first ${maxSpans} were not sent`);
  try {
    for (const x of languagePromptExtras(finding, fileContents)) {
      const n = x.text.split('\n').length;
      spans.push({ id: `S${spans.length + 1}`, role: 'related', file: x.file, start: x.startLine, end: x.startLine + n - 1, text: x.text });
    }
  } catch { /* related excerpts are advisory */ }
  if (!spans.length) gaps.push('no source text was available for the finding');
  gaps.push('deployment configuration outside the repository (environment, secrets stores, cloud policy) was not collected');
  return { spans, gaps };
}

// ── callers ─────────────────────────────────────────────────────────────────
const NOT_A_NAME = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'else', 'do', 'try', 'new', 'typeof', 'await',
  'with', 'sizeof', 'elif', 'except', 'when', 'match', 'case', 'super', 'this', 'self', 'import', 'require', 'where', 'let', 'in']);
// Lines carrying a CWE-1333 pragma: bounded by MAX_DEF_LINE below, so the polynomial worst case is capped per line.
const LANGS = [
  { ext: /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i, defs: [/\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/, /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/, /^\s*(?:(?:public|private|protected|static|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/] }, // agentic-security-ignore: CWE-1333
  { ext: /\.py$/i, defs: [/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/] },
  { ext: /\.rb$/i, defs: [/^\s*def\s+(?:self\.)?([A-Za-z_]\w*[?!]?)/] },
  { ext: /\.go$/i, defs: [/^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[[(]/] },
  { ext: /\.rs$/i, defs: [/\bfn\s+([A-Za-z_]\w*)/] },
  { ext: /\.php$/i, defs: [/\bfunction\s+([A-Za-z_]\w*)\s*\(/] },
  { ext: /\.(?:java|kt|kts|cs|scala)$/i, defs: [/^\s*(?:(?:public|private|protected|internal|static|final|override|suspend|async|virtual|abstract|synchronized|open)\s+)*(?:fun\s+|def\s+)?(?:[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*\([^;]*$/] }, // agentic-security-ignore: CWE-1333
  { ext: /\.hs$/i, defs: [/^([a-z_][\w']*)\s*::/, /^([a-z_][\w']*)\b[^=\n]*=/], bare: true },
];
const langOf = (file) => LANGS.find((l) => l.ext.test(file)) || null;
const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// The definition patterns run over scanned (untrusted) source. None backtracks exponentially, but the modifier and type groups can go
// quadratic on a long line, so a line longer than any real definition header is never matched.
const MAX_DEF_LINE = 400;
const defName = (lang, line) => {
  if (line.length > MAX_DEF_LINE) return null;
  for (const re of lang.defs) { const m = re.exec(line); if (m && !NOT_A_NAME.has(m[1])) return m[1]; }
  return null;
};

/** The nearest function definition at or above `line` (1-based), within 400 lines. */
export function enclosingFunction(file, code, line) {
  const lang = langOf(file);
  if (!lang) return null;
  const lines = code.split('\n');
  for (let i = Math.min(line, lines.length) - 1; i >= 0 && i >= line - 400; i--) {
    const name = defName(lang, lines[i]);
    if (name) return { name, line: i + 1 };
  }
  return null;
}

function collectCallers(finding, fileContents, { maxCallers, stepWindow, add, gaps }) {
  const lang = langOf(finding.file);
  const fn = lang ? enclosingFunction(finding.file, fileContents[finding.file], finding.line) : null;
  if (!fn) { gaps.push('the enclosing function could not be determined, so callers were not collected'); return; }
  const call = lang.bare ? new RegExp(`(?<![\\w'.])${escapeRe(fn.name)}(?![\\w'])`) : new RegExp(`(?<![\\w$])${escapeRe(fn.name)}\\s*\\(`);
  const sites = [];
  for (const [file, code] of Object.entries(fileContents)) {
    if (typeof code !== 'string' || code.length > 1_000_000 || !lang.ext.test(file) || !code.includes(fn.name)) continue;
    code.split('\n').forEach((text, i) => {
      if (!call.test(text) || defName(lang, text) === fn.name) return;               // the definition (or a signature) is not a call
      if (file === finding.file && i + 1 >= fn.line && i + 1 <= finding.line) return;  // recursion inside the finding's own function
      sites.push({ file, line: i + 1 });
    });
  }
  if (!sites.length) {
    gaps.push(`no call site of ${fn.name} was found by name in the scanned files of the same language (it may be an entry point, exported, or called dynamically)`);
    return;
  }
  for (const s of sites.slice(0, maxCallers)) add('caller', s.file, s.line, stepWindow);
  gaps.push(`callers of ${fn.name} were matched by name, not resolved: a same-named function can appear, and calls through aliases, callbacks or dynamic dispatch are missed`);
  if (sites.length > maxCallers) gaps.push(`${sites.length - maxCallers} further call site(s) of ${fn.name} were not sent`);
}

// ── configuration ───────────────────────────────────────────────────────────
const ENV_READS = [
  /process\.env\.([A-Za-z_][\w]*)/g, /process\.env\[\s*['"]([^'"]+)['"]\s*\]/g, /os\.environ(?:\.get)?\s*[[(]\s*['"]([^'"]+)['"]/g,
  /\bgetenv\(\s*['"]([^'"]+)['"]/g, /\b(?:getEnv|lookupEnv)\s+"([^"]+)"/g, /System\.getenv\(\s*"([^"]+)"/g,
  /\bENV(?:\.fetch\(\s*|\[\s*)['"]([^'"]+)['"]/g, /os\.(?:Getenv|LookupEnv)\(\s*"([^"]+)"/g, /env::var\(\s*"([^"]+)"/g,
];
const CONFIG_FILE = /(?:^|\/)(?:\.env\.(?:example|sample|template|dist)|[^/]+\.(?:ya?ml|toml|ini|conf|cfg|properties|nix)|docker-compose[^/]*|Dockerfile[^/]*|app\.json)$/i;
const SECRET_KEY = /secret|token|passw|pwd|credential|private|api[_-]?key|auth/i;
// Masks the value of a secret-like key; the generic redaction then runs over the whole span.
const maskSecretValues = (text) => text.replace(/^(\s*(?:export\s+|-\s+)?["']?([\w.-]+)["']?\s*[:=]\s*)(.+)$/, (all, head, key) => (SECRET_KEY.test(key) ? `${head}<masked>` : all));

function collectConfiguration(finding, fileContents, { window, maxConfig, add, gaps }) {
  const lines = fileContents[finding.file].split('\n');
  const span = lines.slice(Math.max(0, finding.line - 1 - window), finding.line + window).join('\n');
  const keys = new Set();
  for (const re of ENV_READS) for (const m of span.matchAll(re)) keys.add(m[1]);
  if (!keys.size) { gaps.push("no configuration key is read near the finding, so no configuration file was collected"); return; }
  const found = new Set(); let sent = 0; let more = 0;
  for (const [file, code] of Object.entries(fileContents)) {
    if (typeof code !== 'string' || !CONFIG_FILE.test(file) || code.length > 500_000) continue;
    const cl = code.split('\n');
    for (const key of keys) {
      // the key is escaped before it reaches the pattern, which has no quantifier at all
      const re = new RegExp(`(?<![\\w])${escapeRe(key)}(?![\\w])`); // agentic-security-ignore: CWE-1333
      const i = cl.findIndex((t) => re.test(t));
      if (i < 0) continue;
      found.add(key);
      if (sent < maxConfig) { add('configuration', file, i + 1, 1, maskSecretValues); sent++; } else more++;
    }
  }
  const missing = [...keys].filter((k) => !found.has(k)).sort();
  if (missing.length) gaps.push(`configuration key(s) ${missing.join(', ')} read near the finding are set in no scanned configuration file (they may be set at deploy time)`);
  if (more) gaps.push(`${more} further configuration match(es) were not sent`);
}

/** Render spans as the untrusted excerpt block. */
export function renderSpans(spans) {
  return spans.map((s) => `[${s.id} ${s.role}${s.alsoRoles ? `+${s.alsoRoles.join('+')}` : ''}] ${s.file}:${s.start}-${s.end}\n${s.text}`).join('\n\n');
}

/** Check a reply's citations against the spans that were sent. */
export function checkCitations(citations, spans) {
  if (citations === undefined || citations === null || (Array.isArray(citations) && citations.length === 0)) return { status: 'none', resolved: [], invalid: [] };
  if (!Array.isArray(citations)) return { status: 'invalid', resolved: [], invalid: [String(citations).slice(0, 40)] };
  const byId = new Map(spans.map((s) => [s.id, s]));
  const resolved = []; const invalid = [];
  for (const c of citations.slice(0, 20)) {
    const m = /^\s*(S\d+)\s*:\s*(\d+)\s*$/.exec(String(c));
    const s = m && byId.get(m[1]);
    const line = m ? Number(m[2]) : NaN;
    if (s && line >= s.start && line <= s.end) resolved.push({ span: s.id, file: s.file, line });
    else invalid.push(String(c).slice(0, 40));
  }
  return { status: invalid.length ? 'invalid' : 'valid', resolved, invalid };
}

/** The span list as recorded on a finding: bounds and roles, never the text. */
export const spanRecord = (spans) => spans.map(({ text, ...rest }) => rest);
