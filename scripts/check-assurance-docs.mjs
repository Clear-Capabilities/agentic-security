#!/usr/bin/env node
// Documentation drift check for the assurance pages (DOC-001.AC03).
//
//   node scripts/check-assurance-docs.mjs            # human report; exit 1 on any finding
//   node scripts/check-assurance-docs.mjs --json     # machine-readable
//
// check-doc-drift.mjs checks that a CLAUDE.md names real files and that markdown links resolve. This sibling checks what the
// assurance pages promise a reader will be able to RUN or FIND, and what they must never claim:
//
//   unknown-npm-script     `npm run <name>` where <name> is not a script in scanner/package.json
//   missing-script-path    `node scripts/<file>` (or `../scripts/<file>`) where the file does not exist
//   unknown-cli-command    `agentic-security <command> [<sub>]` that bin/agentic-security.js does not dispatch
//   unknown-schema         a quoted `agentic-security/<schema>` identifier that appears nowhere in the code or docs/schemas
//   missing-path           a repository path (in a link, an inline code span or a command) that resolves nowhere
//   unknown-env            an AGENTIC_SECURITY_* variable the code never reads
//   universal-claim        "safe to deploy", "fully covered", "guaranteed", "certified" and kin, used as a claim
//   em-dash                an em-dash in prose
//
// A fenced block tagged `text` is OUTPUT: it is not read for commands or paths. An untagged fence is a command listing. A
// universal-claim phrase is allowed inside a sentence that negates it earlier in the same sentence ("this does not mean the
// software is safe"), because the pages must be able to say what they do not claim. Pure and offline: it reads files only.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..');

// The pages this check owns. The generated pages are included: they must obey the same rules as the hand-written ones.
export const ASSURANCE_DOCS = Object.freeze([
  'docs/guides/assurance-documentation-index.md',
  'docs/guides/assurance-scope-and-contracts.md',
  'docs/guides/assurance-examples.md',
  'docs/guides/measurement-status.md',
  'docs/guides/evaluation-policy-card.md',
  'docs/guides/routing-policy-card.md',
  'docs/guides/offline-reproduction.md',
  'docs/guides/background-controller-operations.md',
  'docs/guides/portfolio-recovery.md',
  'docs/guides/assurance-review.md',
  'docs/guides/assurance-rollout-and-rollback.md',
  'docs/reference/mcp-tool-contract.md',
  'docs/reference/assurance-capability-matrix.md',
]);

const PATH_ROOTS = ['scanner/', 'scripts/', 'docs/', 'bench/', 'test/', 'src/', 'bin/', 'hooks/', 'commands/', 'examples/'];

// ---------------------------------------------------------------- repository indexes (built lazily, per repo root)

const cache = new Map();
function walk(dir, out, skip) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (skip.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out, skip);
    else if (e.isFile() && /\.(?:js|mjs|cjs|json)$/.test(e.name)) out.push(full);
  }
}
function indexFor(repo) {
  if (cache.has(repo)) return cache.get(repo);
  const skip = new Set(['node_modules', '.git', 'dist', 'coverage', 'worktrees', '.agentic-security', '.loop-engineering', 'cache']);
  const files = [];
  for (const d of ['scanner/src', 'scanner/bin', 'scripts', 'hooks', 'docs/schemas']) walk(path.join(repo, d), files, skip);
  let code = '';
  for (const f of files) { try { const st = fs.statSync(f); if (st.size < 3 * 1024 * 1024) code += `\n${fs.readFileSync(f, 'utf8')}`; } catch { /* unreadable */ } }
  let scripts = {};
  try { scripts = JSON.parse(fs.readFileSync(path.join(repo, 'scanner', 'package.json'), 'utf8')).scripts ?? {}; } catch { /* none */ }
  let bin = '';
  try { bin = fs.readFileSync(path.join(repo, 'scanner', 'bin', 'agentic-security.js'), 'utf8'); } catch { /* none */ }
  const idx = { code, scripts, bin };
  cache.set(repo, idx);
  return idx;
}

// Environment variables derived rather than spelled out: AGENTIC_SECURITY_ASSURANCE_<FEATURE> and AGENTIC_SECURITY_NO_<FEATURE>.
const derivedEnv = new Map();
async function derivedEnvNames(repo) {
  if (derivedEnv.has(repo)) return derivedEnv.get(repo);
  const names = new Set();
  try {
    const { FEATURES } = await import(pathToFileURL(path.join(repo, 'scanner', 'src', 'posture', 'assurance', 'config.js')).href);
    for (const id of Object.keys(FEATURES)) {
      const n = id.toUpperCase().replace(/-/g, '_');
      names.add(`AGENTIC_SECURITY_ASSURANCE_${n}`);
      names.add(`AGENTIC_SECURITY_NO_${n}`);
    }
  } catch { /* the config could not be loaded: derived names are simply unknown */ }
  derivedEnv.set(repo, names);
  return names;
}

// ---------------------------------------------------------------- markdown scanning helpers

/** Split a document into prose lines and fenced blocks. A fence's info string decides whether it is output. */
export function splitMarkdown(text) {
  const lines = text.split('\n');
  const prose = [];
  const commands = [];
  const output = [];
  let fence = null;
  lines.forEach((line, i) => {
    const m = /^\s*```(\S*)/.exec(line);
    if (m) {
      if (fence === null) fence = { info: m[1] }; else fence = null;
      return;
    }
    if (fence === null) prose.push({ line: i + 1, text: line });
    else if (fence.info === 'text') output.push({ line: i + 1, text: line });
    else commands.push({ line: i + 1, text: line });
  });
  return { prose, commands, output };
}

const INLINE_CODE = /`([^`\n]+)`/g;
const LINK = /!?\[[^\]]*\]\(([^()\s]+)(?:\s+"[^"]*")?\)/g;
const stripInline = (s) => s.replace(INLINE_CODE, (m) => ' '.repeat(m.length));
const GENERATED_MARK = /<!--[\s\S]*?-->/g;

function candidatePathToken(raw) {
  let t = raw.trim().replace(/^["'(]+|["'),.;:]+$/g, '');
  t = t.split('#')[0].replace(/:\d+(?:-\d+)?$/, '');
  if (!t || /[*<>{}$|\s]/.test(t) || /^https?:/.test(t) || t.startsWith('-') || t.includes('://')) return null;
  if (!(PATH_ROOTS.some((r) => t.startsWith(r)) || t.startsWith('../') || t.startsWith('./'))) return null;
  if (!/[\w]\//.test(t) && !/\.\w+$/.test(t)) return null;
  return t.replace(/\/+$/, '');
}

function resolvesAnywhere(repo, docDir, token) {
  const bases = [docDir, repo, path.join(repo, 'scanner'), path.join(repo, 'docs')];
  for (const b of bases) {
    const cand = path.resolve(b, token);
    if (cand.startsWith(repo + path.sep) && fs.existsSync(cand)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- universal claims

const UNIVERSAL = [
  /\bsafe to (?:deploy|ship|release|use|merge|run)\b/i,
  /\b(?:is|are|be|remains?|stays?|deemed|declared|considered|proven|provably)\s+(?:fully\s+|completely\s+|totally\s+|100%\s+)?(?:safe|secure)\b/i,
  /\bfully (?:covered|verified|tested|secure|safe|protected|checked)\b/i,
  /\b(?:full|complete|total|exhaustive|100%) (?:coverage|verification|protection|assurance)\b/i,
  /\bcompletely (?:covered|safe|secure|verified|protected)\b/i,
  /\bguarantee[sd]?\b/i,
  /\bcertified\b/i,
  /\bcertif(?:y|ies)\b/i,
  /\b(?:vulnerability|bug|defect)[- ]free\b/i,
  /\bfree of (?:vulnerabilities|bugs|defects)\b/i,
];
const NEGATION = /\b(?:not|no|never|cannot|can't|without|nothing|neither|nor|none|n't|refus\w*|reject\w*|instead of|rather than|unless|prohibit\w*|avoid\w*|forbid\w*|stop\w*|nobody)\b|n't\b/i;

/** Sentences of one prose line (a table row is split by cell). */
function sentencesOf(text) {
  const out = [];
  for (const cell of text.split('|')) for (const s of cell.split(/(?<=[.!?;])\s+/)) if (s.trim()) out.push(s);
  return out;
}

export function universalClaimsIn(text) {
  const hits = [];
  for (const sentence of sentencesOf(text)) {
    for (const re of UNIVERSAL) {
      const m = re.exec(sentence);
      if (!m) continue;
      const before = sentence.slice(0, m.index);
      if (NEGATION.test(before)) continue;
      hits.push({ phrase: m[0], sentence: sentence.trim().slice(0, 160) });
    }
  }
  return hits;
}

// ---------------------------------------------------------------- the check

/**
 * @param {string} absPath  the markdown file
 * @param {{ repo?: string }} [o]
 * @returns {Promise<Array<{file:string, line:number, kind:string, ref:string, detail?:string}>>}
 */
export async function checkAssuranceDoc(absPath, { repo = REPO } = {}) {
  const raw = fs.readFileSync(absPath, 'utf8');
  const { prose, commands } = splitMarkdown(raw.replace(GENERATED_MARK, (m) => ' '.repeat(m.length)));
  const idx = indexFor(repo);
  const envDerived = await derivedEnvNames(repo);
  const findings = [];
  const add = (line, kind, ref, detail) => findings.push({ file: absPath, line, kind, ref, ...(detail ? { detail } : {}) });
  const docDir = path.dirname(absPath);
  const seen = new Set();
  const once = (line, kind, ref, detail) => { const k = `${kind}|${ref}`; if (seen.has(k)) return; seen.add(k); add(line, kind, ref, detail); };

  // every searchable surface: command lines, prose (including inline code), nothing from output fences
  const surfaces = [...prose.map((p) => ({ ...p, from: 'prose' })), ...commands.map((c) => ({ ...c, from: 'command' }))];

  for (const { line, text, from } of surfaces) {
    // npm scripts
    for (const m of text.matchAll(/\bnpm run(?: --silent)? ([A-Za-z0-9:_-]+)/g)) {
      if (!(m[1] in idx.scripts)) once(line, 'unknown-npm-script', m[1], 'not a script in scanner/package.json');
    }
    // node scripts
    for (const m of text.matchAll(/\bnode (?:\.\.\/)?((?:scripts)\/[\w./-]+\.(?:mjs|js|cjs))/g)) {
      if (!fs.existsSync(path.join(repo, m[1]))) once(line, 'missing-script-path', m[1], 'no such file');
    }
    // CLI commands: only where the text is a command (a command line, or an inline code span that starts with it)
    const spans = from === 'command' ? [text] : [...text.matchAll(INLINE_CODE)].map((x) => x[1]);
    for (const span of spans) {
      const m = /^\s*(?:\$ )?(?:[A-Z_][A-Z0-9_]*=\S+ )*(?:agentic-security|node bin\/agentic-security\.js)\s+([a-z][a-z-]*)(?:\s+([a-z][a-z-]*))?/.exec(span);
      if (!m) continue;
      const [, sub, sub2] = m;
      const dispatched = idx.bin.includes(`case '${sub}'`) || new RegExp(`(?:^|\\n)\\s*${sub}[ \\n]`).test(idx.bin);
      if (!dispatched) { once(line, 'unknown-cli-command', sub, 'bin/agentic-security.js does not dispatch it'); continue; }
      if (sub2 && ['portfolio', 'invariants'].includes(sub) && !idx.bin.includes(`${sub} ${sub2}`)) once(line, 'unknown-cli-command', `${sub} ${sub2}`, 'no such sub-command in the usage text');
    }
    // schemas
    for (const m of text.matchAll(/(?<![\w/.-])agentic-security\/([a-z][a-z0-9-]+)(?![\w/.-])/g)) {
      const id = `agentic-security/${m[1]}`;
      if (!idx.code.includes(`'${id}`) && !idx.code.includes(`"${id}`) && !idx.code.includes(`\`${id}`)) once(line, 'unknown-schema', id, 'appears in no module and no docs/schemas file');
    }
    // environment variables
    for (const m of text.matchAll(/\bAGENTIC_SECURITY_[A-Z0-9_]+\b/g)) {
      if (!idx.code.includes(m[0]) && !envDerived.has(m[0])) once(line, 'unknown-env', m[0], 'no module reads it');
    }
    // paths: links, inline code spans, and path words on command lines
    const tokens = [];
    if (from === 'prose') {
      for (const m of text.matchAll(LINK)) tokens.push(m[1]);
      for (const m of text.matchAll(INLINE_CODE)) tokens.push(m[1]);
    } else for (const w of text.split(/\s+/)) tokens.push(w);
    for (const t of tokens) {
      const tok = candidatePathToken(t);
      if (tok && !resolvesAnywhere(repo, docDir, tok)) once(line, 'missing-path', tok, 'resolves nowhere');
    }
  }

  // prose-only rules
  for (const { line, text } of prose) {
    const plainText = stripInline(text.replace(LINK, (m) => ' '.repeat(m.length)));
    if (text.includes('—')) once(line, 'em-dash', '—', 'use a comma, a colon or a full stop in prose');
    for (const h of universalClaimsIn(plainText)) once(line, 'universal-claim', h.phrase, h.sentence);
  }
  return findings;
}

export async function checkAllAssuranceDocs(repo = REPO) {
  const out = [];
  for (const rel of ASSURANCE_DOCS) {
    const abs = path.join(repo, rel);
    if (!fs.existsSync(abs)) { out.push({ file: abs, line: 0, kind: 'missing-doc', ref: rel, detail: 'a page this check owns does not exist' }); continue; }
    out.push(...await checkAssuranceDoc(abs, { repo }));
  }
  return out;
}

export function formatFinding(f, repo = REPO) {
  return `${path.relative(repo, f.file)}:${f.line}  ${f.kind}: ${f.ref}${f.detail ? `  (${f.detail})` : ''}`;
}

async function main() {
  const findings = await checkAllAssuranceDocs(REPO);
  if (process.argv.includes('--json')) console.log(JSON.stringify({ docs: ASSURANCE_DOCS.length, findings }, null, 2));
  else if (!findings.length) console.log(`assurance docs: ${ASSURANCE_DOCS.length} page(s); every referenced command, script, schema, variable and path exists; no universal claim.`);
  else { console.error(`assurance docs: ${findings.length} finding(s):`); for (const f of findings) console.error(`  ${formatFinding(f)}`); }
  process.exit(findings.length ? 1 : 0);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main();
