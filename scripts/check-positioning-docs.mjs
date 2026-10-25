#!/usr/bin/env node
// Positioning-docs gate: the capability registry, the tables generated from it, and the rules that keep the
// documentation honest about what is shipped. Part of the autonomous-assurance docs repositioning.
//
//   node scripts/check-positioning-docs.mjs            check everything, exit 1 on any finding
//   node scripts/check-positioning-docs.mjs --write    regenerate the generated tables in place, then check
//   node scripts/check-positioning-docs.mjs --json     machine-readable findings
//   node scripts/check-positioning-docs.mjs --root <d> check another checkout (used by the tests to prove it fails closed)
//
// WHAT IT ENFORCES (every rule fails closed)
//   registry     docs/capabilities.yaml: known maturity and lifecycle stage, unique ids, the ten stages in
//                canonical order, docs paths exist, GA/Preview/Labs name real implementation evidence that exists,
//                Roadmap names none.
//   tables       blocks between `<!-- generated:capabilities[:stage]:start -->` and `...:end -->` equal what the
//                registry renders. A stale committed table fails.
//   consistency  a maturity badge (`[GA]` `[Preview]` `[Labs]` `[Roadmap]`) on a line that names exactly one
//                registered capability, and a page-level `**Maturity:** X` line on a capability's primary doc, must
//                equal the registry. One capability cannot be GA on one page and Labs on another.
//   overclaim    a Roadmap capability described in the present tense as shipped, or a Labs capability described as
//                production-ready. Natural-language linting is imperfect, so a line may carry
//                `<!-- positioning-ignore: reason -->` (same line or the line above); the reason is required.
//   commands     documented `agentic-security <command>` and `/agentic-security:<command>` invocations name a command
//                that exists (CLI dispatch table, commands/*.md), and the documented subcommands exist.
//   lifecycle    one canonical ten-stage ordering, everywhere it is written out.
//   style        the terminology guide's avoid-list, and no em-dashes in the pages this work owns.
//   navigation   every role page is one click from docs/README.md and names a core workflow that exists.
//   links        internal markdown links and heading anchors resolve (file-level links also run in check-doc-drift).
//   visuals      the six SVGs exist, carry <title>/<desc>, spell out maturity in text, and state no percentages.
//
// The registry is read by a deliberately small reader (flat records, scalar fields, inline [a, b] lists or `- item`
// block lists) so this gate has no dependency and runs on a bare checkout.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');

export const MATURITIES = ['GA', 'Preview', 'Labs', 'Roadmap'];
export const STAGES = ['discover', 'corroborate', 'prove', 'learn', 'scale', 'observe', 'trace', 'fix', 'verify', 'detect'];
export const CROSS_CUTTING = 'cross-cutting';
export const CANONICAL_CHAIN = 'Discover → Corroborate → Prove → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻';

/** Pages this work owns. The em-dash, avoid-list and command rules apply here, not to every historical page. */
const OWNED_ROOTS = [
  'docs/quickstart', 'docs/how-it-works', 'docs/discover', 'docs/corroborate', 'docs/prove', 'docs/learn',
  'docs/scale', 'docs/observe', 'docs/trace', 'docs/fix', 'docs/verify', 'docs/detect', 'docs/security-graph',
  'docs/trust', 'docs/roles', 'docs/workflows', 'docs/integrations', 'docs/labs', 'docs/roadmap', 'docs/website',
];
const OWNED_FILES = ['README.md', 'docs/README.md', 'docs/STYLE-AND-TERMINOLOGY.md', 'docs/DOCS-MIGRATION.md'];

const SVGS = ['assurance-lifecycle', 'traditional-vs-agentic', 'evidence-model', 'security-graph', 'one-finding-journey', 'platform-architecture'];
/** SVGs that carry a maturity-bearing claim and so must spell the maturity out in text, not in colour alone. */
const SVGS_WITH_MATURITY = ['assurance-lifecycle', 'security-graph', 'one-finding-journey', 'platform-architecture'];

const ROLES = ['developer', 'appsec', 'ciso', 'platform-engineering', 'ai-engineering', 'privacy', 'compliance', 'detection-engineering'];

// ---------------------------------------------------------------------------
// Registry reader
// ---------------------------------------------------------------------------

const LIST_KEYS = new Set(['lifecycleStages', 'aliases', 'platforms']);
const BLOCK_LIST_KEYS = new Set(['docs', 'evidence', 'aliases']);

function scalar(v) {
  v = v.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  return v;
}

export function parseRegistry(text) {
  const out = { lifecycle: [], capabilities: [] };
  let section = null;
  let rec = null;
  let listKey = null;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const top = /^([A-Za-z]+):\s*$/.exec(raw);
    if (top) { section = top[1]; rec = null; listKey = null; if (!(section in out)) out[section] = []; continue; }
    if (!section) throw new Error(`line ${i + 1}: content before a section header`);
    const item = /^  - ([A-Za-z]+):\s*(.*)$/.exec(raw);
    if (item) { rec = { _line: i + 1 }; out[section].push(rec); rec[item[1]] = scalar(item[2]); listKey = null; continue; }
    if (!rec) throw new Error(`line ${i + 1}: field outside a record`);
    const blockItem = /^      - (.*)$/.exec(raw);
    if (blockItem && listKey) { rec[listKey].push(scalar(blockItem[1])); continue; }
    const field = /^    ([A-Za-z]+):\s*(.*)$/.exec(raw);
    if (field) {
      const [, k, v] = field;
      listKey = null;
      if (v === '' && BLOCK_LIST_KEYS.has(k)) { rec[k] = []; listKey = k; continue; }
      if (LIST_KEYS.has(k) && v.startsWith('[') && v.endsWith(']')) {
        rec[k] = v.slice(1, -1).split(',').map(s => scalar(s)).filter(Boolean);
      } else rec[k] = scalar(v);
      continue;
    }
    throw new Error(`line ${i + 1}: cannot read "${raw.trim()}"`);
  }
  return out;
}

export function loadRegistry(repo = REPO_DEFAULT) {
  return parseRegistry(fs.readFileSync(path.join(repo, 'docs', 'capabilities.yaml'), 'utf8'));
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const F = (rule, file, line, message) => ({ rule, file, line, message });

export function formatFinding(f) {
  return `[${f.rule}] ${f.file}${f.line ? `:${f.line}` : ''}  ${f.message}`;
}

// A docs checker over a checkout nobody is writing to: a missing path is reported as a finding, and a read that then fails is a finding too.
const exists = (repo, rel) => fs.statSync(path.join(repo, rel), { throwIfNoEntry: false }) !== undefined;  // agentic-security-ignore: CWE-367
const read = (repo, rel) => fs.readFileSync(path.join(repo, rel), 'utf8');

// ---------------------------------------------------------------------------
// Registry validation
// ---------------------------------------------------------------------------

export function validateRegistry(reg, repo = REPO_DEFAULT) {
  const out = [];
  const file = 'docs/capabilities.yaml';

  const ids = reg.lifecycle.map(s => s.id);
  if (ids.join(',') !== STAGES.join(',')) {
    out.push(F('registry', file, 0, `lifecycle must list exactly ${STAGES.join(' → ')} in that order; found ${ids.join(', ') || 'nothing'}`));
  }
  for (const s of reg.lifecycle) {
    if (!s.question) out.push(F('registry', file, s._line, `stage ${s.id} has no question`));
    if (!s.page || !exists(repo, s.page)) out.push(F('registry', file, s._line, `stage ${s.id} page ${s.page || '(none)'} does not exist`));
  }

  if (!reg.capabilities.length) out.push(F('registry', file, 0, 'no capabilities are registered'));
  const seen = new Set();
  for (const c of reg.capabilities) {
    const where = c._line;
    if (!c.id) { out.push(F('registry', file, where, 'a capability has no id')); continue; }
    if (seen.has(c.id)) out.push(F('registry', file, where, `duplicate capability id ${c.id}`));
    seen.add(c.id);
    if (!c.name) out.push(F('registry', file, where, `${c.id}: no name`));
    if (!c.establishes) out.push(F('registry', file, where, `${c.id}: no "establishes" sentence (it feeds the generated table)`));
    if (!MATURITIES.includes(c.maturity)) {
      out.push(F('registry', file, where, `${c.id}: maturity "${c.maturity}" is not one of ${MATURITIES.join(', ')}`));
    }
    const stages = c.lifecycleStages;
    if (!Array.isArray(stages) || !stages.length) out.push(F('registry', file, where, `${c.id}: lifecycleStages must be a non-empty list`));
    else for (const s of stages) {
      if (!STAGES.includes(s) && s !== CROSS_CUTTING) out.push(F('registry', file, where, `${c.id}: unknown lifecycle stage "${s}"`));
    }
    const ev = c.evidence || [];
    if (c.maturity === 'Roadmap') {
      if (ev.length) out.push(F('registry', file, where, `${c.id}: a Roadmap capability must not list implementation evidence (it would claim code that is not there)`));
    } else if (MATURITIES.includes(c.maturity)) {
      if (!ev.length) out.push(F('registry', file, where, `${c.id}: ${c.maturity} requires implementation evidence`));
    }
    for (const e of ev) if (!exists(repo, e)) out.push(F('registry', file, where, `${c.id}: evidence path ${e} does not exist`));
    if (!(c.docs || []).length) out.push(F('registry', file, where, `${c.id}: no docs page`));
    for (const d of c.docs || []) if (!exists(repo, d)) out.push(F('registry', file, where, `${c.id}: docs path ${d} does not exist`));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Generated tables
// ---------------------------------------------------------------------------

const cap = s => s.charAt(0).toUpperCase() + s.slice(1);

export function stageLabel(c) {
  return c.lifecycleStages.map(s => (s === CROSS_CUTTING ? 'Cross-cutting' : cap(s))).join(', ');
}

function docLink(c, fromDir) {
  const target = (c.docs || [])[0];
  if (!target) return c.name;
  let rel = path.posix.relative(fromDir, target);
  if (!rel.startsWith('.')) rel = `./${rel}`;
  return `[${c.name}](${rel})`;
}

/** Render the table for `stage` (or all capabilities), links relative to `fromDir` (repo-relative, posix). */
export function renderTable(reg, { stage = null, fromDir = '.' } = {}) {
  const rows = reg.capabilities.filter(c => !stage || c.lifecycleStages.includes(stage));
  const lines = [
    '| Capability | Lifecycle Stage | Maturity | What It Establishes |',
    '|---|---|---|---|',
  ];
  for (const c of rows) lines.push(`| ${docLink(c, fromDir)} | ${stageLabel(c)} | **${c.maturity}** | ${c.establishes} |`);
  return lines.join('\n');
}

export function renderCounts(reg) {
  const n = Object.fromEntries(MATURITIES.map(m => [m, 0]));
  for (const c of reg.capabilities) if (c.maturity in n) n[c.maturity]++;
  return n;
}

/** One row per lifecycle stage: its question, the maturities of what ships there, and its page. */
export function renderLifecycleTable(reg, { fromDir = '.' } = {}) {
  const lines = [
    '| Stage | Question | Maturity at this stage | Read |',
    '|---|---|---|---|',
  ];
  reg.lifecycle.forEach((st, i) => {
    const mats = MATURITIES.filter(m => reg.capabilities.some(c => c.maturity === m && c.lifecycleStages.includes(st.id)));
    let rel = path.posix.relative(fromDir, st.page);
    if (!rel.startsWith('.')) rel = `./${rel}`;
    lines.push(`| ${i + 1}. ${cap(st.id)} | ${st.question} | ${mats.map(m => `**${m}**`).join(', ') || '(none registered)'} | [${cap(st.id)}](${rel}) |`);
  });
  return lines.join('\n');
}

/**
 * Replace every generated block in `text`. A block is a start marker line, body lines that contain no other generated marker, and an end
 * marker line. Read line by line (not with one regular expression) so an unterminated block, or two blocks run together, can never make
 * one match swallow the prose between them. `markers` is [startRe, endRe]; `want(match)` returns the full replacement text or null to keep.
 */
export function mapBlocks(text, startRe, endRe, want) {
  const lines = text.split('\n');
  const out = [];
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const m = startRe.exec(lines[i]);
    if (!m) { out.push(lines[i]); continue; }
    let j = i + 1;
    while (j < lines.length && !endRe.test(lines[j]) && !lines[j].startsWith('<!-- generated:')) j++;
    if (j >= lines.length || !endRe.test(lines[j])) { out.push(lines[i]); continue; } // unterminated: leave it alone
    const whole = lines.slice(i, j + 1).join('\n');
    const next = want(m, whole);
    if (next !== null && next !== whole) changed = true;
    out.push(next === null ? whole : next);
    i = j;
  }
  return { text: out.join('\n'), changed };
}

const CAP_START = /^<!-- generated:capabilities(?::([a-z-]+))?:start -->$/;
const CAP_END = /^<!-- generated:capabilities(?::[a-z-]+)?:end -->$/;
const LIFE_START = /^<!-- generated:lifecycle:start -->$/;
const LIFE_END = /^<!-- generated:lifecycle:end -->$/;

/** Every markdown file that may hold a generated block. */
function generatedHosts(repo) {
  const hosts = ['README.md', 'docs/README.md'];
  for (const root of OWNED_ROOTS) for (const f of walkMarkdown(repo, root)) hosts.push(f);
  return [...new Set(hosts)].filter(f => exists(repo, f));
}

export function checkTables(reg, repo = REPO_DEFAULT, { write = false } = {}) {
  const out = [];
  let blocks = 0;
  for (const rel of generatedHosts(repo)) {
    const text = read(repo, rel);
    if (!text.includes('<!-- generated:capabilities') && !text.includes('<!-- generated:lifecycle')) continue;
    const dir = path.posix.dirname(rel);
    const caps = mapBlocks(text, CAP_START, CAP_END, (m, whole) => {
      blocks++;
      const stage = m[1];
      if (stage && !STAGES.includes(stage)) { out.push(F('table', rel, lineOf(text, whole), `generated block names unknown stage "${stage}"`)); return null; }
      const tag = stage ? `:${stage}` : '';
      const want = `<!-- generated:capabilities${tag}:start -->\n${renderTable(reg, { stage: stage || null, fromDir: dir })}\n<!-- generated:capabilities${tag}:end -->`;
      if (whole !== want && !write) out.push(F('table', rel, lineOf(text, whole), `generated capability table${stage ? ` (${stage})` : ''} is stale; run node scripts/check-positioning-docs.mjs --write`));
      return want;
    });
    const life = mapBlocks(caps.text, LIFE_START, LIFE_END, (m, whole) => {
      blocks++;
      const want = `<!-- generated:lifecycle:start -->\n${renderLifecycleTable(reg, { fromDir: dir })}\n<!-- generated:lifecycle:end -->`;
      if (whole !== want && !write) out.push(F('table', rel, lineOf(text, whole), 'generated lifecycle table is stale; run node scripts/check-positioning-docs.mjs --write'));
      return want;
    });
    if (write && life.text !== text) fs.writeFileSync(path.join(repo, rel), life.text);
  }
  if (!blocks) out.push(F('table', 'README.md', 0, 'no generated capability block found; the README capability snapshot must be generated from docs/capabilities.yaml'));
  return out;
}

function lineOf(text, fragment) {
  const i = text.indexOf(fragment);
  return i < 0 ? 0 : text.slice(0, i).split('\n').length;
}

// ---------------------------------------------------------------------------
// File walking helpers
// ---------------------------------------------------------------------------

export function walkMarkdown(repo, rel) {
  const out = [];
  const abs = path.join(repo, rel);
  const walk = (dir, relDir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === '.agentic-security') continue;
      const r = path.posix.join(relDir, e.name);
      if (e.isDirectory()) walk(path.join(dir, e.name), r);
      else if (e.isFile() && e.name.endsWith('.md')) out.push(r);
    }
  };
  if (fs.statSync(abs, { throwIfNoEntry: false })?.isDirectory()) walk(abs, rel);
  return out;
}

export function ownedPages(repo = REPO_DEFAULT) {
  const pages = new Set(OWNED_FILES.filter(f => exists(repo, f)));
  for (const r of OWNED_ROOTS) for (const f of walkMarkdown(repo, r)) pages.add(f);
  return [...pages].sort();
}

/** Every page the maturity checks read: owned pages plus the guides and walkthroughs that carry a capability banner. */
function maturityPages(repo) {
  const pages = new Set(ownedPages(repo));
  for (const r of ['docs/guides', 'docs/walkthroughs', 'docs/security-graph']) for (const f of walkMarkdown(repo, r)) pages.add(f);
  return [...pages].sort();
}

/** Blank fenced code so prose rules do not read examples; keeps line numbers. */
function blankFences(text) {
  return text.replace(/```[\s\S]*?```/g, m => m.replace(/[^\n]/g, ' '));
}

function ignoredLines(lines) {
  const ign = new Set();
  lines.forEach((l, i) => {
    const m = /<!--\s*positioning-ignore:\s*(\S.*?)\s*-->/.exec(l);
    if (m) { ign.add(i); ign.add(i + 1); }
  });
  return ign;
}

// ---------------------------------------------------------------------------
// Maturity consistency
// ---------------------------------------------------------------------------

const BADGE_RE = /\[(GA|Preview|Labs|Roadmap)\](?!\()/g;

function mentions(line, c) {
  const lower = line.toLowerCase();
  const names = [c.name, c.id, ...(c.aliases || [])].map(s => s.toLowerCase());
  return names.some(n => n.length > 3 && lower.includes(n));
}

export function checkMaturityConsistency(reg, repo = REPO_DEFAULT, pages = null) {
  const out = [];
  const files = pages || maturityPages(repo);
  const primary = new Map();
  for (const c of reg.capabilities) {
    const p = (c.docs || [])[0];
    if (!p) continue;
    if (!primary.has(p)) primary.set(p, []);
    primary.get(p).push(c);
  }
  for (const rel of files) {
    const text = read(repo, rel);
    const lines = blankFences(text).split('\n');
    const ign = ignoredLines(text.split('\n'));
    lines.forEach((line, i) => {
      if (ign.has(i)) return;
      const pm = /^\*\*Maturity:\*\*\s*(GA|Preview|Labs|Roadmap)\b/.exec(line.trim());
      if (pm) {
        const owners = primary.get(rel) || [];
        const wrong = owners.filter(c => c.maturity !== pm[1]);
        if (owners.length && wrong.length === owners.length) {
          out.push(F('consistency', rel, i + 1, `page states Maturity: ${pm[1]} but docs/capabilities.yaml has ${wrong.map(c => `${c.id}=${c.maturity}`).join(', ')}`));
        }
        return;
      }
      const badges = [...line.matchAll(BADGE_RE)].map(m => m[1]);
      if (!badges.length) return;
      const named = reg.capabilities.filter(c => mentions(line, c));
      if (named.length !== 1) return; // ambiguous or none: do not guess
      for (const b of badges) {
        if (b !== named[0].maturity) {
          out.push(F('consistency', rel, i + 1, `badge [${b}] on "${named[0].name}" contradicts docs/capabilities.yaml (${named[0].maturity})`));
        }
      }
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Roadmap / Labs overclaim lint
// ---------------------------------------------------------------------------

const SHIPPED_VERB = /\b(ships?|shipped|is available|are available|now (?:supports?|generates?|detects?|observes?|monitors?)|(?:automatically )?(?:generates?|detects?|monitors?|collects?|observes?|streams?|learns?))\b/i;
const HEDGE = /\b(roadmap|planned|not shipped|not yet|future|will|would|could|when implemented|until implemented|once implemented|conceptual|target|aspir\w*|today'?s? [a-z ]*(?:is|are) (?:offline|an input)|input|inputs|does not|do not|is not|are not|never|no |cannot|can't|without)\b/i;
const LABS_OVERCLAIM = /\b(production[- ]ready|production[- ]supported|generally available|fully supported|battle[- ]tested|stable)\b/i;

export function checkOverclaims(reg, repo = REPO_DEFAULT, pages = null) {
  const out = [];
  const files = pages || ownedPages(repo);
  const roadmap = reg.capabilities.filter(c => c.maturity === 'Roadmap');
  const labs = reg.capabilities.filter(c => c.maturity === 'Labs');
  for (const rel of files) {
    const text = read(repo, rel);
    const raw = text.split('\n');
    const lines = blankFences(text).split('\n');
    const ign = ignoredLines(raw);
    lines.forEach((line, i) => {
      if (ign.has(i) || /^\s*\|?\s*\|?\s*-{3,}/.test(line)) return;
      // The registry-rendered table rows state a Roadmap capability with its own maturity; the badge is the hedge.
      if (/\*\*Roadmap\*\*|\[Roadmap\]/.test(line)) return;
      for (const c of roadmap) {
        if (mentions(line, c) && SHIPPED_VERB.test(line) && !HEDGE.test(line)) {
          out.push(F('overclaim', rel, i + 1, `"${c.name}" is Roadmap but this line reads as shipped; hedge it, or add <!-- positioning-ignore: reason -->`));
        }
      }
      if (/\*\*Labs\*\*|\[Labs\]/.test(line) && !LABS_OVERCLAIM.test(line)) return;
      for (const c of labs) {
        if (mentions(line, c) && LABS_OVERCLAIM.test(line) && !/\b(not|never|no longer)\b/i.test(line)) {
          out.push(F('overclaim', rel, i + 1, `"${c.name}" is Labs but this line claims production readiness`));
        }
      }
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** Subcommands that exist per dispatcher, taken from the CLI sources. A documented one outside the list fails. */
export const SUBCOMMANDS = {
  dataflow: ['export', 'diff', 'watch', 'scenario', 'impact', 'observations', 'twin'],
  image: ['scan', 'verify'],
  provenance: ['trace'],
  fleet: ['init', 'scan', 'status', 'resume', 'query'],
  rules: ['validate', 'lock', 'synthesize', 'evaluate', 'promote', 'status', 'rollback'],
  runtime: ['ingest', 'status', 'reconcile', 'query'],
  proof: ['show', 'replay', 'doctor'],
  federate: ['declare', 'list'],
  remediation: ['open', 'update', 'verify', 'accept-risk', 'reopen-check', 'list'],
  governance: ['propose-edit'],
  triage: ['list', 'assign', 'trend', 'show', 'exploit', 'validate'],
  profile: ['set', 'show'],
  models: ['doctor'],
  context: ['build', 'inspect', 'diff', 'review', 'status', 'eval', 'verify', 'export', 'cleanup'],
  compliance: [],
};

export function cliCommands(repo = REPO_DEFAULT) {
  const src = read(repo, 'scanner/bin/agentic-security.js');
  const set = new Set(['help', 'version', 'banner', 'harness', 'scan-baseline', 'attest', 'verify-attestation']);
  for (const m of src.matchAll(/case '([a-z][a-z0-9-]*)'\s*:/g)) set.add(m[1]);
  return set;
}

export function slashCommands(repo = REPO_DEFAULT) {
  const dir = path.join(repo, 'commands');
  return new Set(fs.readdirSync(dir).filter(f => f.endsWith('.md')).map(f => f.replace(/\.md$/, '')));
}

const CLI_LINE = /(?:^|[\s`$>])(?:agentic-security|npx @clear-capabilities\/agentic-security-scanner) +([a-z][a-z0-9-]*)([^`|;&\n]*)/g;
const SLASH = /\/agentic-security:([a-z][a-z0-9-]*)/g;

/** The command-shaped text on each line: inline code spans everywhere, and whole lines inside a code fence. Prose is not parsed. */
function commandSegments(raw) {
  const segs = [];
  let fence = null;
  raw.forEach((line, i) => {
    const f = /^\s*```(\S*)/.exec(line);
    if (f) { fence = fence === null ? f[1] : null; return; }
    // only shell fences hold commands; text, console, json and other fences hold captured output
    if (fence !== null) { if (['bash', 'sh', 'shell', 'zsh'].includes(fence)) segs.push([i, line.replace(/^\s*\$\s*/, '')]); return; }
    for (const m of line.matchAll(/`([^`\n]+)`/g)) segs.push([i, m[1]]);
  });
  return segs;
}

export function checkCommands(repo = REPO_DEFAULT, pages = null) {
  const out = [];
  const cli = cliCommands(repo);
  const slash = slashCommands(repo);
  for (const rel of pages || ownedPages(repo)) {
    const raw = read(repo, rel).split('\n');
    const ign = ignoredLines(raw);
    for (const [i, seg] of commandSegments(raw)) {
      if (ign.has(i)) continue;
      for (const m of seg.matchAll(CLI_LINE)) {
        const [, sub, rest] = m;
        if (!cli.has(sub)) {
          out.push(F('command', rel, i + 1, `documented command "agentic-security ${sub}" does not exist in the CLI`));
          continue;
        }
        const first = (rest || '').trim().split(/\s+/)[0];
        if (SUBCOMMANDS[sub] && SUBCOMMANDS[sub].length && first && /^[a-z][a-z0-9-]*$/.test(first) && !SUBCOMMANDS[sub].includes(first)) {
          // a bare word after a dispatcher whose first argument is always a subcommand must be one of them
          if (['dataflow', 'image', 'provenance', 'fleet', 'rules', 'runtime', 'proof', 'federate', 'remediation', 'governance'].includes(sub)) {
            out.push(F('command', rel, i + 1, `"agentic-security ${sub} ${first}" is not a ${sub} subcommand (${SUBCOMMANDS[sub].join('|')})`));
          }
        }
        if (sub === 'scan' && /\s--assurance\b/.test(rest || '')) {
          out.push(F('command', rel, i + 1, '`--assurance` exists only on `ci`; `scan --assurance` is not a thing'));
        }
      }
    }
    raw.forEach((line, i) => {
      if (ign.has(i)) return;
      for (const m of line.matchAll(SLASH)) {
        if (!slash.has(m[1])) out.push(F('command', rel, i + 1, `documented slash command /agentic-security:${m[1]} has no commands/${m[1]}.md`));
      }
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Lifecycle ordering, style, navigation
// ---------------------------------------------------------------------------

export function checkLifecycleOrder(repo = REPO_DEFAULT, pages = null) {
  const out = [];
  const stageWord = new Map(STAGES.map(x => [cap(x).toLowerCase(), cap(x)]));
  for (const rel of pages || [...ownedPages(repo), 'docs/capabilities.yaml']) {
    if (!exists(repo, rel)) continue;
    read(repo, rel).split('\n').forEach((line, i) => {
      if (!line.includes('→')) return;
      // A "chain" is a run of stage names joined by arrows. Prose that merely mentions stages next to an arrow is not one.
      const parts = line.split('→').map(p => p.replace(/[`*_\[\]()↻.,;:]/g, ' ').trim().split(/\s+/));
      let run = [];
      const runs = [];
      for (const p of parts) {
        const first = (p[p.length - 1] || '').toLowerCase();
        const head = (p[0] || '').toLowerCase();
        if (stageWord.has(head) && p.length <= 2) run.push(stageWord.get(head));
        else if (stageWord.has(first) && run.length === 0 && p.length <= 6) run.push(stageWord.get(first));
        else { if (run.length) runs.push(run); run = []; if (stageWord.has(first)) run.push(stageWord.get(first)); }
      }
      if (run.length) runs.push(run);
      for (const r of runs) {
        if (r.length >= 6 && !line.includes(CANONICAL_CHAIN)) {
          out.push(F('lifecycle', rel, i + 1, `lifecycle written out in a non-canonical order (${r.join(' → ')}); the one ordering is: ${CANONICAL_CHAIN}`));
        }
      }
    });
  }
  return out;
}

const AVOID = [
  [/\bzero false positives?\b/i, '"zero false positives"'],
  [/\bproved? safe\b/i, '"proved safe"'],
  [/\bguarantees?\b/i, '"guarantee"'],
  [/\bcertified\b/i, '"certified"'],
  [/\bcompliant\b/i, '"compliant"'],
];
const NEGATION = /\b(not|never|no|nor|cannot|can't|won't|without|avoid|avoids|refuses?|rather than|isn't|aren't|doesn't|does not|do not|is not|are not|unqualified|instead of|issue|issues|issued)\b/i;

export function checkStyle(repo = REPO_DEFAULT, pages = null) {
  const out = [];
  for (const rel of pages || ownedPages(repo)) {
    if (rel === 'docs/STYLE-AND-TERMINOLOGY.md') continue; // it quotes the avoid-list on purpose
    const text = read(repo, rel);
    const raw = text.split('\n');
    const prose = blankFences(text).split('\n');
    const ign = ignoredLines(raw);
    prose.forEach((line, i) => {
      if (ign.has(i)) return;
      const stripped = line.replace(/`[^`]*`/g, '');
      if (/—/.test(stripped) && !/^\s*[>]?\s*"/.test(stripped)) out.push(F('style', rel, i + 1, 'em-dash in prose; use a comma, colon or period'));
      for (const [re, label] of AVOID) {
        if (re.test(stripped) && !NEGATION.test(stripped)) out.push(F('style', rel, i + 1, `unqualified ${label}; see docs/STYLE-AND-TERMINOLOGY.md`));
      }
    });
  }
  return out;
}

export function checkNavigation(repo = REPO_DEFAULT) {
  const out = [];
  const home = 'docs/README.md';
  if (!exists(repo, home)) return [F('navigation', home, 0, 'docs home is missing')];
  const homeText = read(repo, home);
  for (const role of ROLES) {
    const rel = `docs/roles/${role}.md`;
    if (!exists(repo, rel)) { out.push(F('navigation', rel, 0, 'role page is missing')); continue; }
    if (!homeText.includes(`roles/${role}.md`)) out.push(F('navigation', home, 0, `docs home does not link to roles/${role}.md`));
    const text = read(repo, rel);
    const m = /^\*\*Core workflow:\*\*[^\n]*\]\(([^)]+)\)/m.exec(text);
    if (!m) { out.push(F('navigation', rel, 0, 'role page has no "**Core workflow:** [..](..)" line')); continue; }
    const target = path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1].split('#')[0]));
    if (!exists(repo, target)) out.push(F('navigation', rel, 0, `core workflow link ${m[1]} does not resolve`));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Links and anchors
// ---------------------------------------------------------------------------

export function slug(heading) {
  return heading.trim().toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-');
}

function anchorsOf(text) {
  const set = new Set();
  const count = new Map();
  for (const line of blankFences(text).split('\n')) {
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    let s = slug(m[1].replace(/<[^>]+>/g, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1'));
    const n = count.get(s) || 0;
    count.set(s, n + 1);
    set.add(n ? `${s}-${n}` : s);
  }
  for (const m of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) set.add(m[1]);
  return set;
}

const LINK = /!?\[[^\]]*\]\(([^()\s]+)(?:\s+"[^"]*")?\)/g;

export function checkLinks(repo = REPO_DEFAULT, pages = null) {
  const out = [];
  const cache = new Map();
  const anchors = rel => {
    if (!cache.has(rel)) cache.set(rel, anchorsOf(read(repo, rel)));
    return cache.get(rel);
  };
  for (const rel of pages || ownedPages(repo)) {
    const text = blankFences(read(repo, rel)).replace(/`[^`\n]*`/g, m => ' '.repeat(m.length));
    const lines = text.split('\n');
    lines.forEach((line, i) => {
      for (const m of line.matchAll(LINK)) {
        const target = m[1];
        if (/^(?:https?:|mailto:|data:)/i.test(target)) continue;
        const [pathPart, frag] = target.split('#');
        let resolvedRel;
        if (!pathPart) resolvedRel = rel;
        else {
          let p = pathPart;
          try { p = decodeURIComponent(p); } catch { /* keep */ }
          resolvedRel = p.startsWith('/') ? p.slice(1) : path.posix.normalize(path.posix.join(path.posix.dirname(rel), p));
        }
        const abs = path.join(repo, resolvedRel);
        const st = fs.statSync(abs, { throwIfNoEntry: false });
        if (!st) { out.push(F('link', rel, i + 1, `broken link ${target}`)); continue; }
        if (frag && resolvedRel.endsWith('.md') && st.isFile()) {
          let f = frag;
          try { f = decodeURIComponent(f); } catch { /* keep */ }
          if (!anchors(resolvedRel).has(f)) out.push(F('link', rel, i + 1, `anchor #${frag} not found in ${resolvedRel}`));
        }
      }
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Visuals and required pages
// ---------------------------------------------------------------------------

export function checkVisuals(repo = REPO_DEFAULT) {
  const out = [];
  for (const name of SVGS) {
    const rel = `docs/assets/positioning/${name}.svg`;
    if (!exists(repo, rel)) { out.push(F('visual', rel, 0, 'required SVG is missing')); continue; }
    const svg = read(repo, rel);
    if (!/<svg\b[^>]*\bviewBox=/.test(svg)) out.push(F('visual', rel, 0, 'no viewBox (it will not scale on GitHub)'));
    if (!/<title\b[^>]*>[^<]{8,}<\/title>/.test(svg)) out.push(F('visual', rel, 0, 'no <title> alt text'));
    if (!/<desc\b[^>]*>[^<]{20,}<\/desc>/.test(svg)) out.push(F('visual', rel, 0, 'no <desc> long description'));
    if (/\d\s?%/.test(svg.replace(/<style[\s\S]*?<\/style>/g, ''))) out.push(F('visual', rel, 0, 'states a percentage; no invented quantitative claims'));
    if (SVGS_WITH_MATURITY.includes(name)) {
      const texts = [...svg.matchAll(/<text\b[^>]*>([\s\S]*?)<\/text>/g)].map(m => m[1].replace(/<[^>]+>/g, '')).join(' ');
      for (const w of ['GA', 'Preview', 'Labs', 'Roadmap']) {
        if (!new RegExp(`\\b${w}\\b`).test(texts)) out.push(F('visual', rel, 0, `maturity "${w}" is not spelled out in text; maturity must not rely on colour alone`));
      }
    }
  }
  return out;
}

const REQUIRED_PAGES = [
  'docs/README.md', 'docs/capabilities.yaml', 'docs/STYLE-AND-TERMINOLOGY.md', 'docs/DOCS-MIGRATION.md',
  'docs/quickstart/5-minute-demo.md', 'docs/quickstart/15-minute-quickstart.md',
  'docs/how-it-works/assurance-lifecycle.md', 'docs/how-it-works/evidence-model.md',
  'docs/how-it-works/deterministic-and-agentic.md', 'docs/how-it-works/finding-lifecycle.md', 'docs/how-it-works/maturity-model.md',
  'docs/security-graph/code-boundaries.md', 'docs/security-graph/data-flow.md', 'docs/security-graph/provenance.md', 'docs/security-graph/blast-radius.md',
  'docs/trust/trust-and-limitations.md', 'docs/trust/scan-health.md', 'docs/trust/assurance-modes.md', 'docs/trust/verified-remediation.md',
  'docs/trust/agent-threat-model.md', 'docs/trust/model-egress.md', 'docs/trust/benchmarking-methodology.md',
  'docs/workflows/one-findings-journey.md', 'docs/workflows/vulnerability-response.md', 'docs/workflows/ci-gating.md', 'docs/workflows/compliance-evidence.md',
  'docs/implementation-status/autonomous-assurance-docs-repositioning.md',
  ...STAGES.map(s => `docs/${s}/README.md`),
  ...ROLES.map(r => `docs/roles/${r}.md`),
  'docs/integrations/README.md', 'docs/reference/README.md', 'docs/labs/README.md', 'docs/roadmap/README.md',
  'docs/website/README.md',
];

export function checkRequiredPages(repo = REPO_DEFAULT) {
  return REQUIRED_PAGES.filter(p => !exists(repo, p)).map(p => F('structure', p, 0, 'required page is missing'));
}

/** The README must lead with the repositioned hero, in the PRD's exact words. */
export function checkReadmeHero(repo = REPO_DEFAULT) {
  const out = [];
  const text = read(repo, 'README.md');
  const head = text.split('\n').slice(0, 40).join('\n');
  for (const needle of [
    '# Agentic Security',
    '## Autonomous Security Assurance for the AI Software Era',
    "**Discover vulnerabilities. Prove what's exploitable. Understand what's exposed. Fix it safely. Learn from every finding.**",
  ]) if (!head.includes(needle)) out.push(F('readme', 'README.md', 0, `the first screen must contain: ${needle}`));
  if (!text.includes(CANONICAL_CHAIN)) out.push(F('readme', 'README.md', 0, 'the README must show the canonical ten-stage lifecycle'));
  if (!/\*\*Evidence, not magic\.\*\*/.test(text)) out.push(F('readme', 'README.md', 0, 'the README trust statement is missing'));
  return out;
}

// ---------------------------------------------------------------------------
// The GA bar (GA promotion PRD, section 3)
// ---------------------------------------------------------------------------
//
// A capability is GA only when the registry names the evidence for each mechanical criterion and every named thing exists:
//   G1 contract + contractTest : a reference page and a compatibility test that a scanner test script runs
//   G3 gate                    : a release-gate check id that `release-check.mjs` actually evaluates
//   G4 platforms               : `os:job` pairs, at least one linux, each job present in .github/workflows
//   G5 limits                  : `page#anchor` whose section exists and carries a `limits-verified` date
//   G6 since                   : the version the capability was promoted in
// G2 (both-direction tests) and G7 (honest degradation) are reviewed, not mechanical; the promotion record lists them.
// Preview needs a frozen `contract` or a dated `contractNote` saying which fields may still change.

export const GA_PLATFORMS = ['linux', 'macos'];
const VERIFIED_RE = /<!--\s*limits-verified:\s*(\d{4}-\d{2}-\d{2})\s*-->/;
export const LIMITS_MAX_AGE_DAYS = 90;

function workflowJobs(repo) {
  const dir = path.join(repo, '.github', 'workflows');
  const jobs = new Set();
  for (const f of fs.readdirSync(dir)) {
    if (!/\.ya?ml$/.test(f)) continue;
    let inJobs = false;
    for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
      if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
      if (inJobs && /^[A-Za-z]/.test(line)) inJobs = false;
      const m = inJobs ? /^  ([A-Za-z0-9_-]+):\s*$/.exec(line) : null;
      if (m) jobs.add(m[1]);
    }
  }
  return jobs;
}

function releaseGateIds(repo) {
  const text = read(repo, 'scripts/release-check.mjs');
  return new Set([...text.matchAll(/evaluate\('([a-z0-9-]+)'/g)].map(m => m[1]));
}

/** The text of the section under `anchor` (up to the next heading of the same or a higher level), or null. */
export function sectionByAnchor(text, anchor) {
  const lines = blankFences(text).split('\n');
  const count = new Map();
  for (let i = 0; i < lines.length; i++) {
    const m = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(lines[i]);
    if (!m) continue;
    let sl = slug(m[2].replace(/<[^>]+>/g, '').replace(/\[([^\]]*)\]\([^)]*\)/g, '$1'));
    const n = count.get(sl) || 0;
    count.set(sl, n + 1);
    if (n) sl = `${sl}-${n}`;
    if (sl !== anchor) continue;
    const level = m[1].length;
    const body = [];
    for (let j = i + 1; j < lines.length; j++) {
      const h = /^(#{1,6})\s/.exec(lines[j]);
      if (h && h[1].length <= level) break;
      body.push(lines[j]);
    }
    return body.join('\n');
  }
  return null;
}

/** The date in a GA capability's limits section, or null (shared with the freshness check). */
function limitsMarker(repo, limits) {
  const [page, anchor] = String(limits).split('#');
  if (!page || !anchor || !exists(repo, page)) return null;
  const body = sectionByAnchor(fs.readFileSync(path.join(repo, page), 'utf8'), anchor);
  const m = body === null ? null : VERIFIED_RE.exec(body);
  return m ? m[1] : null;
}

export function checkGaBar(reg, repo = REPO_DEFAULT) {
  const out = [];
  const file = 'docs/capabilities.yaml';
  const jobs = workflowJobs(repo);
  const gates = releaseGateIds(repo);
  const scripts = JSON.stringify((JSON.parse(read(repo, 'scanner/package.json')).scripts) || {});
  for (const c of reg.capabilities) {
    const at = c._line;
    if (c.maturity === 'Preview') {
      if (!c.contract && !c.contractNote) out.push(F('bar', file, at, `${c.id}: Preview needs a \`contract\` page or a dated \`contractNote\` saying which fields may still change`));
      if (c.contract && !exists(repo, c.contract)) out.push(F('bar', file, at, `${c.id}: contract page ${c.contract} does not exist`));
      continue;
    }
    if (c.maturity !== 'GA') continue;
    for (const k of ['contract', 'contractTest', 'gate', 'limits', 'since']) {
      if (!c[k]) out.push(F('bar', file, at, `${c.id}: GA requires \`${k}\` (the GA bar, docs/how-it-works/maturity-model.md)`));
    }
    if (c.since && !/^\d+\.\d+\.\d+$/.test(c.since)) out.push(F('bar', file, at, `${c.id}: since "${c.since}" is not a version`));
    if (c.contract && !exists(repo, c.contract)) out.push(F('bar', file, at, `${c.id}: contract page ${c.contract} does not exist`));
    if (c.contractTest) {
      if (!exists(repo, c.contractTest)) out.push(F('bar', file, at, `${c.id}: contract test ${c.contractTest} does not exist`));
      else if (!scripts.includes(c.contractTest.replace(/^scanner\//, ''))) out.push(F('bar', file, at, `${c.id}: contract test ${c.contractTest} is not run by any scanner test script`));
    }
    if (c.gate && !gates.has(c.gate)) out.push(F('bar', file, at, `${c.id}: gate "${c.gate}" is not a check release-check.mjs evaluates`));
    const plats = c.platforms || [];
    if (!plats.length) out.push(F('bar', file, at, `${c.id}: GA requires \`platforms\` (os:job pairs)`));
    for (const pl of plats) {
      const m = /^([a-z]+):([A-Za-z0-9_-]+)$/.exec(pl);
      if (!m || !GA_PLATFORMS.includes(m[1])) { out.push(F('bar', file, at, `${c.id}: platform "${pl}" must be os:job with os in ${GA_PLATFORMS.join(', ')}`)); continue; }
      if (!jobs.has(m[2])) out.push(F('bar', file, at, `${c.id}: platform job "${m[2]}" is not a job in .github/workflows`));
    }
    if (plats.length && !plats.some(pl => pl.startsWith('linux:'))) out.push(F('bar', file, at, `${c.id}: GA needs a linux job`));
    if (c.limits) {
      const [page, anchor] = c.limits.split('#');
      if (!page || !anchor || !exists(repo, page)) out.push(F('bar', file, at, `${c.id}: limits must be an existing page#anchor, got "${c.limits}"`));
      else {
        const body = sectionByAnchor(fs.readFileSync(path.join(repo, page), 'utf8'), anchor);
        if (body === null) out.push(F('bar', file, at, `${c.id}: limits anchor #${anchor} is not a heading in ${page}`));
        else if (!VERIFIED_RE.test(body)) out.push(F('bar', file, at, `${c.id}: the section ${c.limits} has no <!-- limits-verified: YYYY-MM-DD --> marker`));
      }
    }
  }
  return out;
}

/** A GA limits section must have been re-read recently, measured against the checkout's own HEAD date so the result is stable. */
export function checkLimitsFreshness(reg, repo = REPO_DEFAULT, { headDate = null } = {}) {
  const out = [];
  const file = 'docs/capabilities.yaml';
  let head = headDate;
  if (!head) {
    const r = spawnSync('git', ['log', '-1', '--format=%cs'], { cwd: repo, encoding: 'utf8' });
    head = r.status === 0 ? r.stdout.trim() : null;
  }
  if (!head || !/^\d{4}-\d{2}-\d{2}$/.test(head)) return [F('limits', file, 0, 'cannot read the HEAD commit date, so limits freshness is unverified')];
  const headMs = Date.parse(head);
  for (const c of reg.capabilities.filter(x => x.maturity === 'GA' && x.limits)) {
    const d = limitsMarker(repo, c.limits);
    if (!d) continue;                                        // a missing marker is reported by checkGaBar
    const ms = Date.parse(d);
    if (Number.isNaN(ms)) out.push(F('limits', file, c._line, `${c.id}: limits-verified "${d}" is not a date`));
    else if (ms > headMs + 2 * 86400000) out.push(F('limits', file, c._line, `${c.id}: limits-verified ${d} is after the HEAD commit (${head})`));
    else if (headMs - ms > LIMITS_MAX_AGE_DAYS * 86400000) out.push(F('limits', file, c._line, `${c.id}: limits-verified ${d} is more than ${LIMITS_MAX_AGE_DAYS} days before HEAD (${head}); re-read ${c.limits} and update the date`));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** A check that throws is a failure, never a skip: an unreadable input must not read as a pass. */
function guarded(name, fn) {
  try { return fn(); } catch (e) { return [F(name, '(check)', 0, `the ${name} check could not run: ${e && e.message ? e.message : e}`)]; }
}

export function checkPositioningDocs(repo = REPO_DEFAULT, { write = false } = {}) {
  let reg;
  try { reg = loadRegistry(repo); } catch (e) { return [F('registry', 'docs/capabilities.yaml', 0, `cannot read registry: ${e.message}`)]; }
  const findings = [
    ...guarded('registry', () => validateRegistry(reg, repo)),
    ...guarded('bar', () => checkGaBar(reg, repo)),
    ...guarded('limits', () => checkLimitsFreshness(reg, repo)),
    ...guarded('structure', () => checkRequiredPages(repo)),
  ];
  if (exists(repo, 'README.md')) findings.push(...guarded('readme', () => checkReadmeHero(repo)));
  else findings.push(F('readme', 'README.md', 0, 'README.md is missing'));
  findings.push(...guarded('table', () => checkTables(reg, repo, { write })));
  findings.push(...guarded('consistency', () => checkMaturityConsistency(reg, repo)));
  findings.push(...guarded('overclaim', () => checkOverclaims(reg, repo)));
  findings.push(...guarded('command', () => checkCommands(repo)));
  findings.push(...guarded('lifecycle', () => checkLifecycleOrder(repo)));
  findings.push(...guarded('style', () => checkStyle(repo)));
  findings.push(...guarded('navigation', () => checkNavigation(repo)));
  findings.push(...guarded('link', () => checkLinks(repo)));
  findings.push(...guarded('visual', () => checkVisuals(repo)));
  return findings;
}

async function main() {
  const args = process.argv.slice(2);
  const write = args.includes('--write');
  const json = args.includes('--json');
  const rootIdx = args.indexOf('--root');
  const root = rootIdx >= 0 && args[rootIdx + 1] ? path.resolve(args[rootIdx + 1]) : REPO_DEFAULT;
  const findings = checkPositioningDocs(root, { write });
  if (json) { console.log(JSON.stringify(findings, null, 2)); process.exit(findings.length ? 1 : 0); }
  if (!findings.length) {
    const reg = loadRegistry(root);
    const n = renderCounts(reg);
    console.log(`positioning-docs: ok. ${reg.capabilities.length} capabilities (${MATURITIES.map(m => `${n[m]} ${m}`).join(', ')}); tables fresh; links, commands, lifecycle order and style clean.`);
    process.exit(0);
  }
  console.error(`positioning-docs: ${findings.length} finding(s):`);
  for (const f of findings) console.error(`  ${formatFinding(f)}`);
  process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
