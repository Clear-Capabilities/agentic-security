#!/usr/bin/env node
// Doc-example verification (documentation-overhaul plan, Task 14).
//
// WHY THIS EXISTS
// ----------------
// `scripts/check-doc-drift.mjs` catches structural drift in CLAUDE.md files
// and dangling markdown links. It does NOT check whether the *content*
// inside a fenced code block is actually correct: a `agentic-security scan
// --help` example that silently runs a real scan instead of printing help
// (per-subcommand `--help` is not implemented anywhere in this CLI — only
// bare `agentic-security help` is), a `\`\`\`json` block that doesn't parse,
// or a `\`\`\`mermaid` block with unbalanced brackets. This script is that
// missing half, scoped to the user-facing docs surface this project ships
// to users (not spec/plan narrative, not historical PRD reports, not
// generated state).
//
// Imports `checkAllLinks()` from `check-doc-drift.mjs` directly rather than
// reimplementing link-checking — its findings are filtered down to this
// script's own in-scope doc set and folded into this script's own report,
// so one `npm run docs:verify-examples` covers dangling links *and* the
// three new checks below for the docs this plan touches (link-checking
// across the FULL docs/** tree remains `check-doc-drift.mjs --gate`'s job
// as a release gate; this is a narrower, informational re-use of it).
//
// Does NOT reuse `exportExistsIn()`'s literal "bare substring anywhere in
// the file" check for CLI commands — that check is deliberately permissive
// (designed for prose mentions of exported names, see that file's own
// header) and would be close to useless here: common words like `scan` or
// `export` appear as substrings throughout bin/agentic-security.js
// regardless of whether they're real subcommands. Instead,
// `parseCommandTable()` below parses the actual `switch (cmd) { case
// '...': }` dispatch table (and each subcommand-routing handler's own
// `args._[1]` comparisons) out of the real source, so the command list
// can't silently drift out of sync the way a hand-maintained list would.
//
// SCOPE (pre-adjudicated ruling, SDD ledger 2026-09-03-documentation-overhaul)
// ------------------------------------------------------------------------
// README.md, docs/walkthroughs/, docs/governance/, docs/troubleshooting/,
// docs/examples/, docs/reference/, docs/architecture/, docs/concepts.md,
// docs/guides/, docs/ARCHITECTURE.md, docs/README.md — i.e. the docs tree
// this plan actually touches. Deliberately EXCLUDES docs/superpowers/
// (spec/plan narrative, not product docs), docs/implementation/
// (historical PRD reports — narrate what was decided, not live
// instructions), docs/.agentic-security/ (generated runtime state — see
// root CLAUDE.md's own note on this), and docs/standards/ (raw upstream
// material, never read at runtime). Everything else under docs/
// (docs/compliance/, docs/lineage/, docs/schemas/, top-level docs like
// docs/METRICS.md, docs/OSCAL.md, ...) is out of scope for THIS script by
// the same ruling — narrower than check-doc-drift.mjs's own broader
// `docs/**` link-check scope, and deliberately so.
//
// THREE CHECKS
// ------------
//   1. CLI-invocation validity — every `agentic-security <...>` or
//      `npx @clear-capabilities/agentic-security-scanner <...>` invocation
//      inside a fenced ```bash / ```text block is checked against the
//      real command dispatch table in bin/agentic-security.js, parsed
//      from the source (not hand-duplicated, so it can't silently drift):
//        - unknown top-level command  -> error
//        - unknown second-level subcommand (for the handful of commands
//          that route on args._[1], e.g. `dataflow export`, `rules
//          validate`, `legal-hold add`) -> error
//        - a `--help` (or bare `-h`) token following a real subcommand
//          -> error, ALWAYS, regardless of whether the subcommand/flags
//          are otherwise valid. This is the landmine: per-subcommand
//          --help is not wired to anything in this CLI's parseArgs/switch,
//          so `agentic-security scan --help` silently runs a real scan.
//          Only bare `agentic-security help` (or `--help`/`-h` with no
//          preceding subcommand) is valid.
//   2. JSON validity — every fenced ```json block must `JSON.parse`.
//   3. Mermaid syntax sanity — every fenced ```mermaid block (and any
//      `<pre class="mermaid">` block, in case a doc ever uses that form
//      instead — docs/ARCHITECTURE.md does not, as of this writing, but
//      the brief asked this to be checked rather than assumed) gets a
//      lightweight syntax sanity pass: balanced ()/[]/{}, balanced quotes,
//      balanced `|...|` edge-label pipes, and a recognized diagram-type
//      keyword on the first content line. This is NOT a real render — a
//      real `mermaid-cli` render was confirmed non-functional in this
//      sandbox (Chromium launch fails), so this is intentionally shallow.
//
// NOT wired into `.githooks/` or the pre-push gate — standalone
// `npm run docs:verify-examples` only, per the plan's explicit constraint.
'use strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAllLinks } from './check-doc-drift.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const BIN_PATH = path.join(REPO, 'scanner/bin/agentic-security.js');

// ---------------------------------------------------------------------------
// Scope: the exact in-scope doc set (pre-adjudicated ruling — see header)
// ---------------------------------------------------------------------------

const IN_SCOPE_ROOTS = [
  'README.md',
  'docs/walkthroughs',
  'docs/governance',
  'docs/troubleshooting',
  'docs/examples',
  'docs/reference',
  'docs/architecture',
  'docs/concepts.md',
  'docs/guides',
  'docs/ARCHITECTURE.md',
  'docs/README.md',
];

// Never descend into generated runtime state, even if it somehow ends up
// tracked — see root CLAUDE.md's `.agentic-security/` note. Also skip the
// usual noise dirs defensively (none of the roots above should contain
// them, but a directory root is walked recursively).
const SKIP_DIRS = new Set(['node_modules', '.git', '.agentic-security', 'dist', 'coverage']);

export function findInScopeDocs(repo = REPO) {
  const out = [];
  for (const rel of IN_SCOPE_ROOTS) {
    const full = path.join(repo, rel);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.isFile()) {
      if (full.endsWith('.md')) out.push(full);
      continue;
    }
    const walk = (dir) => {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (e.isDirectory()) {
          if (SKIP_DIRS.has(e.name)) continue;
          walk(path.join(dir, e.name));
          continue;
        }
        if (e.isFile() && e.name.endsWith('.md')) out.push(path.join(dir, e.name));
      }
    };
    walk(full);
  }
  return out.sort();
}

function lineNumberAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

// ---------------------------------------------------------------------------
// Fenced-block extraction
// ---------------------------------------------------------------------------

// Matches a fenced code block: ```lang\n...content...\n```
// Non-greedy content match; `lang` may be empty.
const FENCE_RE = /```([\w+-]*)\r?\n([\s\S]*?)\r?\n```/g;
const PRE_MERMAID_RE = /<pre class="mermaid">([\s\S]*?)<\/pre>/g;

export function extractFences(text) {
  const out = [];
  const re = new RegExp(FENCE_RE.source, 'g');
  let m;
  while ((m = re.exec(text))) {
    out.push({ lang: m[1].toLowerCase(), content: m[2], index: m.index });
  }
  return out;
}

function unescapeHtmlEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

export function extractPreMermaidBlocks(text) {
  const out = [];
  const re = new RegExp(PRE_MERMAID_RE.source, 'g');
  let m;
  while ((m = re.exec(text))) {
    out.push({ content: unescapeHtmlEntities(m[1]), index: m.index });
  }
  return out;
}

// ---------------------------------------------------------------------------
// CLI command dispatch table — parsed from bin/agentic-security.js itself
// ---------------------------------------------------------------------------
//
// Rather than hand-maintain a second copy of the command list (which is
// exactly the kind of doc/reality gap this whole plan exists to close),
// this reflects the actual `switch (cmd) { case '...': ... }` in main(),
// plus the `const sub = args._[1]; if (sub === '...')` pattern each
// subcommand-routing command uses internally (either inline in the switch
// arm, e.g. `dataflow`/`governance`/`federate`/`remediation`, or inside
// its own `cmdXxx(args)` handler, e.g. `profile`/`rules`/`triage`/...).
//
// A command with an EMPTY subcommand set means "no second-level routing
// found" — the second token, if any, is a path/id/flag-value, not a
// subcommand, and is not validated. This is deliberately conservative: it
// only flags a second token as wrong when the source proves a closed set
// of valid values exists.

function extractFunctionBody(fullText, functionName) {
  const declRe = new RegExp(`(?:async\\s+)?function\\s+${functionName}\\b\\s*\\(args\\)\\s*\\{`);
  const m = declRe.exec(fullText);
  if (!m) return null;
  let depth = 1;
  let i = m.index + m[0].length;
  const start = i;
  for (; i < fullText.length && depth > 0; i++) {
    const c = fullText[i];
    if (c === '{') depth++;
    else if (c === '}') depth--;
  }
  if (depth !== 0) return null; // unbalanced — bail rather than mis-slice
  return fullText.slice(start, i - 1);
}

// All `varName === 'literal'` comparisons for one specific variable name —
// used both for the generic single-level extraction and (given a
// deeper-nesting variable name like `scenarioSub`) for dataflow's
// third level. Variable names for each nesting depth are distinct by
// construction in this file (scenarioSub/impactSub/obsSub each only
// appear inside their own branch), so a plain global match is already
// correctly scoped without needing brace-based branch isolation.
function subcommandsForVar(text, varName) {
  const re = new RegExp(`\\b${varName}\\s*===\\s*'([A-Za-z0-9_-]+)'`, 'g');
  const out = new Set();
  let m;
  while ((m = re.exec(text))) out.add(m[1]);
  return out;
}

function firstLevel1Var(text) {
  const m = /(?:const|let)\s+(\w+)\s*=\s*args\._\[1\]/.exec(text);
  return m ? m[1] : null;
}

export function parseCommandTable(binPath = BIN_PATH) {
  const fullText = fs.readFileSync(binPath, 'utf8');
  const switchStart = fullText.indexOf('switch (cmd) {');
  if (switchStart < 0) throw new Error('parseCommandTable: could not find "switch (cmd) {" in ' + binPath);
  const switchText = fullText.slice(switchStart);

  // Every `case '<name>':` or `default:` boundary, in source order — used
  // to slice out each arm's own text (arms never contain a nested `case`
  // keyword in this file; subcommand routing inside an arm uses
  // `if (sub === ...)`, not a nested switch).
  const boundaryRe = /case\s+'([\w-]+)'\s*:|default\s*:/g;
  const boundaries = [];
  let bm;
  while ((bm = boundaryRe.exec(switchText))) {
    boundaries.push({ name: bm[1] || null, index: bm.index });
  }

  const table = new Map(); // name -> { subcommands: Set, level3: Map<sub, Set> }
  for (let i = 0; i < boundaries.length; i++) {
    const b = boundaries[i];
    if (!b.name) continue; // the `default:` boundary itself
    if (['help', '--help', '-h'].includes(b.name)) continue; // not real commands
    const armEnd = i + 1 < boundaries.length ? boundaries[i + 1].index : switchText.length;
    const armText = switchText.slice(b.index, armEnd);

    // Only substitute in a called function's body when the ENTIRE arm is
    // nothing but that one delegation (`case 'x': process.exit(await
    // cmdX(args));`) — an inline block (`case 'x': { ... }`, used by
    // dataflow/governance/federate/remediation for their own args._[1]
    // routing) may ALSO contain a `process.exit(await cmdY(args))` call
    // nested inside one branch, and blindly matching the first such call
    // anywhere in the arm would replace the arm's own routing logic with
    // an unrelated leaf function's body, silently emptying the subcommand
    // set. Anchoring the match to the whole (trimmed) arm avoids that.
    let bodyText = armText;
    const simpleMatch = /^case\s+'[\w-]+'\s*:\s*process\.exit\(await (cmd\w+)\(args\)\);?\s*$/.exec(armText.trim());
    if (simpleMatch) {
      const fnBody = extractFunctionBody(fullText, simpleMatch[1]);
      if (fnBody != null) bodyText = fnBody;
    }

    const level1Var = firstLevel1Var(bodyText);
    const subcommands = level1Var ? subcommandsForVar(bodyText, level1Var) : new Set();

    const level3 = new Map();
    if (b.name === 'dataflow') {
      // Known deeper dispatchers, per the source's own `scenarioSub` /
      // `impactSub` / `obsSub` names — see cmdDataflow* arm comments.
      for (const [parent, varName] of [['scenario', 'scenarioSub'], ['impact', 'impactSub'], ['observations', 'obsSub']]) {
        const set = subcommandsForVar(bodyText, varName);
        if (set.size) level3.set(parent, set);
      }
    }

    table.set(b.name, { subcommands, level3 });
  }
  return table;
}

// ---------------------------------------------------------------------------
// Check 1: CLI-invocation validity
// ---------------------------------------------------------------------------

const TRIGGER_RE = /(?:^|[\s;&|`(])(?:agentic-security|npx(?:\s+-y)?\s+@clear-capabilities\/agentic-security-scanner)(?=\s|$)/g;

function tokenize(rest) {
  const noComment = rest.replace(/(^|\s)#.*$/, '');
  return noComment.match(/"[^"]*"|'[^']*'|\S+/g) || [];
}

export function checkCliInvocations(content, commandTable) {
  const findings = [];
  const lines = content.split('\n');
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const triggerRe = new RegExp(TRIGGER_RE.source, 'g');
    let m;
    while ((m = triggerRe.exec(line))) {
      const rest = line.slice(m.index + m[0].length);
      const tokens = tokenize(rest);
      if (!tokens.length) continue; // bare `agentic-security` — prints usage, not an error

      const t0 = tokens[0];
      if (t0 === '--help' || t0 === '-h' || t0 === 'help') continue; // bare help — valid

      if (t0.startsWith('-')) continue; // e.g. `agentic-security --version`-shaped; out of scope for this check

      // A trailing colon means this isn't an invocation at all — it's a
      // ```text block showing example OUTPUT in the tool's own
      // "<command>: <message>" log-line style (e.g. `agentic-security
      // explore: serving /path` — the server's own startup banner, not
      // something a reader types). Real command words never carry a
      // trailing colon.
      if (t0.endsWith(':')) continue;

      const cmdName = t0;
      const entry = commandTable.get(cmdName);
      if (!entry) {
        findings.push({ line: li + 1, kind: 'unknown-command', ref: cmdName, invocation: line.trim() });
        continue;
      }

      // The landmine: `--help`/`-h` anywhere after a real subcommand.
      const rest1 = tokens.slice(1);
      if (rest1.some((t) => t === '--help' || t === '-h')) {
        findings.push({ line: li + 1, kind: 'subcommand-help-landmine', ref: `${cmdName} --help`, invocation: line.trim() });
        continue; // don't also report subcommand-name findings for the same line
      }

      if (entry.subcommands.size && tokens[1] && !tokens[1].startsWith('-')) {
        const sub = tokens[1];
        if (!entry.subcommands.has(sub)) {
          findings.push({ line: li + 1, kind: 'unknown-subcommand', ref: `${cmdName} ${sub}`, invocation: line.trim() });
          continue;
        }
        const level3 = entry.level3.get(sub);
        if (level3 && level3.size && tokens[2] && !tokens[2].startsWith('-')) {
          const sub2 = tokens[2];
          if (!level3.has(sub2)) {
            findings.push({ line: li + 1, kind: 'unknown-subcommand', ref: `${cmdName} ${sub} ${sub2}`, invocation: line.trim() });
          }
        }
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check 2: JSON validity
// ---------------------------------------------------------------------------

export function checkJsonBlock(content) {
  try {
    JSON.parse(content);
    return null;
  } catch (wholeBlockErr) {
    // NDJSON fallback: some docs legitimately show a hash-chained audit
    // log (one JSON object per line, e.g. docs/walkthroughs/model-egress.md's
    // egress-audit.log excerpt) inside a ```json fence — a real,
    // documented on-disk format in this repo, not a mistake. The whole
    // block is not one JSON *document*, but each line is independently
    // valid JSON. Only accept this fallback when there's more than one
    // non-empty line (a single malformed line should still fail as
    // itself, via the original whole-block error).
    const lines = content.split('\n').map((l) => l.trim()).filter(Boolean);
    if (lines.length > 1) {
      const allLinesParse = lines.every((l) => {
        try { JSON.parse(l); return true; } catch { return false; }
      });
      if (allLinesParse) return null;
    }
    return wholeBlockErr.message;
  }
}

// ---------------------------------------------------------------------------
// Check 3: Mermaid syntax sanity (not a real render — see header)
// ---------------------------------------------------------------------------

const MERMAID_KEYWORDS = [
  'flowchart', 'graph', 'sequenceDiagram', 'classDiagram', 'classDiagram-v2',
  'stateDiagram', 'stateDiagram-v2', 'erDiagram', 'journey', 'gantt', 'pie',
  'quadrantChart', 'requirementDiagram', 'gitGraph', 'mindmap', 'timeline',
  'sankey-beta', 'block-beta', 'C4Context', 'C4Container', 'C4Component',
  'C4Dynamic', 'C4Deployment', 'xychart-beta', 'packet-beta', 'kanban',
  'architecture-beta', 'zenuml',
];
const MERMAID_KEYWORD_RE = new RegExp('^(' + MERMAID_KEYWORDS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')\\b');

function countChar(s, ch) {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

export function checkMermaidBlock(content) {
  const errors = [];
  const trimmed = content.trim();
  const firstLine = trimmed.split('\n')[0]?.trim() || '';
  if (!MERMAID_KEYWORD_RE.test(firstLine)) {
    errors.push(`first content line "${firstLine}" does not start with a recognized diagram-type keyword`);
  }
  const pairs = [['(', ')'], ['[', ']'], ['{', '}']];
  for (const [open, close] of pairs) {
    const o = countChar(trimmed, open);
    const c = countChar(trimmed, close);
    if (o !== c) errors.push(`unbalanced "${open}" / "${close}" (${o} vs ${c})`);
  }
  const quotes = countChar(trimmed, '"');
  if (quotes % 2 !== 0) errors.push(`unbalanced quotes (${quotes} double-quote chars)`);
  const pipes = countChar(trimmed, '|');
  if (pipes % 2 !== 0) errors.push(`unbalanced "|" edge-label delimiters (${pipes} pipe chars)`);
  return errors;
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

export function verifyDocExamples(repo = REPO) {
  const commandTable = parseCommandTable(path.join(repo, 'scanner/bin/agentic-security.js'));
  const docs = findInScopeDocs(repo);
  const docSet = new Set(docs);
  const findings = [];
  let fenceCounts = { bash: 0, json: 0, mermaid: 0 };

  // Link integrity, scoped down to this script's own in-scope doc set —
  // reuses check-doc-drift.mjs's link checker rather than reimplementing
  // it (see header). `check-doc-drift.mjs --gate` remains the release
  // gate covering the full docs/** tree; this is a narrower, additive view.
  for (const l of checkAllLinks(repo)) {
    if (!docSet.has(l.file)) continue;
    findings.push({ file: path.relative(repo, l.file), line: l.line, kind: 'dangling-link', ref: l.ref });
  }

  for (const docPath of docs) {
    const raw = fs.readFileSync(docPath, 'utf8');
    const rel = path.relative(repo, docPath);

    for (const fence of extractFences(raw)) {
      const line = lineNumberAt(raw, fence.index);
      if (fence.lang === 'bash' || fence.lang === 'text') {
        fenceCounts.bash++;
        for (const f of checkCliInvocations(fence.content, commandTable)) {
          findings.push({ file: rel, line: line + f.line, kind: f.kind, ref: f.ref, invocation: f.invocation });
        }
      } else if (fence.lang === 'json') {
        fenceCounts.json++;
        const err = checkJsonBlock(fence.content);
        if (err) findings.push({ file: rel, line, kind: 'invalid-json', ref: err });
      } else if (fence.lang === 'mermaid') {
        fenceCounts.mermaid++;
        const errs = checkMermaidBlock(fence.content);
        for (const e of errs) findings.push({ file: rel, line, kind: 'mermaid-syntax', ref: e });
      }
    }

    for (const pre of extractPreMermaidBlocks(raw)) {
      fenceCounts.mermaid++;
      const line = lineNumberAt(raw, pre.index);
      const errs = checkMermaidBlock(pre.content);
      for (const e of errs) findings.push({ file: rel, line, kind: 'mermaid-syntax', ref: e });
    }
  }

  return { scannedFiles: docs.length, fenceCounts, findings };
}

function main() {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');

  const result = verifyDocExamples(REPO);

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Scanned ${result.scannedFiles} in-scope doc file(s): ${result.fenceCounts.bash} bash/text fence(s), ${result.fenceCounts.json} json fence(s), ${result.fenceCounts.mermaid} mermaid block(s).`);
    if (!result.findings.length) {
      console.log('No issues found: all links resolve, all CLI invocations resolve to real commands (no --help landmine), all JSON blocks parse, all Mermaid blocks pass the syntax sanity check.');
    } else {
      console.log(`${result.findings.length} issue(s):\n`);
      for (const f of result.findings) {
        if (f.kind === 'subcommand-help-landmine') {
          console.log(`  ${f.file}:${f.line}  LANDMINE: "${f.ref}" does not print help — per-subcommand --help silently runs the real command. Only bare "agentic-security help" is valid.\n    > ${f.invocation}`);
        } else if (f.kind === 'unknown-command') {
          console.log(`  ${f.file}:${f.line}  unknown command "${f.ref}"\n    > ${f.invocation}`);
        } else if (f.kind === 'unknown-subcommand') {
          console.log(`  ${f.file}:${f.line}  unknown subcommand "${f.ref}"\n    > ${f.invocation}`);
        } else if (f.kind === 'invalid-json') {
          console.log(`  ${f.file}:${f.line}  invalid JSON: ${f.ref}`);
        } else if (f.kind === 'mermaid-syntax') {
          console.log(`  ${f.file}:${f.line}  mermaid: ${f.ref}`);
        } else if (f.kind === 'dangling-link') {
          console.log(`  ${f.file}:${f.line}  dangling link → ${f.ref}`);
        }
      }
    }
  }

  process.exit(result.findings.length ? 1 : 0);
}

if (import.meta.main ?? (import.meta.url === `file://${process.argv[1]}`)) {
  main();
}
