#!/usr/bin/env node
// Mechanical doc-drift checker for CLAUDE.md files (Stage 6 correctness
// audit, item 4).
//
// WHY THIS EXISTS
// ----------------
// An earlier audit stage (Stage 0) hand-processed a 146-item doc-drift
// punch list — prose claims in CLAUDE.md files that had gone stale
// relative to the code — but only got through ~30 items before the
// session moved on, and the remaining enumeration was never persisted
// anywhere durable. It existed only in conversation context and was lost
// to compaction: "not recoverable from the transcript... I won't
// fabricate one."
//
// Rather than try to reconstruct that lost list from memory, this script
// regenerates the mechanically-checkable SUBSET of doc drift on demand —
// and, being a checked-in script rather than a one-time list, it can't be
// lost the same way again. It does not replace human judgment on prose
// claims ("X is default-on", "Y degrades gracefully") — those still need
// a real read. It catches the concrete, structural subset: a
// backtick-quoted file path that no longer exists, or a
// `file.js#exportedName` reference where the name is no longer exported
// from that file.
//
// SCOPE (deliberately narrow, to keep the false-positive rate low)
// ------------------------------------------------------------------
//   1. Backtick spans that look like a source file path (contains a `/`
//      or a recognized code extension) are resolved against several
//      plausible bases (repo root, the CLAUDE.md's own directory, one
//      level up) — a candidate is only reported if NONE of those resolve.
//   2. Backtick spans shaped `path/to/file.js#exportName` or
//      `path/to/file.js::exportName` additionally check that `exportName`
//      appears in the file as an `export function|const|class exportName`.
//      This only checks *presence* of the token, not that it's actually
//      the intended export (a name mentioned in a comment would still
//      pass) — deliberately permissive to avoid false positives on a
//      purely textual check.
//
// Skips code fences (own risk of false positives from example snippets),
// CLI flags (`--foo`), env vars (`$FOO`/`AGENTIC_SECURITY_*`), and bare
// words with no path-like shape.
//
// Usage:
//   node scripts/check-doc-drift.mjs               # human report, exit 0
//   node scripts/check-doc-drift.mjs --json         # machine-readable
//   node scripts/check-doc-drift.mjs --strict       # exit 1 if any found
//
// This is a LINT, not a release gate — wiring it into release-check.mjs
// would need a period of tuning against false positives first. Run it by
// hand or from a CI lint step.
'use strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

function findClaudeMdFiles(root) {
  const out = [];
  // .claude/worktrees and bench/*/cache hold OTHER repositories' own
  // CLAUDE.md files (agent worktree copies, real-world benchmark fixtures)
  // — not this project's documentation, and checking them against paths
  // resolved relative to THIS repo is meaningless noise.
  const skipDirs = new Set([
    'node_modules', '.git', '.bench-cache', 'dist', 'coverage', '.agentic-security',
    'worktrees', 'cache', 'polyglot', 'owasp-benchmark-v1.2', 'sard-juliet-java',
  ]);
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (skipDirs.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (e.isFile() && e.name === 'CLAUDE.md') out.push(full);
    }
  };
  walk(root);
  return out;
}

// Strip fenced code blocks (```...```) before scanning — example snippets
// inside them commonly contain non-existent illustrative paths/names.
function stripCodeFences(text) {
  return text.replace(/```[\s\S]*?```/g, (m) => m.replace(/[^\n]/g, ' '));
}

// Longest alternative first: `json` must precede `js` or the alternation
// matches the "js" prefix of "json" and leaves "on" to be misread as an
// export-name group (the exact class of bug documented for `find -regex`
// alternation — it bit this regex too).
const PATH_LIKE_RE = /`([A-Za-z0-9_.\/-]+\.(?:json|yaml|mjs|cjs|yml|js|ts|py|sh|md))(#|::)?([A-Za-z_][A-Za-z0-9_]*)?`/g;

// Paths this codebase's own CLAUDE.md files legitimately reference without
// claiming they exist in THIS repo: runtime state written into a SCANNED
// project (`.agentic-security/...`), and example manifest/config filenames
// the scanner recognizes by name in projects it scans (docker-compose.yml,
// composer.json, pnpm-lock.yaml, vcpkg.json, vcpkg-configuration.json,
// pubspec.yaml, internal-scopes.yml, sca-policy.yml). Checking these against
// this repo's own tree is a category error, not a drift signal.
const RUNTIME_OR_EXAMPLE_RE = /^\.agentic-security\//;
const KNOWN_EXAMPLE_BASENAMES = new Set([
  'docker-compose.yml', 'composer.json', 'pnpm-lock.yaml', 'vcpkg.json',
  'vcpkg-configuration.json', 'pubspec.yaml', 'internal-scopes.yml', 'sca-policy.yml',
  // Runtime state written into a SCANNED project (bare mentions without the
  // .agentic-security/ prefix RUNTIME_OR_EXAMPLE_RE already catches), and
  // example contract-artifact filenames the scanner recognizes in projects
  // it scans — neither is a source file in THIS repo.
  'last-scan.json', 'openapi.json',
  // Gitignored, user-created override file (root CLAUDE.md documents it as
  // exactly that: "Override locally via `.claude/settings.local.json`
  // (gitignored)"). It exists only on machines where someone created one —
  // never on a fresh checkout — so its absence is never drift.
  'settings.local.json',
]);

export function candidatesIn(text) {
  const out = [];
  let m;
  const re = new RegExp(PATH_LIKE_RE.source, 'g');
  while ((m = re.exec(text))) {
    const [, filePath, , exportName] = m;
    // Skip obvious non-file shapes that happen to match the extension
    // pattern: URLs, and CLI-flag-looking or env-var-looking tokens.
    if (filePath.startsWith('http') || filePath.startsWith('-') || filePath.startsWith('$')) continue;
    if (RUNTIME_OR_EXAMPLE_RE.test(filePath) || KNOWN_EXAMPLE_BASENAMES.has(path.basename(filePath))) continue;
    out.push({ filePath, exportName: exportName || null, index: m.index });
  }
  return out;
}

let _basenameIndex = null;
function basenameIndex(root) {
  if (_basenameIndex) return _basenameIndex;
  _basenameIndex = new Map();
  const skipDirs = new Set(['node_modules', '.git', '.bench-cache', 'dist', 'coverage', '.agentic-security', 'worktrees', 'cache']);
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (skipDirs.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile()) continue;
      if (!_basenameIndex.has(e.name)) _basenameIndex.set(e.name, []);
      _basenameIndex.get(e.name).push(full);
    }
  };
  walk(root);
  return _basenameIndex;
}

export function resolveCandidate(claudeMdPath, filePath) {
  const claudeDir = path.dirname(claudeMdPath);
  const bases = [
    REPO,
    claudeDir,
    path.resolve(claudeDir, '..'),
    path.resolve(claudeDir, '../..'),
    // `scanner/` is this repo's one large sub-package, and root CLAUDE.md's
    // own repository-layout table names paths relative to a row's own
    // "Path" column ("`scanner/` | ... Bundle at `dist/agentic-security.mjs`.")
    // rather than repeating the full prefix inline every time.
    path.resolve(REPO, 'scanner'),
  ];
  // Every accepted resolution must stay inside the repo. For a CLAUDE.md
  // near the repo root, "two levels up from its own directory" escapes the
  // checkout entirely — into a dev's home directory or a CI runner's work
  // root, both arbitrary and machine-dependent. That let this checker
  // resolve `.claude/settings.local.json` against the maintainer's own
  // machine-global `~/.claude/settings.local.json`, an unrelated file that
  // happens to share a name, passing locally and failing on a clean CI
  // checkout where no such coincidence exists.
  const isInsideRepo = (p) => p === REPO || p.startsWith(REPO + path.sep);
  for (const base of bases) {
    if (!isInsideRepo(base)) continue;
    const candidate = path.resolve(base, filePath);
    if (isInsideRepo(candidate) && fs.existsSync(candidate)) return candidate;
  }
  // Last resort: a partial path (e.g. `posture/finding-defaults.js`
  // mentioned from a doc several directories up) — search the whole repo
  // by basename+trailing-segment match. Accept a hit only when the
  // candidate's path ENDS with the referenced segments, so `foo/bar.js`
  // doesn't spuriously match an unrelated `other/foo/bar.js`.
  const idx = basenameIndex(REPO);
  const base = path.basename(filePath);
  const hits = idx.get(base) || [];
  const normalizedRef = filePath.replace(/\\/g, '/');
  const suffixMatch = hits.find((h) => h.replace(/\\/g, '/').endsWith('/' + normalizedRef) || h.replace(/\\/g, '/').endsWith(normalizedRef));
  if (suffixMatch) return suffixMatch;
  // Bare filename (no directory in the reference) with exactly one match
  // anywhere in the repo — low ambiguity, accept it.
  if (!filePath.includes('/') && hits.length === 1) return hits[0];
  return null;
}

export function exportExistsIn(resolvedPath, exportName) {
  let content;
  try { content = fs.readFileSync(resolvedPath, 'utf8'); } catch { return null; /* unreadable, can't judge */ }
  // Permissive textual presence check — see header for why.
  const re = new RegExp(`\\bexport\\s+(?:async\\s+)?(?:function|const|class)\\s+${exportName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
  if (re.test(content)) return true;
  // Also accept a bare mention anywhere (covers `_internals` re-exports,
  // `export { a, b }` list-style, and destructured imports elsewhere) —
  // deliberately permissive per the header's false-positive-avoidance goal.
  return content.includes(exportName);
}

function lineNumberAt(text, index) {
  return text.slice(0, index).split('\n').length;
}

export function checkFile(claudeMdPath) {
  const raw = fs.readFileSync(claudeMdPath, 'utf8');
  const scanned = stripCodeFences(raw);
  const findings = [];
  for (const c of candidatesIn(scanned)) {
    const resolved = resolveCandidate(claudeMdPath, c.filePath);
    const line = lineNumberAt(raw, c.index);
    if (!resolved) {
      findings.push({ file: claudeMdPath, line, kind: 'missing-path', ref: c.filePath });
      continue;
    }
    if (c.exportName) {
      const exists = exportExistsIn(resolved, c.exportName);
      if (exists === false) {
        findings.push({ file: claudeMdPath, line, kind: 'missing-export', ref: `${c.filePath}#${c.exportName}`, resolved: path.relative(REPO, resolved) });
      }
    }
  }
  return findings;
}

function main() {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');
  const strict = args.includes('--strict');

  const files = findClaudeMdFiles(REPO);
  const allFindings = [];
  for (const f of files) allFindings.push(...checkFile(f));

  if (asJson) {
    console.log(JSON.stringify({ scanned: files.length, findings: allFindings }, null, 2));
  } else {
    console.log(`Scanned ${files.length} CLAUDE.md file(s).`);
    if (!allFindings.length) {
      console.log('No mechanically-checkable drift found (missing paths / missing exports).');
      console.log('Note: this only catches structural drift — prose claims about behavior still need a human read.');
    } else {
      console.log(`${allFindings.length} possible drift item(s):\n`);
      for (const f of allFindings) {
        const rel = path.relative(REPO, f.file);
        if (f.kind === 'missing-path') {
          console.log(`  ${rel}:${f.line}  references \`${f.ref}\` — no file found at any plausible base path`);
        } else {
          console.log(`  ${rel}:${f.line}  references \`${f.ref}\` — ${f.resolved} exists but does not export/mention "${f.ref.split(/[#:]/).pop()}"`);
        }
      }
    }
  }

  if (strict && allFindings.length) process.exit(1);
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
