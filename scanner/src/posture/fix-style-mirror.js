// Fix style mirror — find existing fix patterns in the repo for the
// security-fixer agent to mirror, so remediation matches house style
// rather than producing canned generic replacements.
//
// Strategy: for a given finding (family + file), look at sibling files
// in the same directory tree for instances of the canonical safe pattern
// for that family (e.g. parameterized queries for sqli). Return up to 5
// real examples the agent can reference.
//
// Cheap implementation — grep-style search via fs.readdirSync. No regex
// engine deps. v1 covers the canonical fix patterns for the 8 most-
// common families.

import * as fs from 'node:fs';
import * as path from 'node:path';

const SAFE_PATTERNS = {
  'sqli':              ['\\.query\\([^,)]+,\\s*\\[', '\\.prepare\\(', '\\.execute\\([^,)]+,\\s*\\['],
  'sql-injection':     ['\\.query\\([^,)]+,\\s*\\[', '\\.prepare\\(', '\\.execute\\([^,)]+,\\s*\\['],
  'xss':               ['escapeHtml\\(', 'sanitize\\(', 'DOMPurify\\.', '\\bencodeHTML\\b'],
  'command-injection': ['\\bexecFile\\(', '\\bspawn\\([^,)]+,\\s*\\['],
  'path-traversal':    ['path\\.resolve\\(', 'path\\.normalize\\(', 'startsWith\\(.*path\\.sep'],
  'ssrf':              ['allowlist\\.includes\\(', 'url\\.hostname'],
  'crypto-weak-cipher':['createCipheriv\\(\\s*[\'"`]aes-256-gcm', 'createCipheriv\\(\\s*[\'"`]chacha20'],
  'crypto-weak-hash':  ['createHash\\(\\s*[\'"`]sha-?256', 'createHash\\(\\s*[\'"`]sha-?512', 'createHash\\(\\s*[\'"`]blake'],
  'hardcoded-secret':  ['process\\.env\\.[A-Z_]+', 'config\\.[a-z_]+'],
};

const SKIP_DIRS = new Set(['node_modules', '.git', '.bench-cache', 'dist', 'build', 'coverage', '.next']);
const MAX_FILES = 200;
const MAX_EXAMPLES = 5;
const MAX_FILE_SIZE = 100_000;

function _siblings(scanRoot, file, maxDepth = 3) {
  if (!file) return [];
  const abs = path.isAbsolute(file) ? file : path.join(scanRoot, file);
  const baseDir = path.dirname(abs);
  // Walk upward maxDepth levels and collect files of the same extension.
  const ext = path.extname(abs);
  if (!ext) return [];
  const candidates = [];
  let cur = baseDir;
  for (let d = 0; d < maxDepth; d++) {
    if (!fs.existsSync(cur)) break;
    _walkUp(cur, ext, candidates);
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return candidates.slice(0, MAX_FILES).filter(p => p !== abs);
}

function _walkUp(dir, ext, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      // Stop one level deep here; outer loop walks upward.
      try {
        const childEntries = fs.readdirSync(p, { withFileTypes: true });
        for (const ce of childEntries) {
          if (ce.isFile() && ce.name.endsWith(ext)) {
            out.push(path.join(p, ce.name));
            if (out.length >= MAX_FILES) return;
          }
        }
      } catch {}
      continue;
    }
    if (e.isFile() && e.name.endsWith(ext)) {
      out.push(p);
      if (out.length >= MAX_FILES) return;
    }
  }
}

/**
 * Returns up to 5 style-mirror examples for a finding's family. Each
 * example is `{ file, line, snippet }`. The agent can quote these as
 * "here's how this codebase already does it."
 */
export function findStyleExamples(scanRoot, finding) {
  if (!finding || !finding.family) return [];
  const patterns = SAFE_PATTERNS[finding.family] ||
                   SAFE_PATTERNS[String(finding.family).toLowerCase()] || null;
  if (!patterns) return [];
  const files = _siblings(scanRoot, finding.file || '');
  const examples = [];
  const patternRes = patterns.map(p => new RegExp(p));

  for (const fp of files) {
    if (examples.length >= MAX_EXAMPLES) break;
    let content;
    try {
      const stat = fs.statSync(fp);
      if (stat.size > MAX_FILE_SIZE) continue;
      content = fs.readFileSync(fp, 'utf8');
    } catch { continue; }
    for (const re of patternRes) {
      const m = re.exec(content);
      if (!m) continue;
      const line = content.slice(0, m.index).split('\n').length;
      const lines = content.split('\n');
      const snippet = lines.slice(Math.max(0, line - 2), Math.min(lines.length, line + 1)).join('\n').trim();
      examples.push({
        file: path.relative(scanRoot, fp),
        line,
        snippet: snippet.slice(0, 240),
      });
      break;
    }
  }
  return examples;
}

export const _internals = { SAFE_PATTERNS, _siblings };
