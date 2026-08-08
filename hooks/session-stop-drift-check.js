#!/usr/bin/env node
// Stop hook: at session end, diff the working tree against HEAD and surface
// any new modules under scanner/src/{sast,posture,dataflow,discovery}/ that
// aren't yet mentioned in the relevant subdir CLAUDE.md.
//
// The point isn't to block the session — it's to prevent the "ship a module,
// forget to index it" failure that the dead-modules guard only catches at
// `npm test` time. Surfaces a one-line nudge that Claude can choose to act on
// in the next turn or relay to the user.
//
// Output: stderr only. Exits 0 always so Stop hook chaining isn't disrupted.
'use strict';
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    if (process.stdin.isTTY) return resolve({});
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    // Hard cap — Stop hooks must be fast.
    setTimeout(() => resolve({}), 800);
  });
}

const WATCHED = [
  // [dir-prefix, where the subdir CLAUDE.md lives]
  ['scanner/src/sast/',     'scanner/src/sast/CLAUDE.md'],
  ['scanner/src/posture/',  'scanner/src/posture/CLAUDE.md'],
  ['scanner/src/dataflow/', 'scanner/src/dataflow/CLAUDE.md'],
  ['scanner/src/mcp/',      'scanner/src/mcp/CLAUDE.md'],
  ['scanner/src/discovery/', 'scanner/src/discovery/CLAUDE.md'],
];

function gitNewFiles() {
  try {
    // -A = staged + unstaged; --diff-filter=A = newly added
    const out = cp.execFileSync('git', ['status', '--porcelain', '-uall'], {
      cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 1500,
    });
    const files = [];
    for (const line of out.split('\n')) {
      const status = line.slice(0, 2);
      const p = line.slice(3).trim();
      if (!p) continue;
      // Newly tracked (A) or untracked (??) — both are "added in this session-ish"
      if (status.startsWith('A') || status === '??') files.push(p);
    }
    return files;
  } catch { return []; }
}

function isIndexed(claudeMdPath, basename) {
  const abs = path.join(cwd, claudeMdPath);
  if (!fs.existsSync(abs)) return false;
  try {
    const body = fs.readFileSync(abs, 'utf8');
    // Match the bare module name (no extension) OR the basename.
    const stem = basename.replace(/\.[^.]+$/, '');
    return body.includes(basename) || body.includes(stem);
  } catch { return false; }
}

(async () => {
  await readStdinJSON(); // consume stdin so the parent doesn't hang
  const added = gitNewFiles();
  if (added.length === 0) { process.exit(0); }
  const warnings = [];
  for (const f of added) {
    if (!f.endsWith('.js')) continue;
    if (f.includes('/test/') || f.endsWith('.test.js')) continue;
    if (f.includes('/fixtures/')) continue;
    for (const [prefix, claudeMd] of WATCHED) {
      if (f.startsWith(prefix)) {
        const basename = path.basename(f);
        if (!isIndexed(claudeMd, basename)) {
          warnings.push(`  · ${f}  →  add a one-line entry in ${claudeMd}`);
        }
        break;
      }
    }
  }
  if (warnings.length) {
    process.stderr.write(`agentic-security: CLAUDE.md drift — ${warnings.length} new module(s) not yet indexed:\n`);
    process.stderr.write(warnings.join('\n') + '\n');
    process.stderr.write(`  (Stop-hook warning only; not blocking. See "Recent hardening" in CLAUDE.md.)\n`);
  }

  // Harness-anatomy #2: nudge the agent to record a continual-learning entry
  // in AGENTS.md before exit. We reuse the same filter as the drift check
  // (skip test files, fixtures) so the two hooks share a definition of
  // "the agent did real work." Quiet when there is no real work — the
  // existing Stop-hook tests rely on silence in those cases.
  try {
    const trackedDirs = ['scanner/src/', 'commands/', 'agents/', 'hooks/', 'bench/'];
    const touched = added.filter(f => {
      if (!f.endsWith('.js')) return false;          // same filter as drift check
      if (!trackedDirs.some(d => f.startsWith(d))) return false;
      if (f.includes('/test/') || f.endsWith('.test.js')) return false;
      if (f.includes('/fixtures/')) return false;
      return true;
    });
    const mdPath = path.join(cwd, '.agentic-security', 'AGENTS.md');
    const mdExists = fs.existsSync(mdPath);
    const mdMtime = mdExists ? fs.statSync(mdPath).mtimeMs : 0;
    const recentlyAppended = (Date.now() - mdMtime) < 5 * 60 * 1000;
    if (touched.length && !recentlyAppended) {
      process.stderr.write(`agentic-security: this session touched ${touched.length} tracked file(s) but didn't append to .agentic-security/AGENTS.md.\n`);
      process.stderr.write(`  Consider calling MCP tool append_agents_memory({ agent: "<name>", body: "<what worked / didn't work / what next>" }).\n`);
      process.stderr.write(`  AGENTS.md is the continual-learning surface — next session reads it on start.\n`);
    }
  } catch { /* nudge failure is non-fatal */ }
  process.exit(0);
})();
