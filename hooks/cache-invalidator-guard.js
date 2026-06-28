#!/usr/bin/env node
// PreToolUse(Edit|Write) hook: warn before an edit that silently invalidates the
// prompt cache.
//
// Editing a "cache anchor" — CLAUDE.md (injected into the system context) or a
// .claude/settings*.json (changes hooks/tools/permissions) — changes the cached
// prefix, so the NEXT turn re-ingests the whole conversation cold instead of
// reading it from cache (~0.1×). Deep into a session that can cost real money.
// This hook flags it with the estimated re-warm cost so the user can choose to
// batch the edit at a natural break.
//
// Advisory only: warns to stderr, never blocks, always exits 0. Silenced by
// AGENTIC_SECURITY_QUIET=1; disabled by AGENTIC_SECURITY_CACHE_GUARD=off.
// Throttled per file so rapid re-edits don't spam.
//
// Plain CommonJS — zero deps beyond the standard library + hooks/lib/transcript.
'use strict';
const fs = require('fs');
const path = require('path');
const { latest } = require('./lib/transcript.js');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const throttlePath = path.join(stateDir, 'hook-throttle.json');

const THROTTLE_MS = 30000;       // don't re-warn about the same anchor within 30s
const MIN_WARM_TOKENS = 5000;    // below this the cache isn't worth protecting
const CACHE_READ_MULT = 0.1;
const IN_RATE = { haiku: 1, sonnet: 3, opus: 5 }; // $/1M input

function readStdinJSON() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve({});
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    setTimeout(() => resolve({}), 500).unref?.();
  });
}

// Is `file` a prompt-cache anchor? (basename CLAUDE.md, or a .claude/settings*.json)
function isCacheAnchor(file) {
  if (typeof file !== 'string' || !file) return null;
  const norm = file.replace(/\\/g, '/');
  const base = norm.split('/').pop();
  if (base === 'CLAUDE.md') return 'CLAUDE.md (project context / system prompt)';
  if (/\.claude\/settings(\.[\w.-]+)?\.json$/.test(norm)) return 'Claude Code settings (hooks / tools / permissions)';
  return null;
}

function inRateFor(model) {
  const s = String(model || '').toLowerCase();
  if (s.includes('haiku')) return IN_RATE.haiku;
  if (s.includes('sonnet')) return IN_RATE.sonnet;
  if (s.includes('opus')) return IN_RATE.opus;
  return IN_RATE.opus; // unknown → assume the priciest input (conservative warning)
}

function throttled(key) {
  try {
    const t = JSON.parse(fs.readFileSync(throttlePath, 'utf8'));
    const now = Date.now();
    if (now - (t[key] || 0) < THROTTLE_MS) return true;
    t[key] = now;
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(throttlePath, JSON.stringify(t));
    return false;
  } catch {
    try {
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(throttlePath, JSON.stringify({ [key]: Date.now() }));
    } catch {}
    return false;
  }
}

function money(n) { return Math.abs(n) >= 1 ? `$${n.toFixed(2)}` : `$${n.toFixed(4)}`; }

(async () => {
  if (process.env.AGENTIC_SECURITY_CACHE_GUARD === 'off') process.exit(0);
  if (process.env.AGENTIC_SECURITY_QUIET === '1') process.exit(0);

  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (!['Edit', 'Write', 'MultiEdit'].includes(tool)) process.exit(0);
  const file = evt.tool_input?.file_path || evt.tool_input?.filePath || evt.tool_input?.path;
  const anchorLabel = isCacheAnchor(file);
  if (!anchorLabel) process.exit(0);

  const warm = latest({ transcriptPath: evt.transcript_path, projectDir: cwd });
  if (!warm || warm.cacheTokens < MIN_WARM_TOKENS) process.exit(0);

  const key = `cache-anchor:${path.basename(String(file))}`;
  if (throttled(key)) process.exit(0);

  const rewarmUsd = warm.cacheTokens * (inRateFor(warm.model) / 1e6) * (1 - CACHE_READ_MULT);
  process.stderr.write(
    `✂️  agentic-security: editing ${anchorLabel} invalidates your prompt cache.\n` +
    `   ~${warm.cacheTokens.toLocaleString()} cached tokens would re-ingest cold next turn (est. ~${money(rewarmUsd)}).\n` +
    `   If the change can wait for a natural break, you'll keep the cache warm.\n`
  );
  process.exit(0);
})();
