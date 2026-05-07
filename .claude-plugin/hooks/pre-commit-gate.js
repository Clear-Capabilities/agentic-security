#!/usr/bin/env node
// PreToolUse hook for `git commit*`: block commits that add NEW critical
// findings vs. baseline. Override with AGENTIC_SECURITY_BYPASS=1.
//
// Plain CommonJS, shells out to the bundled CLI — no engine imports.
'use strict';
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

(async () => {
  const evt = await readStdinJSON();
  if ((evt.tool_name || evt.toolName) !== 'Bash') process.exit(0);
  const command = evt.tool_input?.command || '';
  if (!/\bgit\s+commit\b/.test(command)) process.exit(0);
  if (process.env.AGENTIC_SECURITY_BYPASS === '1') process.exit(0);

  const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const blPath = path.join(cwd, '.agentic-security', 'baseline.json');
  if (!fs.existsSync(blPath)) process.exit(0);

  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.join(__dirname, '..', '..');
  const bundle = path.join(pluginRoot, 'scanner', 'dist', 'agentic-security.mjs');
  if (!fs.existsSync(bundle)) process.exit(0);

  let baselineIds;
  try {
    const baseline = JSON.parse(fs.readFileSync(blPath, 'utf8'));
    baselineIds = new Set((baseline.findings || []).map(f => f.id));
  } catch { process.exit(0); }

  const result = cp.spawnSync('node', [bundle, 'scan', cwd, '--no-network', '--format', 'json'], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === null || result.status > 3) process.exit(0);
  let scan;
  try { scan = JSON.parse(result.stdout); } catch { process.exit(0); }

  const newCritical = (scan.findings || []).filter(f => f.severity === 'critical' && !baselineIds.has(f.id));
  if (!newCritical.length) process.exit(0);

  const lines = newCritical.slice(0, 10).map(f => `  [CRITICAL] ${f.cwe || ''} ${f.vuln} (${f.file}:${f.line})`).join('\n');
  const more = newCritical.length > 10 ? `\n  ...and ${newCritical.length - 10} more` : '';
  console.error(`agentic-security: ${newCritical.length} NEW critical finding(s) since baseline; commit blocked.\n${lines}${more}\n\nResolve via /agentic-security:security-fix-all --severity critical, or set AGENTIC_SECURITY_BYPASS=1 to override.`);
  process.exit(2);
})();
