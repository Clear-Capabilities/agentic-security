#!/usr/bin/env node
// PostToolUse hook: scan only the directory containing the file just edited;
// surface NEW high/critical findings. Throttled per-file ≤1/5s.
//
// Implemented as plain CommonJS that shells out to the bundled CLI, so the
// hook has zero external dependencies and runs even without scanner/node_modules.
'use strict';
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const THROTTLE_MS = 5000;
const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const throttlePath = path.join(stateDir, 'hook-throttle.json');
const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.join(__dirname, '..', '..');
const bundle = path.join(pluginRoot, 'scanner', 'dist', 'agentic-security.mjs');

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}
function readThrottle() { try { return JSON.parse(fs.readFileSync(throttlePath, 'utf8')); } catch { return {}; } }
function writeThrottle(t) { try { fs.mkdirSync(stateDir, { recursive: true }); fs.writeFileSync(throttlePath, JSON.stringify(t)); } catch {} }

(async () => {
  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (!['Edit', 'Write', 'MultiEdit'].includes(tool)) process.exit(0);
  const file = evt.tool_input?.file_path || evt.tool_input?.filePath;
  if (!file) process.exit(0);
  const rel = path.relative(cwd, file);
  if (rel.startsWith('..')) process.exit(0);

  const throttle = readThrottle();
  const now = Date.now();
  if (now - (throttle[rel] || 0) < THROTTLE_MS) process.exit(0);
  throttle[rel] = now;
  writeThrottle(throttle);

  if (!fs.existsSync(bundle)) process.exit(0);

  // Scan the file's parent directory; the bundle handles fast-glob etc. internally.
  const scanRoot = path.dirname(file);
  const result = cp.spawnSync('node', [bundle, 'scan', scanRoot, '--no-network', '--format', 'json'], {
    encoding: 'utf8', timeout: 12000, maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status === null || result.status > 3) process.exit(0); // 0–3 are valid scan codes
  let scan;
  try { scan = JSON.parse(result.stdout); } catch { process.exit(0); }

  const baseName = path.basename(file);
  const fileFindings = (scan.findings || [])
    .filter(f => f.file && f.file.endsWith(baseName))
    .filter(f => f.severity === 'critical' || f.severity === 'high');

  let baselineIds = new Set();
  try {
    const last = JSON.parse(fs.readFileSync(path.join(stateDir, 'last-scan.json'), 'utf8'));
    baselineIds = new Set((last.findings || []).filter(f => f.file && f.file.endsWith(baseName)).map(f => f.id));
  } catch {}
  const fresh = fileFindings.filter(f => !baselineIds.has(f.id));
  if (!fresh.length) process.exit(0);

  const top = fresh.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.cwe || ''} ${f.vuln} (${f.file}:${f.line})`).join('\n');
  const more = fresh.length > 5 ? `\n  ...and ${fresh.length - 5} more` : '';
  console.error(`agentic-security: ${fresh.length} new high/critical finding(s) from this edit:\n${top}${more}\n→ Run \`/agentic-security:security-fix-all --severity high\` to remediate.`);
  process.exit(0);
})();
