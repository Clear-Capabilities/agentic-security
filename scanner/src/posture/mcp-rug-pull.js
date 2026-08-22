// PRD F5.2 — rug-pull detection for MCP tool definitions.
//
// THE ATTACK
// ----------
// A user approves an MCP server by reading what its tools claim to do. The
// agent then loads those tool DESCRIPTIONS into its context on every session,
// and acts on them. If a description changes after approval — new instructions
// appended, the schema widened to accept a path it never took, the stated
// purpose rewritten — the agent obeys the new text while the human still
// believes they approved the old one.
//
// Nothing in mcp-audit.js could see this. Every rule there judges a definition
// on its CURRENT content, so a description that is innocuous today and hostile
// tomorrow passes both times. Rug-pull is a property of the CHANGE, not of any
// single snapshot, which is why it needs its own mechanism.
//
// WHAT IS AND IS NOT A RUG-PULL
// -----------------------------
// A NEW tool is not a rug-pull — nobody approved it yet, and mcp-audit judges it
// on content like any other. A REMOVED tool is not a rug-pull either; it can no
// longer instruct anything. The finding is specifically: this exact tool name
// was seen before, and what it says has changed since.
//
// The FIRST run records and reports nothing. There is no prior state to compare
// against, and inventing a finding on first sight would make every new project
// noisy while teaching people to ignore the rule that matters.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { statePath, stateWritesEnabled, isSafeStateDir } from './state-dir.js';

const BASELINE_FILE = 'mcp-tool-baseline.json';

/**
 * Fingerprint the parts of a tool definition an agent actually ACTS on.
 *
 * Description and input schema, not the name — the name is the identity being
 * tracked, so folding it in would make every tool its own fingerprint and the
 * comparison vacuous. Ordering inside the schema is normalised so a formatting
 * change is not reported as a behavioural one; a reader chasing a false
 * rug-pull alert stops reading them.
 */
export function fingerprintTool(tool) {
  const payload = JSON.stringify({
    description: String((tool && tool.description) || ''),
    inputSchema: _canonical((tool && (tool.inputSchema || tool.input_schema)) || null),
  });
  return crypto.createHash('sha256').update(payload).digest('hex').slice(0, 32);
}

function _canonical(v) {
  if (Array.isArray(v)) return v.map(_canonical);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = _canonical(v[k]);
    return out;
  }
  return v;
}

/** { serverName: { toolName: fingerprint } } from an MCP config object. */
export function fingerprintConfig(config) {
  const out = {};
  const servers = (config && (config.mcpServers || config.servers)) || {};
  for (const [server, def] of Object.entries(servers)) {
    const tools = (def && def.tools) || [];
    if (!Array.isArray(tools) || !tools.length) continue;
    out[server] = {};
    for (const t of tools) {
      if (t && t.name) out[server][t.name] = fingerprintTool(t);
    }
  }
  return out;
}

export function loadBaseline(scanRoot) {
  try {
    return JSON.parse(fs.readFileSync(statePath(scanRoot, BASELINE_FILE), 'utf8'));
  } catch { return null; }
}

export function saveBaseline(scanRoot, fingerprints) {
  // Same discipline as every other state writer here: decline rather than
  // create a stray state dir outside a real project.
  if (!stateWritesEnabled() || !isSafeStateDir(path.dirname(statePath(scanRoot, BASELINE_FILE)))) return false;
  try {
    fs.mkdirSync(path.dirname(statePath(scanRoot, BASELINE_FILE)), { recursive: true });
    fs.writeFileSync(statePath(scanRoot, BASELINE_FILE),
      JSON.stringify({ schema: 'mcp-tool-baseline/v1', recordedAt: new Date().toISOString(), fingerprints }, null, 1));
    return true;
  } catch { return false; }
}

/**
 * Compare current tool definitions against the recorded baseline.
 *
 * Returns { findings, firstRun, changed, added, removed }. `findings` is empty
 * on a first run by design.
 */
export function detectRugPull(scanRoot, config, { file = '.mcp.json' } = {}) {
  const current = fingerprintConfig(config);
  const prior = loadBaseline(scanRoot);
  const findings = [];
  const changed = [], added = [], removed = [];

  if (!prior || !prior.fingerprints) {
    return { findings, firstRun: true, changed, added, removed, current };
  }

  for (const [server, tools] of Object.entries(current)) {
    const before = prior.fingerprints[server] || {};
    for (const [name, fp] of Object.entries(tools)) {
      if (!(name in before)) { added.push(`${server}/${name}`); continue; }
      if (before[name] === fp) continue;
      changed.push(`${server}/${name}`);
      findings.push({
        id: `mcp-rug-pull:${file}:${server}:${name}`,
        file,
        line: 1,
        vuln: `MCP: tool "${name}" definition CHANGED after approval (rug-pull)`,
        severity: 'high',
        cwe: 'CWE-494',
        family: 'mcp-rug-pull',
        parser: 'MCP-RUGPULL',
        confidence: 0.9,
        description:
          `The tool "${name}" on server "${server}" was approved with one definition and now has another. `
          + 'An agent loads tool descriptions into its context and acts on them, so a changed description is a '
          + 'changed instruction — the human still believes they approved the previous text. This is the '
          + 'documented rug-pull shape: benign at review time, hostile afterwards.',
        remediation:
          `Re-review "${name}" against what it claimed when approved. If the change is legitimate, refresh the `
          + `baseline at .agentic-security/${BASELINE_FILE}; if it is not, remove the server before the next agent run.`,
      });
    }
  }
  for (const [server, tools] of Object.entries(prior.fingerprints)) {
    for (const name of Object.keys(tools)) {
      if (!current[server] || !(name in current[server])) removed.push(`${server}/${name}`);
    }
  }

  return { findings, firstRun: false, changed, added, removed, current };
}
