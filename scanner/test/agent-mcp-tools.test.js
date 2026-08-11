// S5 — a subagent's `tools:` frontmatter is an ALLOWLIST. When an agent's
// body instructs it to call an MCP tool that isn't in that list, the
// instruction is unfollowable: the agent has no way to actually invoke it.
//
// Reproduced (by direct inspection, since there's no local harness that
// loads a subagent and tries the call): agents/security-fixer.md's body
// mandated synthesize_fix/verify_fix/apply_fix/append_scratchpad/
// read_scratchpad/append_agents_memory while its `tools:` line declared only
// `Read, Bash, Grep` — none of the six. Fixed by adding each as
// `mcp__plugin_agentic-security_agentic-security__<tool>`, the naming
// convention Claude Code uses for a tool from a plugin-bundled MCP server
// (`mcp__plugin_<plugin-name>_<server-name>__<tool-name>`; this plugin and
// its bundled server are both named "agentic-security").
//
// This guards the whole class: any agents/*.md body that mentions a real MCP
// tool name by its bare identifier must also declare the qualified form in
// `tools:`, checked against src/mcp/tools.js's ALL_TOOLS — the same registry
// the MCP server itself uses, so this can't silently drift from the real
// tool set.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_TOOLS } from '../src/mcp/tools.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const AGENTS_DIR = path.join(REPO_ROOT, 'agents');
const MCP_PREFIX = 'mcp__plugin_agentic-security_agentic-security__';

const TOOL_NAMES = ALL_TOOLS.map((t) => t.name);

// Mentioning a tool by name is not always an instruction to call it — this
// file explicitly tells the agent it CANNOT run the tool and to route around
// its absence instead ("you can't run synthesize_sca_upgrade from here, but
// check whether fixedVersions[0] major > current major"). Flagging that as
// "must declare the tool" would be exactly backwards. Precise per-mention
// exceptions, not a blunter matcher, keep the check meaningful elsewhere.
const ALLOWED_UNDECLARED_MENTIONS = {
  'sca-triager.md': new Set(['synthesize_sca_upgrade']),
};

function frontmatterToolsLine(content) {
  const m = /^tools:\s*(.+)$/m.exec(content);
  return m ? m[1] : null;
}

const agentFiles = fs.readdirSync(AGENTS_DIR)
  .filter((f) => f.endsWith('.md'))
  .filter((f) => f !== '_CONFINEMENT.md'); // shared contract doc, not itself an agent

for (const file of agentFiles) {
  test(`S5: agents/${file} declares every MCP tool its body mentions by name`, () => {
    const content = fs.readFileSync(path.join(AGENTS_DIR, file), 'utf8');
    const toolsLine = frontmatterToolsLine(content);
    if (toolsLine === null) return; // no tools: frontmatter — nothing to check

    // Body = everything after the closing frontmatter fence, so a tool name
    // appearing inside the `tools:` line itself is never mistaken for a
    // body-level "you must call this" instruction.
    const closeIdx = content.indexOf('\n---\n');
    const body = closeIdx >= 0 ? content.slice(closeIdx + 5) : content;

    const allowed = ALLOWED_UNDECLARED_MENTIONS[file] || new Set();
    for (const name of TOOL_NAMES) {
      if (allowed.has(name)) continue;
      const mentioned = new RegExp(`(?<!mcp__plugin_agentic-security_agentic-security__)\\b${name}\\b`).test(body);
      if (!mentioned) continue;
      assert.ok(
        toolsLine.includes(`${MCP_PREFIX}${name}`),
        `agents/${file} body calls MCP tool '${name}' but 'tools:' does not declare ` +
        `'${MCP_PREFIX}${name}' — the agent has no way to actually invoke it`
      );
    }
  });
}
