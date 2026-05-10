// MCP / Agent tool security audit.
//
// Scans MCP server config files (claude_desktop_config.json, *.mcp.json, mcp.json,
// .claude/mcp.json) and tool-definition source for the canonical agent-host
// risks:
//   - Untrusted server install vector  (curl|sh, http://, unpinned npx)
//   - Over-scoped filesystem grant      (root, $HOME, /, *)
//   - Hardcoded credential in env       (sk-…, github_pat_…, AKIA…, ghp_…)
//   - Prompt injection in description   (instruction overrides in tool descriptions)
//   - Dangerous tool capability         (shell/exec/eval/sql exposed to model)
//   - Unrestricted network passthrough  (proxy tools without allow-list)
//
// F1 strategy:
//   Recall    — broad config-file matching across config name variants.
//   Precision — fire only when one of the patterns above is concretely present
//               in a JSON config or in a tool definition with description+name.

const _MCP_FILE_RE = /(?:^|[\\/])(?:claude_desktop_config\.json|\.?mcp\.json|[^/\\]+\.mcp\.json|mcp_servers\.json)$/i;
const _NONPROD_RE = /(?:^|[\\/])(?:tests?|examples?|fixtures?|node_modules|docs?)[\\/]/i;

// Hardcoded credential shapes commonly leaked in MCP env: blocks
const _HARDCODED_CRED_RE = [
  /\b(?:sk-[A-Za-z0-9]{20,})\b/,                  // OpenAI / Anthropic
  /\b(?:sk-ant-[A-Za-z0-9_-]{20,})\b/,             // Anthropic
  /\b(?:ghp_[A-Za-z0-9]{36})\b/,                   // GitHub PAT
  /\b(?:github_pat_[A-Za-z0-9_]{20,})\b/,          // GitHub fine-grained PAT
  /\b(?:gho_[A-Za-z0-9]{36})\b/,                   // GitHub OAuth
  /\bAKIA[0-9A-Z]{16}\b/,                          // AWS access key id
  /\b(?:xox[abprs]-[A-Za-z0-9-]{10,})\b/,          // Slack
  /\b(?:gsk_[A-Za-z0-9]{30,})\b/,                  // Groq
];

// Description fields that try to inject instructions into the agent
const _PROMPT_INJECTION_RE = [
  /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+(?:instructions|directives|prompts|rules)/i,
  /\b(?:you\s+are\s+now|new\s+system\s+prompt|act\s+as|pretend\s+to\s+be)\b/i,
  /\b(?:before\s+(?:running|invoking|using)\s+this\s+tool[^.]*?(?:read|exfiltrate|send|leak|copy|reveal|exec))/i,
  /<\s*\|?\s*(?:system|im_start|im_end|assistant|user)\s*\|?\s*>/i,
  /\b(?:print|reveal|output|show|expose|reveal)\s+(?:your|the)?\s*(?:system\s+prompt|instructions|api\s+key|credentials|secrets?)\b/i,
];

// Tool/server names that imply dangerous capabilities
const _DANGEROUS_CAPABILITY_NAMES = /\b(?:shell|bash|exec|run_command|run_shell|execute_shell|eval|eval_python|sandbox_exec|run_code|sudo|root|kubectl|docker_exec|admin|drop_table|raw_query|ssh|fetch_url_unrestricted)\b/i;

// Filesystem args / env paths that grant excessive scope
const _FS_OVERSCOPE_RE = [
  /^(?:\/|~\/?|\$HOME\/?|\$\{?HOME\}?\/?)$/,
  /^(?:\/|~|\$HOME|\$\{HOME\})\s*\*$/,
  /^(?:\/|~|\$HOME|\$\{HOME\})\/\*\*$/,
];
const _FS_LIKE_PATH_RE = /^(?:[A-Za-z]:|\/|~\/?|\$HOME|\$\{HOME\}|\.\.?\/)/;

// Untrusted install / command vectors
const _UNTRUSTED_INSTALL_RE = [
  /\bcurl\s+[^|]*\|\s*(?:sh|bash|zsh)\b/,
  /\bwget\s+[^|]*\|\s*(?:sh|bash|zsh)\b/,
  /^http:\/\//i,
];

// Floating npx pins / unpinned versions in command:/args:
const _FLOATING_PIN_RE = /@(?:latest|next|main|master|beta|canary)\b/;

function _stringsFromValue(v, out=[]) {
  if (v === null || v === undefined) return out;
  if (typeof v === 'string') { out.push(v); return out; }
  if (typeof v === 'number' || typeof v === 'boolean') { out.push(String(v)); return out; }
  if (Array.isArray(v)) { for (const x of v) _stringsFromValue(x, out); return out; }
  if (typeof v === 'object') { for (const k of Object.keys(v)) _stringsFromValue(v[k], out); return out; }
  return out;
}

function _findLineOf(raw, needle) {
  if (!raw || !needle) return 1;
  const idx = raw.indexOf(needle);
  if (idx === -1) return 1;
  return raw.substring(0, idx).split('\n').length;
}

function _findKeyLine(raw, key) {
  if (!raw || !key) return 1;
  const re = new RegExp('"' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"\\s*:');
  const m = raw.match(re);
  if (!m) return 1;
  return raw.substring(0, m.index).split('\n').length;
}

function _isMcpConfigFile(fp) {
  const norm = fp.replace(/\\/g, '/');
  if (_NONPROD_RE.test(norm)) return false;
  return _MCP_FILE_RE.test(norm);
}

// Public: scan a single file. Mirrors scanLLM/scanPipeline shape so the engine
// can call it inline for each file.
export function scanMCP(fp, raw) {
  if (!_isMcpConfigFile(fp)) return [];
  if (!raw || raw.length > 200_000) return [];
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  if (!parsed || typeof parsed !== 'object') return [];

  const findings = [];
  const seen = new Set();
  const push = (f) => {
    const key = `${f.file}:${f.line}:${f.vuln}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  // Both `mcpServers` (Claude desktop config) and top-level server maps
  const servers = (parsed.mcpServers && typeof parsed.mcpServers === 'object')
    ? parsed.mcpServers
    : (parsed.servers && typeof parsed.servers === 'object')
      ? parsed.servers
      : parsed;

  for (const [name, srv] of Object.entries(servers || {})) {
    if (!srv || typeof srv !== 'object') continue;
    const line = _findKeyLine(raw, name);

    // 1. Untrusted install vector in command/args
    const cmd = typeof srv.command === 'string' ? srv.command : '';
    const args = Array.isArray(srv.args) ? srv.args.filter(a => typeof a === 'string') : [];
    const fullCmd = [cmd, ...args].join(' ');
    if (fullCmd && _UNTRUSTED_INSTALL_RE.some(re => re.test(fullCmd))) {
      push({
        id: `mcp-audit:${fp}:${line}:untrusted-install`,
        kind: 'mcp', severity: 'critical',
        vuln: 'MCP: untrusted install vector (curl|sh / http://) in server command',
        cwe: 'CWE-494', stride: 'Tampering',
        file: fp, line, snippet: `${name}: ${fullCmd}`.slice(0, 200),
        fix: `MCP server "${name}" runs through an untrusted bootstrap (curl|sh or http://). Pin to a published, signed package and use https. Example: replace \`curl http://… | sh\` with an explicit \`npx -y package@<sha>\` that you have audited.`,
      });
    }

    // 2. Floating tag pin in npx/uvx invocations
    if (args.some(a => _FLOATING_PIN_RE.test(a))) {
      const offending = args.find(a => _FLOATING_PIN_RE.test(a));
      push({
        id: `mcp-audit:${fp}:${line}:floating-pin`,
        kind: 'mcp', severity: 'high',
        vuln: 'MCP: server pinned to a floating tag (@latest/@main)',
        cwe: 'CWE-1357', stride: 'Tampering',
        file: fp, line, snippet: `${name}: ${offending}`,
        fix: `Floating tag means the publisher (or an attacker who compromises them) can ship new code into your agent any time. Pin to a specific semver: \`pkg@1.2.3\` — or, even better, a published SHA.`,
      });
    }

    // 3. Hardcoded credentials in env or args
    const envObj = (srv.env && typeof srv.env === 'object') ? srv.env : {};
    const allEnvStrings = _stringsFromValue(envObj);
    const allArgStrings = _stringsFromValue(args);
    const allHaystacks = [...allEnvStrings, ...allArgStrings];
    for (const s of allHaystacks) {
      if (_HARDCODED_CRED_RE.some(re => re.test(s))) {
        push({
          id: `mcp-audit:${fp}:${line}:hardcoded-cred`,
          kind: 'mcp', severity: 'critical',
          vuln: 'MCP: hardcoded credential in server env/args',
          cwe: 'CWE-798', stride: 'Information Disclosure',
          file: fp, line, snippet: `${name}: <credential redacted>`,
          fix: `MCP server "${name}" carries a hardcoded API key. Move it to a secret store and reference via \`env: { API_KEY: "\${{ secrets.API_KEY }}" }\` or read from the user's keychain at startup.`,
        });
        break;
      }
    }

    // 4. Filesystem over-scope. Common when @modelcontextprotocol/server-filesystem
    //    is invoked with a root/home arg.
    const isFsServer = /filesystem|files?|fs/i.test(name) || /server-filesystem/.test(fullCmd);
    if (isFsServer || args.some(a => _FS_LIKE_PATH_RE.test(a))) {
      const overscoped = args.find(a =>
        typeof a === 'string' && _FS_OVERSCOPE_RE.some(re => re.test(a.trim()))
      );
      if (overscoped) {
        push({
          id: `mcp-audit:${fp}:${line}:fs-overscope`,
          kind: 'mcp', severity: 'high',
          vuln: 'MCP: filesystem server granted root or $HOME scope',
          cwe: 'CWE-732', stride: 'Elevation of Privilege',
          file: fp, line, snippet: `${name}: ${overscoped}`,
          fix: `Filesystem MCP server "${name}" can read every file in ${overscoped}. Scope to the specific project directory the agent needs, e.g. \`/Users/me/code/this-project\`. Never grant \`/\`, \`$HOME\`, or \`~\`.`,
        });
      }
    }

    // 5. Dangerous capability name (shell, exec, eval, etc.) exposed unscoped
    if (_DANGEROUS_CAPABILITY_NAMES.test(name) || _DANGEROUS_CAPABILITY_NAMES.test(fullCmd)) {
      push({
        id: `mcp-audit:${fp}:${line}:dangerous-capability`,
        kind: 'mcp', severity: 'high',
        vuln: 'MCP: server exposes a dangerous capability (shell/exec/eval) to the model',
        cwe: 'CWE-77', stride: 'Elevation of Privilege',
        file: fp, line, snippet: `${name}`,
        fix: `Server "${name}" lets the model run arbitrary commands. If you keep it, restrict the working directory and the allowed binary list, and require user confirmation per call (most clients support an \`approval: ask\` flag).`,
      });
    }

    // 6. Description-field prompt injection
    const desc = typeof srv.description === 'string' ? srv.description : '';
    if (desc && _PROMPT_INJECTION_RE.some(re => re.test(desc))) {
      const dline = _findLineOf(raw, desc.slice(0, 40));
      push({
        id: `mcp-audit:${fp}:${dline}:prompt-injection-description`,
        kind: 'mcp', severity: 'critical',
        vuln: 'MCP: prompt-injection text inside server description',
        cwe: 'CWE-1336', stride: 'Spoofing',
        file: fp, line: dline, snippet: desc.slice(0, 200),
        fix: `The description for "${name}" contains an instruction that overrides agent behavior. Treat MCP server metadata as untrusted input — the agent reads it. Strip the override and only describe what the server actually does.`,
      });
    }

    // Also: prompt injection inside any tool definitions embedded in this config
    const toolsArr = Array.isArray(srv.tools) ? srv.tools : [];
    for (const t of toolsArr) {
      if (!t || typeof t !== 'object') continue;
      const tDesc = typeof t.description === 'string' ? t.description : '';
      if (tDesc && _PROMPT_INJECTION_RE.some(re => re.test(tDesc))) {
        const tline = _findLineOf(raw, tDesc.slice(0, 40));
        push({
          id: `mcp-audit:${fp}:${tline}:prompt-injection-tool-desc`,
          kind: 'mcp', severity: 'critical',
          vuln: 'MCP: prompt-injection text inside tool description',
          cwe: 'CWE-1336', stride: 'Spoofing',
          file: fp, line: tline, snippet: tDesc.slice(0, 200),
          fix: `Tool "${t.name || '(unnamed)'}" carries an instruction inside its description. The agent reads tool descriptions as part of its system context. Remove the injection.`,
        });
      }
    }
  }

  return findings;
}

// Public for tests + the engine
export const _internal = {
  _isMcpConfigFile,
  _HARDCODED_CRED_RE,
  _PROMPT_INJECTION_RE,
  _DANGEROUS_CAPABILITY_NAMES,
};
