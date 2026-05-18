// MCP server core — JSON-RPC 2.0 handler for the Model Context Protocol.
//
// Hardening posture (mapped to OWASP MCP Top 10):
//   - Session root chosen at server boot, no per-call retargeting (MCP02)
//   - Every tools/call argument validated against the tool's inputSchema (MCP02/MCP05)
//   - Every tools/call audited with a hash-chained log (MCP08)
//   - serverInfo.codeFingerprint = SHA-256 of MCP source files (MCP04/MCP09)
//     so a fleet can detect tampered or unauthorized server deployments
//   - AGENTIC_SECURITY_MCP_DISABLED=1 hard-disables all tool calls (MCP09)
//   - Stdio transport caps line/buffer size (./stdio.js) (MCP05 DoS)

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_TOOLS } from './tools.js';
import { validate } from './validate.js';
import { auditCall } from './audit.js';

const PROTOCOL_VERSION = '2025-03-26';
const SERVER_NAME = 'agentic-security';
const SERVER_VERSION = '0.39.2';

const TOOLS_BY_NAME = Object.fromEntries(ALL_TOOLS.map(t => [t.name, t]));

// Code fingerprint — SHA-256 of the MCP source files concatenated in a
// stable order. Embedded in `initialize` response so a fleet operator can
// detect when an unapproved build is running (OWASP MCP04/MCP09).
function _codeFingerprint() {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const files = ['server.js', 'tools.js', 'stdio.js', 'audit.js', 'validate.js', 'redact.js'];
    const h = crypto.createHash('sha256');
    for (const f of files) {
      try { h.update(f); h.update(fs.readFileSync(path.join(here, f))); } catch {}
    }
    return h.digest('hex');
  } catch { return null; }
}
const CODE_FINGERPRINT = _codeFingerprint();

function _err(id, code, message, data) {
  const out = { jsonrpc: '2.0', id, error: { code, message } };
  if (data !== undefined) out.error.data = data;
  return out;
}

function _ok(id, result) {
  return { jsonrpc: '2.0', id, result };
}

export function createServer({ sessionRoot = process.cwd() } = {}) {
  const ctx = { sessionRoot };

  async function handleRequest(msg) {
    if (!msg || typeof msg !== 'object') return _err(null, -32600, 'Invalid Request');
    if (msg.jsonrpc !== '2.0') return _err(msg.id ?? null, -32600, 'Invalid Request: jsonrpc must be "2.0"');

    const isNotification = msg.id === undefined || msg.id === null;
    const id = msg.id ?? null;
    const disabled = process.env.AGENTIC_SECURITY_MCP_DISABLED === '1';

    switch (msg.method) {
      case 'initialize':
        return _ok(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
            codeFingerprint: CODE_FINGERPRINT,
            disabled,
          },
        });

      case 'notifications/initialized':
        return null;

      case 'ping':
        return _ok(id, {});

      case 'tools/list':
        return _ok(id, {
          tools: ALL_TOOLS.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });

      case 'tools/call': {
        const name = msg.params?.name;
        const args = msg.params?.arguments ?? {};
        if (disabled) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'server-disabled' });
          return _ok(id, {
            content: [{ type: 'text', text: 'MCP server is disabled (AGENTIC_SECURITY_MCP_DISABLED=1).' }],
            isError: true,
          });
        }
        const tool = TOOLS_BY_NAME[name];
        if (!tool) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'unknown-tool' });
          return _err(id, -32602, `Unknown tool: ${name}`);
        }
        try { validate(tool.inputSchema, args); }
        catch (e) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: `invalid-args: ${e.message}` });
          return _ok(id, {
            content: [{ type: 'text', text: `Invalid arguments: ${e.message}` }],
            isError: true,
          });
        }
        try {
          const result = await tool.handler(args, ctx);
          auditCall({ sessionRoot, tool: name, args, outcome: 'ok' });
          return _ok(id, {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            isError: false,
          });
        } catch (e) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'error', reason: e.message });
          return _ok(id, {
            content: [{ type: 'text', text: `Error: ${e.message}` }],
            isError: true,
          });
        }
      }

      default:
        if (isNotification) return null;
        return _err(id, -32601, `Method not found: ${msg.method}`);
    }
  }

  return { handleRequest, sessionRoot };
}

// NOTE: no default-singleton export. Callers must use createServer({...})
// with an explicit sessionRoot. Removed because the prior default was bound
// to process.cwd() at module-load time — a footgun for any caller that
// imported `handleRequest` directly (OWASP A05).

export { SERVER_NAME, SERVER_VERSION, PROTOCOL_VERSION, CODE_FINGERPRINT };
