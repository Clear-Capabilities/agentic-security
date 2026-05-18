// Minimal LSP server for agentic-security.
//
// Speaks the Language Server Protocol over stdio. On every textDocument/
// didSave (and didOpen), the server runs runScan on the file and emits
// textDocument/publishDiagnostics with the resulting findings mapped to
// LSP Diagnostic objects.
//
// This is a STARTER implementation — feature-complete enough that JetBrains
// (via LSP4IJ) and Neovim (via built-in LSP) can both attach and see
// findings inline. The full feature set (code actions for /fix, inline
// remediation hover, exploitability tooltip) is future work.
//
// Wire-format: vscode-jsonrpc framing (Content-Length headers). Stateless
// per file — no incremental analysis yet.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { runScan } from '../runScan.js';

const PROTOCOL_VERSION = '3.17';
const SERVER_NAME = 'agentic-security-lsp';
const SERVER_VERSION = '0.1.0';

let _rootUri = null;
let _rootDir = process.cwd();
let _stdoutMutex = Promise.resolve();
const _diagnosticsByUri = new Map();

function uriToPath(uri) {
  if (!uri) return null;
  if (uri.startsWith('file://')) return decodeURIComponent(uri.slice(7));
  return uri;
}

function pathToUri(p) {
  if (!p) return null;
  if (p.startsWith('file://')) return p;
  return 'file://' + encodeURI(path.resolve(p));
}

function sevToLsp(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 1;  // Error
    case 'high':     return 1;  // Error
    case 'medium':   return 2;  // Warning
    case 'low':      return 3;  // Information
    default:         return 4;  // Hint
  }
}

function findingToDiagnostic(f) {
  const line = Math.max(0, (f.line || 1) - 1);
  return {
    range: {
      start: { line, character: 0 },
      end:   { line, character: 200 },
    },
    severity: sevToLsp(f.severity),
    source: 'agentic-security',
    code: f.cwe || f.family || 'finding',
    message: `${f.vuln || 'Security finding'}${f.remediation ? '\n\n' + (typeof f.remediation === 'string' ? f.remediation : '') : ''}`.slice(0, 2000),
    tags: [],
  };
}

function send(message) {
  const json = JSON.stringify({ jsonrpc: '2.0', ...message });
  _stdoutMutex = _stdoutMutex.then(() => new Promise(resolve => {
    process.stdout.write(`Content-Length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}`, resolve);
  }));
  return _stdoutMutex;
}

async function publishDiagnostics(uri, findings) {
  await send({
    method: 'textDocument/publishDiagnostics',
    params: { uri, diagnostics: findings.map(findingToDiagnostic) },
  });
  _diagnosticsByUri.set(uri, findings);
}

async function scanFile(uri) {
  const filePath = uriToPath(uri);
  if (!filePath || !fs.existsSync(filePath)) return;
  // Incremental scan: hand runScan a single-file `fileContents` map so the
  // engine processes only this file. Cross-file taint/call-graph passes that
  // need the rest of the project are silently no-ops here — the trade-off is
  // worth it: a 100k-LoC project saves a file every few seconds, and the
  // engine reading every file on every save (the previous behavior) made the
  // plugin unusable.
  //
  // Operators who want cross-file analysis can run `/scan --all` from a
  // separate terminal; the LSP path is for editor-visible immediate feedback.
  try {
    const rel = path.relative(_rootDir, filePath);
    const content = fs.readFileSync(filePath, 'utf8');
    const fileContents = { [rel]: content };
    const { scan } = await runScan(_rootDir, { fileContents });
    const findings = (scan.findings || []).filter(f => f.file === rel);
    await publishDiagnostics(uri, findings);
  } catch (e) {
    process.stderr.write(`agentic-security-lsp: scan failed: ${e.message}\n`);
  }
}

function handleInitialize(params) {
  if (params.rootUri) {
    _rootUri = params.rootUri;
    _rootDir = uriToPath(params.rootUri) || process.cwd();
  } else if (params.rootPath) {
    _rootDir = params.rootPath;
  }
  return {
    capabilities: {
      textDocumentSync: {
        openClose: true,
        change: 1,
        save: { includeText: false },
      },
      diagnosticProvider: { interFileDependencies: true, workspaceDiagnostics: false },
    },
    serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
  };
}

async function handleMessage(msg) {
  if (msg.method === 'initialize') {
    return { id: msg.id, result: handleInitialize(msg.params || {}) };
  }
  if (msg.method === 'initialized' || msg.method === 'workspace/didChangeConfiguration') {
    return null;  // notification, no response
  }
  if (msg.method === 'shutdown') {
    return { id: msg.id, result: null };
  }
  if (msg.method === 'exit') {
    process.exit(0);
  }
  if (msg.method === 'textDocument/didOpen') {
    const uri = msg.params?.textDocument?.uri;
    if (uri) scanFile(uri);
    return null;
  }
  if (msg.method === 'textDocument/didSave') {
    const uri = msg.params?.textDocument?.uri;
    if (uri) scanFile(uri);
    return null;
  }
  if (msg.method === 'textDocument/didClose') {
    const uri = msg.params?.textDocument?.uri;
    if (uri) await publishDiagnostics(uri, []);
    return null;
  }
  // Unknown method.
  if (msg.id != null) {
    return { id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } };
  }
  return null;
}

export function startLspServer() {
  let buffer = Buffer.alloc(0);
  let expected = -1;
  process.stdin.on('data', async (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      if (expected < 0) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd < 0) break;
        const headers = buffer.slice(0, headerEnd).toString('utf8');
        const m = headers.match(/Content-Length:\s*(\d+)/i);
        if (!m) {
          process.stderr.write('agentic-security-lsp: missing Content-Length header\n');
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
        expected = parseInt(m[1], 10);
        buffer = buffer.slice(headerEnd + 4);
      }
      if (buffer.length < expected) break;
      const body = buffer.slice(0, expected).toString('utf8');
      buffer = buffer.slice(expected);
      expected = -1;
      let msg;
      try { msg = JSON.parse(body); }
      catch { process.stderr.write('agentic-security-lsp: malformed JSON\n'); continue; }
      try {
        const response = await handleMessage(msg);
        if (response) await send(response);
      } catch (e) {
        if (msg.id != null) await send({ id: msg.id, error: { code: -32603, message: e.message } });
      }
    }
  });
  process.stdin.on('end', () => process.exit(0));
}

// Allow direct invocation as a bin entry: `node lsp/server.js`.
if (import.meta.url === `file://${process.argv[1]}`) {
  startLspServer();
}
