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
import { resetCustomRulesBudget } from '../posture/custom-rules.js';
import { redactFinding } from '../mcp/redact.js';
import { _remediationOf } from '../report/index.js';

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
  // Stage 6 correctness audit: this read f.remediation directly, but raw
  // scan.findings entries (what this consumes, pre-normalizeFindings) come
  // from two conventions — most posture/*.js and newer sast/*.js modules
  // set `remediation`, while ~127 of engine.js's own detectors set a `fix`
  // STRING field instead. _remediationOf carries the same precedence
  // report/index.js already established for this exact split (CMP-3).
  const remediation = _remediationOf(f);
  return {
    range: {
      start: { line, character: 0 },
      end:   { line, character: 200 },
    },
    severity: sevToLsp(f.severity),
    source: 'agentic-security',
    code: f.cwe || f.family || 'finding',
    message: `${f.vuln || 'Security finding'}${remediation ? '\n\n' + remediation : ''}`.slice(0, 2000),
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

// Manifest / schema files that downstream passes (SCA, cross-language) read.
// We walk the project tree once per LSP session and cache these so the
// per-save scan has them.
const DEP_BASE_NAMES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile.lock',
  'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock',
  'go.mod', 'Cargo.toml', 'Cargo.lock',
  'pom.xml', 'build.gradle', 'build.gradle.kts',
]);
const DEP_EXT_RE = /\.(?:proto|graphql|gql|tf)$/i;
const DEP_NAME_RE = /(?:openapi|swagger)\.(?:ya?ml|json)$/i;

let _depCache = { rootDir: null, depFileContents: {} };

function _loadDepFileContents(rootDir) {
  if (_depCache.rootDir === rootDir) return _depCache.depFileContents;
  const out = {};
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'target', 'vendor', '.bench-cache']);
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (skipDirs.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile()) continue;
      const base = e.name;
      if (DEP_BASE_NAMES.has(base) || DEP_EXT_RE.test(base) || DEP_NAME_RE.test(base)) {
        let stat;
        try { stat = fs.statSync(full); } catch { continue; }
        if (stat.size > 500_000) continue;
        try { out[path.relative(rootDir, full)] = fs.readFileSync(full, 'utf8'); }
        catch { /* skip unreadable */ }
      }
    }
  }
  walk(rootDir);
  _depCache = { rootDir, depFileContents: out };
  return out;
}

async function scanFile(uri) {
  const filePath = uriToPath(uri);
  if (!filePath || !fs.existsSync(filePath)) return;
  // Incremental scan (premortem 2R4.5 / 2R-10): hand runScan a single-file
  // fileContents map for the saved code, AND a cached set of dep-manifest /
  // schema files so SCA + cross-language passes have their inputs. Without
  // depFileContents, the LSP path would silently drop CVE / OpenAPI / proto
  // findings on the saved file.
  try {
    const rel = path.relative(_rootDir, filePath);
    const content = fs.readFileSync(filePath, 'utf8');
    const fileContents = { [rel]: content };
    const depFileContents = _loadDepFileContents(_rootDir);
    // Premortem 4R-12 + 4R-15: reset the per-process custom-rules budget at
    // the start of each LSP scan. Each save is a logical scan session; without
    // the reset, a long-lived LSP server would accumulate budget across saves
    // and eventually start skipping custom rules.
    resetCustomRulesBudget(_rootDir);
    // PRD R1 (docs/DETECTION_GAP_REMEDIATION_PRD.md): deep mode is
    // default-on for the interactive CLI scan but was never requested here,
    // so every on-save diagnostic pass was regex/AST-only — blind to any bug
    // whose source and sink are connected only through a call. Scoped to
    // exactly the saved file (fileContents has one entry), so this does not
    // turn every keystroke's save into a full-project deep scan.
    const { scan } = await runScan(_rootDir, { fileContents, depFileContents, deep: true, deepInCi: true });
    // Stage 6 correctness audit: this only ever read scan.findings (the SAST
    // channel). scan.secrets and scan.logicVulns are separate arrays on the
    // raw runScan() result — normalizeFindings is what merges all four
    // channels, and that hasn't run here — so a saved file with a hardcoded
    // credential got a clean problem pane, no diagnostic at all. Unlike the
    // MCP surface, this server never applied redactFinding either (nothing
    // here imported mcp/redact.js), which would have been a landmine the
    // moment secrets/logicVulns were added without it: those channels are
    // exactly where raw secret material shows up in `snippet`. Both fixed
    // together — merge the channels AND redact — so the fix for one gap
    // doesn't open the other.
    const findings = [...(scan.findings || []), ...(scan.secrets || []), ...(scan.logicVulns || [])]
      .filter(f => f.file === rel)
      .map(f => redactFinding(f));
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
    if (uri) {
      // Premortem 3R-9 / 4R-5: when the user saves a manifest file, the
      // dep-cache entry for THAT file is stale. Granular invalidation (only
      // re-read the saved file from disk) avoids the O(project) re-walk that
      // 3R-9 introduced — important in monorepos where mass manifest edits
      // would otherwise re-scan thousands of files per save.
      const savedPath = uriToPath(uri);
      if (savedPath && _depCache.rootDir === _rootDir) {
        const base = path.basename(savedPath);
        if (DEP_BASE_NAMES.has(base) || DEP_EXT_RE.test(base) || DEP_NAME_RE.test(base)) {
          try {
            const rel = path.relative(_rootDir, savedPath);
            const st = fs.statSync(savedPath);
            if (st.size <= 500_000) {
              _depCache.depFileContents[rel] = fs.readFileSync(savedPath, 'utf8');
            } else {
              delete _depCache.depFileContents[rel];
            }
          } catch {
            // File vanished between save event and stat — drop from cache.
            try {
              const rel = path.relative(_rootDir, savedPath);
              delete _depCache.depFileContents[rel];
            } catch {}
          }
        }
      }
      scanFile(uri);
    }
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

function _setRootDir(dir) { _rootDir = dir; _depCache = { rootDir: null, depFileContents: {} }; }

export const _internals = { findingToDiagnostic, scanFile, uriToPath, pathToUri, _diagnosticsByUri, _setRootDir };
