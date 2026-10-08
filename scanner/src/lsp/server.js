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

import { isLanguageManifest } from '../language/discovery.js';
import { withLanguageContext, loadLanguageProject, languageOfFinding, languageFixPreview, minimalEdit } from '../language/context.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { runScan } from '../runScan.js';
import { resetCustomRulesBudget } from '../posture/custom-rules.js';
import { withStateWritesDisabled } from '../posture/state-dir.js';
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

// The most precise location a finding carries. Haskell and Nix findings keep their ORIGINAL span (0-based columns); a
// finding with only a line is reported across that line, as before.
function _rangeOf(f) {
  const o = f && f.originalLocation;
  if (o && Number.isInteger(o.startLine) && Number.isInteger(o.startColumn)) {
    return { start: { line: Math.max(0, o.startLine - 1), character: o.startColumn }, end: { line: Math.max(0, (Number.isInteger(o.endLine) ? o.endLine : o.startLine) - 1), character: Number.isInteger(o.endColumn) ? o.endColumn : o.startColumn + 1 } };
  }
  if (o && Number.isInteger(o.line) && Number.isInteger(o.column)) {
    const line = Math.max(0, o.line - 1);
    return { start: { line, character: o.column }, end: { line, character: 200 } };
  }
  const line = Math.max(0, ((f && f.line) || 1) - 1);
  return { start: { line, character: 0 }, end: { line, character: 200 } };
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
    range: _rangeOf(f),
    severity: sevToLsp(f.severity),
    source: 'agentic-security',
    code: f.cwe || f.family || 'finding',
    // carried back by the client in codeAction requests, so a fix is offered for exactly this finding
    data: { id: f.id || null, stableId: f.stableId || null, rule: f.rule || null, family: f.family || null, language: f.language || languageOfFinding(f) || null },
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
const DEP_EXT_RE = /\.(?:proto|graphql|gql|tf|cabal)$/i;
// Haskell and Nix project manifests and lock files (cabal.project*, stack.yaml*, package.yaml, flake.lock, ...) are
// recognised by the shared language discovery module, never by a second list here.
const _isLanguageDep = (base) => isLanguageManifest(base);
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
      if (DEP_BASE_NAMES.has(base) || DEP_EXT_RE.test(base) || DEP_NAME_RE.test(base) || _isLanguageDep(base)) {
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
    let fileContents = { [rel]: content };
    let depFileContents = _loadDepFileContents(_rootDir);
    // Haskell/Nix: scan the saved file together with the modules it imports and the ones that import it (bounded).
    const lc = withLanguageContext(_rootDir, fileContents, depFileContents);
    fileContents = lc.fileContents; depFileContents = lc.depFileContents;
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
    // withStateWritesDisabled, for the same reason mcp/tools.js's scan_diff
    // wraps its own partial-set scan (FR-704). This is a DIAGNOSTIC surface: it
    // runs on every file save, against the user's real project root, with a
    // fileContents map holding exactly one file. Without the wrapper,
    // runFullScan's state writers fire on every keystroke-save — dpia.md,
    // ropa.md, privacy-framework.json, threat-model.json and the rest, written
    // into the user's tree by an editor plugin they never asked to mutate
    // anything.
    //
    // The provenance lifecycle store makes that actively destructive rather
    // than merely noisy: updateLifecycle marks every open stableId ABSENT from
    // the finding set it is handed as `remediated`, and this set is one file's
    // worth of findings. Every save would remediate the whole project, and the
    // next real scan would reintroduce it.
    //
    // Chosen over forwarding `provenance:false` through runScan because that
    // would fix only the lifecycle half and leave the other state writers
    // firing. The flag is process-global (see its KNOWN LIMITATION), which is
    // harmless here: this server is a read-only surface whose every scan wants
    // writes off, so overlapping saves can only ever agree, and the `finally`
    // restores the prior value either way. exceptCategories:['provenance-cache']
    // (M2 §2.4) is the one deliberate exception — every OTHER write this scan
    // would make stays suppressed, but the provenance disk cache stays live so
    // repeated saves of the same file are not each paying the full uncached
    // resolution cost.
    const { scan } = await withStateWritesDisabled(() =>
      runScan(_rootDir, { fileContents, depFileContents, deep: true, deepInCi: true }),
      { exceptCategories: ['provenance-cache'] });
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
      // quick fixes for Haskell and Nix findings (preview edits from the verified language fixers)
      codeActionProvider: { codeActionKinds: ['quickfix'], resolveProvider: false },
    },
    serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
  };
}

/**
 * textDocument/codeAction: a quick fix for each agentic-security diagnostic in range that a language fixer can repair.
 * The edit is a PREVIEW the editor applies; nothing is written here. A finding with no safe fix gets a disabled
 * action that says why, never a silent omission.
 */
async function codeActionsFor(params) {
  const uri = params && params.textDocument && params.textDocument.uri;
  const diags = ((params && params.context && params.context.diagnostics) || []).filter((d) => d && d.source === 'agentic-security' && d.data && d.data.id);
  const stored = (uri && _diagnosticsByUri.get(uri)) || [];
  if (!diags.length || !stored.length) return [];
  let files = null;
  const actions = [];
  for (const d of diags) {
    const f = stored.find((x) => x && x.id === d.data.id);
    if (!f || !languageOfFinding(f)) continue;
    if (!files) files = loadLanguageProject(_rootDir).files;
    let prev;
    try { prev = await languageFixPreview(f, files); } catch (e) { prev = { ok: false, reason: String((e && e.message) || e) }; }
    if (prev && prev.ok && prev.file) {
      // A fix that spans several files (the winning definitions of one option) is ONE workspace edit over all of them: offering
      // only the first file would leave the configuration in a state the verification never saw.
      const changes = {};
      for (const e of (prev.edits || [{ file: prev.file, before: prev.before, after: prev.after }])) changes[pathToUri(path.join(_rootDir, e.file))] = [minimalEdit(e.before, e.after)];
      actions.push({
        title: `Fix${prev.label ? ` (${prev.label})` : ''}: ${f.vuln || f.rule || 'finding'}`,
        kind: 'quickfix', diagnostics: [d], isPreferred: false,
        edit: { changes },
        data: { stableId: f.stableId || null, verified: { syntax: true, rescan: true } },
      });
    } else {
      actions.push({ title: `No automatic fix: ${f.vuln || f.rule || 'finding'}`, kind: 'quickfix', diagnostics: [d], disabled: { reason: (prev && (prev.reason || prev.status)) || 'no deterministic fix exists for this finding' } });
    }
  }
  return actions;
}

async function handleMessage(msg) {
  if (msg.method === 'textDocument/codeAction') {
    return { id: msg.id, result: await codeActionsFor(msg.params || {}) };
  }
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
        if (DEP_BASE_NAMES.has(base) || DEP_EXT_RE.test(base) || DEP_NAME_RE.test(base) || _isLanguageDep(base)) {
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
//
// `import.meta.url === file://${process.argv[1]}` looks equivalent but is
// NOT: when this script is invoked through a symlink (exactly what
// `npm install -g`, `npx`, and `node_modules/.bin/<name>` all do for a
// package's `bin` entries — and `agentic-security-lsp` IS one of this
// package's bin entries), Node resolves `import.meta.url` to the symlink's
// realpath while `process.argv[1]` stays the symlink path as invoked, so the
// two never match, the guard is always false, and the server silently exits
// with no output — an editor would see the language server start and
// immediately die with nothing on stderr to explain it. `import.meta.main` is
// resolved correctly through a symlink. It was added in Node v24.2.0
// (backported to v22.18.0) and is currently Stability 1.0 (early development)
// per Node's own docs — NOT stable, and NOT available on v20.11. Concretely:
// it is `undefined` on Node 24.0.0/24.1.x, which satisfy this repo's declared
// `engines.node: ">=24.0.0"` floor, so `import.meta.main` alone would
// reproduce this exact bug on a plain non-symlinked invocation under those two
// point releases. The `??` fallback covers that gap without bumping the
// engines floor. Identical to bin/agentic-security.js's guard, deliberately —
// see the long-form note there.
if (import.meta.main ?? (import.meta.url === `file://${process.argv[1]}`)) {
  startLspServer();
}

function _setRootDir(dir) { _rootDir = dir; _depCache = { rootDir: null, depFileContents: {} }; }

export const _internals = { findingToDiagnostic, scanFile, uriToPath, pathToUri, _diagnosticsByUri, _setRootDir };
