// X-014: CLI, hooks, MCP, LSP, IDE and CI parity for Haskell and Nix. Tests are tagged [X-014.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { minimalEdit } from '../../src/language/context.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..', '..');
const REPO = path.join(SCANNER, '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');
const MCP = path.join(SCANNER, 'bin', 'agentic-security-mcp.js');
const LSP = path.join(SCANNER, 'bin', 'agentic-security-lsp.js');
const require = createRequire(import.meta.url);

const HS_BAD = 'module App where\nimport System.Process (callCommand)\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  callCommand ("echo " ++ name)\n';
const HS_OK = 'module App where\n\nrun :: IO ()\nrun = do\n  name <- getLine\n  putStrLn ("hello " ++ name)\n';
const NIX_BAD = '{ config, pkgs, lib, ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = "yes";\n}\n';
const NIX_OK = '{ config, pkgs, lib, ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = "no";\n  services.openssh.settings.PasswordAuthentication = false;\n  services.openssh.settings.KbdInteractiveAuthentication = false;\n}\n';

const proj = (files) => { const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'x014-'))); fs.writeFileSync(path.join(d, 'package.json'), '{}'); for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(d, f)), { recursive: true }); fs.writeFileSync(path.join(d, f), t); } return d; };
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const cli = (cwd, args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', AGENTIC_SECURITY_OFFLINE: '1', ...env }, timeout: 240_000, maxBuffer: 1 << 26 });

// ── AC01: CLI and hook simulations ───────────────────────────────────────────
test('[X-014.AC01] the pre-edit hook flags vulnerable Haskell and Nix, and lets safe examples through', async () => {
  const { evaluate } = require(path.join(REPO, 'hooks', 'pre-edit-bodyguard.js'));
  const cwd = process.cwd();
  const ev = (file, content) => evaluate({ tool_name: 'Write', tool_input: { file_path: path.join(cwd, file), content } });
  const bad = [['src/App.hs', 'run = do\n  n <- getLine\n  callCommand ("echo " ++ n)\n', 'hs-cmd'], ['src/Db.hs', 'save conn n = execute conn ("INSERT INTO t VALUES (" ++ n ++ ")") ()\n', 'hs-sql'], ['src/Net.hs', 'm <- newManager (mkManagerSettings (TLSSettingsSimple True False False) Nothing)\n', 'hs-tls'], ['configuration.nix', '{ services.openssh.settings.PermitRootLogin = "yes"; }\n', 'nix-root'], ['configuration.nix', 'networking.firewall.enable = false;\n', 'nix-fw'], ['configuration.nix', 'script = \'\'\n    cp a ${cfg.dest}\n\'\';\n', 'nix-script']];
  for (const [f, c, id] of bad) { const d = await ev(f, c); assert.notEqual(d.action, 'allow', `${id}: a vulnerable edit is flagged`); assert.match(d.message, /agentic-security bodyguard/); }
  const safe = [['src/App.hs', 'run = do\n  n <- getLine\n  callProcess "echo" [n]\n'], ['src/Db.hs', 'save conn n = execute conn "INSERT INTO t VALUES (?)" (Only n)\n'], ['configuration.nix', '{ services.openssh.settings.PermitRootLogin = "no"; }\n'], ['configuration.nix', 'script = \'\'\n    cp a ${lib.escapeShellArg cfg.dest}\n\'\';\n']];
  for (const [f, c] of safe) assert.equal((await ev(f, c)).action, 'allow', `safe example allowed: ${c.slice(0, 40)}`);
  // the rules are language-scoped: Haskell text in a JS file is not judged by a Haskell rule
  assert.equal((await ev('src/app.js', 'const s = "x"; // callCommand ("echo " ++ n)\n')).action, 'allow');
});

test('[X-014.AC01] the post-edit hook scans a Haskell file through the CLI and reports only NEW high/critical findings', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'x014-plugin-'));
  const p = proj({ 'src/App.hs': HS_BAD });
  try {
    fs.mkdirSync(path.join(root, 'scanner', 'dist'), { recursive: true });
    // the hook runs the bundled CLI; point it at the source entry point through a stub with the same argv contract
    fs.writeFileSync(path.join(root, 'scanner', 'dist', 'agentic-security.mjs'), `import { spawnSync } from 'node:child_process';\nconst r = spawnSync(process.execPath, [${JSON.stringify(CLI)}, ...process.argv.slice(2)], { stdio: 'inherit' });\nprocess.exit(r.status === null ? 1 : r.status);\n`);
    const run = (file) => spawnSync(process.execPath, [path.join(REPO, 'hooks', 'post-edit-scan.js')], {
      input: JSON.stringify({ tool_name: 'Edit', tool_input: { file_path: path.join(p, file) } }), encoding: 'utf8',
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: root, CLAUDE_PROJECT_DIR: p, AGENTIC_SECURITY_OFFLINE: '1', AGENTIC_SECURITY_DEEP: '1' }, timeout: 120_000,
    });
    const r = run('src/App.hs');
    assert.match(r.stderr, /OS Command Injection|CWE-78|command/i, `the hook reports the Haskell finding: ${r.stderr.slice(0, 300)}`);
    fs.writeFileSync(path.join(p, 'src', 'App.hs'), HS_OK);
    fs.rmSync(path.join(p, '.agentic-security', 'hook-throttle.json'), { force: true });
    const r2 = run('src/App.hs');
    assert.doesNotMatch(r2.stderr, /Command Injection/, 'the fixed file reports nothing');
  } finally { rm(root); rm(p); }
});

test('[X-014.AC01] no filter silently excludes the newly supported files: they are found in every common project layout', () => {
  const layout = {
    'app/Main.hs': HS_BAD, 'src/Lib/Util.hs': 'module Lib.Util where\nimport System.Process (callCommand)\nu :: IO ()\nu = do\n  n <- getLine\n  callCommand ("a " ++ n)\n',
    'Setup.hs': 'import Distribution.Simple\nimport System.Process (callCommand)\nmain :: IO ()\nmain = do\n  n <- getLine\n  callCommand ("b " ++ n)\n',
    'test/Spec.hs': 'module Spec where\nimport System.Process (callCommand)\ns :: IO ()\ns = do\n  n <- getLine\n  callCommand ("c " ++ n)\n',
    'configuration.nix': NIX_BAD, 'hosts/box/configuration.nix': NIX_BAD, 'modules/ssh.nix': NIX_BAD,
    'demo.cabal': 'cabal-version: 2.4\nname: demo\nversion: 0.1\nexecutable demo\n  main-is: Main.hs\n  hs-source-dirs: app\n  build-depends: base\n',
  };
  const p = proj(layout);
  try {
    const r = cli(p, ['scan', '.', '--format', 'json', '--no-provenance']);
    const j = JSON.parse(r.stdout);
    const files = new Set(j.findings.map((f) => f.file));
    for (const f of ['app/Main.hs', 'src/Lib/Util.hs', 'Setup.hs', 'configuration.nix']) assert.ok(files.has(f), `${f} was scanned and reported`);
    assert.ok([...files].some((f) => f === 'hosts/box/configuration.nix') || files.has('configuration.nix'), 'a nested host configuration is analysed');
    assert.equal(j.scanHealth.languageCoverage.totals.discovered, 6, 'every scanned source is accounted for in the ledger: 3 Haskell + 3 Nix');
    const lim = j.scanHealth.languageCoverage.limitations.find((l) => l.kind === 'default-ignore');
    assert.ok(lim && lim.files.includes('test/Spec.hs'), 'the test source the default ignore list kept out is NOT silent: it is listed as a limitation');
    assert.equal(r.status, 3);
  } finally { rm(p); }
});

// ── AC02: MCP and LSP over real stdio ────────────────────────────────────────
function mcpSession(root, requests) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [MCP, '--root', root], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' } });
    let out = ''; let err = '';
    c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; });
    for (const q of requests) c.stdin.write(`${JSON.stringify(q)}\n`);
    const want = requests.filter((q) => q.id !== undefined).length;
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (out.trim().split('\n').filter(Boolean).length >= want || Date.now() - t0 > 90_000) { clearInterval(iv); c.stdin.end(); setTimeout(() => { c.kill('SIGKILL'); resolve({ out, err }); }, 300); }
    }, 100);
  });
}
const call = (id, name, args) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
const unwrap = (msg) => JSON.parse(msg.result.content[0].text);

test('[X-014.AC02] MCP scan_diff, explain_finding, synthesize_fix and verify_fix work for Haskell and Nix over stdio, with clean framing', async () => {
  const p = proj({ 'src/App.hs': HS_BAD, 'configuration.nix': NIX_BAD });
  try {
    const sc = cli(p, ['scan', '.', '--format', 'json', '--no-provenance']); assert.equal(sc.status, 3);
    const last = JSON.parse(fs.readFileSync(path.join(p, '.agentic-security', 'last-scan.json'), 'utf8'));
    const hs = last.findings.find((f) => f.file === 'src/App.hs'); const nx = last.findings.find((f) => f.rule === 'ssh-root-login');
    assert.ok(hs && nx);
    const { out, err } = await mcpSession(p, [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } },
      call(2, 'scan_diff', { files: ['src/App.hs', 'configuration.nix'] }),
      call(3, 'explain_finding', { finding_id: hs.id }),
      call(4, 'synthesize_fix', { finding_id: nx.id }),
      call(5, 'verify_fix', { stable_id: nx.stableId, files: { 'configuration.nix': NIX_OK } }),
      call(6, 'verify_fix', { stable_id: nx.stableId, files: { 'configuration.nix': NIX_BAD + '# unrelated edit\n' } }),
    ]);
    const lines = out.trim().split('\n').filter(Boolean);
    for (const l of lines) { const m = JSON.parse(l); assert.equal(m.jsonrpc, '2.0', 'every stdout line is a JSON-RPC message (stderr logging never leaks into the stream)'); }
    assert.match(err, /session root/, 'the server logs to stderr');
    const by = new Map(lines.map((l) => { const m = JSON.parse(l); return [m.id, m]; }));
    const scan = unwrap(by.get(2));
    assert.ok(scan.findings.some((f) => f.file === 'src/App.hs' && f.line === 7 && f.severity === 'critical'), 'scan_diff reports the Haskell finding at its real file and line');
    assert.ok(scan.findings.some((f) => f.file === 'configuration.nix' && f.cwe), 'and the Nix finding');
    const ex = unwrap(by.get(3));
    assert.equal(ex.file, 'src/App.hs'); assert.match(ex.snippet, /callCommand/); assert.ok(ex.remediation);
    const fix = unwrap(by.get(4));
    assert.equal(fix.ok, true); assert.ok(fix.autofix && fix.autofix.verified === true && /PermitRootLogin = "no"|"no"/.test(fix.autofix.patch), 'a verified fix preview, read-only');
    assert.ok(['FULL', 'MITIGATION', 'WORKAROUND'].includes(fix.languageFix.label));
    assert.equal(fs.readFileSync(path.join(p, 'configuration.nix'), 'utf8'), NIX_BAD, 'synthesize_fix wrote nothing');
    const good = unwrap(by.get(5)); const noop = unwrap(by.get(6));
    assert.equal(good.rescan.ok, true, 'a patch that removes the Nix finding verifies');
    assert.equal(noop.rescan.ok, false); assert.equal(noop.rescan.reason, 'original-finding-still-present', 'a patch that changes nothing relevant does NOT verify');
    // the Haskell original is judged too: leaving the sink in place never verifies
    const hsNoop = (await mcpSession(p, [{ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } }, call(2, 'verify_fix', { stable_id: hs.stableId, files: { 'src/App.hs': `${HS_BAD}\n-- touched\n` } }), call(3, 'verify_fix', { stable_id: hs.stableId, files: { 'src/App.hs': HS_OK } })])).out;
    const hb = new Map(hsNoop.trim().split('\n').filter(Boolean).map((l) => { const m = JSON.parse(l); return [m.id, m]; }));
    assert.equal(unwrap(hb.get(2)).rescan.ok, false, 'an unchanged Haskell sink is still reported by the verifier');
    assert.equal(unwrap(hb.get(3)).rescan.ok, true, 'the argv form verifies');
  } finally { rm(p); }
});

function lspSession(root, steps) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [LSP], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' } });
    let buf = Buffer.alloc(0); const msgs = []; let err = '';
    c.stdout.on('data', (d) => { buf = Buffer.concat([buf, d]); for (;;) { const he = buf.indexOf('\r\n\r\n'); if (he < 0) break; const m = /Content-Length:\s*(\d+)/i.exec(buf.slice(0, he).toString()); if (!m) break; const len = Number(m[1]); if (buf.length < he + 4 + len) break; msgs.push(JSON.parse(buf.slice(he + 4, he + 4 + len).toString())); buf = buf.slice(he + 4 + len); } });
    c.stderr.on('data', (d) => { err += d; });
    const send = (o) => { const j = JSON.stringify({ jsonrpc: '2.0', ...o }); c.stdin.write(`Content-Length: ${Buffer.byteLength(j)}\r\n\r\n${j}`); };
    const waitFor = (pred, ms = 60_000) => new Promise((r) => { const t0 = Date.now(); const iv = setInterval(() => { const hit = msgs.find(pred); if (hit || Date.now() - t0 > ms) { clearInterval(iv); r(hit); } }, 50); });
    steps({ send, waitFor, msgs, raw: (s) => c.stdin.write(s), stop: () => { try { send({ method: 'shutdown', id: 9999 }); send({ method: 'exit' }); } catch { /* closed */ } setTimeout(() => { c.kill('SIGKILL'); resolve({ msgs, err }); }, 400); } });
  });
}

test('[X-014.AC02] LSP: precise Haskell/Nix diagnostics and verified quick fixes, framing intact when the server logs to stderr', async () => {
  const p = proj({ 'src/App.hs': HS_BAD, 'configuration.nix': NIX_BAD });
  try {
    const uriNix = pathToFileURL(path.join(p, 'configuration.nix')).href; const uriHs = pathToFileURL(path.join(p, 'src', 'App.hs')).href;
    let result;
    await lspSession(p, async ({ send, waitFor, raw, stop, msgs }) => {
      send({ id: 1, method: 'initialize', params: { rootUri: pathToFileURL(p).href, capabilities: {} } });
      const init = await waitFor((m) => m.id === 1);
      raw('Content-Length: 5\r\n\r\n{bad}');                                   // malformed JSON: logged to stderr, never answered with garbage
      raw('this is not a header\r\n\r\n');
      send({ method: 'initialized', params: {} });
      send({ method: 'textDocument/didSave', params: { textDocument: { uri: uriHs } } });
      const hsDiag = await waitFor((m) => m.method === 'textDocument/publishDiagnostics' && m.params.uri === uriHs && m.params.diagnostics.length);
      send({ method: 'textDocument/didSave', params: { textDocument: { uri: uriNix } } });
      const nixDiag = await waitFor((m) => m.method === 'textDocument/publishDiagnostics' && m.params.uri === uriNix && m.params.diagnostics.length);
      const root = nixDiag && nixDiag.params.diagnostics.find((d) => d.data && d.data.rule === 'ssh-root-login');
      send({ id: 2, method: 'textDocument/codeAction', params: { textDocument: { uri: uriNix }, range: root ? root.range : { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }, context: { diagnostics: root ? [root] : [] } } });
      const actions = await waitFor((m) => m.id === 2);
      result = { init, hsDiag, nixDiag, root, actions, count: msgs.length };
      stop();
    });
    assert.ok(result.init.result.capabilities.codeActionProvider, 'the server advertises code actions');
    const hd = result.hsDiag.params.diagnostics[0];
    assert.equal(hd.range.start.line, 6, 'the Haskell diagnostic is on line 7 (0-based 6)'); assert.equal(hd.source, 'agentic-security'); assert.equal(hd.data.language, 'haskell');
    assert.ok(result.root, 'the Nix root-login diagnostic carries its rule id');
    assert.equal(result.root.range.start.line, 3, 'at the option that decides it (line 4)');
    const act = result.actions.result.find((a) => /^Fix/.test(a.title));
    assert.ok(act, `a quick fix is offered: ${JSON.stringify(result.actions.result).slice(0, 300)}`);
    assert.equal(act.kind, 'quickfix'); assert.ok(act.edit.changes[pathToFileURL(path.join(p, 'configuration.nix')).href]);
    // applying the edit yields a configuration the scanner no longer flags
    const edit = act.edit.changes[pathToFileURL(path.join(p, 'configuration.nix')).href][0];
    const L = NIX_BAD.split('\n'); const off = (pos) => L.slice(0, pos.line).reduce((n, l) => n + l.length + 1, 0) + pos.character;
    const patched = NIX_BAD.slice(0, off(edit.range.start)) + edit.newText + NIX_BAD.slice(off(edit.range.end));
    fs.writeFileSync(path.join(p, 'configuration.nix'), patched);
    const after = JSON.parse(cli(p, ['scan', '.', '--format', 'json', '--no-provenance']).stdout);
    assert.equal(after.findings.some((f) => f.rule === 'ssh-root-login'), false, 'the quick fix removes the finding');
    // a finding with no safe fix gets a disabled action with a reason, never silence
    assert.ok(minimalEdit('a\nb', 'a\nb\nc').newText.includes('c'));
  } finally { rm(p); }
});

// ── AC03: IDE language registration ──────────────────────────────────────────
test('[X-014.AC03] VS Code, JetBrains and Neovim register Haskell and Nix source and project metadata', () => {
  const vs = JSON.parse(fs.readFileSync(path.join(REPO, 'ide', 'vscode', 'package.json'), 'utf8'));
  for (const e of ['onLanguage:haskell', 'onLanguage:nix', 'onLanguage:cabal', 'workspaceContains:**/*.cabal', 'workspaceContains:**/flake.nix']) assert.ok(vs.activationEvents.includes(e), `VS Code activates on ${e}`);
  const ext = fs.readFileSync(path.join(REPO, 'ide', 'vscode', 'src', 'extension.ts'), 'utf8');
  const m = /if \(!\/(\\\.\([^/]+\))\$\/i\.test\(doc\.fileName\)/.exec(ext); assert.ok(m, 'the on-save extension filter exists');
  const re = new RegExp(`${m[1]}$`, 'i');
  const proj2 = /\|\|\s*(?:\n\s*)?\s*!\/(\(\?:\^\|\[\\\\\/\]\)\(\?:[^/]+\)\$)\/i\.test\(doc\.fileName\)/.exec(ext) || /&&\s*\n?\s*!\/(\(\?:\^\|\[\\\\\/\]\)\(\?:[^/]+\)\$)\/i\.test\(doc\.fileName\)/.exec(ext);
  for (const f of ['A.hs', 'A.lhs', 'a.nix', 'demo.cabal', 'C.hsc']) assert.ok(re.test(f), `on-save scans ${f}`);
  assert.ok(proj2, 'the on-save filter also names project files');
  const pr = new RegExp(proj2[1], 'i');
  for (const f of ['cabal.project', 'cabal.project.freeze', 'stack.yaml', 'stack.yaml.lock', 'package.yaml', 'flake.lock', '/x/cabal.project.local']) assert.ok(pr.test(f), `on-save scans ${f}`);
  assert.equal(pr.test('notstack.yaml'), false);
  const xml = fs.readFileSync(path.join(REPO, 'ide', 'jetbrains', 'src', 'main', 'resources', 'META-INF', 'plugin.xml'), 'utf8');
  assert.match(xml, /<languageMapping language="Haskell"/); assert.match(xml, /<languageMapping language="Nix"/);
  const pat = /<fileNamePatternMapping patterns="([^"]+)"/.exec(xml); assert.ok(pat);
  for (const g of ['*.hs', '*.nix', '*.cabal', 'cabal.project', 'cabal.project.freeze', 'stack.yaml', 'package.yaml', 'flake.lock']) assert.ok(pat[1].split(';').includes(g), `JetBrains matches ${g}`);
  const lua = fs.readFileSync(path.join(REPO, 'ide', 'nvim', 'lua', 'agentic-security', 'init.lua'), 'utf8');
  for (const ft of ['"haskell"', '"lhaskell"', '"cabal"', '"nix"']) assert.ok(lua.includes(ft), `Neovim attaches for ${ft}`);
  for (const root of ['"cabal.project"', '"stack.yaml"', '"flake.nix"']) assert.ok(lua.includes(root), `Neovim recognises the project root marker ${root}`);
});

test('[X-014.AC03] the executable protocol fixture each IDE runs: the exact command VS Code issues, and the LSP both JetBrains and Neovim attach to', async () => {
  const p = proj({ 'src/App.hs': HS_BAD, 'configuration.nix': NIX_BAD });
  try {
    // VS Code: `node <scanner> scan <folder> --no-network --format json` (ide/vscode/src/extension.ts)
    const r = cli(p, ['scan', p, '--no-network', '--format', 'json']);
    assert.ok([0, 1, 2, 3].includes(r.status)); const j = JSON.parse(r.stdout);
    const diag = j.findings.filter((f) => /\.(hs|nix)$/.test(f.file)).map((f) => ({ file: f.file, line: Math.max(0, (f.line || 1) - 1), sev: f.severity }));
    assert.ok(diag.some((d) => d.file === 'src/App.hs' && d.line === 6) && diag.some((d) => d.file === 'configuration.nix'), 'the extension would publish diagnostics for both files');
    // JetBrains (LSP4IJ) and Neovim (vim.lsp.start) both launch `agentic-security-lsp`: bin name and entry point exist
    const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
    assert.ok(pkg.bin['agentic-security-lsp'] && fs.existsSync(path.join(SCANNER, pkg.bin['agentic-security-lsp'])));
  } finally { rm(p); }
});

// ── AC04: CI, strict, predeploy and pipeline/container checks ────────────────
test('[X-014.AC04] ci fails on bad Haskell and Nix fixtures and passes clean, complete ones, keeping the documented exit codes', () => {
  const bad = proj({ 'src/App.hs': HS_BAD, 'configuration.nix': NIX_BAD });
  const clean = proj({ 'src/App.hs': HS_OK, 'configuration.nix': NIX_OK });
  try {
    const b = cli(bad, ['ci', '.', '--fail-on', 'critical', '--no-provenance']);
    assert.notEqual(b.status, 0, 'a critical Haskell finding fails the gate'); assert.match(b.stderr, /1 critical/);
    assert.equal(cli(bad, ['ci', '.', '--fail-on', 'critical', '--no-provenance'], { CI: 'true' }).status, b.status, 'the same verdict in a CI environment (Haskell taint is not skipped there)');
    const hi = cli(bad, ['ci', '.', '--fail-on', 'high', '--no-provenance']); assert.notEqual(hi.status, 0);
    const c = cli(clean, ['ci', '.', '--fail-on', 'medium', '--assurance', 'strict', '--no-provenance']);
    assert.equal(c.status, 0, `a clean, complete scan passes even under strict: ${c.stderr.slice(0, 300)}`);
    // an explicitly disabled deep layer is not silent, and strict assurance refuses to pass it
    const off = cli(clean, ['ci', '.', '--assurance', 'strict', '--no-provenance'], { AGENTIC_SECURITY_DEEP: '0' });
    assert.notEqual(off.status, 0); assert.match(off.stderr, /strict mode requires a fully complete scan/);
    const std = cli(clean, ['ci', '.', '--assurance', 'standard', '--no-provenance'], { AGENTIC_SECURITY_DEEP: '0' });
    assert.equal(std.status, 0, 'standard assurance reports the gap without failing the build');
    // the predeploy gate reads the same persisted scan
    cli(bad, ['scan', '.', '--format', 'json', '--no-provenance']);
    const gate = spawnSync('bash', [path.join(REPO, 'scripts', 'predeploy-gate.sh'), 'check'], { cwd: bad, encoding: 'utf8', timeout: 60_000 });
    assert.notEqual(gate.status, 0, `predeploy blocks on the critical Haskell finding: ${gate.stdout.slice(0, 200)}`);
    cli(clean, ['scan', '.', '--format', 'json', '--no-provenance']);
    const gate2 = spawnSync('bash', [path.join(REPO, 'scripts', 'predeploy-gate.sh'), 'check'], { cwd: clean, encoding: 'utf8', timeout: 60_000 });
    assert.equal(gate2.status, 0, `predeploy passes the clean fixture: ${gate2.stdout.slice(-200)}`);
  } finally { rm(bad); rm(clean); }
});

test('[X-014.AC04] pipeline, Dockerfile and compose analyzers see Haskell and Nix project contexts, and container limits stay explicit', () => {
  const WF = 'name: ci\non:\n  pull_request_target:\nenv:\n  HACKAGE_TOKEN: ${{ secrets.HACKAGE_TOKEN }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: haskell-actions/setup@v2\n      - run: curl -sSf https://get-ghcup.haskell.org | sh\n      - run: nix run github:someone/tool -- --go\n      - run: nix build --accept-flake-config\n      - run: cabal build all\n';
  const WF_OK = 'name: ci\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v4\n      - uses: haskell-actions/setup@0123456789abcdef0123456789abcdef01234567\n      - run: nix run github:someone/tool/0123456789abcdef0123456789abcdef01234567 -- --go\n      - run: cabal build all\n';
  const bad = proj({ '.github/workflows/ci.yml': WF, Dockerfile: 'FROM haskell:latest\nWORKDIR /app\nCOPY . .\nRUN stack build --system-ghc\nCMD ["stack", "exec", "app"]\n', 'docker-compose.yml': 'services:\n  app:\n    build: .\n    privileged: true\n', 'app/Main.hs': 'module Main where\nmain :: IO ()\nmain = pure ()\n', 'configuration.nix': '{ config, ... }: { virtualisation.oci-containers.containers.web = { image = "nginx:latest"; }; }\n' });
  const good = proj({ '.github/workflows/ci.yml': WF_OK, Dockerfile: 'FROM haskell:9.4.7@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nUSER 1000\nWORKDIR /app\nCOPY app/ app/\nCMD ["app"]\n', 'app/Main.hs': 'module Main where\nmain :: IO ()\nmain = pure ()\n' });
  try {
    const j = JSON.parse(cli(bad, ['scan', '.', '--format', 'json', '--no-provenance']).stdout);
    const v = j.findings.map((f) => `${f.file}|${f.vuln}`).join('\n');
    for (const re of [/ci\.yml\|Pipeline: remote script piped into a shell/, /ci\.yml\|Pipeline: Nix flake reference executed without a pinned revision/, /ci\.yml\|Pipeline: Nix evaluation or build trust relaxed/, /ci\.yml\|Pipeline: secret exposed at workflow-wide environment scope/, /ci\.yml\|Pipeline: pull_request_target checks out untrusted/, /Dockerfile\|Base image "haskell:latest"/, /docker-compose\.yml\|docker-compose: privileged/]) assert.match(v, re);
    assert.ok(j.scanHealth.languageCoverage.limitations.some((l) => l.kind === 'container-image-scan' && /NOT scanned/.test(l.note)), 'the Nix OCI declaration discloses that images are not layer-scanned');
    const g = JSON.parse(cli(good, ['scan', '.', '--format', 'json', '--no-provenance']).stdout);
    assert.deepEqual(g.findings.filter((f) => /ci\.yml|Dockerfile/.test(f.file) && /Pipeline|Base image|Dockerfile/.test(f.vuln)).map((f) => f.vuln), [], 'the pinned, least-privilege fixture is clean');
  } finally { rm(bad); rm(good); }
});
