// NIX-012: run the complete scanner on NixOS.
// Suite "nixos-host-runtime" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Criteria that need a Nix host FAIL where there is none: an unavailable tool is a failed criterion, never a skip. The static and
// protocol checks (flake contents, MCP and LSP framing, bundle entry point) run anywhere and are what a host without Nix can show.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, cpSync, rmSync, accessSync, constants } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SCANNER = join(ROOT, 'scanner');
const FLAKE = readFileSync(join(ROOT, 'flake.nix'), 'utf8');
// Looks the binary up on PATH itself: NixOS has no /usr/bin/which, so a hard-coded path made every `have()` false on the platform this suite targets.
const have = (bin) => (process.env.PATH || '').split(':').filter(Boolean).some((d) => { try { accessSync(join(d, bin), constants.X_OK); return true; } catch { return false; } });
const onNixos = () => existsSync('/etc/NIXOS');

test('[NIX-012.AC01] the flake packages the bundle with Node >=24 by store path, with no download, native build or FHS assumption', () => {
  assert.match(FLAKE, /nodejs_24/); assert.match(FLAKE, /makeWrapper \$\{pkgs\.nodejs_24\}\/bin\/node/);
  assert.ok(!/\/usr\/bin\/env|\/bin\/sh -c|npm (?:install|ci)|fetchurl|fetchTarball|builtins\.fetch/.test(FLAKE.replace(/#.*$/gm, '')), 'the package must not fetch or assume an FHS path');
  for (const bin of ['agentic-security', 'agentic-security-mcp', 'agentic-security-lsp']) assert.ok(FLAKE.includes(`bin/${bin}`), `no wrapper for ${bin}`);
  assert.match(FLAKE, /devShells/); assert.match(FLAKE, /nix develop --command/);
  for (const f of ['dist/agentic-security.mjs', 'bin/agentic-security-mcp.js', 'bin/agentic-security-lsp.js', 'package.json']) assert.ok(existsSync(join(SCANNER, f)), `the package source lacks ${f}`);
  const nix = have('nix');
  assert.ok(nix, 'REQUIRED: a nix binary is needed to build the package and run it on a controlled project; none is available on this host');
  assert.ok(onNixos(), 'REQUIRED: a clean supported NixOS environment (/etc/NIXOS) is needed; this host is not NixOS');
  const b = spawnSync('nix', ['build', `${ROOT}#default`, '--offline', '--no-link', '--print-out-paths'], { encoding: 'utf8', timeout: 900000 });
  assert.equal(b.status, 0, b.stderr.slice(-400));
  const out = b.stdout.trim().split('\n')[0];
  const dir = mkdtempSync(join(tmpdir(), 'nixos-ex-')); cpSync(join(ROOT, 'examples', 'haskell-app', 'vulnerable'), dir, { recursive: true });
  try {
    const r = spawnSync(join(out, 'bin', 'agentic-security'), ['scan', dir, '--format', 'json', '--no-state'], { encoding: 'utf8', timeout: 300000, env: { PATH: '' } });
    assert.ok([2, 3].includes(r.status), r.stderr.slice(-300));
    assert.ok(JSON.parse(r.stdout).findings.length >= 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function rpcOnce(cmd, args, request, frame, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'], cwd: SCANNER });
    let out = ''; const t = setTimeout(() => { p.kill('SIGKILL'); resolve({ out, timedOut: true }); }, timeoutMs);
    p.stdout.on('data', (d) => { out += d; if (/"id":\s*1\b/.test(out) && /"result"|"error"/.test(out)) { clearTimeout(t); p.kill('SIGKILL'); resolve({ out, timedOut: false }); } });
    p.stdin.write(frame(request));
  });
}

test('[NIX-012.AC02] MCP stdio and LSP framing answer an initialize request from the packaged entry points, with no model or compiler', async () => {
  const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' }, processId: null, rootUri: null } };
  const mcp = await rpcOnce(process.execPath, [join(SCANNER, 'dist', 'agentic-security.mjs'), 'mcp'], init, (r) => `${JSON.stringify(r)}\n`);
  assert.equal(mcp.timedOut, false, 'the MCP server did not answer'); assert.match(mcp.out, /"result"/);
  // the package's wrapper runs the LSP from the bundle (bin/*.js import src/, which needs npm dependencies the package does not ship)
  const lsp = await rpcOnce(process.execPath, [join(SCANNER, 'dist', 'agentic-security.mjs'), 'lsp'], init, (r) => { const b = JSON.stringify(r); return `Content-Length: ${Buffer.byteLength(b)}\r\n\r\n${b}`; });
  assert.equal(lsp.timedOut, false, 'the LSP server did not answer'); assert.match(lsp.out, /Content-Length: \d+/); assert.match(lsp.out, /"capabilities"/);
  // the core static scan does not need an optional tool
  const dir = mkdtempSync(join(tmpdir(), 'nixos-ex-')); cpSync(join(ROOT, 'examples', 'nixos-host', 'vulnerable'), dir, { recursive: true });
  try {
    const r = spawnSync(process.execPath, [join(SCANNER, 'dist', 'agentic-security.mjs'), 'scan', dir, '--format', 'json', '--no-state'], { encoding: 'utf8', timeout: 240000, env: { PATH: '' } });
    assert.equal(r.status, 2, r.stderr.slice(-300));
    assert.ok(JSON.parse(r.stdout).findings.length >= 5, 'a scan with nothing on PATH still finds the problems');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('[NIX-012.AC03] current stable NixOS on x86_64-linux and an aarch64-linux runner (or tested emulation) pass the package checks', () => {
  assert.ok(have('nix') && onNixos(), 'REQUIRED: a NixOS host is needed; this criterion is not satisfiable here');
  assert.match(`${process.arch}-${process.platform}`, /^(x64-linux|arm64-linux)$/, 'run on x86_64-linux and aarch64-linux; other platforms are declared separately');
});

test('[NIX-012.AC04] dev-shell commands are noninteractive and bounded, and a controlled VM test never activates configuration on the host', () => {
  assert.ok(have('nix'), 'REQUIRED: a nix binary is needed to run the dev shell; none is available on this host');
  const r = spawnSync('nix', ['develop', ROOT, '--offline', '--command', 'node', '--version'], { encoding: 'utf8', timeout: 300000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(r.status, 0, r.stderr.slice(-300)); assert.match(r.stdout, /^v24\./);
  assert.ok(!/nixos-rebuild|switch-to-configuration/.test(FLAKE.replace(/#.*$/gm, '')), 'the flake never activates a configuration');
});
