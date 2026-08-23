// PRD F11.1 remainder — MCP end to end, over stdio, through the SHIPPED binary.
//
// `test/mcp.test.js` is thorough and almost entirely in-process: it imports
// `createServer` and calls `handleRequest` directly. That measures the server
// logic and says nothing about the thing a user actually runs. The same gap
// existed for the LSP until `test/lsp-protocol-smoke.test.js` closed it, and
// the gap there was real — `bin/agentic-security-lsp.js` was referenced by no
// test, no script and no workflow.
//
// The case that matters is the pair of WRITE tools. `apply_fix` and
// `apply_sca_upgrade` are the only two tools in the server that can modify a
// file, and the confinement they rely on is established in the *binary*
// (`_parseRoot` → `path.resolve` → `runStdio({ sessionRoot })`), not in the
// handler under test. An in-process test constructs `sessionRoot` itself and
// therefore cannot catch a binary that resolves the root wrongly, drops the
// argument, or falls back to `process.cwd()`.
//
// So every refusal here is asserted through a real child process speaking real
// NDJSON, and every one is checked in BOTH directions: the tool refused, AND
// the out-of-tree file on disk is byte-identical afterwards. A refusal message
// is a string; an unmodified file is the property.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { signLastScan } from '../src/posture/integrity.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const MCP_BIN = path.join(REPO_ROOT, 'bin', 'agentic-security-mcp.js');

// A run of the shipped binary: write every request, read every response,
// close stdin, wait for exit. Returns responses keyed by JSON-RPC id so a
// test never depends on ordering, plus the exit code and stderr.
//
// The 15 s ceiling exists because the failure this file is most likely to
// catch — a server that neither answers nor exits — presents as a hang, and a
// hung test in a gate is indistinguishable from a broken machine.
async function rpc(requests, { root, env = {} } = {}) {
  const child = spawn(process.execPath, [MCP_BIN, '--root', root], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, ...env },
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  for (const req of requests) child.stdin.write(JSON.stringify(req) + '\n');

  const seen = () => stdout.trim().split('\n').filter(Boolean).length;
  const deadline = Date.now() + 15_000;
  while (seen() < requests.length && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  child.stdin.end();
  const exitCode = await new Promise((resolve) => {
    const t = setTimeout(() => { child.kill('SIGKILL'); resolve('TIMEOUT'); }, 5000);
    child.on('exit', (c) => { clearTimeout(t); resolve(c); });
  });

  const byId = new Map();
  for (const line of stdout.trim().split('\n').filter(Boolean)) {
    const msg = JSON.parse(line);
    byId.set(msg.id, msg);
  }
  return { byId, exitCode, stderr, raw: stdout };
}

// tools/call responses carry their payload as JSON inside a text content
// block — the same unwrapping every MCP client has to do.
function payload(msg) {
  assert.ok(msg, 'no response for that request id');
  assert.ok(msg.result, `expected a result, got: ${JSON.stringify(msg.error)}`);
  return JSON.parse(msg.result.content[0].text);
}

// A session root with a SIGNED last-scan.json. `apply_fix` and
// `apply_sca_upgrade` both refuse unsigned state outright, so an unsigned
// fixture would pass every refusal assertion here for entirely the wrong
// reason — the confinement check would never be reached.
async function session(findings) {
  const outer = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-smoke-'));
  const root = path.join(outer, 'project');
  const stateDir = path.join(root, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.writeFile(path.join(root, 'package.json'), '{"name":"smoke","version":"1.0.0"}');
  const body = JSON.stringify({ findings });
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), body);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  // The out-of-tree target lives beside the root, not inside it.
  const outside = path.join(outer, 'outside');
  await fsp.mkdir(outside, { recursive: true });
  const target = path.join(outside, 'target.txt');
  await fsp.writeFile(target, 'UNTOUCHED');
  return {
    outer, root, outside, target,
    cleanup: () => fsp.rm(outer, { recursive: true, force: true }).catch(() => {}),
  };
}

const PWNED = 'PWNED-BY-MCP-SMOKE';

// ─── The binary boots and speaks the protocol ────────────────────────────────

test('shipped mcp bin: initialize → tools/list → ping over stdio', async () => {
  const s = await session([]);
  const { byId, exitCode, stderr } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'ping' },
  ], { root: s.root });

  assert.equal(byId.get(1).result.serverInfo.name, 'agentic-security');
  assert.ok(byId.get(1).result.protocolVersion, 'initialize must advertise a protocol version');

  const names = byId.get(2).result.tools.map((t) => t.name);
  // Deliberately NOT an exact list: which tools exist is `mcp.test.js`'s
  // business. What this file cares about is that the shipped binary exposes
  // the two write tools, because those are what the rest of it exercises.
  assert.ok(names.includes('apply_fix'), 'apply_fix must be exposed by the shipped bin');
  assert.ok(names.includes('apply_sca_upgrade'), 'apply_sca_upgrade must be exposed by the shipped bin');

  assert.ok(byId.get(3).result, 'ping must be answered');
  assert.equal(exitCode, 0, `bin should exit 0 on stdin close; stderr: ${stderr}`);

  // The binary must resolve the root it was GIVEN, not cwd. This is the
  // specific defect an in-process test cannot see.
  assert.match(stderr, new RegExp(`session root = ${s.root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  await s.cleanup();
});

// ─── apply_fix: out-of-tree writes, three shapes ─────────────────────────────

test('shipped mcp bin: apply_fix refuses a relative path escaping the root', async () => {
  const s = await session([{
    id: 'ESCAPE-REL', severity: 'critical', line: 1, vuln: 'x',
    file: path.join('..', 'outside', 'target.txt'),
    fix: { replacement: PWNED },
  }]);
  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_fix', arguments: { finding_id: 'ESCAPE-REL', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false, 'a ../ escape must not be applied');
  assert.equal(await fsp.readFile(s.target, 'utf8'), 'UNTOUCHED');
  await s.cleanup();
});

test('shipped mcp bin: apply_fix refuses an absolute path outside the root', async () => {
  const s = await session([]);
  // Re-sign with the absolute path now that the temp layout is known.
  const findings = [{
    id: 'ESCAPE-ABS', severity: 'critical', line: 1, vuln: 'x',
    file: s.target, fix: { replacement: PWNED },
  }];
  const body = JSON.stringify({ findings });
  await fsp.writeFile(path.join(s.root, '.agentic-security', 'last-scan.json'), body);
  await fsp.writeFile(path.join(s.root, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));

  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_fix', arguments: { finding_id: 'ESCAPE-ABS', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false, 'an absolute out-of-tree path must not be applied');
  assert.equal(await fsp.readFile(s.target, 'utf8'), 'UNTOUCHED');
  await s.cleanup();
});

test('shipped mcp bin: apply_fix refuses a symlink that leaves the root', async () => {
  const s = await session([{
    id: 'ESCAPE-LINK', severity: 'critical', line: 1, vuln: 'x',
    file: 'link.txt', fix: { replacement: PWNED },
  }]);
  // An in-tree name whose real destination is outside. Path-string checks
  // pass this; only a realpath check catches it.
  await fsp.symlink(s.target, path.join(s.root, 'link.txt'));

  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_fix', arguments: { finding_id: 'ESCAPE-LINK', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false, 'a symlink leaving the root must not be applied');
  assert.equal(await fsp.readFile(s.target, 'utf8'), 'UNTOUCHED');
  await s.cleanup();
});

// The negative control. Without it, every assertion above is satisfiable by a
// server that refuses everything — which is the failure mode that gets a
// security gate switched off rather than fixed.
test('shipped mcp bin: apply_fix DOES apply an in-tree fix', async () => {
  const s = await session([{
    id: 'IN-TREE', severity: 'high', line: 1, vuln: 'x',
    file: 'src/app.js', fix: { replacement: 'const safe = 1;\n' },
  }]);
  await fsp.mkdir(path.join(s.root, 'src'), { recursive: true });
  await fsp.writeFile(path.join(s.root, 'src', 'app.js'), 'const unsafe = eval(x);\n');

  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_fix', arguments: { finding_id: 'IN-TREE', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, true, `an in-tree fix must apply, else the refusals above prove nothing: ${JSON.stringify(p)}`);
  assert.equal(await fsp.readFile(path.join(s.root, 'src', 'app.js'), 'utf8'), 'const safe = 1;\n');
  await s.cleanup();
});

// ─── apply_sca_upgrade: the other write tool ─────────────────────────────────

test('shipped mcp bin: apply_sca_upgrade refuses without confirm', async () => {
  const s = await session([{
    id: 'DEP-1', type: 'vulnerable_dep', severity: 'high',
    ecosystem: 'npm', name: 'lodash', version: '4.17.15', fixedVersions: ['4.17.21'],
  }]);
  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_sca_upgrade', arguments: { finding_id: 'DEP-1', confirm: false } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false);
  assert.match(p.reason, /confirm/i);
  await s.cleanup();
});

test('shipped mcp bin: apply_sca_upgrade refuses a SAST finding', async () => {
  const s = await session([{
    id: 'SAST-1', severity: 'high', file: 'src/app.js', line: 1, vuln: 'x',
    fix: { replacement: 'safe' },
  }]);
  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_sca_upgrade', arguments: { finding_id: 'SAST-1', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false);
  assert.match(p.reason, /vulnerable_dep/);
  await s.cleanup();
});

test('shipped mcp bin: apply_sca_upgrade refuses unsigned scan state', async () => {
  const s = await session([{
    id: 'DEP-1', type: 'vulnerable_dep', severity: 'high',
    ecosystem: 'npm', name: 'lodash', version: '4.17.15', fixedVersions: ['4.17.21'],
  }]);
  // Strip the signature: this is what a planted last-scan.json looks like.
  await fsp.rm(path.join(s.root, '.agentic-security', 'last-scan.json.sig'));

  const { byId } = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'apply_sca_upgrade', arguments: { finding_id: 'DEP-1', confirm: true } } },
  ], { root: s.root });

  const p = payload(byId.get(1));
  assert.equal(p.applied, false);
  assert.match(p.reason, /integrity/i);
  await s.cleanup();
});

// ─── The server survives malformed input ─────────────────────────────────────

test('shipped mcp bin: a malformed frame does not kill the session', async () => {
  const s = await session([]);
  const child = spawn(process.execPath, [MCP_BIN, '--root', s.root], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stdin.write('{ this is not json\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'ping' }) + '\n');
  const deadline = Date.now() + 10_000;
  while (!/"id":99/.test(stdout) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  child.stdin.end();
  await new Promise((r) => child.on('exit', r));

  const msgs = stdout.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.ok(msgs.some((m) => m.error && m.error.code === -32700), 'malformed frame should get a parse error');
  assert.ok(msgs.some((m) => m.id === 99 && m.result), 'the session must still answer after a bad frame');
  await s.cleanup();
});
