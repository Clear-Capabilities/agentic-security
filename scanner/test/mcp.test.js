// MCP server unit tests. Drives the JSON-RPC handler directly — no child
// process — except for one end-to-end check of stdio framing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, SERVER_NAME, PROTOCOL_VERSION, CODE_FINGERPRINT } from '../src/mcp/server.js';
import { signLastScan } from '../src/posture/integrity.js';
import { redactString } from '../src/mcp/redact.js';
import { verifyAuditLog } from '../src/mcp/audit.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const MCP_BIN = path.join(REPO_ROOT, 'bin', 'agentic-security-mcp.js');

// Build an isolated session root with a signed last-scan.json. Returns
// { root, handleRequest, cleanup } so each test gets its own sandbox.
async function makeSession({ findings = null } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  // Project marker — audit.js refuses to write the audit log unless the
  // session root contains a recognized marker (package.json, .git, etc).
  // Drop a stub package.json so the audit-chain tests can observe the log.
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"as-mcp-test-session"}');
  if (findings) {
    const body = JSON.stringify({ findings });
    await fsp.writeFile(path.join(stateDir, 'last-scan.json'), body);
    await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  }
  const { handleRequest } = createServer({ sessionRoot: dir });
  return {
    root: dir,
    handleRequest,
    cleanup: async () => { try { await fsp.rm(dir, { recursive: true, force: true }); } catch {} },
  };
}

function call(handleRequest, name, args, id = 1) {
  return handleRequest({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
}
function payload(r) { return JSON.parse(r.result.content[0].text); }

// ─── Protocol surface ────────────────────────────────────────────────────────

test('initialize returns protocol version and server info', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(r.result.protocolVersion, PROTOCOL_VERSION);
  assert.equal(r.result.serverInfo.name, SERVER_NAME);
  await cleanup();
});

test('tools/list exposes the PRD-named tools', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = r.result.tools.map(t => t.name).sort();
  // Phase-2: verify_fix + synthesize_fix. C.6: find_rule_module.
  // Harness-anatomy #4: append/read_scratchpad. #2: AGENTS.md. #8: lookup_cve.
  // SCA-plan Phase 3 / Item 5: apply_sca_upgrade + synthesize_sca_upgrade.
  // Chat enhancements: query_triage_memory (#4) + query_findings_memory (#12).
  assert.deepEqual(names, [
    'append_agents_memory', 'append_scratchpad', 'apply_fix',
    'apply_sca_upgrade',
    'explain_finding', 'find_rule_module', 'lookup_cve',
    'query_findings_memory', 'query_taint', 'query_triage_memory',
    'read_agents_memory', 'read_scratchpad', 'scan_diff',
    'synthesize_fix', 'synthesize_sca_upgrade', 'verify_fix',
  ]);
  for (const t of r.result.tools) {
    assert.equal(t.inputSchema.type, 'object');
    assert.equal(t.inputSchema.additionalProperties, false, `${t.name} schema must reject additional properties`);
  }
  await cleanup();
});

test('find_rule_module refuses with no query', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({
    jsonrpc: '2.0', id: 100, method: 'tools/call',
    params: { name: 'find_rule_module', arguments: {} },
  });
  const text = r.result.content[0].text;
  assert.match(text, /provide cwe.*family/);
  await cleanup();
});

test('find_rule_module rejects malformed CWE id', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({
    jsonrpc: '2.0', id: 101, method: 'tools/call',
    params: { name: 'find_rule_module', arguments: { cwe: 'not-a-cwe' } },
  });
  // Handler-level format check (the mini-validator doesn't do `pattern`).
  const body = JSON.parse(r.result.content[0].text);
  assert.equal(body.ok, false);
  assert.match(body.reason, /CWE-\\d/);
  await cleanup();
});

test('find_rule_module rejects additionalProperties', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({
    jsonrpc: '2.0', id: 102, method: 'tools/call',
    params: { name: 'find_rule_module', arguments: { cwe: 'CWE-89', extra: 'rejected' } },
  });
  assert.equal(r.result.isError, true);
  await cleanup();
});

test('unknown method returns -32601', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({ jsonrpc: '2.0', id: 4, method: 'fictional/method' });
  assert.equal(r.error.code, -32601);
  await cleanup();
});

// ─── Input validation ────────────────────────────────────────────────────────

test('scan_diff rejects missing required arg', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'scan_diff', {});
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /missing required property "files"/);
  await cleanup();
});

test('scan_diff rejects non-string in files array', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'scan_diff', { files: ['a.js', 42] });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /expected string/);
  await cleanup();
});

test('scan_diff rejects additionalProperties', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'scan_diff', { files: ['a.js'], rogue: true });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /unexpected property "rogue"/);
  await cleanup();
});

test('apply_fix rejects when confirm is missing', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'X' });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /missing required property "confirm"/);
  await cleanup();
});

// ─── Path traversal confinement ──────────────────────────────────────────────

test('scan_diff refuses paths that escape session root', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'scan_diff', { files: ['../../../etc/passwd'] });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /escapes session root/);
  await cleanup();
});

test('scan_diff refuses absolute paths outside session root', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await call(handleRequest, 'scan_diff', { files: ['/etc/passwd'] });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /escapes session root/);
  await cleanup();
});

test('apply_fix refuses finding whose file field escapes session root', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{
      id: 'F1', severity: 'high', file: '../../../etc/passwd', line: 1,
      title: 'X', fix: { replacement: 'pwned' },
    }],
  });
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /path-escape refused/);
  // File at /etc/passwd was NOT touched (we obviously can't write there in tests anyway)
  assert.ok(fs.existsSync(path.join(root, '.agentic-security', 'last-scan.json')));
  await cleanup();
});

// ─── HMAC integrity ──────────────────────────────────────────────────────────

test('apply_fix refuses when last-scan.json is unsigned (no .sig file)', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  // Write an UNSIGNED last-scan.json — simulates a planted file.
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), JSON.stringify({
    findings: [{ id: 'EVIL', severity: 'high', file: 'a.js', line: 1, fix: { replacement: 'pwned' } }],
  }));
  await fsp.writeFile(path.join(dir, 'a.js'), 'original');
  const { handleRequest } = createServer({ sessionRoot: dir });
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'EVIL', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /unsigned/);
  // a.js was NOT modified
  assert.equal(await fsp.readFile(path.join(dir, 'a.js'), 'utf8'), 'original');
  await fsp.rm(dir, { recursive: true, force: true });
});

test('apply_fix refuses when last-scan.json is tampered (bad signature)', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  // Plant a fake .sig that won't match
  const goodBody = JSON.stringify({ findings: [{ id: 'X', file: 'a.js', fix: { replacement: 'pwned' } }] });
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), goodBody);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), 'deadbeef'.repeat(8));
  await fsp.writeFile(path.join(dir, 'a.js'), 'original');
  const { handleRequest } = createServer({ sessionRoot: dir });
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'X', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /tampered/);
  assert.equal(await fsp.readFile(path.join(dir, 'a.js'), 'utf8'), 'original');
  await fsp.rm(dir, { recursive: true, force: true });
});

// ─── Shadow finding refusal ──────────────────────────────────────────────────

test('apply_fix refuses shadow findings', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{
      id: 'SHADOW', severity: 'high', file: 'a.js', line: 1, _shadow: true,
      fix: { replacement: 'shouldnt apply' },
    }],
  });
  await fsp.writeFile(path.join(root, 'a.js'), 'original');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'SHADOW', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /shadow/);
  assert.equal(await fsp.readFile(path.join(root, 'a.js'), 'utf8'), 'original');
  await cleanup();
});

// ─── confirm: true requirement ───────────────────────────────────────────────

test('apply_fix refuses without confirm: true even when everything else is valid', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'a.js', line: 1, fix: { replacement: 'SAFE' } }],
  });
  await fsp.writeFile(path.join(root, 'a.js'), 'ORIGINAL');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: false });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /requires confirm/);
  assert.equal(await fsp.readFile(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  await cleanup();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

test('apply_fix writes replacement when all gates pass', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'a.js', line: 1, rule: 'demo', vuln: 'demo', fix: { replacement: 'SAFE' } }],
  });
  await fsp.writeFile(path.join(root, 'a.js'), 'ORIGINAL');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, true);
  assert.equal(p.integrity, 'verified');
  assert.equal(await fsp.readFile(path.join(root, 'a.js'), 'utf8'), 'SAFE');
  await cleanup();
});

test('query_taint matches across findings', async () => {
  const { handleRequest, cleanup } = await makeSession({
    findings: [
      { id: 'F1', severity: 'high', file: 'a.js', line: 7, title: 'CMDi', description: 'req.body flows to child_process.exec' },
      { id: 'F2', severity: 'low', file: 'b.js', line: 1, title: 'Other', description: 'unrelated finding' },
    ],
  });
  const r = await call(handleRequest, 'query_taint', { source: 'req.body', sink: 'exec' });
  const p = payload(r);
  assert.equal(p.matchCount, 1);
  assert.equal(p.matches[0].id, 'F1');
  await cleanup();
});

test('explain_finding returns the matching finding payload', async () => {
  const { handleRequest, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'a.js', line: 7, title: 'X', description: 'Y', remediation: 'Z', cwe: 'CWE-78' }],
  });
  const r = await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  const p = payload(r);
  assert.equal(p.id, 'F1');
  assert.equal(p.cwe, 'CWE-78');
  await cleanup();
});

// ─── Audit log ───────────────────────────────────────────────────────────────

test('every tools/call is recorded in mcp-audit.log', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'a.js', line: 1 }],
  });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  await call(handleRequest, 'explain_finding', { finding_id: 'NOPE' });
  await call(handleRequest, 'scan_diff', { files: ['../../etc/passwd'] });
  const logPath = path.join(root, '.agentic-security', 'mcp-audit.log');
  const lines = (await fsp.readFile(logPath, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 3);
  assert.equal(lines[0].outcome, 'ok');
  assert.equal(lines[1].outcome, 'error');
  assert.equal(lines[2].outcome, 'error');
  await cleanup();
});

// ─── Stdio transport caps ────────────────────────────────────────────────────

test('stdio: oversize line is dropped with parse-error response', async () => {
  const child = spawn('node', [MCP_BIN, '--root', os.tmpdir()], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  // 5 MB single line, well over the 4 MB cap
  child.stdin.write('x'.repeat(5 * 1024 * 1024) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }) + '\n');
  await new Promise(r => setTimeout(r, 500));
  child.stdin.end();
  await new Promise(r => child.on('exit', r));
  const lines = stdout.trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  // First response: parse-error for the oversized line.
  assert.equal(lines[0].error.code, -32700);
  // Second response: ping reply — proves the server didn't crash on overflow.
  assert.equal(lines[1].result && typeof lines[1].result, 'object');
});

test('stdio: spawned bin handles initialize+tools/list over NDJSON', async () => {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-e2e-'));
  const child = spawn('node', [MCP_BIN, '--root', tmpRoot], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
  await new Promise(r => setTimeout(r, 300));
  child.stdin.end();
  await new Promise(r => child.on('exit', r));
  const lines = stdout.trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  assert.equal(lines[0].result.serverInfo.name, SERVER_NAME);
  // 16 tools: 15 (after query_triage_memory) + query_findings_memory
  // added in the findings-memory chat-enhancement change.
  assert.equal(lines[1].result.tools.length, 16);
  await fsp.rm(tmpRoot, { recursive: true, force: true });
});

// ─── OWASP MCP01 / MCP10 — Secret redaction in tool outputs ──────────────────

test('redactString redacts known provider key shapes', () => {
  const samples = [
    'AKIAIOSFODNN7EXAMPLE',
    'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'xoxb-1234567890-abcdefghij',
    'sk-ant-abcdefghijklmnopqrstuv0123456789',
    'sk-' + 'a'.repeat(48),
    'sk_live_' + 'X'.repeat(24),
    'AIzaSy' + 'X'.repeat(33),
    'eyJhbGciOiJI' + 'a'.repeat(20) + '.eyJzdWIi' + 'b'.repeat(20) + '.' + 'c'.repeat(20),
    'password = "hunter2hunter2"',
  ];
  for (const s of samples) {
    const out = redactString(s);
    assert.match(out, /\[REDACTED:/, `not redacted: ${s.slice(0, 30)}…`);
  }
});

test('explain_finding redacts secret in snippet before returning to agent', async () => {
  const { handleRequest, cleanup } = await makeSession({
    findings: [{
      id: 'F1', severity: 'high', file: 'a.js', line: 1,
      title: 'Hardcoded credential',
      snippet: 'const KEY = "AKIAIOSFODNN7EXAMPLE";',
      description: 'AWS key AKIAIOSFODNN7EXAMPLE detected at line 1',
    }],
  });
  const r = await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  const p = payload(r);
  assert.doesNotMatch(p.snippet, /AKIAIOSFODNN7EXAMPLE/, 'raw AWS key leaked in snippet');
  assert.doesNotMatch(p.description, /AKIAIOSFODNN7EXAMPLE/, 'raw AWS key leaked in description');
  assert.match(p.snippet, /\[REDACTED:/);
  await cleanup();
});

test('query_taint redacts secrets in matched finding descriptions', async () => {
  const { handleRequest, cleanup } = await makeSession({
    findings: [{
      id: 'F1', severity: 'high', file: 'a.js', line: 1,
      title: 'Leak', vuln: 'leak',
      description: 'req.body.user used as exec arg with ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    }],
  });
  const r = await call(handleRequest, 'query_taint', { source: 'req.body', sink: 'exec' });
  const p = payload(r);
  assert.equal(p.matchCount, 1);
  assert.doesNotMatch(p.matches[0].description, /ghp_a/);
  await cleanup();
});

// ─── OWASP MCP03 / MCP06 — Untrusted-excerpts marker on every output ─────────

test('every tool response carries _meta.untrusted_excerpts:true', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'low', file: 'a.js', line: 1, title: 'X' }],
  });
  await fsp.writeFile(path.join(root, 'a.js'), '// empty file');
  const calls = [
    ['scan_diff', { files: ['a.js'] }],
    ['query_taint', { source: 'req', sink: 'exec' }],
    ['explain_finding', { finding_id: 'F1' }],
    ['apply_fix', { finding_id: 'F1', confirm: true }],
  ];
  for (const [name, args] of calls) {
    const r = await call(handleRequest, name, args);
    const p = payload(r);
    assert.equal(p._meta?.untrusted_excerpts, true, `${name}: missing untrusted_excerpts marker`);
    assert.equal(p._meta?.source, 'agentic-security-mcp');
  }
  await cleanup();
});

// ─── OWASP MCP04 / MCP09 — Code fingerprint exposed to fleet observers ───────

test('initialize returns codeFingerprint for fleet integrity detection', async () => {
  const { handleRequest, cleanup } = await makeSession();
  const r = await handleRequest({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.ok(CODE_FINGERPRINT, 'fingerprint should be computable from disk');
  assert.equal(r.result.serverInfo.codeFingerprint, CODE_FINGERPRINT);
  assert.match(r.result.serverInfo.codeFingerprint, /^[0-9a-f]{64}$/);
  await cleanup();
});

// ─── OWASP MCP05 — Symlink traversal refused ─────────────────────────────────

test('scan_diff refuses a symlink in session root pointing outside', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-sl-'));
  // Build target outside the session root and a symlink inside it
  const outside = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-outside-'));
  await fsp.writeFile(path.join(outside, 'secret.txt'), 'AKIAIOSFODNN7EXAMPLE');
  await fsp.symlink(path.join(outside, 'secret.txt'), path.join(dir, 'link.js'));
  const { handleRequest } = createServer({ sessionRoot: dir });
  const r = await call(handleRequest, 'scan_diff', { files: ['link.js'] });
  assert.equal(r.result.isError, true, 'symlink should be refused');
  assert.match(r.result.content[0].text, /symbolic link/i);
  await fsp.rm(dir, { recursive: true, force: true });
  await fsp.rm(outside, { recursive: true, force: true });
});

test('apply_fix refuses to overwrite a symlinked finding.file', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-sl-'));
  const outside = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-outside-'));
  await fsp.writeFile(path.join(outside, 'target.txt'), 'ORIGINAL');
  await fsp.symlink(path.join(outside, 'target.txt'), path.join(dir, 'innocent.js'));
  // Plant a signed scan that points at the symlinked file.
  const body = JSON.stringify({
    findings: [{ id: 'F1', severity: 'high', file: 'innocent.js', line: 1, fix: { replacement: 'PWNED' } }],
  });
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), body);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: dir });
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /symbolic link|path-escape/);
  assert.equal(await fsp.readFile(path.join(outside, 'target.txt'), 'utf8'), 'ORIGINAL');
  await fsp.rm(dir, { recursive: true, force: true });
  await fsp.rm(outside, { recursive: true, force: true });
});

// ─── OWASP MCP08 — Audit-log hash chain detects tampering ────────────────────

test('audit log forms a hash chain that verifyAuditLog accepts', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'low', file: 'a.js', line: 1 }],
  });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  const logFile = path.join(root, '.agentic-security', 'mcp-audit.log');
  const result = verifyAuditLog(logFile);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.entries, 3);
  await cleanup();
});

test('audit log tampering is detected by verifyAuditLog', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'low', file: 'a.js', line: 1 }],
  });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
  const logFile = path.join(root, '.agentic-security', 'mcp-audit.log');
  // Edit line 2 in place
  const text = await fsp.readFile(logFile, 'utf8');
  const lines = text.split('\n');
  const e = JSON.parse(lines[1]);
  e.outcome = 'rejected';
  lines[1] = JSON.stringify(e);
  await fsp.writeFile(logFile, lines.join('\n'));
  const result = verifyAuditLog(logFile);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 2);
  await cleanup();
});

// ─── OWASP MCP09 — Server kill-switch ────────────────────────────────────────

test('AGENTIC_SECURITY_MCP_DISABLED=1 refuses every tool call', async () => {
  const { handleRequest, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'low', file: 'a.js', line: 1 }],
  });
  process.env.AGENTIC_SECURITY_MCP_DISABLED = '1';
  try {
    const r = await call(handleRequest, 'explain_finding', { finding_id: 'F1' });
    assert.equal(r.result.isError, true);
    assert.match(r.result.content[0].text, /disabled/);
  } finally {
    delete process.env.AGENTIC_SECURITY_MCP_DISABLED;
  }
  await cleanup();
});

test('AGENTIC_SECURITY_MCP_DISABLED=1 causes bin to exit immediately', async () => {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-mcp-dis-'));
  const child = spawn('node', [MCP_BIN, '--root', tmpRoot], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, AGENTIC_SECURITY_MCP_DISABLED: '1' },
  });
  const exitCode = await new Promise(r => child.on('exit', r));
  assert.equal(exitCode, 0);
  await fsp.rm(tmpRoot, { recursive: true, force: true });
});

// ─── OWASP MCP02 — dry_run prevents writes ───────────────────────────────────

test('apply_fix dry_run reports the diff without writing', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'a.js', line: 1, rule: 'demo', vuln: 'demo', fix: { replacement: 'NEW' } }],
  });
  await fsp.writeFile(path.join(root, 'a.js'), 'ORIGINAL');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true, dry_run: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.equal(p.dryRun, true);
  assert.equal(p.originalSize, 8);
  assert.equal(p.newSize, 3);
  assert.equal(await fsp.readFile(path.join(root, 'a.js'), 'utf8'), 'ORIGINAL');
  await cleanup();
});

// ─── OWASP MCP01 — Audit log redacts secrets in arg blobs ────────────────────

test('audit log redacts secrets that appear in tool arguments', async () => {
  const { handleRequest, root, cleanup } = await makeSession();
  // Pass a key-shaped string as a tool argument (would happen if an agent
  // accidentally pasted a token from prior context into a query).
  await call(handleRequest, 'query_taint', { source: 'req.body', sink: 'AKIAIOSFODNN7EXAMPLE' });
  const logFile = path.join(root, '.agentic-security', 'mcp-audit.log');
  const log = await fsp.readFile(logFile, 'utf8');
  assert.doesNotMatch(log, /AKIAIOSFODNN7EXAMPLE/);
  assert.match(log, /\[REDACTED:aws-access-key\]/);
  await cleanup();
});

// ─── OWASP A01 — apply_fix refuses reserved write paths ──────────────────────

test('apply_fix refuses to write under .git/', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: '.git/hooks/post-commit', line: 1, fix: { replacement: '#!/bin/sh\nrm -rf /\n' } }],
  });
  await fsp.mkdir(path.join(root, '.git', 'hooks'), { recursive: true });
  await fsp.writeFile(path.join(root, '.git', 'hooks', 'post-commit'), 'original');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /reserved path/);
  assert.equal(await fsp.readFile(path.join(root, '.git', 'hooks', 'post-commit'), 'utf8'), 'original');
  await cleanup();
});

test('apply_fix refuses to write under .agentic-security/ (self-modification)', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: '.agentic-security/rules.yml', line: 1, fix: { replacement: 'disable: all' } }],
  });
  await fsp.writeFile(path.join(root, '.agentic-security', 'rules.yml'), 'original rules');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /reserved path/);
  assert.equal(await fsp.readFile(path.join(root, '.agentic-security', 'rules.yml'), 'utf8'), 'original rules');
  await cleanup();
});

test('apply_fix refuses to write under node_modules/ (supply-chain)', async () => {
  const { handleRequest, root, cleanup } = await makeSession({
    findings: [{ id: 'F1', severity: 'high', file: 'node_modules/express/index.js', line: 1, fix: { replacement: 'malicious()' } }],
  });
  await fsp.mkdir(path.join(root, 'node_modules', 'express'), { recursive: true });
  await fsp.writeFile(path.join(root, 'node_modules', 'express', 'index.js'), 'legit module');
  const r = await call(handleRequest, 'apply_fix', { finding_id: 'F1', confirm: true });
  const p = payload(r);
  assert.equal(p.applied, false);
  assert.match(p.reason, /reserved path/);
  assert.equal(await fsp.readFile(path.join(root, 'node_modules', 'express', 'index.js'), 'utf8'), 'legit module');
  await cleanup();
});

// ─── OWASP A03 — redactString input-size cap ─────────────────────────────────

test('redactString caps very large inputs before regex pass (DoS defense)', () => {
  // 1 MB string — well over INPUT_MAX. Should return quickly and not lock CPU.
  const huge = 'x'.repeat(1_000_000);
  const t0 = Date.now();
  const out = redactString(huge);
  const ms = Date.now() - t0;
  assert.ok(ms < 500, `redactString took ${ms}ms on 1MB input (should be fast after cap)`);
  // Output truncated to SNIPPET_MAX (2000) + ellipsis suffix
  assert.ok(out.length < 3000, `output not capped: length=${out.length}`);
});

// ─── OWASP A05 — no default singleton, no surprise cwd binding ───────────────

test('server.js does not export a default handleRequest singleton', async () => {
  const mod = await import('../src/mcp/server.js');
  assert.equal(typeof mod.handleRequest, 'undefined',
    'handleRequest must NOT be exported as a singleton (footgun: binds to import-time cwd)');
  assert.equal(typeof mod.createServer, 'function');
});
