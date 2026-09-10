// agentic-security-ollama-offline-prd.md §18.2/§18.3 — the local agent
// loop's read-only tool registry and its eight-point safety gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { TOOL_ALLOWLIST, TOOL_ERROR, runTool } from '../src/llm-validator/agent-tools.js';

function mkFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tools-'));
  fs.writeFileSync(path.join(root, 'app.js'), "const crypto = require('crypto');\nfunction hash(pw) { return crypto.createHash('md5').update(pw).digest('hex'); }\n");
  fs.mkdirSync(path.join(root, 'lib'));
  fs.writeFileSync(path.join(root, 'lib', 'util.js'), 'module.exports = {};\n');
  return root;
}

function statePathFor(root) {
  return (scanRoot, ...parts) => path.join(scanRoot, '.agentic-security', ...parts);
}

test('TOOL_ALLOWLIST is exactly the four read-only tools', () => {
  assert.deepEqual([...TOOL_ALLOWLIST].sort(), ['list_files', 'read_file', 'read_finding', 'search_code']);
});

test('runTool: an unregistered tool name is refused, not silently attempted', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('run_shell', {}, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, false);
    assert.equal(r.code, TOOL_ERROR.UNKNOWN_TOOL);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: missing required argument is rejected before any filesystem access', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('read_file', {}, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, false);
    assert.equal(r.code, TOOL_ERROR.INVALID_ARGS);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_file returns content wrapped in the untrusted-output frame', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('read_file', { path: 'app.js' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /BEGIN-UNTRUSTED-TOOL-OUTPUT/);
    assert.match(r.result, /createHash\('md5'\)/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_file redacts a real-looking secret before it re-enters the model context', async () => {
  const root = mkFixture();
  try {
    fs.writeFileSync(path.join(root, 'config.js'), "const apiKey = 'zzqx9k2m4p7r1t5v8w3y6b0c2e4g6j8h';\n");
    const r = await runTool('read_file', { path: 'config.js' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.doesNotMatch(r.result, /zzqx9k2m4p7r1t5v8w3y6b0c2e4g6j8h/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: search_code redacts a secret in a matched line', async () => {
  const root = mkFixture();
  try {
    fs.writeFileSync(path.join(root, 'config.js'), "const apiKey = 'zzqx9k2m4p7r1t5v8w3y6b0c2e4g6j8h';\n");
    const r = await runTool('search_code', { query: 'apiKey' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /config\.js:1:/);
    assert.doesNotMatch(r.result, /zzqx9k2m4p7r1t5v8w3y6b0c2e4g6j8h/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_file refuses a path that escapes the scan root', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('read_file', { path: '../../../../etc/passwd' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, false);
    assert.equal(r.code, TOOL_ERROR.EXECUTION_FAILED);
    assert.match(r.reason, /escapes the scan root/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_file refuses a symlink even if it points back inside the root', async () => {
  const root = mkFixture();
  try {
    fs.symlinkSync(path.join(root, 'app.js'), path.join(root, 'link.js'));
    const r = await runTool('read_file', { path: 'link.js' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, false);
    assert.match(r.reason, /symbolic link/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: list_files lists nested files relative to the scan root, excludes node_modules', async () => {
  const root = mkFixture();
  try {
    fs.mkdirSync(path.join(root, 'node_modules', 'x'), { recursive: true });
    fs.writeFileSync(path.join(root, 'node_modules', 'x', 'index.js'), '');
    const r = await runTool('list_files', {}, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /app\.js/);
    assert.match(r.result, /lib\/util\.js|lib\\util\.js/);
    assert.doesNotMatch(r.result, /node_modules/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: search_code finds a literal match with file:line', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('search_code', { query: 'createHash' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /app\.js:2:/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: search_code with no matches returns a clean "(no matches)" result, not an error', async () => {
  const root = mkFixture();
  try {
    const r = await runTool('search_code', { query: 'no-such-string-anywhere' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /\(no matches\)/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_finding returns the matching finding by id', async () => {
  const root = mkFixture();
  try {
    const stateDir = path.join(root, '.agentic-security');
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, 'last-scan.json'), JSON.stringify({
      findings: [{ id: 'crypto-weak-hash:app.js:2', vuln: 'Weak hash', severity: 'medium', cwe: 'CWE-327', file: 'app.js', line: 2, description: 'MD5 is weak' }],
    }));
    const r = await runTool('read_finding', { id: 'crypto-weak-hash:app.js:2' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, true);
    assert.match(r.result, /Weak hash/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('runTool: read_finding on an id that does not exist fails cleanly', async () => {
  const root = mkFixture();
  try {
    const stateDir = path.join(root, '.agentic-security');
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, 'last-scan.json'), JSON.stringify({ findings: [] }));
    const r = await runTool('read_finding', { id: 'nope' }, { scanRoot: root, statePath: statePathFor(root) });
    assert.equal(r.ok, false);
    assert.equal(r.code, TOOL_ERROR.EXECUTION_FAILED);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
