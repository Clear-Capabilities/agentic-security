// agentic-security-ollama-offline-prd.md §11.1 — `agentic-security setup
// --llm ollama [--model X] [--offline]`. Same real-spawned-CLI pattern as
// cli/models.test.js, including its documented sandbox limitation (a
// spawned child process cannot reach a fake-Ollama server this test process
// binds on loopback, in this specific execution environment) — the success
// path is `itNetwork`-skipped for the same reason, flip to `test` in an
// environment where a spawned child can reach the parent's loopback server.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: SCANNER, encoding: 'utf8', timeout: 30_000, ...opts });
}

const itNetwork = test.skip;

function startFakeOllama() {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/tags') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ models: [{ name: 'qwen3.5:4b', digest: 'sha256:abc', size: 3_400_000_000 }] }));
      return;
    }
    res.writeHead(404); res.end('{}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, host: `http://127.0.0.1:${port}` });
    });
  });
}

test('setup --llm ollama: an unsupported provider name is refused with a clear message, exit 4', () => {
  const r = run(['setup', '--llm', 'openai']);
  assert.equal(r.status, 4);
  assert.match(r.stderr, /unsupported provider "openai"/);
});

test('setup --llm ollama: honest degradation when Ollama is not reachable, exit 1', () => {
  const r = run(['setup', '--llm', 'ollama', '--host', 'http://127.0.0.1:1']);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /not reachable/);
  assert.match(r.stdout, /deterministic scanner will still run/);
});

test('setup with no --llm flag still runs the original slash-command bootstrapper (backward compatible)', () => {
  // A real project dir, not SCANNER itself — cmdSetup writes real files
  // under <target>/.claude/commands/, and this must never touch the
  // scanner's own working tree.
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'setup-llm-backcompat-'));
  try {
    const r = run(['setup', scratch]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Installed \d+ command shortcuts/);
    assert.doesNotMatch(r.stderr, /unsupported provider/);
    assert.ok(fs.existsSync(path.join(scratch, '.claude', 'commands', 'security-scan-all.md')));
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
});

itNetwork('setup --llm ollama --model <installed>: noninteractive, prints export lines and offline guarantee', async () => {
  const { server, host } = await startFakeOllama();
  try {
    const r = run(['setup', '--llm', 'ollama', '--host', host, '--model', 'qwen3.5:4b']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Choose default model: qwen3\.5:4b/);
    assert.match(r.stdout, /Only loopback model requests are allowed/);
    assert.match(r.stdout, /export AGENTIC_SECURITY_LLM_PRESET=ollama/);
    assert.match(r.stdout, /export AGENTIC_SECURITY_LLM_MODEL=qwen3\.5:4b/);
  } finally { server.close(); }
});

itNetwork('setup --llm ollama: no --model auto-selects a sane default from installed models', async () => {
  const { server, host } = await startFakeOllama();
  try {
    const r = run(['setup', '--llm', 'ollama', '--host', host]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /auto-selected for your/);
  } finally { server.close(); }
});
