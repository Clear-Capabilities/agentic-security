// Second-round adversarial-review finding (2026-09): `cmdFix`'s bounded
// one-time retry-with-feedback (bin/agentic-security.js, wired when an
// Ollama-proposed patch is rejected) had ZERO automated test coverage — the
// only verification it ever received was a single manual smoke test run
// once in conversation, never captured as a repeatable check. This file is
// that missing coverage: real spawned CLI, real scan, a real fake Ollama
// server serving a deliberately-bad-then-good patch sequence, same pattern
// as cli/models.test.js and cli/setup-llm.test.js (including their
// documented sandbox limitation — see `itNetwork` below).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd: SCANNER, encoding: 'utf8', timeout: 30_000, ...opts });
}

// Same documented sandbox limitation as cli/models.test.js: a spawned child
// process cannot reach a fake-Ollama server this test process binds on
// loopback in this specific execution environment. Flip to `test` in an
// environment where a spawned child can reach the parent's loopback server.
const itNetwork = test.skip;

function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-fix-retry-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"fix-retry-fixture"}\n');
  fs.writeFileSync(path.join(dir, 'app.js'), [
    "const crypto = require('crypto');",
    'function hashPassword(pw) {',
    "  return crypto.createHash('md5').update(pw).digest('hex');",
    '}',
    'module.exports = { hashPassword };',
  ].join('\n') + '\n');
  return dir;
}

// A fake Ollama server that serves a BAD patch (still weak-hashed, so the
// deterministic gate genuinely rejects it) on the first /api/chat call, then
// a GOOD patch (sha256) on the second — the exact shape cmdFix's retry path
// exists to handle.
function startFakeOllamaFixRetry() {
  let call = 0;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      call++;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (call === 1) {
        const badPatch = [
          "const crypto = require('crypto');",
          'function hashPassword(pw) {',
          "  return crypto.createHash('md5').update(pw).digest('hex');", // unchanged — still fails the rescan
          '}',
          'module.exports = { hashPassword };',
        ].join('\n') + '\n';
        res.end(JSON.stringify({
          message: { content: JSON.stringify({ target_file: 'app.js', patch: badPatch, rationale: 'first attempt (deliberately unfixed)' }) },
          done: true,
        }));
      } else {
        const goodPatch = [
          "const crypto = require('crypto');",
          'function hashPassword(pw) {',
          "  return crypto.createHash('sha256').update(pw).digest('hex');",
          '}',
          'module.exports = { hashPassword };',
        ].join('\n') + '\n';
        res.end(JSON.stringify({
          message: { content: JSON.stringify({ target_file: 'app.js', patch: goodPatch, rationale: 'revised: sha256' }) },
          done: true,
        }));
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, host: `http://127.0.0.1:${port}`, callCount: () => call });
    });
  });
}

itNetwork('cmdFix: a rejected Ollama-proposed patch triggers exactly one retry with feedback, and the revised patch is applied', async () => {
  const dir = mkFixture();
  const { server, host } = await startFakeOllamaFixRetry();
  try {
    const scanResult = run(['scan', dir, '--format', 'json'], { env: { ...process.env } });
    assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'last-scan.json')), 'scan must have written last-scan.json');

    const env = {
      ...process.env,
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: host,
      AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b',
    };
    const fixResult = run(['fix', '--finding', 'crypto-weak-hash:app.js:3', '--root', dir, '--apply'], { env });
    assert.equal(fixResult.status, 0, fixResult.stderr);
    assert.match(fixResult.stdout, /rejected/i, 'the first (bad) proposal must be reported as rejected');
    assert.match(fixResult.stdout, /asking for one revised attempt/i);
    assert.match(fixResult.stdout, /revised proposal accepted/i);
    assert.match(fixResult.stdout, /✓ applied fix/);

    const finalContent = fs.readFileSync(path.join(dir, 'app.js'), 'utf8');
    assert.match(finalContent, /sha256/, 'the file must reflect the REVISED (second) proposal, not the rejected first one');
    assert.doesNotMatch(finalContent, /createHash\('md5'\)/);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

itNetwork('cmdFix: a SECOND rejected proposal is never retried again — the bound is exactly one, not open-ended', async () => {
  const dir = mkFixture();
  // Both calls return the identical bad patch — if the retry bound were not
  // truly hard-capped at one, this would loop or burn the whole apply-fix-
  // service attempt budget silently; instead it must fail cleanly after
  // exactly the deterministic 1 (original) + 1 (retry) = 2 attempts.
  let calls = 0;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      calls++;
      const badPatch = [
        "const crypto = require('crypto');",
        'function hashPassword(pw) {',
        "  return crypto.createHash('md5').update(pw).digest('hex');",
        '}',
        'module.exports = { hashPassword };',
      ].join('\n') + '\n';
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: { content: JSON.stringify({ target_file: 'app.js', patch: badPatch, rationale: 'always bad' }) },
        done: true,
      }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const host = `http://127.0.0.1:${server.address().port}`;
  try {
    const scanResult = run(['scan', dir, '--format', 'json']);
    assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'last-scan.json')), 'scan must have written last-scan.json');

    const env = {
      ...process.env,
      AGENTIC_SECURITY_LLM_PRESET: 'ollama',
      AGENTIC_SECURITY_OLLAMA_HOST: host,
      AGENTIC_SECURITY_LLM_MODEL: 'qwen3.5:4b',
    };
    const fixResult = run(['fix', '--finding', 'crypto-weak-hash:app.js:3', '--root', dir, '--apply'], { env });
    assert.notEqual(fixResult.status, 0, 'a still-rejected patch after the one retry must fail, not silently succeed');
    assert.equal(calls, 2, `expected exactly 2 model calls (original + one retry), got ${calls}`);
    assert.match(fixResult.stderr, /Refusing to apply/);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
