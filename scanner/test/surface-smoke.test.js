// PRD F11.5 / F11.1 — every shipped surface has a golden path, exercised in CI.
//
// The package advertises NINE binaries. A binary that ships broken — a bad
// import, a syntax error in a rarely-loaded branch, a file missing from `files`
// — fails only for the user who runs it, and the unit tests stay green because
// they import modules rather than executing what was published.
//
// This is the same class as the dark-detector defects: the thing exists, the
// tests pass, and the path nobody exercises is the one that is broken. So each
// entry point is SPAWNED and required to start, not imported.
//
// Deliberately NOT asserted: what each tool prints. This is a liveness gate, and
// pinning output would make it a brittle duplicate of the tests that own those
// behaviours. The bar is: it starts, it does not crash on load, it identifies
// itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.join(HERE, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));

// A load-time failure looks like this, whatever the exit code. Checking for the
// SHAPE of the failure catches a broken import even in a tool that legitimately
// exits non-zero when given no useful arguments.
const LOAD_FAILURE = /Cannot find module|ERR_MODULE_NOT_FOUND|SyntaxError|ERR_REQUIRE_ESM|is not defined|Unexpected token/;

// The LSP server is excluded from the --help smoke on purpose: a language
// server is not a CLI. It waits on stdin for JSON-RPC and correctly prints
// nothing for --help, so asserting output here would be asserting the wrong
// contract. Its golden path is test/lsp-protocol-smoke.test.js, which speaks
// the protocol it actually implements.
const NOT_A_CLI = new Set(['bin/agentic-security-lsp.js']);
const uniqueBins = [...new Set(Object.values(PKG.bin))].filter((b) => !NOT_A_CLI.has(b));

test('every advertised binary exists on disk', () => {
  const missing = Object.entries(PKG.bin).filter(([, f]) => !fs.existsSync(path.join(SCANNER, f)));
  assert.deepEqual(missing.map(([n]) => n), [], 'package.json advertises a binary that is not present');
});

for (const rel of uniqueBins) {
  test(`${rel} starts without a load-time failure`, () => {
    const r = spawnSync(process.execPath, [path.join(SCANNER, rel), '--help'], {
      cwd: os.tmpdir(), encoding: 'utf8', timeout: 60_000, maxBuffer: 16 * 1024 * 1024,
    });
    const out = `${r.stdout || ''}${r.stderr || ''}`;
    assert.ok(!r.error, `${rel} failed to spawn: ${r.error && r.error.message}`);
    assert.doesNotMatch(out, LOAD_FAILURE, `${rel} failed at load time:\n${out.slice(0, 600)}`);
    assert.ok(out.trim().length > 0, `${rel} produced no output at all — it may not be a working entry point`);
  });
}

test('the LSP binary is covered by its own protocol smoke, not by --help', () => {
  // Recorded so the exclusion above is a decision with a visible owner rather
  // than a gap someone re-discovers.
  assert.ok(fs.existsSync(path.join(HERE, 'lsp-protocol-smoke.test.js')),
    'the LSP surface must keep a protocol-level smoke test if it is excluded from the CLI smoke');
});

test('the MCP server speaks JSON-RPC over stdio when SPAWNED as a binary', async () => {
  // The MCP module is unit-tested, but the published surface is a spawned
  // process speaking framed JSON-RPC on stdin/stdout. That is what an agent
  // host actually connects to, and nothing exercised it end to end.
  const bin = path.join(SCANNER, 'bin', 'agentic-security-mcp.js');
  const child = spawn(process.execPath, [bin], {
    cwd: os.tmpdir(), stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1' },
  });

  const reply = await new Promise((resolve) => {
    let buf = '';
    const timer = setTimeout(() => resolve({ timedOut: true, buf }), 20_000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      // Accept either framed or line-delimited JSON-RPC; the assertion is that
      // a well-formed response for OUR id comes back, not which framing is used.
      if (/"id"\s*:\s*1\b/.test(buf)) { clearTimeout(timer); resolve({ timedOut: false, buf }); }
    });
    child.on('error', () => { clearTimeout(timer); resolve({ timedOut: true, buf }); });
    child.on('exit', () => { clearTimeout(timer); resolve({ timedOut: false, buf }); });

    // LINE-DELIMITED JSON-RPC, which is what this server implements (see
    // test/mcp.test.js's framing cases). An earlier draft also wrote a
    // Content-Length frame "to cover both" — that prefix is garbage to a
    // line-delimited parser and made a working server look dead. Speak the
    // protocol the server actually speaks.
    const msg = JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } },
    });
    child.stdin.write(`${msg}\n`);
  });

  try { child.kill('SIGKILL'); } catch { /* already gone */ }

  assert.ok(!reply.timedOut, 'the MCP binary did not answer an initialize request within 20s');
  assert.doesNotMatch(reply.buf, LOAD_FAILURE, `the MCP binary failed at load time:\n${reply.buf.slice(0, 600)}`);
  assert.match(reply.buf, /"jsonrpc"\s*:\s*"2\.0"/, 'the reply is not JSON-RPC');
});

test('the IDE distributions each carry a manifest', () => {
  // The three IDE surfaces ship from this repo. A distribution whose manifest
  // has gone missing is broken for its users and invisible here otherwise.
  const ide = path.join(SCANNER, '..', 'ide');
  const expected = { jetbrains: null, nvim: null, vscode: 'package.json' };
  for (const dir of Object.keys(expected)) {
    const p = path.join(ide, dir);
    assert.ok(fs.existsSync(p), `ide/${dir} is advertised but absent`);
    assert.ok(fs.readdirSync(p).length > 0, `ide/${dir} is empty`);
    if (expected[dir]) {
      assert.ok(fs.existsSync(path.join(p, expected[dir])), `ide/${dir}/${expected[dir]} is missing`);
    }
  }
});
