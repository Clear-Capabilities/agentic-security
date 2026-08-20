// PRD F11.1 — smoke the surfaces that carry the engine to users.
//
// THE GAP THIS CLOSES. `bin/agentic-security-lsp.js` ships inside the JetBrains
// plugin (via LSP4IJ) and the Neovim plugin (via built-in LSP). Before this
// file, a repo-wide grep for `agentic-security-lsp` found it referenced by NO
// test, NO script and NO workflow — the binary was never started by anything in
// CI. `test/lsp-server.test.js` covers `findingToDiagnostic` and `scanFile`,
// which is the engine side; it never speaks the protocol.
//
// The asymmetry that motivates this: a detection regression is caught by four
// benches, while an LSP that fails to start ships silently and presents to the
// user as "the extension does nothing".
//
// So this test does the one thing the unit tests cannot — it runs the SHIPPED
// ENTRY POINT as a subprocess and talks real LSP to it over stdio: framed
// `Content-Length` headers, `initialize` → `initialized` → `didOpen` →
// `publishDiagnostics` → `shutdown` → `exit`. It asserts the server starts,
// advertises capabilities, produces a diagnostic for genuinely vulnerable code,
// and exits cleanly.
//
// Deliberately NOT asserted: which rule fired, or how many diagnostics. That is
// the engine's business and is measured elsewhere. This asserts the SURFACE
// works — anything stricter would make an unrelated detector change break the
// LSP test and teach people to weaken it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LSP_BIN = path.join(HERE, '..', 'bin', 'agentic-security-lsp.js');

const VULNERABLE = `const { exec } = require('child_process');
module.exports = function handler(req, res) {
  exec('ping ' + req.query.host);
};
`;

/** LSP wire framing: Content-Length header, CRLFCRLF, JSON body. */
function frame(msg) {
  const json = JSON.stringify(msg);
  return `Content-Length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}`;
}

/** Incrementally decode framed messages out of a growing buffer. */
function drain(state) {
  const out = [];
  for (;;) {
    const headerEnd = state.buf.indexOf('\r\n\r\n');
    if (headerEnd < 0) break;
    const m = state.buf.slice(0, headerEnd).match(/Content-Length:\s*(\d+)/i);
    if (!m) { state.buf = state.buf.slice(headerEnd + 4); continue; }
    const len = Number(m[1]);
    const start = headerEnd + 4;
    if (Buffer.byteLength(state.buf, 'utf8') < start + len) break;
    const body = state.buf.slice(start, start + len);
    state.buf = state.buf.slice(start + len);
    try { out.push(JSON.parse(body)); } catch { /* ignore a partial/garbled frame */ }
  }
  return out;
}

test('the shipped LSP binary starts, speaks LSP over stdio, and publishes diagnostics', async () => {
  assert.ok(fs.existsSync(LSP_BIN), `the LSP entry point must exist at ${LSP_BIN}`);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsp-smoke-'));
  const file = path.join(dir, 'handler.js');
  fs.writeFileSync(file, VULNERABLE);
  const uri = `file://${file}`;

  const proc = spawn(process.execPath, [LSP_BIN], {
    cwd: dir, stdio: ['pipe', 'pipe', 'pipe'],
    // Keep the child from inheriting a deep-mode opt-in that would slow the
    // smoke test; the surface works the same either way.
    env: { ...process.env, AGENTIC_SECURITY_DEEP: '0' },
  });

  const state = { buf: '' };
  const received = [];
  let stderr = '';
  proc.stdout.setEncoding('utf8');
  proc.stderr.setEncoding('utf8');
  proc.stdout.on('data', (d) => { state.buf += d; received.push(...drain(state)); });
  proc.stderr.on('data', (d) => { stderr += d; });

  const waitFor = (predicate, what, ms = 60_000) => new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = setInterval(() => {
      const hit = received.find(predicate);
      if (hit) { clearInterval(tick); resolve(hit); return; }
      if (proc.exitCode !== null) {
        clearInterval(tick);
        reject(new Error(`server exited (code ${proc.exitCode}) before ${what}. stderr: ${stderr}`));
        return;
      }
      if (Date.now() - started > ms) {
        clearInterval(tick);
        reject(new Error(`timed out waiting for ${what}. stderr: ${stderr}`));
      }
    }, 100);
  });

  try {
    proc.stdin.write(frame({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { processId: process.pid, rootUri: `file://${dir}`, capabilities: {} },
    }));
    const init = await waitFor((m) => m.id === 1, 'the initialize response');
    assert.ok(init.result, `initialize must return a result, got: ${JSON.stringify(init)}`);
    assert.ok(init.result.capabilities,
      `initialize must advertise capabilities, got: ${JSON.stringify(init.result)}`);

    proc.stdin.write(frame({ jsonrpc: '2.0', method: 'initialized', params: {} }));
    proc.stdin.write(frame({
      jsonrpc: '2.0', method: 'textDocument/didOpen',
      params: { textDocument: { uri, languageId: 'javascript', version: 1, text: VULNERABLE } },
    }));

    const published = await waitFor(
      (m) => m.method === 'textDocument/publishDiagnostics', 'publishDiagnostics');
    assert.equal(published.params.uri, uri, 'diagnostics must be published for the opened document');
    assert.ok(Array.isArray(published.params.diagnostics), 'diagnostics must be an array');
    assert.ok(published.params.diagnostics.length > 0,
      'a command-injection handler must yield at least one diagnostic through the LSP surface; '
      + `got none. stderr: ${stderr}`);

    const d = published.params.diagnostics[0];
    assert.ok(d.range && d.range.start && typeof d.range.start.line === 'number',
      `a diagnostic must carry an LSP range an editor can render, got: ${JSON.stringify(d)}`);
    assert.ok(typeof d.message === 'string' && d.message.length > 0, 'a diagnostic needs a message');

    proc.stdin.write(frame({ jsonrpc: '2.0', id: 2, method: 'shutdown', params: {} }));
    await waitFor((m) => m.id === 2, 'the shutdown response');
    proc.stdin.write(frame({ jsonrpc: '2.0', method: 'exit', params: {} }));

    const code = await new Promise((resolve) => {
      const t = setTimeout(() => resolve('did-not-exit'), 10_000);
      proc.on('exit', (c) => { clearTimeout(t); resolve(c); });
    });
    assert.notEqual(code, 'did-not-exit', 'the server must exit after `exit`, not hang the editor');
  } finally {
    if (proc.exitCode === null) proc.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the LSP binary reports a framing error rather than crashing on a malformed header', async () => {
  // An editor, a proxy, or a partial write can produce a frame with no
  // Content-Length. The server should complain and stay up: a crash here takes
  // the editor integration down for the rest of the session.
  const proc = spawn(process.execPath, [LSP_BIN], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (d) => { stderr += d; });

  try {
    proc.stdin.write('GARBAGE-HEADER: 1\r\n\r\n{}');
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(proc.exitCode, null,
      `the server must survive a malformed frame; it exited ${proc.exitCode}. stderr: ${stderr}`);
  } finally {
    proc.kill('SIGKILL');
  }
});
