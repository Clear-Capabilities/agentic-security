// PRD Epic 4.1 — the autopilot CLI, end to end.
//
// `autopilot.test.js` pins the loop's decisions against injected stages. This
// file pins the wiring: a real scan, a real sandboxed exploit, a real patch
// from a real HTTP endpoint, and the real gate. The property that matters is
// the same one, but here nothing is stubbed out of the path that could hide a
// mistake — in particular, a patch that does NOT close the hole must not be
// written to disk, and that is settled by running the exploit against it.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { sandboxAvailable } from '../src/sandbox/index.js';

const execFileAsync = promisify(execFile);
const CLI = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'autopilot.mjs');

const VULNERABLE = [
  "const { exec } = require('child_process');",
  'module.exports = function handler(req, res) {',
  "  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));",
  '};',
  '',
].join('\n');

// A genuine fix: the payload can no longer reach a shell.
const REAL_FIX = [
  "const { execFile } = require('child_process');",
  'module.exports = function handler(req, res) {',
  "  execFile('ping', ['-c', '1', req.query.host], (e, out) => res.send(out));",
  '};',
  '',
].join('\n');

// A patch that changes the file and looks plausible but leaves the shell call
// intact. This is the one the gate exists for.
const FAKE_FIX = [
  "const { exec } = require('child_process');",
  '// Input is validated below.',
  'module.exports = function handler(req, res) {',
  '  const host = String(req.query.host || "");',
  "  exec('ping -c 1 ' + host, (e, out) => res.send(out));",
  '};',
  '',
].join('\n');

function project() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autopilot-cli-')));
  fs.writeFileSync(path.join(dir, 'handler.js'), VULNERABLE);
  return dir;
}

// A BYO endpoint speaking the generic `{prompt, model}` / `{response}` shape.
async function fixServer(reply) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push(JSON.parse(body || '{}'));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ response: reply }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}/fix`, seen, close: () => server.close() };
}

async function runCli(dir, endpoint, extra = []) {
  try {
    const r = await execFileAsync(process.execPath, [CLI, dir, ...extra], {
      env: { ...process.env, AGENTIC_SECURITY_LLM_ENDPOINT: endpoint },
      timeout: 180000,
    });
    return { code: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

test('a patch that really fixes the bug reaches VERIFIED_FIXED but is NOT written without --apply', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const dir = project();
  const srv = await fixServer(REAL_FIX);
  try {
    const r = await runCli(dir, srv.url);
    assert.equal(r.code, 0, `expected a clean run:\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /VERIFIED_FIXED/);
    assert.ok(srv.seen.length > 0, 'the fix model was never called');
    assert.equal(fs.readFileSync(path.join(dir, 'handler.js'), 'utf8'), VULNERABLE,
      'gates are on by default — a verified patch must still not be written');
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('--apply writes the verified patch', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const dir = project();
  const srv = await fixServer(REAL_FIX);
  try {
    const r = await runCli(dir, srv.url, ['--apply']);
    assert.equal(r.code, 0, `${r.stdout}\n${r.stderr}`);
    const after = fs.readFileSync(path.join(dir, 'handler.js'), 'utf8');
    assert.match(after, /execFile/, 'the verified patch was not written');
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a plausible patch that leaves the hole open is NEVER written, even with --apply', async (t) => {
  // The whole reason the loop is allowed to exist. The patch changes the file,
  // reads like a fix, and would satisfy any "did the scanner go quiet?" check —
  // the exploit is what refuses it.
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const dir = project();
  const srv = await fixServer(FAKE_FIX);
  try {
    const r = await runCli(dir, srv.url, ['--apply']);
    assert.equal(r.code, 1, 'an unfixed finding must not exit clean');
    assert.match(r.stdout, /NEEDS_REVIEW/);
    assert.match(r.stdout, /still fires/);
    assert.equal(fs.readFileSync(path.join(dir, 'handler.js'), 'utf8'), VULNERABLE,
      'a patch that did not close the hole was written to disk');
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('with no fix model configured the finding is NO_FIX, not silently clean', async (t) => {
  if (!sandboxAvailable()) { t.skip('SKIPPED, NOT PASSED: no confinement backend'); return; }
  const dir = project();
  try {
    const r = await execFileAsync(process.execPath, [CLI, dir], { timeout: 180000 })
      .then((x) => ({ code: 0, stdout: x.stdout }))
      .catch((e) => ({ code: e.code ?? 1, stdout: e.stdout || '' }));
    assert.equal(r.code, 1);
    assert.match(r.stdout, /NO_FIX/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
