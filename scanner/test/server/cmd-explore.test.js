// End-to-end tests of `agentic-security explore` as a real CLI subcommand —
// spawns the real bin/agentic-security.js, not the in-process modules
// tested elsewhere in this directory.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as http from 'node:http';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { signLastScan } from '../../src/posture/integrity.js';
import { statePath } from '../../src/posture/state-dir.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(__dirname, '..', '..');
const CLI = path.join(SCANNER, 'bin', 'agentic-security.js');

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-explore-cli-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _writeSignedGraph(root) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(
    {
      schemaVersion: '1.0.0',
      graphId: 'dfg:cli-test',
      generatedAt: '1970-01-01T00:00:00.000Z',
      scope: { source: 'fixture' },
      scanHealth: {},
      nodes: [],
      edges: [],
      dataElements: [],
      transformations: [],
      flows: [],
      controls: [],
      policies: [],
      evidence: [],
      coverage: {},
      limitations: [],
      extensions: {},
    },
    null,
    2,
  );
  fs.writeFileSync(graphPath, body);
  fs.writeFileSync(graphPath + '.sig', signLastScan(body));
}

function request(port, { path: reqPath, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: reqPath, method: 'GET', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('cmdExplore: missing graph -> clear error message, non-zero exit, and the token is never printed', () => {
  const root = _mkTmpProject();
  try {
    const r = spawnSync(process.execPath, [CLI, 'explore', root, '--port', '0'], { encoding: 'utf8', timeout: 10_000 });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /No lineage graph found/);
    assert.ok(!r.stdout.includes('Token:'), 'must never print a token when the server never started');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cmdExplore: missing graph -> the server genuinely never starts (a real connection attempt is refused)', async () => {
  const root = _mkTmpProject();
  const port = 58124; // fixed, unlikely-in-use port so we can positively assert refusal
  try {
    const r = spawnSync(process.execPath, [CLI, 'explore', root, '--port', String(port)], { encoding: 'utf8', timeout: 10_000 });
    assert.notEqual(r.status, 0);
    await assert.rejects(
      () => request(port, { path: '/api/v1/scan' }),
      /ECONNREFUSED/,
      'no server should be listening on the requested port after a failed loadSignedGraph',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cmdExplore: a valid signed graph starts a real server, prints the URL + token to stdout exactly once, and the printed token authenticates a real request', async () => {
  const root = _mkTmpProject();
  _writeSignedGraph(root);
  let child;
  try {
    child = spawn(process.execPath, [CLI, 'explore', root, '--port', '0'], { stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out waiting for explore to print its token; stdout so far: ${stdout}`)), 10_000);
      const onExit = (code) => { clearTimeout(timer); reject(new Error(`explore exited early with code ${code}`)); };
      child.on('exit', onExit);
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString('utf8');
        if (/URL:\s*http:\/\/127\.0\.0\.1:(\d+)\/#token=[0-9a-f]{64}/.test(stdout)) {
          clearTimeout(timer);
          child.removeListener('exit', onExit);
          resolve();
        }
      });
    });

    // The URL now carries the token as a fragment (#token=...), never a
    // query string or a separate "Token:" line — see the M3-Wire scoping
    // doc's Decision 1 (a URL fragment is never sent to the server).
    const urlMatch = stdout.match(/URL:\s*http:\/\/127\.0\.0\.1:(\d+)\/#token=([0-9a-f]{64})/g);
    assert.ok(urlMatch, `must print the URL with a fragment token; stdout was: ${stdout}`);
    assert.equal(urlMatch.length, 1, 'the URL (and its token) must be printed exactly once');

    const singleMatch = /URL:\s*http:\/\/127\.0\.0\.1:(\d+)\/#token=([0-9a-f]{64})/.exec(stdout);
    const port = Number(singleMatch[1]);
    const token = singleMatch[2];
    assert.ok(!stdout.includes('Token:'), 'must never print a separate "Token:" line now that the token lives in the URL fragment');

    const res = await request(port, {
      path: '/api/v1/scan',
      headers: { host: `127.0.0.1:${port}`, 'x-agentic-security-token': token },
    });
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.digest, 'dfg:cli-test');
  } finally {
    if (child && !child.killed) child.kill('SIGTERM');
    fs.rmSync(root, { recursive: true, force: true });
  }
});
