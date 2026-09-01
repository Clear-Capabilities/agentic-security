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
        if (/Token:\s*[0-9a-f]{64}/.test(stdout) && /URL:\s*http:\/\/127\.0\.0\.1:(\d+)/.test(stdout)) {
          clearTimeout(timer);
          child.removeListener('exit', onExit);
          resolve();
        }
      });
    });

    const portMatch = stdout.match(/URL:\s*http:\/\/127\.0\.0\.1:(\d+)/);
    const tokenMatches = stdout.match(/Token:\s*[0-9a-f]{64}/g) || [];
    assert.ok(portMatch, `must print the bound port; stdout was: ${stdout}`);
    assert.equal(tokenMatches.length, 1, 'the token must be printed exactly once');

    const port = Number(portMatch[1]);
    const token = stdout.match(/Token:\s*([0-9a-f]{64})/)[1];

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
