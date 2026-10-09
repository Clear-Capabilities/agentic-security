// MCP scratchpad tools — append_scratchpad / read_scratchpad (harness-anatomy #4).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { append_scratchpad, read_scratchpad } from '../src/mcp/tools.js';
import { mkTestTmp } from './helpers/tmp.js';

function mkRoot() {
  return mkTestTmp('scratch-');
}

test('append + read round-trips a small payload', async () => {
  const root = mkRoot();
  const ctx = { sessionRoot: root };
  const rel = '.agentic-security/agent-scratchpad/security-fixer/s1/notes.md';
  const r1 = await append_scratchpad.handler({ path: rel, content: 'first line\n' }, ctx);
  assert.equal(r1.ok, true);
  assert.equal(r1.bytesWritten, 11);
  const r2 = await append_scratchpad.handler({ path: rel, content: 'second line\n' }, ctx);
  assert.equal(r2.ok, true);
  assert.equal(r2.fileSize, 23);
  const r3 = await read_scratchpad.handler({ path: rel }, ctx);
  assert.equal(r3.ok, true);
  assert.equal(r3.content, 'first line\nsecond line\n');
  assert.equal(r3.truncated, false);
});

test('append refuses path outside the scratchpad prefix', async () => {
  const root = mkRoot();
  const ctx = { sessionRoot: root };
  const bad = [
    '/absolute/path.md',
    '../escape.md',
    'src/app.js',
    '.agentic-security/last-scan.json',
    '.agentic-security/agent-scratchpad/../escape.md',
    '.agentic-security/agent-scratchpad/bad agent/s1/n.md',  // space rejected
    '.agentic-security/agent-scratchpad/security-fixer/s1/n;rm -rf.md',
  ];
  for (const p of bad) {
    const r = await append_scratchpad.handler({ path: p, content: 'x' }, ctx);
    assert.equal(r.ok, false, `path "${p}" should have been refused`);
  }
});

test('append enforces the per-file byte cap', async () => {
  const root = mkRoot();
  const ctx = { sessionRoot: root };
  const rel = '.agentic-security/agent-scratchpad/security-fixer/s2/big.bin';
  // Per-call write is bounded by the schema (256 KB max). The per-file cap
  // is 2 MB — so the 9th write should trip the refusal.
  const chunk = 'X'.repeat(256 * 1024);
  for (let i = 0; i < 20; i++) {
    const r = await append_scratchpad.handler({ path: rel, content: chunk }, ctx);
    if (!r.ok) {
      assert.match(r.reason, /scratchpad-file-exceeded/);
      return;
    }
  }
  assert.fail('expected scratchpad-file-exceeded refusal');
});

test('read paginates with offset+limit', async () => {
  const root = mkRoot();
  const ctx = { sessionRoot: root };
  const rel = '.agentic-security/agent-scratchpad/security-fixer/s3/page.txt';
  await append_scratchpad.handler({ path: rel, content: 'A'.repeat(1000) }, ctx);
  await append_scratchpad.handler({ path: rel, content: 'B'.repeat(1000) }, ctx);
  await append_scratchpad.handler({ path: rel, content: 'C'.repeat(1000) }, ctx);
  // Page through in 512-byte chunks.
  let off = 0, seen = 0, last = null;
  for (let i = 0; i < 10; i++) {
    const r = await read_scratchpad.handler({ path: rel, offset: off, limit: 512 }, ctx);
    assert.equal(r.ok, true);
    seen += r.bytesRead;
    last = r;
    if (!r.truncated) break;
    off = r.nextOffset;
  }
  assert.equal(seen, 3000);
  assert.equal(last.truncated, false);
});

test('read on missing file returns ok:false not-found', async () => {
  const root = mkRoot();
  const r = await read_scratchpad.handler({
    path: '.agentic-security/agent-scratchpad/security-fixer/s4/none.md',
  }, { sessionRoot: root });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'not-found');
});

test('append refuses paths without three deep components', async () => {
  const root = mkRoot();
  const ctx = { sessionRoot: root };
  // Only two parts (no <session>) — must refuse.
  const r1 = await append_scratchpad.handler({
    path: '.agentic-security/agent-scratchpad/agent/notes.md',
    content: 'x',
  }, ctx);
  assert.equal(r1.ok, false);
  assert.match(r1.reason, /agent-scratchpad/);
});
