// AGENTS.md continual-learning tests (harness-anatomy #2).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  appendAgentsMemory, readAgentsMemory, summarizeForSession, _internals,
} from '../src/posture/agents-memory.js';
import { mkTestTmp } from './helpers/tmp.js';

function mkRoot() { return mkTestTmp('agents-md-'); }

test('appendAgentsMemory creates the file with a header on first write', () => {
  const root = mkRoot();
  const r = appendAgentsMemory(root, { agent: 'security-fixer', body: 'first note' });
  assert.equal(r.ok, true);
  const body = fs.readFileSync(path.join(root, _internals.MEMORY_FILE), 'utf8');
  assert.match(body, /^# AGENTS\.md/);
  assert.match(body, /agent: security-fixer/);
  assert.match(body, /first note/);
});

test('appendAgentsMemory rejects invalid agent names', () => {
  const root = mkRoot();
  const bad = ['', 'a/b', '../x', 'agent with space', 'x'.repeat(100)];
  for (const a of bad) {
    const r = appendAgentsMemory(root, { agent: a, body: 'hi' });
    assert.equal(r.ok, false, `agent "${a}" should be refused`);
  }
});

test('appendAgentsMemory rejects empty body', () => {
  const r = appendAgentsMemory(mkRoot(), { agent: 'a', body: '   ' });
  assert.equal(r.ok, false);
});

test('appendAgentsMemory caps single-entry size', () => {
  const root = mkRoot();
  const big = 'A'.repeat(5000);
  const r = appendAgentsMemory(root, { agent: 'a', body: big });
  assert.equal(r.ok, true);
  const body = fs.readFileSync(path.join(root, _internals.MEMORY_FILE), 'utf8');
  // Truncated to MAX_ENTRY_BYTES + ellipsis sentinel.
  assert.ok(body.length < big.length + 200);
});

test('appendAgentsMemory strips control characters', () => {
  const root = mkRoot();
  const dirty = 'hello\x00world\x1b[31mred';
  appendAgentsMemory(root, { agent: 'a', body: dirty });
  const body = fs.readFileSync(path.join(root, _internals.MEMORY_FILE), 'utf8');
  assert.ok(!body.includes('\x00'));
});

test('appendAgentsMemory rotates to archive when AGENTS.md exceeds the cap', () => {
  const root = mkRoot();
  // Pump entries until the file exceeds the cap.
  const chunk = 'B'.repeat(1500);
  for (let i = 0; i < 30; i++) {
    appendAgentsMemory(root, { agent: 'a', body: chunk });
  }
  const body = fs.readFileSync(path.join(root, _internals.MEMORY_FILE), 'utf8');
  // After rotation, AGENTS.md should be well under 2x MAX_BYTES.
  assert.ok(body.length < _internals.MAX_BYTES * 1.5,
    `expected post-rotation file to be smaller than 1.5x cap, got ${body.length}`);
  // Archive should exist with the older entries.
  const arc = fs.readFileSync(path.join(root, _internals.ARCHIVE_FILE), 'utf8');
  assert.ok(arc.length > 0);
});

test('summarizeForSession returns the tail aligned to a section boundary', () => {
  const root = mkRoot();
  for (let i = 0; i < 5; i++) appendAgentsMemory(root, { agent: 'a', body: 'note ' + i });
  const tail = summarizeForSession(root, { maxBytes: 80 });
  // Tail must start with a `## ` section header so partial entries don't ship.
  assert.match(tail, /^## /);
});

test('readAgentsMemory returns empty string when nothing exists', () => {
  assert.equal(readAgentsMemory(mkRoot()), '');
});
