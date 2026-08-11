// S7 (posture --playbook) — stack-playbook.js has no test coverage at all.
// Investigating --playbook mode turned up a real content gap: _detectStack
// recognizes 'express' (and 'react', 'fastify', 'hono', 'lucia') as a stack,
// but _buildPlaybook had no corresponding section for any of them — so a
// project using Express (the most common Node backend framework, and the
// one named first in commands/posture.md's own mode description) got a
// silent empty playbook: stack detected, zero checklist items, zero
// findings. Reproduced live against test/fixtures/vulnerable-js, which
// genuinely depends on express in its package.json.
//
// Fixed with a real Express section (mirroring the existing sections'
// style: 5-6 specific, actionable items naming real APIs). react/fastify/
// hono/lucia remain undocumented gaps — content-authoring work, not a
// wiring fix, and out of scope for this pass; not silently claimed as
// fixed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { runStackPlaybook, _detectStack, _buildPlaybook } from '../src/posture/stack-playbook.js';

async function mkProject(pkg) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'stack-pb-'));
  await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg));
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

test('an express project produces real playbook findings, not a silent empty set', async () => {
  const p = await mkProject({ dependencies: { express: '4.16.0' } });
  try {
    const r = runStackPlaybook(p.dir);
    assert.deepEqual(r.stack, ['express']);
    assert.ok(r.playbook.length > 0, 'express must have a real playbook section');
    assert.ok(r.findings.length > 0, 'express must produce at least one checklist finding');
    assert.ok(r.findings.every(f => f.id.startsWith('stack-playbook:EXPRESS:')));
  } finally { await p.cleanup(); }
});

// Second, independent bug found while verifying the above end-to-end through
// a real scan: every stack-playbook finding set `title` instead of the
// schema-required `vuln` field (root CLAUDE.md: findings must carry `vuln`).
// engine.js's generic `_shouldKeep` filter treats any non-SCA finding with no
// `vuln` string as "unenriched noise" and silently drops it — confirmed live
// via a real CLI scan of a project with express in package.json: 6 real
// checklist findings were computed, pushed into aLogic, and then all 6
// vanished before the return, logged as `no-vuln-name:unenriched-finding`
// suppressions. The playbook feature has therefore never actually surfaced a
// finding through a real scan, for ANY stack, regardless of section content.
test('every playbook finding sets vuln (not title) so the engine does not drop it as unenriched', async () => {
  const p = await mkProject({ dependencies: { express: '4.16.0' } });
  try {
    const r = runStackPlaybook(p.dir);
    assert.ok(r.findings.length > 0);
    for (const f of r.findings) {
      assert.equal(typeof f.vuln, 'string', `finding ${f.id} must set a string 'vuln' field, not 'title'`);
      assert.ok(f.vuln.length > 0);
    }
  } finally { await p.cleanup(); }
});

test('the express section names real, specific Express APIs, not generic advice', () => {
  const sections = _buildPlaybook(new Set(['express']));
  const express = sections.find(s => s.title === 'Express');
  assert.ok(express, 'expected an Express section');
  assert.ok(express.items.length >= 4);
  const joined = express.items.join(' ');
  assert.match(joined, /helmet/i);
});

test('a project with no recognized stack produces an empty playbook, not an error', async () => {
  const p = await mkProject({ dependencies: { 'left-pad': '1.0.0' } });
  try {
    const r = runStackPlaybook(p.dir);
    assert.deepEqual(r, []);
  } finally { await p.cleanup(); }
});

// End-to-end: proves the findings survive the real engine pipeline
// (specifically engine.js's `_shouldKeep` no-vuln-name filter), not just
// runStackPlaybook() in isolation — that's exactly the gap that hid this
// bug from the unit-level tests above.
test('stack-playbook findings survive a real runScan() end to end, not just runStackPlaybook() in isolation', async () => {
  const dir = await mkProjectWithFile();
  try {
    const { runScan } = await import('../src/runScan.js');
    const { scan } = await runScan(dir, { network: false });
    const spFindings = (scan.logicVulns || []).filter((f) => (f.id || '').startsWith('stack-playbook:'));
    assert.ok(spFindings.length > 0,
      'stack-playbook findings must survive to scan.logicVulns after a real scan, not be silently dropped as "no-vuln-name:unenriched-finding"');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

async function mkProjectWithFile() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'stack-pb-e2e-'));
  await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { express: '4.16.0' } }));
  await fsp.writeFile(path.join(dir, 'app.js'), 'const express = require("express");\nconst app = express();\n');
  return dir;
}
