// The lifecycle's preWrite hook: the last check after every gate has passed and before the first byte is written. It exists so a
// caller that bound a plan to something outside the lifecycle (the MCP apply_fix plan digest and confinement policy) refuses
// atomically with the write it guards.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { validateNixFix } from '../../src/language/nix-fix.js';
import { analyzeNixosHardening } from '../../src/language/nixos-hardening.js';
import { listHistory } from '../../src/posture/fix-history.js';

const OPT = 'services.openssh.settings.PermitRootLogin';
const ENTRY = (imports) => `{ config, lib, ... }:\n{\n  imports = [ ${imports.join(' ')} ];\n  services.openssh.enable = true;\n}\n`;
const MOD = (body) => `{ lib, ... }:\n{\n  ${OPT} = ${body};\n}\n`;
const files = () => ({ 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') });
const finding = (f) => analyzeNixosHardening({ entry: 'configuration.nix', files: f }).findings.find((x) => x.rule === 'ssh-root-login');
function project(f) {
  const root = mkdtempSync(join(tmpdir(), 'nix-prewrite-'));
  for (const [p, t] of Object.entries(f)) { const abs = join(root, p); mkdirSync(dirname(abs), { recursive: true }); writeFileSync(abs, t); }
  return root;
}
const onDisk = (root, f) => Object.fromEntries(Object.keys(f).map((p) => [p, readFileSync(join(root, p), 'utf8')]));

test('preWrite sees the verified plan; ok:true writes', async () => {
  const f = files(); const root = project(f);
  let seen = null;
  const res = await validateNixFix(finding(f), { files: f, apply: true, root, preWrite: (plan) => { seen = plan.edits.map((e) => e.file).sort(); return { ok: true }; } });
  assert.equal(res.status, 'applied', res.reason);
  assert.deepEqual(seen, ['a.nix', 'b.nix']);
  assert.match(onDisk(root, f)['a.nix'], /"no"/);
  assert.equal(listHistory(root).length, 2);
});

for (const [label, hook, re] of [
  ['refuses', () => ({ ok: false, detail: 'digest mismatch' }), /^pre-write: digest mismatch \(no file was written\)/],
  ['throws', () => { throw new Error('boom'); }, /^pre-write: pre-write check failed: boom/],
  ['answers nothing', () => undefined, /^pre-write: no pre-write result/],
  ['answers a truthy non-true ok', () => ({ ok: 'yes' }), /^pre-write:/],
]) {
  test(`preWrite that ${label} blocks with nothing written and nothing recorded`, async () => {
    const f = files(); const root = project(f);
    const res = await validateNixFix(finding(f), { files: f, apply: true, root, preWrite: hook });
    assert.equal(res.status, 'blocked'); assert.equal(res.applied, false);
    assert.match(res.reason, re);
    assert.deepEqual(onDisk(root, f), f);
    assert.equal(listHistory(root).length, 0);
  });
}

test('a preview (apply:false) never invokes preWrite', async () => {
  const f = files(); let called = false;
  const res = await validateNixFix(finding(f), { files: f, apply: false, root: project(f), preWrite: () => { called = true; return { ok: false }; } });
  assert.equal(res.status, 'verified'); assert.equal(called, false);
});
