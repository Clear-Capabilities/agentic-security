// MCP apply_fix for a MULTI-FILE NixOS fix (plan_digest). The plan is recomputed by the server from the signed finding and the
// live tree and bound to the plan synthesize_fix returned by a digest; the write is the language lifecycle's all-or-nothing
// writeManyWithBackup with one history group. Every precondition of the single-file tool applies to EVERY file, and each is
// pinned here in both directions: the good path writes, the hostile one leaves the tree byte-identical.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { createServer } from '../src/mcp/server.js';
import { signLastScan } from '../src/posture/integrity.js';
import { analyzeNixosHardening } from '../src/language/nixos-hardening.js';
import { listHistory, undoLast } from '../src/posture/fix-history.js';
import { _internals } from '../src/mcp/tools.js';

const OPT = 'services.openssh.settings.PermitRootLogin';
const ENTRY = (imports) => `{ config, lib, ... }:\n{\n  imports = [ ${imports.join(' ')} ];\n  services.openssh.enable = true;\n}\n`;
const MOD = (body) => `{ lib, ... }:\n{\n  ${OPT} = ${body};\n}\n`;
const TWO = () => ({ 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') });

function findingOf(files, extra = {}) {
  const f = analyzeNixosHardening({ entry: 'configuration.nix', files }).findings.find((x) => x.rule === 'ssh-root-login');
  assert.ok(f, 'the fixture produces the ssh-root-login finding');
  return { ...JSON.parse(JSON.stringify(f)), id: 'NIX-MF-1', stableId: 'stable-nix-mf-1', ...extra };
}

function session(files, { finding = null, sign = true, scanBody = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-mcp-mf-'));
  for (const [p, t] of Object.entries(files)) {
    const abs = path.join(root, p);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, t);
  }
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"as-mcp-mf"}');
  const state = path.join(root, '.agentic-security');
  fs.mkdirSync(state, { recursive: true });
  const fnd = finding || findingOf(files);
  const body = scanBody || JSON.stringify({ findings: [fnd] });
  fs.writeFileSync(path.join(state, 'last-scan.json'), body);
  if (sign) fs.writeFileSync(path.join(state, 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: root });
  return { root, handleRequest, finding: fnd, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
const call = (h, name, args) => h({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
const out = (r) => {
  if (r.error) return { rpcError: r.error.message };
  const t = r.result.content[0].text;
  try { return JSON.parse(t); } catch { return { rpcError: t }; }
};
const disk = (root, files) => Object.fromEntries(Object.keys(files).map((p) => [p, fs.readFileSync(path.join(root, p), 'utf8')]));

async function synth(s) {
  const p = out(await call(s.handleRequest, 'synthesize_fix', { finding_id: 'NIX-MF-1' }));
  assert.equal(p.ok, true);
  return p;
}
const apply = async (s, extra = {}) => out(await call(s.handleRequest, 'apply_fix', { finding_id: 'NIX-MF-1', confirm: true, ...extra }));

// ─── the good path ──────────────────────────────────────────────────────────

test('synthesize_fix offers a multi-file plan with a digest and NO file content; apply_fix with that digest edits every file, verified, in one history group', async () => {
  const files = TWO();
  const s = session(files);
  try {
    const p = await synth(s);
    assert.deepEqual([...p.languageFix.multiFile].sort(), ['a.nix', 'b.nix']);
    assert.match(p.languageFix.planDigest, /^[0-9a-f]{64}$/);
    assert.equal(p.languageFix.applyWith.plan_digest, p.languageFix.planDigest);
    assert.equal(p.autofix, null, 'a multi-file plan is never offered as a single-file autofix');
    for (const e of p.languageFix.edits) assert.deepEqual(Object.keys(e).sort(), ['afterSha256', 'beforeSha256', 'file']);

    const r = await apply(s, { plan_digest: p.languageFix.planDigest });
    assert.equal(r.applied, true, JSON.stringify(r));
    assert.equal(r.multiFile, true);
    assert.deepEqual([...r.files].sort(), ['a.nix', 'b.nix']);
    assert.equal(r.gates.rescan.ok, true);
    assert.equal(r.gates.effective.ran, true);
    assert.match(r.gates.effective.detail, /"no"/);
    const d = disk(s.root, files);
    assert.match(d['a.nix'], /"no"/); assert.match(d['b.nix'], /"no"/);
    assert.equal(d['configuration.nix'], files['configuration.nix']);

    const hist = listHistory(s.root);
    assert.equal(hist.length, 2);
    assert.equal(new Set(hist.map((h) => h.languageGroupId)).size, 1, 'one history group');
    assert.equal(hist[0].languageGroupId, r.groupId);
    assert.ok(!JSON.stringify(r).includes(s.root), 'no absolute path in the result');

    // undo reverts the whole group
    const u = await undoLast(s.root);
    assert.ok(!u.error, JSON.stringify(u));
    assert.deepEqual(disk(s.root, files), files, 'undo restored every file');
  } finally { s.cleanup(); }
});

test('dry_run verifies the multi-file plan and writes nothing', async () => {
  const files = TWO();
  const s = session(files);
  try {
    const p = await synth(s);
    const r = await apply(s, { plan_digest: p.languageFix.planDigest, dry_run: true });
    assert.equal(r.applied, false); assert.equal(r.dryRun, true); assert.equal(r.verified, true);
    assert.match(r.diff, /--- a\/a\.nix/); assert.match(r.diff, /--- a\/b\.nix/);
    assert.deepEqual(disk(s.root, files), files);
    assert.equal(listHistory(s.root).length, 0);
  } finally { s.cleanup(); }
});

// ─── preconditions, each in both directions ─────────────────────────────────

test('refuses without confirm:true, even with a correct digest', async () => {
  const files = TWO(); const s = session(files);
  try {
    const p = await synth(s);
    const r = out(await call(s.handleRequest, 'apply_fix', { finding_id: 'NIX-MF-1', plan_digest: p.languageFix.planDigest, confirm: false }));
    assert.equal(r.applied, false); assert.match(r.reason, /confirm: true/);
    assert.deepEqual(disk(s.root, files), files);
    const missing = out(await call(s.handleRequest, 'apply_fix', { finding_id: 'NIX-MF-1', plan_digest: p.languageFix.planDigest }));
    assert.ok(missing.rpcError || missing.applied === false);
    assert.deepEqual(disk(s.root, files), files);
  } finally { s.cleanup(); }
});

test('refuses a stale (unsigned) and a tampered last-scan', async () => {
  const files = TWO();
  const unsigned = session(files, { sign: false });
  try {
    const r = await apply(unsigned, { plan_digest: 'a'.repeat(64) });
    assert.equal(r.applied, false); assert.match(r.reason, /integrity check: unsigned/);
    assert.deepEqual(disk(unsigned.root, files), files);
  } finally { unsigned.cleanup(); }

  const s = session(files);
  try {
    const p = await synth(s);
    // Tamper AFTER signing: the finding is forged to point at other content; the signature no longer verifies.
    const f = path.join(s.root, '.agentic-security', 'last-scan.json');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('NIX-MF-1', 'NIX-MF-1') + ' ');
    const r = await apply(s, { plan_digest: p.languageFix.planDigest });
    assert.equal(r.applied, false); assert.match(r.reason, /integrity check: tampered/);
    assert.deepEqual(disk(s.root, files), files);
  } finally { s.cleanup(); }
});

test('refuses a shadow finding', async () => {
  const files = TWO();
  const s = session(files, { finding: findingOf(files, { _shadow: true }) });
  try {
    const r = await apply(s, { plan_digest: 'b'.repeat(64) });
    assert.equal(r.applied, false); assert.match(r.reason, /shadow findings cannot be auto-applied/);
    assert.deepEqual(disk(s.root, files), files);
  } finally { s.cleanup(); }
});

test('plan_digest cannot be combined with a caller-supplied patch', async () => {
  const files = TWO(); const s = session(files);
  try {
    const p = await synth(s);
    const r = await apply(s, { plan_digest: p.languageFix.planDigest, patch: { 'a.nix': MOD('"no"') } });
    assert.equal(r.applied, false); assert.match(r.reason, /cannot be combined/);
    assert.deepEqual(disk(s.root, files), files);
  } finally { s.cleanup(); }
});

// ─── plan binding ───────────────────────────────────────────────────────────

test('an altered digest, a malformed digest, and another finding\'s digest are all refused', async () => {
  const files = TWO(); const s = session(files);
  try {
    const p = await synth(s);
    const good = p.languageFix.planDigest;
    const flipped = (good[0] === '0' ? '1' : '0') + good.slice(1);
    const r1 = await apply(s, { plan_digest: flipped });
    assert.equal(r1.applied, false); assert.equal(r1.stale, true); assert.match(r1.reason, /does not match the plan/);
    assert.ok(!r1.reason.includes(good), 'the expected digest is not echoed back');
    const r2 = await apply(s, { plan_digest: 'Z'.repeat(64) });
    assert.equal(r2.applied, false); assert.match(r2.reason, /64-character hex/);
    const r3 = out(await call(s.handleRequest, 'apply_fix', { finding_id: 'NIX-MF-1', confirm: true, plan_digest: 'abc' }));
    assert.match(String(r3.rpcError || r3.reason), /minLength|64/);
    assert.deepEqual(disk(s.root, files), files);
    // direction two: the right digest still works afterwards (the refusals changed nothing)
    const ok = await apply(s, { plan_digest: good });
    assert.equal(ok.applied, true, JSON.stringify(ok));
  } finally { s.cleanup(); }
});

test('a file changed since the preview invalidates the digest: nothing is written', async () => {
  const files = TWO(); const s = session(files);
  try {
    const p = await synth(s);
    fs.writeFileSync(path.join(s.root, 'b.nix'), `${files['b.nix']}# edited after the preview\n`);
    const r = await apply(s, { plan_digest: p.languageFix.planDigest });
    assert.equal(r.applied, false); assert.equal(r.stale, true);
    assert.equal(fs.readFileSync(path.join(s.root, 'a.nix'), 'utf8'), files['a.nix'], 'the untouched sibling was not edited either');
    assert.match(fs.readFileSync(path.join(s.root, 'b.nix'), 'utf8'), /edited after the preview/);
    assert.equal(listHistory(s.root).length, 0);
  } finally { s.cleanup(); }
});

test('a plan edited in transit is refused: a digest for a DIFFERENT file set (same finding) does not authorize this one', async () => {
  const files = TWO(); const s = session(files);
  try {
    const f = s.finding;
    const forged = _internals.multiFilePlanDigest(f, [{ file: 'a.nix', before: files['a.nix'], after: MOD('"no"') }, { file: 'evil.nix', before: '', after: 'x' }]);
    const r = await apply(s, { plan_digest: forged });
    assert.equal(r.applied, false); assert.equal(r.stale, true);
    assert.deepEqual(disk(s.root, files), files);
    assert.ok(!fs.existsSync(path.join(s.root, 'evil.nix')));
  } finally { s.cleanup(); }
});

test('the digest binds the finding: the same edits under another finding id do not match', () => {
  const edits = [{ file: 'a.nix', before: 'x', after: 'y' }, { file: 'b.nix', before: 'x', after: 'y' }];
  const d1 = _internals.multiFilePlanDigest({ id: 'A', stableId: 's' }, edits);
  assert.notEqual(d1, _internals.multiFilePlanDigest({ id: 'B', stableId: 's' }, edits));
  assert.notEqual(d1, _internals.multiFilePlanDigest({ id: 'A', stableId: 's' }, [{ ...edits[0], after: 'z' }, edits[1]]));
  assert.equal(d1, _internals.multiFilePlanDigest({ id: 'A', stableId: 's' }, edits.slice().reverse()), 'order of edits does not matter');
});

// ─── confinement / reserved paths, applied to EVERY file ────────────────────

test('checkMultiFileTargets: traversal, absolute, backslash, NUL, duplicate, symlink leaf, symlinked parent, reserved, missing, too many', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-mcp-mf-t-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-mcp-mf-o-'));
  try {
    fs.writeFileSync(path.join(root, 'ok.nix'), 'x'); fs.writeFileSync(path.join(root, 'ok2.nix'), 'x');
    fs.writeFileSync(path.join(outside, 'secret.nix'), 'x');
    fs.symlinkSync(path.join(outside, 'secret.nix'), path.join(root, 'link.nix'));
    fs.symlinkSync(outside, path.join(root, 'linkdir'));
    fs.mkdirSync(path.join(root, 'k8s')); fs.writeFileSync(path.join(root, 'k8s', 'm.nix'), 'x');
    fs.mkdirSync(path.join(root, '.github')); fs.writeFileSync(path.join(root, '.github', 'm.nix'), 'x');
    fs.mkdirSync(path.join(root, 'dist')); fs.writeFileSync(path.join(root, 'dist', 'm.nix'), 'x');
    fs.mkdirSync(path.join(root, '.agentic-security')); fs.writeFileSync(path.join(root, '.agentic-security', 'm.nix'), 'x');
    fs.symlinkSync(path.join(root, '.github'), path.join(root, 'innocent'));
    fs.writeFileSync(path.join(root, 'flake.lock'), '{}');
    const E = (...files) => files.map((file) => ({ file, before: 'x', after: 'y' }));
    const check = (...files) => _internals.checkMultiFileTargets(root, E(...files));

    assert.equal(check('ok.nix', 'ok2.nix').ok, true, 'good: two clean in-root files pass');
    for (const [bad, re] of [
      [['ok.nix', '../x.nix'], /path-escape refused/],
      [['ok.nix', '/etc/passwd'], /path-escape refused/],
      [['ok.nix', path.join(root, 'ok2.nix')], /path-escape refused/],
      [['ok.nix', 'a\\b.nix'], /path-escape refused/],
      [['ok.nix', 'a\0b.nix'], /path-escape refused/],
      [['ok.nix', 'sub/../ok2.nix'], /path-escape refused/],
      [['ok.nix', 'ok.nix'], /twice/],
      [['ok.nix', 'link.nix'], /symbolic link/],
      [['ok.nix', 'linkdir/secret.nix'], /path-escape refused/],
      [['ok.nix', 'innocent/m.nix'], /path-escape refused/],
      [['ok.nix', 'k8s/m.nix'], /reserved path refused: k8s\/m\.nix/],
      [['ok.nix', '.github/m.nix'], /reserved path refused/],
      [['ok.nix', 'dist/m.nix'], /reserved path refused/],
      [['ok.nix', '.agentic-security/m.nix'], /reserved path refused/],
      [['ok.nix', 'flake.lock'], /reserved path refused/],
      [['ok.nix', 'missing.nix'], /not found/],
      [['ok.nix'], /at least two/],
    ]) {
      const r = check(...bad);
      assert.equal(r.ok, false, `refused: ${JSON.stringify(bad)}`);
      assert.match(r.reason, re, JSON.stringify(bad));
      assert.ok(!r.reason.includes(root) && !r.reason.includes(outside), 'no absolute path leaks');
    }
    const many = Array.from({ length: 9 }, (_, i) => `m${i}.nix`);
    for (const m of many) fs.writeFileSync(path.join(root, m), 'x');
    assert.equal(check(...many).ok, false);
    assert.equal(fs.readFileSync(path.join(outside, 'secret.nix'), 'utf8'), 'x', 'the file behind the symlink is untouched');
  } finally { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); }
});

test('end to end: a winning definition in a reserved directory refuses the WHOLE plan, including the clean sibling', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './k8s/b.nix']), 'a.nix': MOD('"yes"'), 'k8s/b.nix': MOD('"yes"') };
  const s = session(files);
  try {
    const p = await synth(s);
    assert.ok(p.languageFix.planDigest, 'the preview itself is read-only and may show the plan');
    const r = await apply(s, { plan_digest: p.languageFix.planDigest });
    assert.equal(r.applied, false); assert.match(r.reason, /reserved path refused: k8s\/b\.nix/);
    assert.deepEqual(disk(s.root, files), files, 'a.nix was not edited either');
    assert.equal(listHistory(s.root).length, 0);
  } finally { s.cleanup(); }
});

test('end to end: a module that is a symlink out of the root is never part of a plan and is never written through', async () => {
  const files = TWO();
  const s = session(files);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'as-mcp-mf-o-'));
  try {
    const target = path.join(outside, 'b.nix');
    fs.writeFileSync(target, files['b.nix']);
    fs.rmSync(path.join(s.root, 'b.nix'));
    fs.symlinkSync(target, path.join(s.root, 'b.nix'));
    const p = out(await call(s.handleRequest, 'synthesize_fix', { finding_id: 'NIX-MF-1' }));
    const digest = p.languageFix && p.languageFix.planDigest;
    const r = await apply(s, { plan_digest: digest || 'c'.repeat(64) });
    assert.equal(r.applied, false);
    assert.equal(fs.readFileSync(target, 'utf8'), files['b.nix'], 'the file outside the root is untouched');
    assert.equal(fs.readFileSync(path.join(s.root, 'a.nix'), 'utf8'), files['a.nix'], 'no partial edit of the sibling');
  } finally { s.cleanup(); fs.rmSync(outside, { recursive: true, force: true }); }
});

// ─── verification gate and partial failure ──────────────────────────────────

test('a plan that does not verify (stale evidence edits only one of two winners) is blocked on the effective value and writes nothing', async () => {
  const files = TWO();
  const f0 = findingOf(files);
  const stale = JSON.parse(JSON.stringify(f0));
  const ev = stale.evidence.find((e) => e.option === OPT);
  ev.sources = ev.sources.filter((x) => x.file === 'a.nix');
  const s = session(files, { finding: stale });
  try {
    const p = out(await call(s.handleRequest, 'synthesize_fix', { finding_id: 'NIX-MF-1' }));
    // a single-file plan is not offered as a multi-file digest, and plan_digest on it is refused
    assert.ok(!p.languageFix || !p.languageFix.planDigest);
    const r = await apply(s, { plan_digest: 'd'.repeat(64) });
    assert.equal(r.applied, false);
    assert.deepEqual(disk(s.root, files), files);
  } finally { s.cleanup(); }
});

test('a write that fails midway: the first file is put back, and a rollback that cannot complete is REPORTED as incomplete, never as success', async (t) => {
  if (process.getuid && process.getuid() === 0) return t.skip('root ignores file modes');
  const files = TWO(); const s = session(files);
  try {
    const p = await synth(s);
    // A read-only b.nix makes its write fail, and the rollback write to the same file fails for the same reason.
    fs.chmodSync(path.join(s.root, 'b.nix'), 0o444);
    const r = await apply(s, { plan_digest: p.languageFix.planDigest });
    assert.equal(r.applied, false);
    assert.equal(r.rolledBack, false); assert.equal(r.rollbackIncomplete, true);
    assert.deepEqual(r.restoreManually, ['b.nix']);
    assert.match(r.reason, /ROLLBACK INCOMPLETE/);
    assert.ok(!JSON.stringify(r).includes(s.root), 'no absolute path leaks from the OS error');
    fs.chmodSync(path.join(s.root, 'b.nix'), 0o644);
    assert.deepEqual(disk(s.root, files), files, 'a.nix, which was written first, is back to its original bytes, and b.nix never changed');
    assert.equal(listHistory(s.root).length, 0, 'a failed apply leaves no history entry');
  } finally { try { fs.chmodSync(path.join(s.root, 'b.nix'), 0o644); } catch {} s.cleanup(); }
});

test('a multi-file plan for a finding with a single-file plan, or a non-Nix finding, is refused', async () => {
  const single = { 'configuration.nix': ENTRY(['./ssh.nix']), 'ssh.nix': MOD('"yes"') };
  const s = session(single);
  try {
    const p = await synth(s);
    assert.ok(!p.languageFix.planDigest, 'no digest is offered for a single-file plan');
    const r = await apply(s, { plan_digest: 'e'.repeat(64) });
    assert.equal(r.applied, false); assert.match(r.reason, /single-file plan/);
    assert.deepEqual(disk(s.root, single), single);
  } finally { s.cleanup(); }
  const js = session({ 'app.js': 'x' }, { finding: { id: 'NIX-MF-1', stableId: 's', severity: 'high', file: 'app.js', line: 1, rule: 'x' } });
  try {
    const r = await apply(js, { plan_digest: 'e'.repeat(64) });
    assert.equal(r.applied, false); assert.match(r.reason, /NixOS findings only/);
  } finally { js.cleanup(); }
});
