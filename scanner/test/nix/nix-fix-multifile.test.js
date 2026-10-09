// Multi-file NixOS fixes. A NixOS option is judged on the EFFECTIVE configuration, so the definition that wins may live in a
// different file than the finding's anchor, several files may hold a definition at the winning priority, and a stronger one
// (mkForce) may sit anywhere. These tests pin: which files a fix edits, what it refuses (with a stated reason and a suggested
// override line), that verification is on the effective value, that every touched file is backed up and recorded, and that a
// failed write or a failed undo never leaves a half-changed tree.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { planNixFix, validateNixFix, undoFix } from '../../src/language/nix-fix.js';
import { runFixLifecycle } from '../../src/language/fix-lifecycle.js';
import { analyzeNixosHardening } from '../../src/language/nixos-hardening.js';
import { resolveNixosConfig } from '../../src/language/nixos-module-resolver.js';
import { listHistory, undoLast } from '../../src/posture/fix-history.js';
import { mkTestTmp } from '../helpers/tmp.js';

const OPT = 'services.openssh.settings.PermitRootLogin';
const ENTRY = (imports) => `{ config, lib, ... }:\n{\n  imports = [ ${imports.join(' ')} ];\n  services.openssh.enable = true;\n}\n`;
const MOD = (body) => `{ lib, ... }:\n{\n  ${OPT} = ${body};\n}\n`;
const hardening = (files) => analyzeNixosHardening({ entry: 'configuration.nix', files }).findings;
const rootFinding = (files) => hardening(files).find((f) => f.rule === 'ssh-root-login');
const effective = (files) => resolveNixosConfig({ entry: 'configuration.nix', files }).lookup(OPT);

function project(files) {
  const root = mkTestTmp('nix-multifile-');
  for (const [p, t] of Object.entries(files)) {
    const abs = join(root, p);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, t);
  }
  return root;
}
const onDisk = (root, files) => Object.fromEntries(Object.keys(files).map((p) => [p, readFileSync(join(root, p), 'utf8')]));

test('[multifile] the winner lives in an imported module: only that file is edited, backed up, recorded, and the effective value is "no"', async () => {
  const files = { 'configuration.nix': ENTRY(['./ssh.nix']), 'ssh.nix': MOD('"yes"') };
  const f = rootFinding(files);
  assert.equal(f.file, 'ssh.nix', 'the finding is anchored on the module that holds the winning definition');
  const root = project(files);
  const res = await validateNixFix(f, { files, apply: true, root });
  assert.equal(res.status, 'applied', `${res.reason} ${JSON.stringify(res.gates)}`);
  assert.deepEqual(res.files, ['ssh.nix']);
  assert.equal(res.gates.effective.ran, true);
  assert.equal(res.gates.effective.value, 'no');
  const disk = onDisk(root, files);
  assert.equal(disk['configuration.nix'], files['configuration.nix'], 'the entry module is untouched');
  assert.match(disk['ssh.nix'], /PermitRootLogin = "no";/);
  assert.equal(effective(disk).value, 'no');
  assert.equal(hardening(disk).filter((x) => x.rule === 'ssh-root-login').length, 0);
  assert.equal(listHistory(root).length, 1);
});

test('[multifile] two files define the option at the winning priority: BOTH are edited, because editing one makes a module-system conflict', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const f = rootFinding(files);
  assert.equal(f.evidence.find((e) => e.option === OPT).sources.filter((s) => s.role === 'winner').length, 2);
  // Why the old single-file edit was wrong: the finding disappears from a rescan, but the configuration no longer evaluates.
  const half = { ...files, 'a.nix': MOD('"no"') };
  assert.equal(hardening(half).filter((x) => x.rule === 'ssh-root-login').length, 0, 'a rescan alone cannot tell this from a fix');
  assert.equal(effective(half).status, 'conflict', 'the effective configuration is a conflict');

  const plan = planNixFix(f, files);
  assert.equal(plan.ok, true, plan.reason);
  assert.deepEqual(plan.edits.map((e) => e.file).sort(), ['a.nix', 'b.nix']);
  assert.match(plan.consequences.join('\n'), /2 files are edited together/);

  const root = project(files);
  const res = await validateNixFix(f, { files, apply: true, root });
  assert.equal(res.status, 'applied', `${res.reason} ${JSON.stringify(res.gates)}`);
  assert.deepEqual([...res.files].sort(), ['a.nix', 'b.nix']);
  const disk = onDisk(root, files);
  assert.match(disk['a.nix'], /"no"/); assert.match(disk['b.nix'], /"no"/);
  assert.equal(effective(disk).status, 'set'); assert.equal(effective(disk).value, 'no');
  assert.match(res.preview, /--- a\/a\.nix/); assert.match(res.preview, /--- a\/b\.nix/);
  // every touched file has its own backup and its own history entry, all tied to one group
  const hist = listHistory(root);
  assert.equal(hist.length, 2);
  assert.equal(new Set(hist.map((h) => h.languageGroupId)).size, 1);
  assert.deepEqual(hist.map((h) => h.file).sort(), ['a.nix', 'b.nix']);
  for (const h of hist) assert.ok(existsSync(join(root, h.backupPath)), `backup exists for ${h.file}`);
});

test('[multifile] a preview never writes, even for a multi-file fix', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const res = await validateNixFix(rootFinding(files), { files, apply: false, root });
  assert.equal(res.status, 'verified'); assert.equal(res.applied, false);
  assert.deepEqual(onDisk(root, files), files);
});

test('[multifile] a mkForce in another module wins: that definition is edited, the weaker one is left, and editing the weaker one is refused naming the winner', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('lib.mkForce "yes"') };
  const f = rootFinding(files);
  const plan = planNixFix(f, files);
  assert.equal(plan.ok, true, plan.reason);
  assert.deepEqual(plan.edits.map((e) => e.file), ['b.nix']);
  assert.match(plan.after, /mkForce "no"/);
  assert.match(plan.consequences.join('\n'), /Weaker definitions[^\n]*a\.nix:\d+/);
  const root = project(files);
  const res = await validateNixFix(f, { files, apply: true, root });
  assert.equal(res.status, 'applied', res.reason);
  const disk = onDisk(root, files);
  assert.equal(disk['a.nix'], files['a.nix']);
  assert.equal(effective(disk).value, 'no');

  // The chosen definition is overridden: nothing is edited and the reason names what wins.
  const root2 = project(files);
  const refused = await validateNixFix(f, { files, source: { file: 'a.nix', line: 3 }, apply: true, root: root2 });
  assert.equal(refused.status, 'blocked'); assert.equal(refused.applied, false);
  assert.match(refused.reason, /overridden by b\.nix:\d+ \(mkForce\)/);
  assert.deepEqual(refused.proposal.editInstead.map((e) => e.file), ['b.nix']);
  assert.deepEqual(onDisk(root2, files), files);
});

test('[multifile] a stale plan that edits only one of two equal-priority winners is blocked on the EFFECTIVE value, not reported fixed', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const f = rootFinding(files);
  // Stale evidence: it lists only a.nix as a winner, so the planner edits a.nix alone. The rescan then sees no finding...
  const stale = JSON.parse(JSON.stringify(f));
  const ev = stale.evidence.find((e) => e.option === OPT);
  ev.sources = ev.sources.filter((s) => s.file === 'a.nix');
  const root = project(files);
  const res = await validateNixFix(stale, { files, apply: true, root });
  assert.equal(res.gates.rescan.originalGone, true, 'the rescan alone would have called this fixed');
  assert.equal(res.status, 'blocked');
  assert.match(res.reason, /^effective:.*conflict/);
  assert.equal(res.applied, false);
  assert.deepEqual(onDisk(root, files), files, 'nothing was written');
});

test('[multifile] a winner outside the project root is refused with a stated reason and the override line to add, never an edit', async () => {
  // A plain winner outside the root: an equal-priority plain line would conflict, so the suggestion needs mkForce.
  const outside = { 'configuration.nix': ENTRY(['../shared/ssh.nix']), '../shared/ssh.nix': MOD('"yes"') };
  const f = rootFinding(outside);
  assert.equal(f.file, '../shared/ssh.nix');
  const root = project({ 'configuration.nix': outside['configuration.nix'] });
  const res = await validateNixFix(f, { files: outside, apply: true, root });
  assert.equal(res.applied, false); assert.equal(res.status, 'manual');
  assert.match(res.reason, /outside the project root/); assert.match(res.reason, /\.\.\/shared\/ssh\.nix/);
  assert.equal(res.proposal.outsideRoot, '../shared/ssh.nix');
  assert.equal(res.proposal.override.automatic, false);
  assert.equal(res.proposal.override.file, 'configuration.nix');
  assert.equal(res.proposal.override.line, `${OPT} = lib.mkForce "no";`);
  assert.equal(res.proposal.override.priority, 50);
  assert.ok(!('after' in res) || res.after === undefined, 'no edit is produced');
  assert.equal(readFileSync(join(root, 'configuration.nix'), 'utf8'), outside['configuration.nix']);
  assert.ok(!existsSync(join(root, '..', 'shared', 'ssh.nix.nix')), 'no sibling file was created');

  // A weaker (mkDefault) winner outside the root: a plain line already beats it, so mkForce would be an unneeded escalation.
  const weak = { 'configuration.nix': ENTRY(['../shared/ssh.nix']), '../shared/ssh.nix': MOD('lib.mkDefault "yes"') };
  const wp = planNixFix(rootFinding(weak), weak);
  assert.equal(wp.ok, false);
  assert.equal(wp.proposal.override.line, `${OPT} = "no";`);
  assert.equal(wp.proposal.override.priority, 100);

  // A mkForce winner outside the root: an override must go below it.
  const forced = { 'configuration.nix': ENTRY(['../shared/ssh.nix']), '../shared/ssh.nix': MOD('lib.mkForce "yes"') };
  const fp = planNixFix(rootFinding(forced), forced);
  assert.equal(fp.ok, false);
  assert.equal(fp.proposal.override.line, `${OPT} = lib.mkOverride 49 "no";`);

  // The lifecycle itself also refuses any edit target that escapes the root, including the second file of a multi-file plan.
  const escaping = await runFixLifecycle({
    plan: { file: 'a.nix', before: 'x', after: 'y', edits: [{ file: 'a.nix', before: 'x', after: 'y' }, { file: '../evil.nix', before: 'x', after: 'y' }] },
    files: { 'a.nix': 'x' }, finding: { rule: 'r' }, matchKey: () => 'k', rescan: async () => [], syntax: () => ({ ok: true }),
  });
  assert.equal(escaping.status, 'blocked'); assert.match(escaping.reason, /path-escape: \.\.\/evil\.nix/);
});

test('[multifile] a winner whose value is not a safe literal is refused with the override suggestion', async () => {
  // The branches of one `if` sit on separate lines. The evidence is forged so that the winner points at a line that holds no
  // definition (what a definition built by a function or a merge looks like to the planner): nothing may be guessed.
  const files = { 'configuration.nix': ENTRY(['./a.nix']), 'a.nix': `{ lib, config, ... }:\n{\n  ${OPT} = lib.mkForce (if config.y\n    then "yes"\n    else "yes");\n}\n` };
  const f = JSON.parse(JSON.stringify(rootFinding(files)));
  const ev = f.evidence.find((e) => e.option === OPT);
  for (const s of ev.sources) { s.line = 99; s.role = 'winner'; s.priority = 50; s.priorityLabel = 'mkForce'; }
  ev.sources = ev.sources.slice(0, 1);
  const plan = planNixFix(f, files);
  assert.equal(plan.ok, false); assert.equal(plan.status, 'manual');
  assert.match(plan.reason, /no literal definition/);
  assert.equal(plan.proposal.override.line, `${OPT} = lib.mkOverride 49 "no";`);
  assert.ok(!('after' in plan), 'no edit is guessed');
});

test('[multifile] a conditional (mkIf) definition is edited only when every branch is then safe; the verification is on the possible values', async () => {
  const cond = { 'configuration.nix': `{ config, lib, ... }:\n{\n  services.openssh.enable = true;\n  ${OPT} = lib.mkIf config.x.dev "yes";\n}\n` };
  const f = rootFinding(cond);
  assert.equal(f.conditional, true);
  const root = project(cond);
  const res = await validateNixFix(f, { files: cond, apply: true, root });
  assert.equal(res.status, 'applied', `${res.reason} ${JSON.stringify(res.gates)}`);
  assert.equal(res.gates.effective.ran, true);
  assert.ok(!res.gates.effective.possibleValues.includes('yes'));
  assert.match(readFileSync(join(root, 'configuration.nix'), 'utf8'), /lib\.mkIf config\.x\.dev "no"/);

  // The same conditional definition PLUS a weaker unconditional one in another module: when the condition is false the other
  // module's "yes" applies, so BOTH files must change or the weakness survives under one branch.
  const both = { 'configuration.nix': `{ config, lib, ... }:\n{\n  imports = [ ./a.nix ];\n  services.openssh.enable = true;\n  ${OPT} = lib.mkIf config.x.dev "yes";\n}\n`, 'a.nix': MOD('lib.mkDefault "yes"') };
  const bf = rootFinding(both);
  const bp = planNixFix(bf, both);
  assert.equal(bp.ok, true, bp.reason);
  assert.deepEqual(bp.edits.map((e) => e.file).sort(), ['a.nix', 'configuration.nix']);
  const bv = await validateNixFix(bf, { files: both });
  assert.equal(bv.status, 'verified', `${bv.reason} ${JSON.stringify(bv.gates)}`);
  assert.equal(bv.gates.effective.ran, true);

  // Stale evidence that forgets the unconditional definition: the conditional one alone is edited, and the verification sees that
  // "yes" is still reachable under the other branch, so the fix is blocked rather than reported applied.
  const stale = JSON.parse(JSON.stringify(bf));
  const sev = stale.evidence.find((e) => e.option === OPT);
  sev.sources = sev.sources.filter((s) => s.file === 'configuration.nix');
  const sv = await validateNixFix(stale, { files: both });
  assert.equal(sv.status, 'blocked');
  assert.match(sv.reason, /still reported/, 'the rescan already sees the surviving weakness');
  // With a rescan that (wrongly) reports nothing, the effective-value gate is what stops it.
  const blind = await validateNixFix(stale, { files: both, rescan: async (fs) => (fs['configuration.nix'] === both['configuration.nix'] ? [stale] : []) });
  assert.equal(blind.status, 'blocked');
  assert.match(blind.reason, /^effective:.*can still be "yes"/);
});

test('[multifile] a changed file on disk refuses the whole fix before any file is written', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const f = rootFinding(files);
  writeFileSync(join(root, 'b.nix'), `${files['b.nix']}# edited by someone else\n`);
  const res = await validateNixFix(f, { files, apply: true, root });
  assert.equal(res.status, 'blocked'); assert.equal(res.applied, false);
  assert.match(res.reason, /changed on disk/); assert.match(res.reason, /no file was written/);
  assert.equal(readFileSync(join(root, 'a.nix'), 'utf8'), files['a.nix'], 'a.nix, checked first, was not touched');
  assert.equal(listHistory(root).length, 0);
});

test('[multifile] a failed write to the second file restores the first, drops the backups, and records nothing', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const f = rootFinding(files);
  const attempted = [];
  const failSecond = (path, data) => {
    attempted.push(path.slice(root.length + 1));
    if (path.endsWith('b.nix') && String(data).includes('"no"')) throw new Error('disk full (simulated)');
    writeFileSync(path, data);
  };
  const res = await validateNixFix(f, { files, apply: true, root, writeFile: failSecond });
  assert.equal(res.status, 'blocked'); assert.equal(res.applied, false);
  assert.match(res.reason, /disk full \(simulated\)/); assert.match(res.reason, /every file in this fix was restored/);
  assert.equal(res.rolledBack, true);
  assert.deepEqual(onDisk(root, files), files, 'both files hold their original bytes');
  assert.ok(attempted.includes('a.nix') && attempted.includes('b.nix'));
  assert.equal(listHistory(root).length, 0, 'a fix that did not land is not in the history');
  const backups = join(root, '.agentic-security', 'fix-backups');
  assert.deepEqual(existsSync(backups) ? readdirSync(backups) : [], [], 'no orphaned backup directories');

  // If the rollback itself cannot complete, that is said plainly and the backups are kept for a manual restore.
  const root2 = project(files);
  const failBoth = (path, data) => {
    if (path.endsWith('b.nix') && String(data).includes('"no"')) throw new Error('disk full (simulated)');
    if (path.endsWith('a.nix') && String(data).includes('"yes"')) throw new Error('read-only (simulated)');
    writeFileSync(path, data);
  };
  const bad = await validateNixFix(f, { files, apply: true, root: root2, writeFile: failBoth });
  assert.equal(bad.status, 'blocked'); assert.equal(bad.rolledBack, false);
  assert.match(bad.reason, /ROLLBACK INCOMPLETE/); assert.deepEqual(bad.rollbackFailed, ['a.nix']);
  assert.ok(readdirSync(join(root2, '.agentic-security', 'fix-backups')).length >= 2, 'backups survive for a manual restore');
});

test('[multifile] undo restores every touched file byte for byte, and marks the history reverted', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const res = await validateNixFix(rootFinding(files), { files, apply: true, root });
  assert.equal(res.status, 'applied');
  assert.notDeepEqual(onDisk(root, files), files);
  const out = undoFix(root, res.backup.id);
  assert.equal(out.ok, true); assert.deepEqual([...out.files].sort(), ['a.nix', 'b.nix']);
  assert.deepEqual(onDisk(root, files), files);
  assert.ok(listHistory(root).every((h) => h.reverted === true));
});

test('[multifile] an undo that fails on the second file leaves NO file half-restored', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const res = await validateNixFix(rootFinding(files), { files, apply: true, root });
  assert.equal(res.status, 'applied');
  const patched = onDisk(root, files);
  const failing = (path, data) => { if (path.endsWith('b.nix') && String(data).includes('"yes"')) throw new Error('permission denied (simulated)'); writeFileSync(path, data); };
  assert.throws(() => undoFix(root, res.backup.id, { writeFile: failing }), (e) => /no file was changed/.test(e.message) && e.rolledBack === true);
  assert.deepEqual(onDisk(root, files), patched, 'the fix is still fully applied, nothing is mixed');
  assert.ok(listHistory(root).every((h) => h.reverted !== true), 'a failed undo does not mark the history reverted');
  // and a later undo, once the obstacle is gone, restores everything
  undoFix(root, res.backup.id);
  assert.deepEqual(onDisk(root, files), files);
});

test('[multifile] the history-level undo reverts the whole group as a unit', async () => {
  const files = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const root = project(files);
  const res = await validateNixFix(rootFinding(files), { files, apply: true, root });
  assert.equal(res.status, 'applied');
  const r = await undoLast(root);
  assert.ok(r && !r.error, JSON.stringify(r));
  assert.deepEqual(onDisk(root, files), files, 'one undo restored both files');
  assert.ok(listHistory(root).every((h) => h.reverted === true));
});

test('[multifile] the editor/MCP preview lists every file of a multi-file fix and none for a single-file one', async () => {
  const { languageFixPreview } = await import('../../src/language/context.js');
  const multi = { 'configuration.nix': ENTRY(['./a.nix', './b.nix']), 'a.nix': MOD('"yes"'), 'b.nix': MOD('"yes"') };
  const p = await languageFixPreview(rootFinding(multi), multi);
  assert.equal(p.ok, true, p.reason);
  assert.deepEqual(p.edits.map((e) => e.file).sort(), ['a.nix', 'b.nix']);
  const single = { 'configuration.nix': ENTRY(['./ssh.nix']), 'ssh.nix': MOD('"yes"') };
  const s = await languageFixPreview(rootFinding(single), single);
  assert.equal(s.ok, true); assert.equal(s.edits, null);
});
