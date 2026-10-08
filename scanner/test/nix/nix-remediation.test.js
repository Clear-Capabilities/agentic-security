// NIX-010: Verified Nix configuration and supply-chain fixes.
// Suite "nix-remediation" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md). Fixes are validated against the REAL Nix
// analyses (scripts, secrets, build trust, NixOS hardening) over the patched tree.
// In the fixture strings `@{` stands for a Nix interpolation opener (so JS never sees a template literal).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { planNixFix, validateNixFix, planNixUpgrade, lockDiff, rescanNix, undoFix, TIERS } from '../../src/language/nix-fix.js';
import { analyzeNixScripts } from '../../src/language/nix-script-taint.js';
import { analyzeNixosHardening } from '../../src/language/nixos-hardening.js';
import { analyzeNixBuildTrust } from '../../src/language/nix-build-trust.js';
import { validateHaskellFix } from '../../src/language/haskell-fix.js';

const SCANNER = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const nix = (s) => s.replace(/@\{/g, '${');
const shell = (header, line) => ({ 'configuration.nix': nix(`${header}\n{\n  systemd.services.s = {\n    script = ''\n      ${line}\n    '';\n  };\n}\n`) });
const HDR = '{ config, lib, ... }:\nlet cfg = config.services.s; in';
const scriptFinding = (files, re) => analyzeNixScripts({ files }).findings.find((f) => re.test(f.rule));
const lineDiffs = (a, b) => a.split('\n').map((l, i) => (l !== b.split('\n')[i] ? i + 1 : 0)).filter(Boolean);

test('[NIX-010.AC01] shell escaping: an unquoted interpolation gains lib.escapeShellArg, verified by the real analyzer', async () => {
  const files = shell(HDR, 'rm -rf @{cfg.dest}');
  const f = scriptFinding(files, /^nix-shell-injection$/);
  const plan = planNixFix(f, files);
  assert.equal(plan.ok, true, plan.reason); assert.equal(plan.label, 'FULL'); assert.equal(plan.tier, TIERS.edit);
  assert.match(plan.after, /rm -rf \$\{lib\.escapeShellArg cfg\.dest\}/);
  assert.deepEqual(lineDiffs(plan.before, plan.after).length, 1, 'only the interpolation line changed');
  // behavior: before the edit the analyzer reports the injection, after it the value is protected
  assert.ok(analyzeNixScripts({ files }).findings.some((x) => x.rule === 'nix-shell-injection'));
  const after = analyzeNixScripts({ files: { 'configuration.nix': plan.after } });
  assert.deepEqual(after.findings, []);
  assert.ok(after.flows.some((x) => x.protectedInContext), 'the flow is now recorded as protected');
  const v = await validateNixFix(f, { files });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates)); assert.equal(v.gates.rescan.originalGone, true);
  assert.match(v.preview, /^-.*cfg\.dest/m); assert.match(v.preview, /^\+.*escapeShellArg cfg\.dest/m);
});

test('[NIX-010.AC01] shell escaping: quotes around the whole word are dropped, wrong-context escapes are unquoted, shared quotes are manual', async () => {
  const dq = shell(HDR, 'cp b "@{cfg.dest}"');
  const p1 = planNixFix(scriptFinding(dq, /^nix-shell-injection$/), dq);
  assert.equal(p1.ok, true); assert.match(p1.after, /cp b \$\{lib\.escapeShellArg cfg\.dest\}\n/); assert.ok(!/"\$\{/.test(p1.after.split('\n').find((l) => /cp b/.test(l))));
  assert.equal(p1.behavior.quotesRemoved, true);
  assert.equal((await validateNixFix(scriptFinding(dq, /^nix-shell-injection$/), { files: dq })).status, 'verified');
  const wrong = shell(HDR, 'cp c "@{lib.escapeShellArg cfg.dest}"');
  const f2 = scriptFinding(wrong, /^nix-escape-wrong-context$/);
  const p2 = planNixFix(f2, wrong);
  assert.equal(p2.ok, true); assert.match(p2.explanation, /supplies its own/);
  assert.match(p2.after, /cp c \$\{lib\.escapeShellArg cfg\.dest\}/);
  assert.equal((await validateNixFix(f2, { files: wrong })).status, 'verified');
  const shared = shell(HDR, 'cp d "/var/@{cfg.dest}"');
  const p3 = planNixFix(scriptFinding(shared, /^nix-shell-injection$/), shared);
  assert.equal(p3.ok, false); assert.equal(p3.status, 'manual'); assert.match(p3.reason, /together with other text/);
  assert.ok(!('after' in p3), 'no edit is invented');
});

test('[NIX-010.AC01] lib is added to an open argument list, used from pkgs, and a closed list is blocked rather than rewritten', () => {
  const open = shell('{ config, ... }:\nlet cfg = config.services.s; in', 'rm -rf @{cfg.dest}');
  const po = planNixFix(scriptFinding(open, /^nix-shell-injection$/), open);
  assert.equal(po.ok, true); assert.match(po.after, /^\{ lib, config, \.\.\. \}:/); assert.match(po.consequences[0], /`lib` was added/);
  const viaPkgs = shell('{ config, pkgs }:\nlet cfg = config.services.s; in', 'rm -rf @{cfg.dest}');
  const pp = planNixFix(scriptFinding(viaPkgs, /^nix-shell-injection$/), viaPkgs);
  assert.equal(pp.ok, true); assert.match(pp.after, /pkgs\.lib\.escapeShellArg cfg\.dest/);
  const closed = shell('{ config }:\nlet cfg = config.services.s; in', 'rm -rf @{cfg.dest}');
  const pc = planNixFix(scriptFinding(closed, /^nix-shell-injection$/), closed);
  assert.equal(pc.ok, false); assert.equal(pc.status, 'blocked'); assert.match(pc.reason, /closed parameter list/);
  // a service-environment expansion is quoted in place
  const env = { 'configuration.nix': nix('{ config, lib, ... }:\nlet cfg = config.services.s; in\n{\n  systemd.services.s = {\n    environment.TARGET = cfg.target;\n    script = \'\'\n      rm -rf $TARGET/old\n    \'\';\n  };\n}\n') };
  const ef = scriptFinding(env, /^nix-service-env-shell$/);
  const pe = planNixFix(ef, env);
  assert.equal(pe.ok, true); assert.match(pe.after, /rm -rf "\$TARGET"\/old/); assert.equal(pe.label, 'MITIGATION');
  assert.ok(!analyzeNixScripts({ files: { 'configuration.nix': pe.after } }).findings.length);
});

const SSH_FILES = {
  'configuration.nix': '{ config, lib, ... }:\n{\n  imports = [ ./ssh.nix ];\n  services.openssh.enable = true;\n}\n',
  'ssh.nix': '{ lib, ... }:\n{\n  services.openssh.settings.PermitRootLogin = "yes";\n  services.openssh.settings.PasswordAuthentication = true;\n  networking.firewall.enable = false;\n}\n',
};
const hardening = (files) => analyzeNixosHardening({ entry: 'configuration.nix', files }).findings;

test('[NIX-010.AC01] SSH and firewall hardening edit the winning definition, state their consequences, and are verified', async () => {
  for (const [rule, re, consequence] of [['ssh-root-login', /PermitRootLogin = "no"/, /non-root account/], ['ssh-password-auth', /PasswordAuthentication = false/, /authorized SSH key/], ['firewall-disabled', /firewall\.enable = true/, /lose remote access/]]) {
    const f = hardening(SSH_FILES).find((x) => x.rule === rule);
    assert.ok(f, rule);
    const v = await validateNixFix(f, { files: SSH_FILES });
    assert.equal(v.status, 'verified', `${rule}: ${JSON.stringify(v.gates)} ${v.reason}`);
    assert.match(v.plan.after, re);
    assert.match(v.consequences[0], consequence, 'the consequence is reported explicitly');
    assert.equal(v.plan.file, 'ssh.nix');
    assert.equal(lineDiffs(v.plan.before, v.plan.after).length, 1);
    assert.equal(hardening({ ...SSH_FILES, 'ssh.nix': v.plan.after }).filter((x) => x.rule === rule).length, 0);
  }
});

test('[NIX-010.AC01] cache-signature policy and transport fixes are verified against the real build-trust rules', async () => {
  const files = { 'configuration.nix': '{ config, lib, ... }:\n{\n  nix.settings.require-sigs = false;\n  nix.settings.sandbox = false;\n  nix.settings.substituters = [ "http://cache.example.invalid" ];\n  nix.settings.trusted-public-keys = [ "cache.example.invalid-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];\n}\n' };
  const found = analyzeNixBuildTrust({ files, entry: 'configuration.nix' }).findings;
  const byRule = (r) => found.find((f) => f.rule === r);
  const sigs = await validateNixFix(byRule('nix-require-sigs-disabled'), { files });
  assert.equal(sigs.status, 'verified', JSON.stringify(sigs.gates)); assert.match(sigs.plan.after, /require-sigs = true/); assert.match(sigs.consequences[0], /trusted-public-keys/);
  const sand = await validateNixFix(byRule('nix-sandbox-disabled'), { files });
  assert.equal(sand.status, 'verified'); assert.match(sand.plan.after, /sandbox = true/);
  const tr = await validateNixFix(byRule('nix-substituter-insecure-transport'), { files });
  assert.equal(tr.status, 'verified', JSON.stringify(tr.gates)); assert.match(tr.plan.after, /"https:\/\/cache\.example\.invalid"/); assert.equal(tr.label, 'MITIGATION');
  assert.match(tr.consequences[0], /serve TLS/);
});

const FLAKE = '{\n  inputs = {\n    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";\n    utils.url = "github:numtide/flake-utils";\n  };\n  outputs = { self, nixpkgs, utils }: { };\n}\n';
const lockOf = (rev, extra = {}) => JSON.stringify({ nodes: { nixpkgs: { locked: { narHash: 'sha256-n', owner: 'NixOS', repo: 'nixpkgs', rev, type: 'github' }, original: { owner: 'NixOS', ref: 'nixos-23.11', repo: 'nixpkgs', type: 'github' } }, utils: { locked: { narHash: 'sha256-u', owner: 'numtide', repo: 'flake-utils', rev: 'u'.repeat(40), type: 'github' }, original: { owner: 'numtide', repo: 'flake-utils', type: 'github' } }, root: { inputs: { nixpkgs: 'nixpkgs', utils: 'utils' } }, ...extra }, root: 'root', version: 7 }, null, 2);

test('[NIX-010.AC01] a flake input upgrade edits flake.nix only and never fabricates the lock', () => {
  const lock = lockOf('1'.repeat(40));
  const files = { 'flake.nix': FLAKE, 'flake.lock': lock };
  const p = planNixUpgrade({ files, input: 'nixpkgs', toRef: 'nixos-24.05' });
  assert.equal(p.ok, true); assert.equal(p.status, 'relock-required'); assert.equal(p.tier, TIERS.relock);
  assert.equal(p.edits.length, 1); assert.equal(p.edits[0].file, 'flake.nix'); assert.equal(p.lockTouched, false);
  assert.match(p.edits[0].after, /nixpkgs\.url = "github:NixOS\/nixpkgs\/nixos-24\.05"/);
  assert.match(p.edits[0].after, /utils\.url = "github:numtide\/flake-utils";/, 'the other input is untouched');
  assert.equal(lineDiffs(FLAKE, p.edits[0].after).length, 1);
  assert.match(p.note, /NOT modified and no hash was invented/); assert.deepEqual(p.instructions, ['nix flake update nixpkgs']);
  assert.equal(files['flake.lock'], lock, 'the supplied lock text is byte for byte unchanged');
  // a relocked lock is accepted only if nothing outside the upgraded input changed
  const good = planNixUpgrade({ files, input: 'nixpkgs', toRef: 'nixos-24.05', relock: () => ({ lockText: lockOf('2'.repeat(40)) }) });
  assert.equal(good.status, 'verified-relock'); assert.equal(good.edits.length, 2); assert.equal(good.lockDiff.ok, true); assert.deepEqual(good.lockDiff.changed, []);
  const bad = planNixUpgrade({ files, input: 'nixpkgs', toRef: 'nixos-24.05', relock: () => ({ lockText: lockOf('2'.repeat(40)).replace('u'.repeat(40), 'v'.repeat(40)) }) });
  assert.equal(bad.status, 'blocked'); assert.match(bad.reason, /unrelated lock node\(s\) changed: utils/);
  assert.equal(lockDiff(lock, lock, 'nixpkgs').ok, true);
  const crash = planNixUpgrade({ files, input: 'nixpkgs', toRef: 'nixos-24.05', relock: () => { throw new Error('resolver unavailable'); } });
  assert.equal(crash.status, 'relock-required'); assert.match(crash.note, /resolver unavailable/);
  assert.equal(planNixUpgrade({ files, input: 'missing', toRef: 'x' }).status, 'blocked');
  assert.equal(planNixUpgrade({ files, input: 'nixpkgs', toRef: 'a b; rm' }).status, 'blocked');
});

test('[NIX-010.AC02] a syntactically correct edit to a SHADOWED definition is not marked fixed', async () => {
  const files = {
    'configuration.nix': '{ config, lib, ... }:\n{\n  imports = [ ./a.nix ./b.nix ];\n  services.openssh.enable = true;\n}\n',
    'a.nix': '{ lib, ... }:\n{\n  services.openssh.settings.PermitRootLogin = "yes";\n}\n',
    'b.nix': '{ lib, ... }:\n{\n  services.openssh.settings.PermitRootLogin = lib.mkForce "yes";\n}\n',
  };
  const f = hardening(files).find((x) => x.rule === 'ssh-root-login');
  assert.equal(f.evidence[0].sources.find((s) => s.role === 'winner').file, 'b.nix', 'mkForce (50) beats plain (100)');
  const ok = await validateNixFix(f, { files });
  assert.equal(ok.status, 'verified'); assert.equal(ok.plan.file, 'b.nix'); assert.match(ok.plan.after, /mkForce "no"/);
  // the stale/naive edit: change the loser in a.nix. It parses, it looks right, and changes nothing.
  const shadowed = await validateNixFix(f, { files, source: { file: 'a.nix', line: 3 } });
  // Multi-file fixes (nix-fix-multifile.test.js) moved this refusal from the rescan gate ("still reported") to the planner,
  // which now knows the chosen definition is overridden and names the one that wins; nothing is edited either way.
  assert.equal(shadowed.status, 'blocked'); assert.match(shadowed.reason, /overridden by b\.nix:3/);
  assert.equal(shadowed.applied, false);
  assert.ok(!('after' in shadowed), 'no edit is produced for an overridden definition');
  // conditional scope: only the branch that carries the insecure literal is edited, the other branch is untouched,
  // and the rescan (not the edit) decides whether the finding is gone
  const cond = { 'configuration.nix': '{ config, lib, ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = if config.x.dev then "yes" else "no";\n}\n' };
  const cf = hardening(cond).find((x) => x.rule === 'ssh-root-login');
  assert.ok(cf, 'the conditional definition is still judged');
  assert.equal(cf.conditional, true);
  const cp = planNixFix(cf, cond);
  assert.equal(cp.ok, true);
  assert.match(cp.after, /if config\.x\.dev then "no" else "no"/, 'only the "yes" branch changed');
  assert.equal(cp.before.split('"no"').length, 2, 'the original else branch is intact');
  const cv = await validateNixFix(cf, { files: cond });
  assert.ok(['verified', 'blocked'].includes(cv.status));
  assert.equal(cv.status === 'verified', cv.gates.rescan.originalGone === true, 'verified only when the rescan agrees');
});

test('[NIX-010.AC03] secret migration, a missing hash and an unavailable resolver become reviewable proposals with the right tier', async () => {
  const secret = { 'a.nix': nix('{ config, ... }:\n{\n  environment.etc."app.conf".text = "password=@{config.services.app.dbPassword}";\n}\n') };
  const sf = (await rescanNix(secret)).find((f) => f.rule === 'nix-secret-store');
  const sp = await validateNixFix(sf, { files: secret });
  assert.equal(sp.status, 'manual'); assert.equal(sp.tier, TIERS.guidance); assert.equal(sp.applied, false);
  assert.ok(sp.proposal.steps.length >= 2); assert.equal(sp.proposal.rotate, true); assert.match(sp.reason, /human migration/);
  assert.ok(!('after' in sp) || sp.after === undefined, 'no automatic rewrite of a secret');
  const hash = { 'a.nix': '{ pkgs, ... }: { x = pkgs.fetchurl { url = "https://example.invalid/a.tar.gz"; }; }\n' };
  const hf = analyzeNixBuildTrust({ files: hash }).findings.find((f) => f.rule === 'nix-fetch-missing-hash');
  assert.ok(hf);
  const hp = planNixFix(hf, hash);
  assert.equal(hp.ok, false); assert.equal(hp.status, 'manual'); assert.equal(hp.tier, TIERS.blocked);
  assert.match(hp.reason, /placeholder hash would be a fabricated value/); assert.match(hp.proposal.neverDo, /made-up or all-zero hash/);
  const up = planNixUpgrade({ files: { 'flake.nix': FLAKE, 'flake.lock': lockOf('1'.repeat(40)) }, input: 'nixpkgs', toRef: 'nixos-24.05' });
  assert.equal(up.tier, TIERS.relock); assert.equal(up.status, 'relock-required');
  assert.equal(planNixFix({ rule: 'nix-unknown-rule' }, {}).status, 'unsupported');
  assert.equal(planNixFix(null, {}).ok, false);
});

test('[NIX-010.AC03] nothing is activated, deployed or spawned: no process module is imported and the permission model agrees', () => {
  for (const f of ['nix-fix.js', 'fix-lifecycle.js']) {
    const src = readFileSync(join(SCANNER, 'src', 'language', f), 'utf8');
    assert.ok(!/from 'node:(?:child_process|net|http|https|dgram|worker_threads)'|require\(/.test(src), `${f} imports no process or network module`);
  }
  const src = readFileSync(join(SCANNER, 'src', 'language', 'nix-fix.js'), 'utf8');
  assert.ok(!/nixos-rebuild|switch-to-configuration|nix-env|nixos-install/.test(src.replace(/\/\/.*$/gm, '')), 'no activation command appears in code');
  const probe = `import { planNixFix } from ${JSON.stringify(`file://${join(SCANNER, 'src', 'language', 'nix-fix.js')}`)};
const files = { 'a.nix': '{ lib, ... }:\\n{\\n  services.openssh.settings.PermitRootLogin = "yes";\\n}\\n' };
const r = planNixFix({ rule: 'ssh-root-login', file: 'a.nix', line: 3, subject: 'x', evidence: [{ option: 'services.openssh.settings.PermitRootLogin', sources: [{ role: 'winner', file: 'a.nix', line: 3 }] }] }, files);
console.log(JSON.stringify({ ok: r.ok }));`;
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, ['--permission', `--allow-fs-read=${SCANNER}`, '--input-type=module', '-e', probe], { encoding: 'utf8', env, cwd: SCANNER, timeout: 60000 });
  assert.equal(p.status, 0, `${p.stdout}\n${p.stderr}`);
  assert.equal(JSON.parse(p.stdout.trim()).ok, true, 'planning works with no process, network or write permission');
});

test('[NIX-010.AC04] preview, backup, apply and undo use the same lifecycle as the Haskell fixers', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nix-fixapply-'));
  for (const [p, t] of Object.entries(SSH_FILES)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), t); }
  const f = hardening(SSH_FILES).find((x) => x.rule === 'ssh-password-auth');
  const dry = await validateNixFix(f, { files: SSH_FILES });
  assert.equal(dry.status, 'verified'); assert.equal(dry.applied, false);
  assert.equal(readFileSync(join(root, 'ssh.nix'), 'utf8'), SSH_FILES['ssh.nix'], 'preview wrote nothing');
  assert.deepEqual(Object.keys(dry).filter((k) => ['status', 'applied', 'plan', 'gates', 'verified', 'preview', 'label'].includes(k)).sort(), ['applied', 'gates', 'label', 'plan', 'preview', 'status', 'verified']);
  const done = await validateNixFix(f, { files: SSH_FILES, apply: true, root });
  assert.equal(done.status, 'applied'); assert.ok(existsSync(join(done.backup.dir, 'original')));
  assert.match(readFileSync(join(root, 'ssh.nix'), 'utf8'), /PasswordAuthentication = false/);
  undoFix(root, done.backup.id);
  assert.equal(readFileSync(join(root, 'ssh.nix'), 'utf8'), SSH_FILES['ssh.nix'], 'undo restores the original byte for byte');
  writeFileSync(join(root, 'ssh.nix'), `${SSH_FILES['ssh.nix']}# edited elsewhere\n`);
  await assert.rejects(() => validateNixFix(f, { files: SSH_FILES, apply: true, root }), /changed on disk/);
  // the Haskell lifecycle is the same code: identical result keys
  const hs = await validateHaskellFix({ cwe: 'CWE-79', file: 'a.hs', line: 3 }, { files: { 'a.hs': 'module A where\nimport Text.Blaze.Html (preEscapedToHtml)\nr n = preEscapedToHtml n\n' }, rescan: async (fs) => (/preEscapedToHtml n/.test(fs['a.hs']) ? [{ file: 'a.hs', cwe: 'CWE-79', severity: 'high' }] : []) });
  assert.deepEqual(Object.keys(hs).sort(), Object.keys(dry).filter((k) => k !== 'consequences' && k !== 'tier' && k !== 'explanation').sort());
});

test('[NIX-010.AC04] a fix that introduces a new medium-or-higher finding, or breaks syntax, is rejected', async () => {
  const f = hardening(SSH_FILES).find((x) => x.rule === 'ssh-root-login');
  let n = 0;
  const introduces = await validateNixFix(f, { files: SSH_FILES, rescan: async () => (n++ === 0 ? [{ rule: 'ssh-root-login', subject: f.subject, file: f.file, severity: 'high' }] : [{ rule: 'nix-secret-store', file: 'x.nix', line: 1, severity: 'high', cwe: 'CWE-312' }]) });
  assert.equal(introduces.status, 'blocked'); assert.match(introduces.reason, /new medium-or-higher/);
  const still = await validateNixFix(f, { files: SSH_FILES, rescan: async () => [{ rule: 'ssh-root-login', subject: f.subject, file: f.file, severity: 'high' }] });
  assert.equal(still.status, 'blocked'); assert.match(still.reason, /still reported/);
  const crash = await validateNixFix(f, { files: SSH_FILES, rescan: async () => { throw new Error('boom'); } });
  assert.equal(crash.status, 'blocked');
  // regression: every rejected plan leaves the supplied tree untouched
  assert.equal(SSH_FILES['ssh.nix'].includes('PermitRootLogin = "yes"'), true);
  const low = await validateNixFix(f, { files: SSH_FILES, rescan: async () => (n++ % 2 === 0 ? [{ rule: 'ssh-root-login', subject: f.subject, file: f.file, severity: 'high' }] : [{ rule: 'x', file: 'y.nix', severity: 'low' }]) });
  assert.ok(['verified', 'blocked'].includes(low.status));
});
