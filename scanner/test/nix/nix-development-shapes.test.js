// Shapes read from the unseen-v3 Nix DEVELOPMENT set on 2026-11-01 (the four it missed and the one it reported twice), each pinned in
// both directions: the shape that was missed or doubled, and the nearest shape whose verdict must not move with it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeNixosHardening } from '../../src/language/nixos-hardening.js';
import { analyzeNixSecrets } from '../../src/language/nix-secrets.js';
import { analyzeNixScripts } from '../../src/language/nix-script-taint.js';

const module_ = (body) => ['{ config, lib, pkgs, ... }:', 'let', '  cfg = config.services.crm;', 'in', '{', ...body.map((l) => `  ${l}`), '}'].join('\n') + '\n';
const harden = (body) => analyzeNixosHardening({ entry: 'configuration.nix', files: { 'configuration.nix': module_(body) }, target: { release: '25.05', system: 'x86_64-linux' } });
const byRule = (rep, rule) => rep.findings.filter((f) => f.rule === rule);

test('systemd capabilities written as one string are read like a list', () => {
  const str = harden(['systemd.services.crm.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "crm-svc"; AmbientCapabilities = "CAP_SYS_ADMIN"; };']);
  assert.equal(byRule(str, 'systemd-dangerous-capability').length, 1);
  const two = harden(['systemd.services.crm.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "crm-svc"; AmbientCapabilities = "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN"; };']);
  assert.deepEqual(byRule(two, 'systemd-dangerous-capability')[0].capabilities, ['CAP_SYS_ADMIN']);
  const narrow = harden(['systemd.services.crm.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "crm-svc"; AmbientCapabilities = "CAP_NET_BIND_SERVICE"; };']);
  assert.equal(byRule(narrow, 'systemd-dangerous-capability').length, 0);
});

test('sudo `Defaults !authenticate` is the passwordless grant written as a default', () => {
  const off = harden(['security.sudo.extraConfig = \'\'', '  Defaults !authenticate', '\'\';']);
  assert.equal(byRule(off, 'sudo-nopasswd-all').length, 1);
  assert.equal(byRule(off, 'sudo-nopasswd-all')[0].directive, 'Defaults !authenticate');
  const scoped = harden(['security.sudo.extraConfig = \'\'', '  Defaults:%wheel !authenticate', '\'\';']);
  assert.equal(byRule(scoped, 'sudo-nopasswd-all').length, 1, 'scoped to a group, still every command');
  const on = harden(['security.sudo.extraConfig = \'\'', '  Defaults authenticate', '  Defaults timestamp_timeout=5', '\'\';']);
  assert.equal(byRule(on, 'sudo-nopasswd-all').length, 0);
});

test('a TLS private key given as a path to a service other than nginx lands in the store', () => {
  const postfix = harden(['services.postfix.enable = true;', 'services.postfix.sslKey = ./crm-mail.key;']);
  assert.equal(byRule(postfix, 'tls-key-in-store').length, 1);
  assert.equal(byRule(postfix, 'tls-key-in-store')[0].subject, 'services.postfix.sslKey');
  const runtime = harden(['services.postfix.enable = true;', 'services.postfix.sslKey = "/var/lib/acme/mail.example.org/key.pem";']);
  assert.equal(byRule(runtime, 'tls-key-in-store').length, 0);
  const disabled = harden(['services.postfix.enable = false;', 'services.postfix.sslKey = ./crm-mail.key;']);
  assert.equal(byRule(disabled, 'tls-key-in-store').length, 0, 'an inactive service produces nothing');
});

test('a `*File` option handed a writeText of a literal puts the secret in the store; a runtime path or a store-written non-secret does not', () => {
  const secrets = (body) => analyzeNixSecrets({ files: { 'configuration.nix': module_(body) } }).findings;
  const literal = secrets(['services.crm.passwordFile = pkgs.writeText "crm-pass" "swordfish-crm";']);
  assert.equal(literal.length, 1, JSON.stringify(literal.map((f) => [f.rule, f.line])));
  assert.equal(literal[0].rule, 'nix-secret-plaintext');
  assert.equal(literal[0].exposure, 'store');
  assert.equal(literal[0].secretValue, 'redacted');
  assert.ok(!JSON.stringify(literal[0]).includes('swordfish'), 'the value never leaves');
  assert.equal(secrets(['services.crm.passwordFile = config.sops.secrets."crm/db-password".path;']).length, 0);
  assert.equal(secrets(['services.crm.passwordFile = "/run/secrets/crm-db";']).length, 0);
  assert.equal(secrets(['services.crm.settingsFile = pkgs.writeText "crm-settings" "verbose = true";']).length, 0, 'not a secret-shaped option');
});

test('one script-taint finding per line and origin class: two configuration interpolations on one command line are one finding', () => {
  const files = { 'configuration.nix': module_(['systemd.services.crm-backup.script = \'\'', '  ${pkgs.rsync}/bin/rsync -a ${cfg.source} ${cfg.destination}', '\'\';']) };
  const r = analyzeNixScripts({ files });
  const cmdi = r.findings.filter((f) => f.family === 'cmdi');
  assert.equal(cmdi.length, 1, JSON.stringify(cmdi.map((f) => [f.line, f.column])));
  assert.ok(cmdi[0].origins.length >= 2, 'both interpolations are recorded on the one finding');
  const twoLines = analyzeNixScripts({ files: { 'configuration.nix': module_(['systemd.services.crm-backup.script = \'\'', '  mkdir -p ${cfg.stateDir}', '  chmod 750 ${cfg.stateDir}', '\'\';']) } });
  assert.equal(twoLines.findings.filter((f) => f.family === 'cmdi').length, 2, 'two lines are two findings');
});
