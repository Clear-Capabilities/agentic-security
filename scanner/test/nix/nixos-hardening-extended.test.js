// NixOS hardening rules added after the first release (NIX-004 extension): root-equivalent group membership, a non-root uid 0, getty and display-manager
// autologin, PAM null passwords, and wildcard bind addresses for redis, mysql, mongodb, memcached, elasticsearch and grafana.
//
// DEVELOPMENT cases: they show the rules are wired, that severity follows the firewall, and that near misses stay silent. They are not an accuracy measurement;
// the frozen holdout and the unseen-shapes split were not read or run to write them. Each case is its own project: cases that set the same option would
// otherwise conflict with each other, which is correct module-system behaviour but not what is being tested here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeNixosHardening, HARDENING_RULES } from '../../src/language/nixos-hardening.js';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const CASES = [
 {
  "id": "ctl-ssh-root",
  "rule": "ssh-root-login",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.openssh.enable = true;\n  services.openssh.settings.PermitRootLogin = \"yes\";\n}\n"
 },
 {
  "id": "ctl-fw-off",
  "rule": "firewall-disabled",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  networking.firewall.enable = false;\n}\n"
 },
 {
  "id": "grp-docker",
  "rule": "user-root-equivalent-group",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.alice = {\n    isNormalUser = true;\n    extraGroups = [ \"wheel\" \"docker\" ];\n  };\n}\n"
 },
 {
  "id": "grp-lxd",
  "rule": "user-root-equivalent-group",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.bob = {\n    isNormalUser = true;\n    extraGroups = [ \"lxd\" ];\n  };\n}\n"
 },
 {
  "id": "grp-disk-flat",
  "rule": "user-root-equivalent-group",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.carol.isNormalUser = true;\n  users.users.carol.extraGroups = [ \"disk\" ];\n}\n"
 },
 {
  "id": "grp-safe",
  "rule": "user-root-equivalent-group",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.dave = {\n    isNormalUser = true;\n    extraGroups = [ \"wheel\" \"networkmanager\" \"audio\" ];\n  };\n}\n"
 },
 {
  "id": "grp-mkforce-safe",
  "rule": "user-root-equivalent-group",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.erin = {\n    isNormalUser = true;\n    extraGroups = lib.mkForce [ \"audio\" ];\n  };\n  users.users.erin.extraGroups = [ \"docker\" ];\n}\n"
 },
 {
  "id": "grp-disabled-cond",
  "rule": "user-root-equivalent-group",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.frank = {\n    isNormalUser = true;\n    extraGroups = lib.optionals false [ \"docker\" ];\n  };\n}\n"
 },
 {
  "id": "uid0",
  "rule": "user-uid-zero",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.toor = {\n    isNormalUser = true;\n    uid = 0;\n  };\n}\n"
 },
 {
  "id": "uid0-root-ok",
  "rule": "user-uid-zero",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.root.uid = 0;\n}\n"
 },
 {
  "id": "uid1000-ok",
  "rule": "user-uid-zero",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.gina = {\n    isNormalUser = true;\n    uid = 1000;\n  };\n}\n"
 },
 {
  "id": "getty-root",
  "rule": "autologin",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = \"root\";\n}\n"
 },
 {
  "id": "getty-user",
  "rule": "autologin",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = \"henry\";\n}\n"
 },
 {
  "id": "dm-autologin",
  "rule": "autologin",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.displayManager.autoLogin = {\n    enable = true;\n    user = \"irene\";\n  };\n}\n"
 },
 {
  "id": "dm-autologin-off",
  "rule": "autologin",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.displayManager.autoLogin.enable = false;\n}\n"
 },
 {
  "id": "getty-null",
  "rule": "autologin",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = null;\n}\n"
 },
 {
  "id": "pam-null",
  "rule": "pam-null-password",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  security.pam.services.login.allowNullPassword = true;\n}\n"
 },
 {
  "id": "pam-null-false",
  "rule": "pam-null-password",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  security.pam.services.login.allowNullPassword = false;\n}\n"
 },
 {
  "id": "redis-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "redis-null-bind",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = null;\n  };\n}\n"
 },
 {
  "id": "redis-local",
  "rule": "listener-all-interfaces",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = \"127.0.0.1\";\n  };\n}\n"
 },
 {
  "id": "redis-disabled",
  "rule": "listener-all-interfaces",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = false;\n    bind = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "mysql-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.mysql = {\n    enable = true;\n    settings.mysqld.bind-address = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "mysql-local",
  "rule": "listener-all-interfaces",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.mysql = {\n    enable = true;\n    settings.mysqld.bind-address = \"127.0.0.1\";\n  };\n}\n"
 },
 {
  "id": "mongo-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.mongodb = {\n    enable = true;\n    bind_ip = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "memcached-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.memcached = {\n    enable = true;\n    listen = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "es-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.elasticsearch = {\n    enable = true;\n    listenAddress = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "grafana-all",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.grafana = {\n    enable = true;\n    settings.server.http_addr = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "grafana-local",
  "rule": "listener-all-interfaces",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.grafana = {\n    enable = true;\n    settings.server.http_addr = \"127.0.0.1\";\n  };\n}\n"
 },
 {
  "id": "redis-fw-open",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "sev": "high",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = \"0.0.0.0\";\n  };\n  networking.firewall.allowedTCPPorts = [ 6379 ];\n}\n"
 },
 {
  "id": "redis-fw-off",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "sev": "high",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = \"0.0.0.0\";\n  };\n  networking.firewall.enable = false;\n}\n"
 },
 {
  "id": "redis-fw-default",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "sev": "low",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"main\" = {\n    enable = true;\n    bind = \"0.0.0.0\";\n  };\n}\n"
 },
 {
  "id": "redis-custom-port-open",
  "rule": "listener-all-interfaces",
  "vuln": true,
  "sev": "high",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.redis.servers.\"cache\" = {\n    enable = true;\n    bind = \"::\";\n    port = 7000;\n  };\n  networking.firewall.allowedTCPPorts = [ 7000 ];\n}\n"
 },
 {
  "id": "grp-renamed",
  "rule": "user-root-equivalent-group",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.\"build-bot\" = {\n    isSystemUser = true;\n    group = \"ci\";\n    extraGroups = [ \"audio\" \"docker\" ];\n  };\n}\n"
 },
 {
  "id": "grp-near-name",
  "rule": "user-root-equivalent-group",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.kim = {\n    isNormalUser = true;\n    extraGroups = [ \"dockerx\" \"disks\" \"lxdbr\" ];\n  };\n}\n"
 },
 {
  "id": "getty-empty",
  "rule": "autologin",
  "vuln": false,
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = \"\";\n}\n"
 },
 {
  "id": "getty-root-sev",
  "rule": "autologin",
  "vuln": true,
  "sev": "high",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = \"root\";\n}\n"
 },
 {
  "id": "getty-user-sev",
  "rule": "autologin",
  "vuln": true,
  "sev": "low",
  "src": "{ config, pkgs, lib, ... }:\n{\n  services.getty.autologinUser = \"lee\";\n}\n"
 },
 {
  "id": "uid0-string-name",
  "rule": "user-uid-zero",
  "vuln": true,
  "src": "{ config, pkgs, lib, ... }:\n{\n  users.users.\"admin-two\" = {\n    isNormalUser = true;\n    uid = 0;\n  };\n}\n"
 }
];

for (const c of CASES) {
  test(`${c.vuln ? 'FOUND' : 'SILENT'}: ${c.id} (${c.rule})`, () => {
    const want = c.rule === 'autologin' ? ['getty-autologin', 'display-autologin'] : [c.rule];
    const hits = analyzeNixosHardening({ files: { 'configuration.nix': c.src }, entry: 'configuration.nix' }).findings.filter((f) => want.includes(f.rule));
    if (c.vuln) { assert.ok(hits.length >= 1, 'a finding'); if (c.sev) assert.ok(hits.some((h) => h.severity === c.sev), `severity ${c.sev}, got ${hits.map((h) => h.severity)}`); }
    else assert.equal(hits.length, 0, JSON.stringify(hits.map((h) => ({ rule: h.rule, scope: h.subject }))));
  });
}

test('every new rule is a registered rule with a CWE, a severity, a reason and a fix', () => {
  for (const id of ['user-root-equivalent-group', 'user-uid-zero', 'getty-autologin', 'display-autologin', 'pam-null-password']) {
    const r = HARDENING_RULES[id]; assert.ok(r, id);
    assert.match(r.cwe, /^CWE-\d+$/); assert.ok(r.why.length > 40 && r.fix.length > 20 && r.vuln.length > 10, id);
  }
});

test('THROUGH THE CLI: a real configuration reports the new findings with their CWE, file and line', () => {
  const dir = mkTestTmp('nix-ext-');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'configuration.nix'), `{ config, pkgs, lib, ... }:
{
  users.users.alice = { isNormalUser = true; extraGroups = [ "wheel" "docker" ]; };
  services.getty.autologinUser = "root";
  security.pam.services.login.allowNullPassword = true;
  services.redis.servers."main" = { enable = true; bind = "0.0.0.0"; };
  networking.firewall.allowedTCPPorts = [ 6379 ];
}
`);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 300000, env, maxBuffer: 1 << 28 });
  const fs_ = JSON.parse(p.stdout).findings.filter((f) => f.parser === 'nixos-hardening');
  const by = Object.fromEntries(fs_.map((f) => [f.rule, f]));
  for (const [rule, cwe, line] of [['user-root-equivalent-group', 'CWE-269', 3], ['getty-autologin', 'CWE-306', 4], ['pam-null-password', 'CWE-258', 5], ['listener-all-interfaces', 'CWE-668', 6]]) {
    assert.ok(by[rule], `${rule} reported`); assert.equal(by[rule].cwe, cwe); assert.equal(by[rule].file, 'configuration.nix'); assert.equal(by[rule].line, line, `${rule} line`);
  }
  assert.equal(by['listener-all-interfaces'].severity, 'high', 'the firewall opens 6379, so the exposure is high');
  assert.equal(by['getty-autologin'].severity, 'high');
});
