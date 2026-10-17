// NixOS hardening rules for the Nix daemon, kernel sysctls, NFS exports and the Docker TCP socket.
// DEVELOPMENT cases only: they show the rules are wired and that near misses stay silent. Not an accuracy measurement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeNixosHardening, HARDENING_RULES } from '../../src/language/nixos-hardening.js';

const wrap = (body) => `{ config, pkgs, lib, ... }:\n{\n${body}\n}\n`;
const CASES = [
  ['nix-sandbox-off', true, 'nix.settings.sandbox = false;'],
  ['nix-sandbox-off', true, 'nix.useSandbox = false;'],
  ['nix-sandbox-off', false, 'nix.settings.sandbox = true;'],
  ['nix-sandbox-off', false, '# nix.settings.sandbox = false;'],
  ['nix-sandbox-off', false, 'nix.settings.sandbox = lib.mkForce true;\n  nix.settings.experimental-features = [ "nix-command" ];'],
  ['nix-signatures-off', true, 'nix.settings.require-sigs = false;'],
  ['nix-signatures-off', false, 'nix.settings.require-sigs = true;'],
  ['nix-trusted-users-wildcard', true, 'nix.settings.trusted-users = [ "root" "*" ];'],
  ['nix-trusted-users-wildcard', true, 'nix.settings.trusted-users = [ "@users" ];'],
  ['nix-trusted-users-wildcard', true, 'nix.trustedUsers = [ "*" ];'],
  ['nix-trusted-users-wildcard', false, 'nix.settings.trusted-users = [ "root" "@wheel" ];'],
  ['nix-trusted-users-wildcard', false, 'nix.settings.trusted-users = [ "root" ];'],
  ['kernel-sysctl-weakened', true, 'boot.kernel.sysctl."kernel.randomize_va_space" = 0;'],
  ['kernel-sysctl-weakened', true, 'boot.kernel.sysctl = { "kernel.kptr_restrict" = 0; };'],
  ['kernel-sysctl-weakened', true, 'boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = 0;'],
  ['kernel-sysctl-weakened', false, 'boot.kernel.sysctl."kernel.randomize_va_space" = 2;'],
  ['kernel-sysctl-weakened', false, 'boot.kernel.sysctl."net.ipv4.ip_forward" = 1;'],
  ['nfs-no-root-squash', true, 'services.nfs.server.exports = "/srv 10.0.0.0/24(rw,sync,no_root_squash)";'],
  ['nfs-no-root-squash', false, 'services.nfs.server.exports = "/srv 10.0.0.0/24(rw,sync,root_squash)";'],
  ['nfs-no-root-squash', false, 'services.nfs.server.exports = "# /srv *(rw,no_root_squash)\\n/srv 10.0.0.5(ro)";'],
  ['docker-tcp-no-tls', true, 'virtualisation.docker.enable = true;\n  virtualisation.docker.extraOptions = "-H tcp://0.0.0.0:2375";'],
  ['docker-tcp-no-tls', true, 'virtualisation.docker.enable = true;\n  virtualisation.docker.daemon.settings = { hosts = [ "tcp://0.0.0.0:2375" "unix:///var/run/docker.sock" ]; };'],
  ['docker-tcp-no-tls', false, 'virtualisation.docker.enable = true;\n  virtualisation.docker.extraOptions = "-H tcp://0.0.0.0:2376 --tlsverify --tlscacert=/run/ca.pem";'],
  ['docker-tcp-no-tls', false, 'virtualisation.docker.enable = true;\n  virtualisation.docker.extraOptions = "--log-level=warn";'],
  ['docker-tcp-no-tls', false, 'virtualisation.docker.enable = false;\n  virtualisation.docker.extraOptions = "-H tcp://0.0.0.0:2375";'],
];

CASES.forEach(([rule, vuln, body], i) => {
  test(`${rule} #${i} ${vuln ? 'fires' : 'stays silent'}`, () => {
    const r = analyzeNixosHardening({ files: { 'configuration.nix': wrap('  ' + body) }, entry: 'configuration.nix' });
    const hits = r.findings.filter((f) => f.rule === rule);
    assert.equal(hits.length > 0, vuln, JSON.stringify(r.findings.map((f) => f.rule)));
  });
});

test('every new rule has a complete catalog entry', () => {
  for (const id of new Set(CASES.map((c) => c[0]))) {
    const r = HARDENING_RULES[id];
    assert.ok(r && r.cwe && r.fix && r.why && r.vuln && r.family, id);
  }
});
