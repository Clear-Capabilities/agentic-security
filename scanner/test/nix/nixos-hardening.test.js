// NIX-004: NixOS service, access and host hardening.
// Suite "nixos-hardening" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeNixosHardening, HARDENING_RULES, HARDENING_RULESET_VERSION } from '../../src/language/nixos-hardening.js';

const lines = (...l) => l.join('\n');
const module_ = (body) => lines('{ config, lib, host, ... }: {', ...body.map((l) => `  ${l}`), '}');
const analyze = (files, extra = {}) => analyzeNixosHardening({ entry: 'configuration.nix', files, target: { release: '25.05', system: 'x86_64-linux' }, ...extra });
const one = (body, extra) => analyze({ 'configuration.nix': module_(body) }, extra);
const byRule = (rep, rule) => rep.findings.filter((f) => f.rule === rule);
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const PROD = { target: { release: '25.05', system: 'x86_64-linux', args: { host: 'prod' } } };

const svc = (extra) => ['systemd.services.web.serviceConfig.ExecStart = "/bin/web";', ...extra];
const COND_ENABLE = 'systemd.services.web.enable = lib.mkIf (host == "prod") true;';

// vulnerable / safe / conditional fixtures for every policy family
const FAMILIES = [
  { rule: 'ssh-root-login',
    vulnerable: ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "yes";'],
    safe: ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "prohibit-password";'],
    conditional: ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = lib.mkIf (host == "prod") "yes";'] },
  { rule: 'ssh-password-auth',
    vulnerable: ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = true;'],
    safe: ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = false;'],
    conditional: ['services.openssh.enable = lib.mkIf (host == "prod") true;', 'services.openssh.settings.PasswordAuthentication = true;'] },
  { rule: 'firewall-disabled',
    vulnerable: ['networking.firewall.enable = false;'],
    safe: ['networking.firewall.enable = true;'],
    conditional: ['networking.firewall.enable = lib.mkIf (host == "prod") false;'] },
  { rule: 'firewall-sensitive-port',
    vulnerable: ['networking.firewall.allowedTCPPorts = [ 5432 ];'],
    safe: ['networking.firewall.allowedTCPPorts = [ 443 ];'],
    conditional: ['networking.firewall.allowedTCPPorts = lib.mkIf (host == "prod") [ 5432 ];'] },
  { rule: 'listener-all-interfaces',
    vulnerable: ['services.postgresql.enable = true;', 'services.postgresql.enableTCPIP = true;'],
    safe: ['services.postgresql.enable = true;', 'services.postgresql.enableTCPIP = false;'],
    conditional: ['services.postgresql.enable = true;', 'services.postgresql.enableTCPIP = lib.mkIf (host == "prod") true;'] },
  { rule: 'service-runs-as-root',
    vulnerable: svc(['systemd.services.web.serviceConfig.User = "root";']),
    safe: svc(['systemd.services.web.serviceConfig.User = "web";']),
    conditional: svc([COND_ENABLE]) },
  { rule: 'systemd-dangerous-capability',
    vulnerable: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];']),
    safe: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];']),
    conditional: svc([COND_ENABLE, 'systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];']) },
  { rule: 'systemd-filesystem-relaxed',
    vulnerable: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.ProtectSystem = false;']),
    safe: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.ProtectSystem = "strict";']),
    conditional: svc([COND_ENABLE, 'systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.serviceConfig.ProtectSystem = false;']) },
  { rule: 'sudo-passwordless-wheel',
    vulnerable: ['security.sudo.wheelNeedsPassword = false;'],
    safe: ['security.sudo.wheelNeedsPassword = true;'],
    conditional: ['security.sudo.wheelNeedsPassword = lib.mkIf (host == "prod") false;'] },
  { rule: 'doas-nopass',
    vulnerable: ['security.doas.enable = true;', "security.doas.extraConfig = ''", '  permit nopass keepenv :wheel', "'';"],
    safe: ['security.doas.enable = true;', "security.doas.extraConfig = ''", '  permit :wheel', "'';"],
    conditional: ['security.doas.enable = lib.mkIf (host == "prod") true;', "security.doas.extraConfig = ''", '  permit nopass keepenv :wheel', "'';"] },
  { rule: 'tls-verification-disabled',
    vulnerable: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.environment.NODE_TLS_REJECT_UNAUTHORIZED = "0";']),
    safe: svc(['systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.environment.NODE_TLS_REJECT_UNAUTHORIZED = "1";']),
    conditional: svc([COND_ENABLE, 'systemd.services.web.serviceConfig.User = "web";', 'systemd.services.web.environment.NODE_TLS_REJECT_UNAUTHORIZED = "0";']) },
  { rule: 'container-privileged',
    vulnerable: ['virtualisation.oci-containers.containers.app.image = "docker.io/app:1";', 'virtualisation.oci-containers.containers.app.extraOptions = [ "--privileged" ];'],
    safe: ['virtualisation.oci-containers.containers.app.image = "docker.io/app:1";', 'virtualisation.oci-containers.containers.app.extraOptions = [ "--read-only" ];'],
    conditional: ['virtualisation.oci-containers.containers.app.image = "docker.io/app:1";', 'virtualisation.oci-containers.containers.app.extraOptions = lib.mkIf (host == "prod") [ "--privileged" ];'] },
];

// ── AC01 ───────────────────────────────────────────────────────────────────

test('[NIX-004.AC01] every policy family has a vulnerable, a safe and a conditional fixture with evidence, severity and rationale', () => {
  assert.ok(Object.keys(HARDENING_RULES).length >= 12);
  assert.equal(new Set(FAMILIES.map((f) => f.rule)).size, FAMILIES.length);
  for (const fam of FAMILIES) {
    assert.ok(HARDENING_RULES[fam.rule], `${fam.rule} is a registered rule`);

    const vuln = byRule(one(fam.vulnerable), fam.rule);
    assert.ok(vuln.length >= 1, `${fam.rule}: vulnerable fixture is reported`);
    const f = vuln[0];
    assert.equal(f.conditional, false, `${fam.rule}: vulnerable is definite`);
    assert.ok(SEV.includes(f.severity), `${fam.rule}: severity`);
    assert.ok(f.remediation && f.remediationRationale && f.description, `${fam.rule}: remediation and rationale`);
    assert.ok(f.cwe && f.parser && f.family, `${fam.rule}: schema fields`);
    assert.equal(f.rulesetVersion, HARDENING_RULESET_VERSION);
    assert.equal(f.ruleVersion, HARDENING_RULES[fam.rule].ruleVersion);
    assert.equal(f.language, 'nix');
    assert.equal(f.file, 'configuration.nix');
    assert.ok(Number.isInteger(f.line) && f.line >= 1, `${fam.rule}: original line`);
    assert.ok(f.evidence.length >= 1);
    const ev = f.evidence[0];
    assert.ok(ev.option && ev.sources.length >= 1, `${fam.rule}: option source evidence`);
    assert.equal(ev.sources[0].file, 'configuration.nix');
    assert.ok(Number.isInteger(ev.sources[0].line));
    assert.ok(ev.valueSource, `${fam.rule}: effective value provenance`);
    assert.ok(ev.catalog.revision.startsWith('nixos-option-catalog/'), 'catalog revision recorded');
    assert.equal(ev.catalog.release, '25.05');

    assert.equal(byRule(one(fam.safe), fam.rule).length, 0, `${fam.rule}: safe fixture is clean`);

    const cond = byRule(one(fam.conditional), fam.rule);
    assert.ok(cond.length >= 1, `${fam.rule}: conditional fixture is reported as conditional`);
    for (const c of cond) {
      assert.equal(c.conditional, true, `${fam.rule}: conditional flag`);
      assert.ok(SEV.indexOf(c.severity) <= SEV.indexOf('medium'), `${fam.rule}: conditional never above medium (got ${c.severity})`);
      assert.ok(c.uncertainty.some((u) => u.kind === 'unresolved-branch'));
    }
    // once the target is known the same source resolves to a definite finding
    const resolved = byRule(one(fam.conditional, PROD), fam.rule);
    assert.ok(resolved.length >= 1 && resolved.every((c) => c.conditional === false), `${fam.rule}: resolves with a known target`);
  }
});

test('[NIX-004.AC01] effective value evidence names the winning source, priority and catalog default', () => {
  const rep = analyze({
    'configuration.nix': lines('{ lib, ... }: {', '  imports = [ ./ssh.nix ];', '  services.openssh.enable = true;', '  services.openssh.settings.PermitRootLogin = lib.mkDefault "no";', '}'),
    'ssh.nix': lines('{ ... }: {', '  services.openssh.settings.PermitRootLogin = "yes";', '}'),
  });
  const f = byRule(rep, 'ssh-root-login')[0];
  assert.ok(f, 'the plain definition in the imported module outranks mkDefault');
  assert.equal(f.file, 'ssh.nix');
  const roles = Object.fromEntries(f.evidence[0].sources.map((s) => [s.file, s.role]));
  assert.deepEqual(roles, { 'configuration.nix': 'shadowed', 'ssh.nix': 'winner' });
  assert.equal(f.evidence[0].effectiveValue, 'yes');
  assert.equal(f.evidence[0].valueSource, 'explicit');

  const dflt = byRule(one(['services.openssh.enable = true;']), 'ssh-password-auth')[0];
  assert.ok(dflt, 'the proven catalog default (password auth on) is reported with its provenance');
  assert.equal(dflt.valueSource, 'catalog-default');
  assert.equal(dflt.evidence[0].valueSource, 'catalog-default');
  assert.equal(dflt.severity, 'medium');
});

test('[NIX-004.AC01] ExecStart and script identity, and root default, are modelled', () => {
  const rep = one([
    'systemd.services.a.serviceConfig.ExecStart = "/bin/a --flag";',
    'systemd.services.b.script = "echo hi";',
    'systemd.services.c.serviceConfig.ExecStart = "+/bin/c";',
    'systemd.services.c.serviceConfig.User = "svc";',
    'systemd.services.d.serviceConfig.ExecStart = "${pkgs.d}/bin/d";',
  ]);
  const inv = Object.fromEntries(rep.inventory.filter((i) => i.kind === 'systemd-service').map((i) => [i.name, i]));
  assert.equal(inv.a.exec.kind, 'exec-start');
  assert.equal(inv.a.exec.command, '/bin/a');
  assert.equal(inv.a.identity.state, 'root-default');
  assert.equal(inv.b.exec.kind, 'generated-script');
  assert.equal(inv.c.exec.elevated, true);
  assert.equal(inv.d.exec.dynamic, true, 'an interpolated ExecStart is not claimed to be a known command');
  const elevated = byRule(rep, 'service-exec-elevated');
  assert.equal(elevated.length, 1);
  assert.equal(elevated[0].subject, 'systemd.services.c');
  // a service that runs as root only by systemd default is never rated above low
  const rootDefault = byRule(rep, 'service-runs-as-root').find((f) => f.subject === 'systemd.services.a');
  assert.equal(rootDefault.severity, 'low');
  assert.equal(rootDefault.identitySource, 'systemd-default');
});

// ── AC02 ───────────────────────────────────────────────────────────────────

test('[NIX-004.AC02] non-root identity and hardening controls are recognized and clear the root finding', () => {
  const rep = one(svc([
    'systemd.services.web.serviceConfig.User = "web";',
    'systemd.services.web.serviceConfig.NoNewPrivileges = true;',
    'systemd.services.web.serviceConfig.ProtectSystem = "strict";',
    'systemd.services.web.serviceConfig.PrivateTmp = true;',
  ]));
  assert.equal(rep.findings.length, 0);
  assert.ok(rep.controls.some((c) => c.control === 'non-root-identity' && c.service === 'web' && c.user === 'web'));
  for (const k of ['noNewPrivs', 'protectSystem', 'privateTmp']) assert.ok(rep.controls.some((c) => c.control === k && c.service === 'web' && c.applies), k);
  const dyn = one(svc(['systemd.services.web.serviceConfig.DynamicUser = true;']));
  assert.equal(byRule(dyn, 'service-runs-as-root').length, 0);
  assert.equal(dyn.inventory.find((i) => i.name === 'web').identity.state, 'dynamic-user');

  const root = one(svc([
    'systemd.services.web.serviceConfig.User = "root";',
    'systemd.services.web.serviceConfig.NoNewPrivileges = true;',
    'systemd.services.web.serviceConfig.ProtectSystem = "strict";',
    'systemd.services.web.serviceConfig.PrivateTmp = true;',
  ]));
  const f = byRule(root, 'service-runs-as-root')[0];
  assert.equal(f.severity, 'low', 'a root service with three hardening controls is mitigated');
  assert.equal(f.mitigations[0].kind, 'hardening-controls');
  const bare = byRule(one(svc(['systemd.services.web.serviceConfig.User = "root";'])), 'service-runs-as-root')[0];
  assert.equal(bare.severity, 'medium');
});

test('[NIX-004.AC02] restrictive ingress is recognized; internet reachability is never claimed', () => {
  const open = one(['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "yes";']);
  const f = byRule(open, 'ssh-root-login')[0];
  assert.equal(f.severity, 'high');
  assert.equal(f.exposure.ingress, 'open-in-firewall', 'openFirewall defaults to true (proven catalog default)');
  assert.equal(f.exposure.reachable, 'unknown');

  const closed = one(['services.openssh.enable = true;', 'services.openssh.openFirewall = false;', 'services.openssh.settings.PermitRootLogin = "yes";']);
  const g = byRule(closed, 'ssh-root-login')[0];
  assert.equal(g.exposure.ingress, 'firewall-closed');
  assert.ok(SEV.indexOf(g.severity) < SEV.indexOf('high'), 'a closed host firewall lowers the rating');
  assert.equal(g.mitigations[0].kind, 'restrictive-ingress');
  assert.equal(g.exposure.reachable, 'unknown', 'still not claimed unreachable: topology is outside the config');

  const iface = one(['networking.firewall.interfaces.eth1.allowedTCPPorts = [ 5432 ];']);
  assert.equal(byRule(iface, 'firewall-sensitive-port').length, 0, 'interface-scoped ports are restrictive ingress');
  assert.ok(iface.controls.some((c) => c.control === 'interface-scoped-ingress' && c.interface === 'eth1'));
  assert.equal(iface.reconciliation.unanalyzed.filter((u) => u.kind === 'unknown-option').length, 0, 'the interfaces namespace is cataloged');
  const global = one(['networking.firewall.allowedTCPPorts = [ 5432 ];']);
  assert.equal(byRule(global, 'firewall-sensitive-port')[0].severity, 'high');

  for (const rep of [open, closed, global]) for (const i of rep.inventory.filter((x) => x.kind === 'declared-service')) assert.equal(i.reachability.internet, 'unknown');
  assert.equal(open.scope.internetReachability, 'unknown');
});

test('[NIX-004.AC02] an unbound target, an unknown condition or default topology stays unknown', () => {
  const body = ['services.openssh.enable = lib.mkIf (host == "prod") true;', 'services.openssh.settings.PermitRootLogin = "yes";'];
  const unbound = one(body);
  const f = byRule(unbound, 'ssh-root-login')[0];
  assert.equal(f.conditional, true);
  assert.notEqual(f.severity, 'high');
  const ssh = unbound.inventory.find((i) => i.name === 'openssh');
  assert.equal(ssh.state, 'conditional');
  assert.equal(ssh.listening, 'unknown', 'enabled-or-not is undecided, so listening is undecided');
  assert.equal(ssh.reachability.internet, 'unknown');

  assert.equal(byRule(one(body, { target: { release: '25.05', args: { host: 'staging' } } }), 'ssh-root-login').length, 0, 'a bound target that disables it clears the finding');
  const prod = byRule(one(body, PROD), 'ssh-root-login')[0];
  assert.equal(prod.conditional, false);
  assert.equal(prod.severity, 'high');

  // a platform flag without target.system is unknown, not false
  const plat = one(['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = lib.mkIf pkgs.stdenv.isLinux "yes";'], { target: { release: '25.05' } });
  assert.equal(byRule(plat, 'ssh-root-login')[0].conditional, true);

  // no setting at all: only a proven default is used, and only for a rule that has one
  const none = one(['services.openssh.enable = true;']);
  assert.equal(byRule(none, 'ssh-root-login').length, 0, 'the default PermitRootLogin is prohibit-password');
  const unknownServiceDefault = one(['services.nginx.enable = true;']);
  assert.equal(unknownServiceDefault.inventory.find((i) => i.name === 'nginx').listening, 'unknown');
  assert.equal(unknownServiceDefault.findings.length, 0);
});

// ── AC03 ───────────────────────────────────────────────────────────────────

const INVENTORY_FILES = {
  'configuration.nix': lines(
    '{ config, lib, host, ... }: {',
    '  imports = [ ./ssh.nix ];',
    '  services.nginx.enable = lib.mkIf (host == "prod") true;',
    '  services.postgresql.enable = false;',
    '  security.sudo.wheelNeedsPassword = false;',
    '  systemd.services.web.serviceConfig.ExecStart = "/bin/web";',
    '  systemd.services.web.serviceConfig.User = "root";',
    '  systemd.services.old.enable = false;',
    '  systemd.services.old.serviceConfig.ExecStart = "/bin/old";',
    '  systemd.services.helper.serviceConfig.ExecStart = "+/bin/helper";',
    '  systemd.services.helper.serviceConfig.User = "helper";',
    '  virtualisation.oci-containers.containers.app.image = "docker.io/app:1";',
    '  virtualisation.oci-containers.containers.app.extraOptions = [ "--privileged" ];',
    '  virtualisation.oci-containers.containers.app.volumes = [ "/var/run/docker.sock:/var/run/docker.sock" ];',
    '  containers.sandbox.privateNetwork = true;',
    '}',
  ),
  'ssh.nix': lines('{ ... }: {', '  services.openssh.enable = true;', '  services.openssh.settings.PermitRootLogin = "yes";', '  services.openssh.settings.PasswordAuthentication = false;', '}'),
};

test('[NIX-004.AC03] service inventory reconciles active, conditional and inactive services', () => {
  const rep = analyze(INVENTORY_FILES);
  const states = Object.fromEntries(rep.inventory.filter((i) => i.kind === 'declared-service' || i.kind === 'systemd-service').map((i) => [`${i.kind}:${i.name}`, i.state]));
  assert.deepEqual(states, {
    'declared-service:nginx': 'conditional',
    'declared-service:openssh': 'active',
    'declared-service:postgresql': 'inactive',
    'systemd-service:helper': 'active',
    'systemd-service:old': 'inactive',
    'systemd-service:web': 'active',
  });
  const r = rep.reconciliation;
  assert.deepEqual(r.services, { total: 6, active: 3, conditional: 1, inactive: 2, unknown: 0 });
  assert.equal(r.consistent, true);
  assert.equal(rep.findings.filter((f) => f.subject.includes('old')).length, 0, 'a disabled service yields nothing');
  const oci = rep.inventory.find((i) => i.kind === 'oci-container');
  assert.equal(oci.name, 'app');
  assert.equal(oci.image, 'docker.io/app:1');
  assert.equal(oci.imageLayerScan, 'not-performed', 'OCI declarations are modelled without claiming layer scanning');
  assert.equal(rep.inventory.find((i) => i.kind === 'nixos-container').privateNetwork, true);
  assert.equal(rep.scope.imageLayerScan, 'not-performed');
});

test('[NIX-004.AC03] privileged entry points map to findings, authz evidence and attack paths', () => {
  const rep = analyze(INVENTORY_FILES);
  const ids = rep.privilegedEntryPoints.map((e) => e.id).sort();
  assert.deepEqual(ids, ['elevated-exec:helper', 'privileged-container:app', 'root-service:web', 'ssh-root-login', 'sudo-wheel-nopasswd']);
  assert.ok(rep.privilegedEntryPoints.every((e) => e.state === 'active' && e.evidence.length >= 1));
  assert.equal(rep.reconciliation.entryPoints.total, 5);
  assert.equal(rep.reconciliation.entryPoints.active, 5);
  assert.equal(rep.reconciliation.consistent, true);

  const map = rep.reconciliation.findingsByEntryPoint;
  assert.deepEqual(map['ssh-root-login'], ['nixos-hardening:ssh-root-login:services.openssh']);
  assert.deepEqual(map['root-service:web'], ['nixos-hardening:service-runs-as-root:systemd.services.web']);
  assert.ok(map['privileged-container:app'].length === 1);
  assert.ok(map['sudo-wheel-nopasswd'].length === 1);
  for (const [entry, fids] of Object.entries(map)) {
    assert.ok(fids.length >= 1, `${entry} is explained by a finding`);
    for (const id of fids) assert.ok(rep.findings.some((f) => f.id === id));
  }

  const ssh = rep.authzEvidence.find((a) => a.entryPoint === 'ssh-root-login');
  assert.equal(ssh.subject, 'network-client');
  assert.equal(ssh.authentication, 'key-only', 'password auth is off, so root login is key-only');
  assert.equal(ssh.privilege, 'root');
  const sudo = rep.authzEvidence.find((a) => a.entryPoint === 'sudo-wheel-nopasswd');
  assert.equal(sudo.authentication, 'none');
  const path = rep.attackPaths.find((p) => p.entryPoint === 'ssh-root-login');
  assert.equal(path.reachable, 'unknown');
  assert.equal(path.state, 'active');
  assert.ok(path.requires.some((r) => /unknown/.test(r)));
  assert.ok(rep.attackPaths.find((p) => p.entryPoint === 'sudo-wheel-nopasswd').requires[0].includes('foothold'));
});

test('[NIX-004.AC03] conditional options stay conditional and unanalyzed options are listed, not dropped', () => {
  const cond = analyze(INVENTORY_FILES, PROD);
  assert.equal(cond.inventory.find((i) => i.name === 'nginx').state, 'active');

  const rep = one([
    'services.openssh.enable = lib.mkIf (host == "prod") true;',
    'services.openssh.settings.PermitRootLogin = "yes";',
    'services.openssh.permitRootLoginn = "yes";',
    'imports = [ ./gone.nix ];',
  ]);
  const e = rep.privilegedEntryPoints.find((p) => p.id === 'ssh-root-login');
  assert.equal(e.state, 'conditional');
  assert.equal(rep.reconciliation.entryPoints.conditional, 1);
  assert.equal(rep.reconciliation.completeness, 'partial');
  const kinds = rep.reconciliation.unanalyzed.map((u) => u.kind);
  assert.ok(kinds.includes('unknown-option'), 'a misspelled option is surfaced, not assumed to have taken effect');
  assert.ok(rep.reconciliation.unanalyzed.some((u) => u.option === 'services.openssh.permitRootLoginn'));
  assert.ok(rep.reconciliation.unanalyzed.length > 1, 'the unresolved import is listed too');
  const f = byRule(rep, 'ssh-root-login')[0];
  assert.equal(f.conditional, true);
  assert.ok(SEV.indexOf(f.severity) <= SEV.indexOf('medium'));
  assert.equal(rep.reconciliation.consistent, true);
});

// ── AC04 ───────────────────────────────────────────────────────────────────

test('[NIX-004.AC04] absent services and inert text produce no findings', () => {
  const rep = analyze({
    'configuration.nix': lines(
      '{ lib, ... }: {',
      '  networking.hostName = "box";',
      '  # services.openssh.settings.PermitRootLogin = "yes";',
      '  # networking.firewall.enable = false;',
      '  /* security.sudo.wheelNeedsPassword = false; */',
      '  environment.etc."motd".text = "services.openssh.settings.PermitRootLogin = yes; NODE_TLS_REJECT_UNAUTHORIZED=0";',
      '  systemd.services.note.serviceConfig.ExecStart = "/bin/echo NODE_TLS_REJECT_UNAUTHORIZED=0 networking.firewall.enable=false";',
      '  systemd.services.note.serviceConfig.User = "note";',
      '}',
    ),
  });
  assert.equal(rep.findings.length, 0, JSON.stringify(rep.findings.map((f) => f.id)));
  assert.equal(rep.privilegedEntryPoints.length, 0);
  assert.equal(rep.inventory.some((i) => i.name === 'openssh'), false, 'a service that is absent is not inventoried');
});

test('[NIX-004.AC04] settings on a disabled service, and a false condition, are inert', () => {
  const disabled = one(['services.openssh.settings.PermitRootLogin = "yes";', 'services.openssh.settings.PasswordAuthentication = true;', 'services.postgresql.enableTCPIP = true;']);
  assert.equal(disabled.findings.length, 0, 'enable defaults to false (proven), so these settings do nothing');
  assert.equal(disabled.inventory.find((i) => i.name === 'openssh').state, 'inactive');
  const off = one(['services.openssh.enable = false;', 'services.openssh.settings.PermitRootLogin = lib.mkIf config.services.openssh.enable "yes";']);
  assert.equal(off.findings.length, 0);
  const dis = one(svc(['systemd.services.web.enable = false;', 'systemd.services.web.serviceConfig.User = "root";']));
  assert.equal(dis.findings.length, 0);
  assert.equal(dis.privilegedEntryPoints.length, 0);
});

test('[NIX-004.AC04] a renamed option is judged under its current name and cannot bypass the rule', () => {
  const bad = one(['services.openssh.enable = true;', 'services.openssh.permitRootLogin = "yes";']);
  const f = byRule(bad, 'ssh-root-login')[0];
  assert.ok(f, 'the old spelling still triggers the rule');
  assert.equal(f.evidence[0].option, 'services.openssh.settings.PermitRootLogin');
  assert.equal(f.evidence[0].sources[0].line, 3);
  const safe = one(['services.openssh.enable = true;', 'services.openssh.permitRootLogin = "no";', 'services.openssh.passwordAuthentication = false;']);
  assert.equal(safe.findings.length, 0);
  assert.ok(safe.controls.some((c) => c.control === 'ssh-key-only'));
  const pw = one(['services.openssh.enable = true;', 'services.openssh.passwordAuthentication = true;']);
  assert.equal(byRule(pw, 'ssh-password-auth').length, 1);
});

test('[NIX-004.AC04] explicit safe overrides win, and an unsafe override of a safe value is still caught', () => {
  const safeForce = analyze({
    'configuration.nix': lines('{ lib, ... }: {', '  imports = [ ./ssh.nix ];', '  services.openssh.enable = true;', '  services.openssh.settings.PermitRootLogin = lib.mkForce "no";', '}'),
    'ssh.nix': lines('{ ... }: {', '  services.openssh.settings.PermitRootLogin = "yes";', '}'),
  });
  assert.equal(byRule(safeForce, 'ssh-root-login').length, 0, 'mkForce "no" outranks a plain "yes"');
  const safeDefault = one(['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = lib.mkDefault "yes";', 'services.openssh.settings.PermitRootLogin = "no";']);
  assert.equal(byRule(safeDefault, 'ssh-root-login').length, 0);
  const unsafeForce = one(['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = lib.mkForce "yes";', 'services.openssh.settings.PermitRootLogin = "no";']);
  assert.equal(byRule(unsafeForce, 'ssh-root-login').length, 1, 'the override is not blindly trusted: mkForce "yes" is the effective value');
  const conflict = one(['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "yes";', 'services.openssh.settings.PermitRootLogin = "no";']);
  assert.equal(byRule(conflict, 'ssh-root-login').length, 0, 'an unresolved conflict is not guessed into a finding');
  assert.ok(conflict.reconciliation.unanalyzed.some((u) => u.kind === 'conflict' && u.option === 'services.openssh.settings.PermitRootLogin'));
  assert.equal(conflict.reconciliation.completeness, 'partial');
});

test('[NIX-004.AC04] no blanket high-severity: conditional, partial-graph and default-root findings are capped', () => {
  for (const fam of FAMILIES) for (const f of byRule(one(fam.conditional), fam.rule)) assert.ok(SEV.indexOf(f.severity) <= SEV.indexOf('medium'), `${fam.rule} conditional`);
  const partial = one(['imports = [ ./gone.nix ];', 'services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "yes";']);
  const f = byRule(partial, 'ssh-root-login')[0];
  assert.ok(f);
  assert.notEqual(f.severity, 'high', 'an unread module could override the value');
  assert.ok(f.uncertainty.some((u) => u.kind === 'unresolved-import'));
  const many = one(svc([]).concat(['systemd.services.b.script = "true";', 'systemd.services.c.serviceConfig.ExecStart = "/bin/c";']));
  assert.ok(many.findings.length >= 3);
  assert.ok(many.findings.every((x) => x.severity !== 'high' && x.severity !== 'critical'), 'services that run as root only by default are never high');
  const pgDefault = one(['services.postgresql.enable = true;']);
  assert.equal(pgDefault.findings.length, 0, 'postgres defaults to localhost only');
  assert.equal(pgDefault.inventory.find((i) => i.name === 'postgresql').listening, 'localhost-only');
});
