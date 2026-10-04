// NIX-002: bounded effective NixOS module/configuration reasoning.
// Suite "nixos-module-resolution" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveNixosConfig } from '../../src/language/nixos-module-resolver.js';
import { defaultCatalog, computeCatalogRevision, CATALOG_REVISION, normalizeRelease } from '../../src/language/nixos-option-catalog.js';

const lines = (...l) => l.join('\n');
const run = (files, extra = {}) => resolveNixosConfig({ entry: 'configuration.nix', files, ...extra });
const ROOT_LOGIN = 'services.openssh.settings.PermitRootLogin';

function withCatalogOption(path, entry) {
  const cat = structuredClone(defaultCatalog());
  cat.nixos.options[path] = entry;
  cat.revision = computeCatalogRevision(cat);
  return cat;
}

// ── AC01 ───────────────────────────────────────────────────────────────────

test('[NIX-002.AC01] priorities across imported modules select the labeled winner and list options merge', () => {
  const r = run({
    'configuration.nix': lines('{ ... }: {', '  imports = [ ./a.nix ./modules/web.nix ];', '  services.openssh.enable = true;', '}'),
    'a.nix': lines('{ lib, ... }: {', `  ${ROOT_LOGIN} = lib.mkDefault "yes";`, '  networking.firewall.allowedTCPPorts = [ 22 ];', '}'),
    'modules/web.nix': lines('{ ... }: {', '  imports = [ ./net.nix ];', `  ${ROOT_LOGIN} = "no";`, '  networking.firewall.allowedTCPPorts = [ 80 443 ];', '}'),
    'modules/net.nix': lines('{ ... }: {', '  networking.firewall.enable = true;', '}'),
  });
  const login = r.lookup(ROOT_LOGIN);
  assert.equal(login.status, 'set');
  assert.equal(login.value, 'no');
  assert.equal(login.definite, true);
  const roles = Object.fromEntries(login.sources.map((s) => [s.file, s.role]));
  assert.deepEqual(roles, { 'a.nix': 'shadowed', 'modules/web.nix': 'winner' });
  assert.equal(login.sources.find((s) => s.file === 'a.nix').priorityLabel, 'mkDefault');
  assert.equal(login.sources.find((s) => s.file === 'a.nix').priority, 1000);
  assert.equal(login.sources.find((s) => s.file === 'modules/web.nix').priority, 100);

  const ports = r.lookup('networking.firewall.allowedTCPPorts');
  assert.equal(ports.status, 'set');
  assert.deepEqual(ports.value, [22, 80, 443]);
  assert.equal(ports.merged, true);
  // the nested import was followed
  assert.equal(r.lookup('networking.firewall.enable').value, true);
  assert.deepEqual(r.files.map((f) => f.file), ['configuration.nix', 'a.nix', 'modules/web.nix', 'modules/net.nix']);
});

test('[NIX-002.AC01] mkForce and mkOverride outrank plain values; equal-priority disagreement is a conflict, never a guess', () => {
  const r = run({
    'configuration.nix': lines('{ ... }: { imports = [ ./a.nix ./b.nix ./c.nix ./d.nix ]; }'),
    'a.nix': lines('{ lib, ... }: {', '  services.openssh.settings.PasswordAuthentication = lib.mkForce false;', '  services.openssh.settings.X11Forwarding = lib.mkOverride 10 true;', `  ${ROOT_LOGIN} = lib.mkForce "yes";`, '}'),
    'b.nix': lines('{ lib, ... }: {', '  services.openssh.settings.PasswordAuthentication = true;', '  services.openssh.settings.X11Forwarding = lib.mkForce false;', '}'),
    'c.nix': lines('{ lib, ... }: {', `  ${ROOT_LOGIN} = lib.mkForce "no";`, '}'),
    'd.nix': lines('{ lib, prio, ... }: {', '  services.nginx.enable = true;', '}'),
  });
  assert.equal(r.lookup('services.openssh.settings.PasswordAuthentication').value, false);
  const x11 = r.lookup('services.openssh.settings.X11Forwarding');
  assert.equal(x11.value, true, 'mkOverride 10 beats mkForce (50)');
  assert.equal(x11.sources.find((s) => s.priorityLabel === 'mkOverride').role, 'winner');
  const conflict = r.lookup(ROOT_LOGIN);
  assert.equal(conflict.status, 'conflict');
  assert.equal(conflict.valueKnown, false);
  assert.equal(conflict.value, undefined);
  assert.deepEqual(conflict.candidates, ['yes', 'no']);
  assert.equal(conflict.definite, false);
});

test('[NIX-002.AC01] a non-literal mkOverride priority leaves precedence unresolved instead of guessing', () => {
  const r = run({
    'configuration.nix': lines('{ lib, prio, ... }: {', '  imports = [ ./a.nix ];', '  services.openssh.settings.X11Forwarding = true;', '}'),
    'a.nix': lines('{ lib, prio, ... }: {', '  services.openssh.settings.X11Forwarding = lib.mkOverride prio false;', '}'),
  });
  const res = r.lookup('services.openssh.settings.X11Forwarding');
  assert.equal(res.status, 'unresolved-precedence');
  assert.equal(res.valueKnown, false);
  assert.equal(res.definite, false);
  assert.equal(res.sources.find((s) => s.priorityLabel === 'mkOverride').priority, null);
});

test('[NIX-002.AC01] mkMerge and mkIf select the branch their conditions decide', () => {
  const r = run({
    'configuration.nix': lines(
      '{ config, lib, ... }: {',
      '  services.nginx.enable = true;',
      '  services.openssh = lib.mkMerge [',
      '    { enable = true; }',
      '    (lib.mkIf config.services.nginx.enable { openFirewall = false; })',
      '    (lib.mkIf (!config.services.nginx.enable) { ports = [ 2222 ]; })',
      '  ];',
      '}',
    ),
  });
  const fw = r.lookup('services.openssh.openFirewall');
  assert.equal(fw.status, 'set');
  assert.equal(fw.value, false);
  assert.equal(fw.sources[0].conditions[0].outcome, 'true');
  const ports = r.lookup('services.openssh.ports');
  assert.equal(ports.status, 'default', 'the mkIf (!nginx.enable) branch is inactive');
  assert.deepEqual(ports.value, [22]);
  assert.equal(ports.sources[0].role, 'inactive-condition-false');
  assert.equal(ports.sources[0].conditions[0].outcome, 'false');
});

test('[NIX-002.AC01] Home Manager options live in a separate namespace and scope per user', () => {
  const r = run({
    'configuration.nix': lines(
      '{ ... }: {',
      '  programs.git.enable = true;',
      '  home-manager.users.alice = { programs.git.enable = false; };',
      '  home-manager.users.bob = import ./bob.nix;',
      '}',
    ),
    'bob.nix': lines('{ programs.git.enable = true; programs.bash.enable = true; }'),
  });
  assert.deepEqual(r.namespaces, ['home-manager', 'nixos']);
  assert.equal(r.lookup('programs.git.enable').value, true);
  assert.equal(r.lookup('programs.git.enable', { namespace: 'home-manager', scope: 'alice' }).value, false);
  assert.equal(r.lookup('programs.git.enable', { namespace: 'home-manager', scope: 'bob' }).value, true);
  assert.equal(r.lookup('programs.bash.enable', { namespace: 'home-manager', scope: 'bob' }).value, true);
  const aliceBash = r.lookup('programs.bash.enable', { namespace: 'home-manager', scope: 'alice' });
  assert.equal(aliceBash.status, 'default');
  assert.equal(aliceBash.value, false);
  const bobFile = r.files.find((f) => f.file === 'bob.nix');
  assert.deepEqual([bobFile.namespace, bobFile.scope], ['home-manager', 'bob']);
});

// ── AC02 ───────────────────────────────────────────────────────────────────

test('[NIX-002.AC02] a disabled service does not produce a definite exposure value', () => {
  const r = run({
    'configuration.nix': lines(
      '{ config, lib, ... }: {',
      '  services.openssh.enable = false;',
      `  ${ROOT_LOGIN} = lib.mkIf config.services.openssh.enable "yes";`,
      '}',
    ),
  });
  const res = r.lookup(ROOT_LOGIN);
  assert.equal(res.status, 'default');
  assert.equal(res.value, 'prohibit-password');
  assert.equal(res.sources[0].role, 'inactive-condition-false');
  assert.ok(!(res.definite && res.value === 'yes'));
  assert.equal(r.lookup('services.openssh.enable').value, false);
});

test('[NIX-002.AC02] a condition without a known target stays conditional; a known target resolves it', () => {
  const files = {
    'configuration.nix': lines(
      '{ config, lib, host, ... }: {',
      `  ${ROOT_LOGIN} = lib.mkIf (host == "prod") "yes";`,
      '  networking.firewall.allowedTCPPorts = lib.mkIf pkgs.stdenv.isLinux [ 8080 ];',
      '}',
    ),
  };
  const unknownTarget = run(files).lookup(ROOT_LOGIN);
  assert.equal(unknownTarget.status, 'conditional');
  assert.equal(unknownTarget.definite, false);
  assert.equal(unknownTarget.value, undefined);
  assert.deepEqual(unknownTarget.possibleValues, ['yes', 'prohibit-password']);
  assert.equal(unknownTarget.sources[0].conditions[0].outcome, 'unknown');
  assert.equal(unknownTarget.sources[0].role, 'conditional');
  assert.equal(run(files).lookup('networking.firewall.allowedTCPPorts').status, 'conditional', 'no target.system, so isLinux is not known');

  const prod = run(files, { target: { name: 'prod', args: { host: 'prod' }, system: 'x86_64-linux' } });
  assert.equal(prod.lookup(ROOT_LOGIN).status, 'set');
  assert.equal(prod.lookup(ROOT_LOGIN).value, 'yes');
  assert.deepEqual(prod.lookup('networking.firewall.allowedTCPPorts').value, [8080]);
  const dev = run(files, { target: { name: 'dev', args: { host: 'dev' }, system: 'aarch64-darwin' } });
  assert.equal(dev.lookup(ROOT_LOGIN).status, 'default');
  assert.equal(dev.lookup(ROOT_LOGIN).value, 'prohibit-password');
  assert.deepEqual(dev.lookup('networking.firewall.allowedTCPPorts').value, []);
});

test('[NIX-002.AC02] a missing setting uses a proven versioned default, otherwise it is unknown', () => {
  const files = { 'configuration.nix': '{ ... }: { services.nginx.enable = true; }' };
  // identical in every cataloged release: proven without knowing the release
  const proven = run(files).lookup('networking.firewall.enable');
  assert.equal(proven.status, 'default');
  assert.equal(proven.value, true);
  assert.match(proven.defaultProof, /every cataloged release/);
  assert.equal(proven.definite, true);

  // a default that differs by release is only proven for a known release
  const catalog = withCatalogOption('services.openssh.settings.LogLevel', { type: 'enum', default: { '24.11': 'INFO', '25.05': 'VERBOSE', '25.11': 'VERBOSE' } });
  const noRelease = run(files, { catalog }).lookup('services.openssh.settings.LogLevel');
  assert.equal(noRelease.status, 'unknown');
  assert.equal(noRelease.value, undefined);
  assert.match(noRelease.reason, /release-unknown/);
  assert.equal(noRelease.definite, false);
  const r2411 = run(files, { catalog, target: { release: '24.11' } }).lookup('services.openssh.settings.LogLevel');
  assert.deepEqual([r2411.status, r2411.value], ['default', 'INFO']);
  assert.match(r2411.defaultProof, /24\.11/);
  const r2505 = run(files, { catalog, target: { release: 'nixos-25.05' } }).lookup('services.openssh.settings.LogLevel');
  assert.deepEqual([r2505.status, r2505.value], ['default', 'VERBOSE']);
  // a release the catalog does not cover is not guessed from its neighbours
  const future = run(files, { catalog, target: { release: '99.11' } });
  assert.equal(future.catalog.matchedRelease, null);
  const futureLog = future.lookup('services.openssh.settings.LogLevel');
  assert.equal(futureLog.status, 'unknown');
  assert.match(futureLog.reason, /not-in-catalog/);

  // an option the catalog has no default for stays unknown
  const none = run(files).lookup('services.example.enable');
  assert.equal(none.status, 'unknown');
  assert.equal(none.definite, false);
});

// ── AC03 ───────────────────────────────────────────────────────────────────

test('[NIX-002.AC03] the report names the target, option sources, precedence evidence and catalog revision', () => {
  const files = {
    'hosts/web/configuration.nix': lines('{ lib, ... }: {', '  imports = [ ./extra.nix ];', `  ${ROOT_LOGIN} = lib.mkDefault "yes";`, '}'),
    'hosts/web/extra.nix': lines('{ ... }: {', `  ${ROOT_LOGIN} = "no";`, '}'),
    'flake.nix': lines('{', '  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";', '  outputs = { self, nixpkgs }: { };', '}'),
  };
  const r = resolveNixosConfig({ entry: 'hosts/web/configuration.nix', files, flake: 'flake.nix', target: { name: 'web', system: 'x86_64-linux' } });
  assert.equal(r.kind, 'nixos-effective-config');
  assert.deepEqual(r.target, { name: 'web', entries: ['hosts/web/configuration.nix'], system: 'x86_64-linux', release: '24.11', releaseSource: 'flake-input:nixpkgs' });
  assert.equal(r.catalog.revision, CATALOG_REVISION);
  assert.match(r.catalog.revision, /^nixos-option-catalog\/\d+\+[0-9a-f]{12}$/);
  assert.equal(r.catalog.matchedRelease, '24.11');

  const res = r.lookup(ROOT_LOGIN);
  assert.equal(res.catalog.revision, CATALOG_REVISION);
  assert.equal(res.catalog.release, '24.11');
  assert.equal(res.catalog.optionStatus, 'known');
  assert.match(res.precedence.rule, /lowest priority number wins/);
  assert.equal(res.precedence.winnerPriority, 100);
  assert.equal(res.sources.length, 2);
  for (const s of res.sources) {
    assert.ok(s.file.startsWith('hosts/web/'));
    assert.ok(Number.isInteger(s.span.startLine) && Number.isInteger(s.span.startOffset));
    assert.ok(['winner', 'shadowed'].includes(s.role));
  }
  // evidence is serializable and the report carries the same revision when read back
  assert.equal(JSON.parse(JSON.stringify(r)).catalog.revision, CATALOG_REVISION);
  assert.equal(normalizeRelease('nixos-25.11'), '25.11');
  assert.equal(normalizeRelease('nixos-unstable'), null);
});

test('[NIX-002.AC03] system.stateVersion is reported as a compatibility marker and never selects a release', () => {
  const files = { 'configuration.nix': lines('{ ... }: {', '  system.stateVersion = "25.05";', '  services.nginx.enable = true;', '}') };
  const catalog = withCatalogOption('services.openssh.settings.LogLevel', { type: 'enum', default: { '24.11': 'INFO', '25.05': 'VERBOSE', '25.11': 'VERBOSE' } });
  const r = run(files, { catalog });
  assert.equal(r.stateVersion.value, '25.05');
  assert.equal(r.stateVersion.role, 'state-compatibility-marker');
  assert.equal(r.stateVersion.usedForRelease, false);
  assert.equal(r.target.release, null);
  assert.equal(r.target.releaseSource, 'unknown');
  assert.equal(r.catalog.matchedRelease, null);
  assert.equal(r.lookup('services.openssh.settings.LogLevel').status, 'unknown', 'a stateVersion of 25.05 must not pick the 25.05 default');
  // an explicit target release wins and is attributed to the target
  const pinned = run(files, { catalog, target: { release: '24.11' } });
  assert.equal(pinned.target.releaseSource, 'target.release');
  assert.equal(pinned.lookup('services.openssh.settings.LogLevel').value, 'INFO');
  assert.equal(pinned.stateVersion.value, '25.05');
});

// ── AC04 ───────────────────────────────────────────────────────────────────

const chain = (n) => ['{ config, ... }: {', ...Array.from({ length: n }, (_, i) => `  x.a${i}.enable = config.x.a${i + 1}.enable;`), `  x.a${n}.enable = true;`, '}'].join('\n');

test('[NIX-002.AC04] cyclic references converge to an unknown value', () => {
  const r = run({ 'configuration.nix': lines('{ config, ... }: {', '  x.a.enable = config.x.b.enable;', '  x.b.enable = config.x.a.enable;', '  y.enable = lib.mkIf config.y.enable true;', '}') });
  for (const p of ['x.a.enable', 'x.b.enable', 'y.enable']) {
    const res = r.lookup(p);
    assert.equal(res.definite, false, p);
    assert.equal(res.value, undefined, p);
  }
  assert.ok(r.unresolved.some((g) => g.kind === 'cyclic-config-reference'));
});

test('[NIX-002.AC04] exceeding the depth, step, definition and file caps is reported as truncation, not a guess', () => {
  const depth = run({ 'configuration.nix': chain(40) }, { budgets: { maxEvalDepth: 8 } });
  assert.ok(depth.truncated.some((t) => t.budget === 'maxEvalDepth'));
  const a0 = depth.lookup('x.a0.enable');
  assert.equal(a0.status, 'unknown');
  assert.equal(a0.reason, 'evaluation-budget');
  assert.equal(a0.definite, false);
  assert.equal(depth.completeness, 'partial');
  // the tail of the chain is shallow enough to resolve inside the cap
  assert.equal(depth.lookup('x.a40.enable').value, true);

  const steps = run({ 'configuration.nix': chain(10) }, { budgets: { maxEvaluations: 4 } });
  assert.ok(steps.truncated.some((t) => t.budget === 'maxEvaluations'));
  assert.equal(steps.lookup('x.a0.enable').definite, false);

  const wide = run({ 'configuration.nix': lines('{ ... }: {', '  imports = [ ./a.nix ];', '}'), 'a.nix': '{ services.nginx.enable = true; }' }, { budgets: { maxDefinitionsPerOption: 0 } });
  assert.ok(wide.truncated.some((t) => t.budget === 'maxDefinitionsPerOption'));
  assert.equal(wide.lookup('services.nginx.enable').status, 'unknown');

  const files = run({
    'configuration.nix': '{ ... }: { imports = [ ./a.nix ./b.nix ./c.nix ]; }',
    'a.nix': '{ }', 'b.nix': '{ }', 'c.nix': '{ services.nginx.enable = true; }',
  }, { budgets: { maxFiles: 2 } });
  assert.ok(files.truncated.some((t) => t.budget === 'maxFiles'));
  assert.equal(files.completeness, 'partial');
  assert.equal(files.lookup('networking.firewall.enable').definite, false, 'an unread module could override it');
});

test('[NIX-002.AC04] a renamed option is evaluated under its current name and cannot bypass the hardening setting', () => {
  const r = run({ 'configuration.nix': lines('{ ... }: {', '  services.openssh.enable = true;', '  services.openssh.permitRootLogin = "yes";', '}') });
  for (const name of [ROOT_LOGIN, 'services.openssh.permitRootLogin']) {
    const res = r.lookup(name);
    assert.equal(res.path, ROOT_LOGIN);
    assert.equal(res.status, 'set');
    assert.equal(res.value, 'yes');
    assert.deepEqual(res.sources[0].viaRename, { from: 'services.openssh.permitRootLogin', to: ROOT_LOGIN });
  }
  assert.deepEqual(r.renamedOptions.map((o) => [o.from, o.to]), [['services.openssh.permitRootLogin', ROOT_LOGIN]]);

  // old and new spelling together are one option: disagreement is a conflict
  const both = run({ 'configuration.nix': lines('{ ... }: {', '  services.openssh.permitRootLogin = "yes";', `  ${ROOT_LOGIN} = "no";`, '}') });
  assert.equal(both.lookup(ROOT_LOGIN).status, 'conflict');
});

test('[NIX-002.AC04] an unknown option under a cataloged namespace is reported and withholds a definite default', () => {
  const r = run({ 'configuration.nix': lines('{ ... }: {', '  services.openssh.enable = true;', '  services.openssh.permitRootLoginn = "yes";', '  services.openssh.settings.LogLevel = "DEBUG";', '}') });
  assert.deepEqual(r.unknownOptions.map((o) => o.path), ['services.openssh.permitRootLoginn']);
  assert.ok(r.unknownOptions[0].sources[0].span.startLine === 3);
  const res = r.lookup(ROOT_LOGIN);
  assert.equal(res.status, 'default');
  assert.equal(res.definite, false);
  assert.ok(res.caveats.some((c) => c.kind === 'unknown-option-in-namespace' && /permitRootLoginn/.test(c.detail)));
  // freeform settings keys are valid, so they are not flagged
  assert.ok(!r.unknownOptions.some((o) => o.path.endsWith('LogLevel')));
  // outside the cataloged namespaces nothing is claimed either way
  const other = run({ 'configuration.nix': '{ ... }: { services.somethingelse.enable = true; }' });
  assert.deepEqual(other.unknownOptions, []);
  assert.equal(other.lookup('services.somethingelse.enable').catalog.optionStatus, 'uncataloged');
});
