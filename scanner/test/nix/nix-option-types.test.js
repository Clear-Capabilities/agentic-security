// A declared option type bounds what a reference to the option can hold, whatever the option is called.
// Every rule is tested in both directions: the semantics-preserving case must stay quiet and the near-miss
// (same shape, an unbounded type or a non-literal origin) must still be reported.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeNixScripts } from '../../src/language/nix-script-taint.js';
import { analyzeNixSecrets } from '../../src/language/nix-secrets.js';
import { parseNix } from '../../src/language/nix-parser.js';
import { buildOptionTypeIndex, classifyOptionType } from '../../src/language/nix-option-types.js';

const mod = (optionType, use) => `{ config, lib, pkgs, ... }:
let cfg = config.services.demo; in {
  options.services.demo.value = lib.mkOption { type = ${optionType}; };
  config.systemd.services.demo = {
    script = ''
      run-demo ${use}
    '';
  };
}`;
const scriptFindings = (files) => analyzeNixScripts({ files }).findings.filter((f) => f.rule === 'nix-shell-injection');
const secretFindings = (files) => analyzeNixSecrets({ files }).findings;

test('an int option interpolated into a script is bounded; a str option is reported', () => {
  assert.equal(scriptFindings({ 'a.nix': mod('lib.types.int', '${toString cfg.value}') }).length, 0);
  assert.ok(scriptFindings({ 'a.nix': mod('lib.types.str', '${toString cfg.value}') }).length > 0);
});

test('metamorphic: renaming the option or switching the bounded type keeps the verdict', () => {
  const renamed = mod('lib.types.port', '${toString cfg.value}').replace(/value/g, 'listenSlot');
  assert.equal(scriptFindings({ 'a.nix': renamed }).length, 0);
  assert.equal(scriptFindings({ 'a.nix': mod('types.bool', '${toString cfg.value}') }).length, 0);
  assert.equal(scriptFindings({ 'a.nix': mod('lib.types.ints.between 1 10', '${toString cfg.value}') }).length, 0);
});

test('near-miss: nullOr of an unbounded type, and an enum with a shell metacharacter, are still reported', () => {
  assert.ok(scriptFindings({ 'a.nix': mod('lib.types.nullOr lib.types.str', '${toString cfg.value}') }).length > 0);
  assert.ok(scriptFindings({ 'a.nix': mod('lib.types.enum [ "a" "b; id" ]', '${toString cfg.value}') }).length > 0);
  assert.equal(scriptFindings({ 'a.nix': mod('lib.types.enum [ "fast" "slow" ]', '${toString cfg.value}') }).length, 0);
});

test('a bool option is not a credential because of its name; the same name with a str type is', () => {
  const unit = (type) => `{ config, lib, ... }:
let cfg = config.services.demo; in {
  options.services.demo.forwardPass = lib.mkOption { type = ${type}; };
  config.systemd.services.demo.environment.FORWARD_PASS = cfg.forwardPass;
}`;
  assert.equal(secretFindings({ 'a.nix': unit('lib.types.bool') }).length, 0);
  assert.ok(secretFindings({ 'a.nix': unit('lib.types.str') }).length > 0);
});

test('mkEnableOption is a bool and mkPackageOption is a package', () => {
  const idx = buildOptionTypeIndex([parseNix(`{ lib, pkgs, ... }: { options.s = { enable = lib.mkEnableOption "x"; package = lib.mkPackageOption pkgs "y" {}; note = lib.mkOption { type = lib.types.str; }; }; }`).ast]);
  assert.equal(idx.get('s.enable').bounded, true);
  assert.equal(idx.get('s.package').bounded, true);
  assert.equal(idx.get('s.note').bounded, false);
});

test('two declarations of one option are bounded only if both are', () => {
  const idx = buildOptionTypeIndex([
    parseNix(`{ lib, ... }: { options.s.v = lib.mkOption { type = lib.types.int; }; }`).ast,
    parseNix(`{ lib, ... }: { options.s.v = lib.mkOption { type = lib.types.str; }; }`).ast,
  ]);
  assert.equal(idx.get('s.v').bounded, false);
});

test('classifyOptionType: unknown or computed types are unbounded', () => {
  const t = (src) => classifyOptionType(parseNix(src).ast);
  assert.equal(t('types.int').bounded, true);
  assert.equal(t('types.str').bounded, false);
  assert.equal(t('computedType').bounded, false);
  assert.equal(t('lib.types.either lib.types.int lib.types.bool').bounded, true);
  assert.equal(t('lib.types.either lib.types.int lib.types.str').bounded, false);
});

test('a hex digest interpolated into a script is bounded whatever it was computed from', () => {
  const unit = (rhs) => `{ config, lib, ... }:
let cfg = config.services.demo; h = ${rhs}; in {
  config.systemd.services.demo.script = ''
    newHash=${'${h}'}
  '';
}`;
  assert.equal(scriptFindings({ 'a.nix': unit('builtins.hashString "sha256" cfg.name') }).length, 0);
  assert.ok(scriptFindings({ 'a.nix': unit('cfg.name') }).length > 0);
});

test('an undeclared option named like a package is a store path; one named otherwise is not', () => {
  const unit = (opt) => `{ config, lib, ... }: {
  config.systemd.services.demo.script = ''
    \${config.programs.demo.${opt}}/bin/run
  '';
}`;
  assert.equal(scriptFindings({ 'a.nix': unit('package') }).length, 0);
  assert.equal(scriptFindings({ 'a.nix': unit('finalPackage') }).length, 0);
  assert.ok(scriptFindings({ 'a.nix': unit('workdir') }).length > 0);
});

test('a declared option shadows the package-name convention: a str option called package is reported', () => {
  const src = `{ config, lib, ... }: {
  options.programs.demo.package = lib.mkOption { type = lib.types.str; };
  config.systemd.services.demo.script = ''
    \${config.programs.demo.package}/bin/run
  '';
}`;
  assert.ok(scriptFindings({ 'a.nix': src }).length > 0);
});

test('example text in mkOption is documentation; the same literal in default is configuration', () => {
  const unit = (attr) => `{ lib, ... }: {
  options.services.demo.extra = lib.mkOption {
    type = lib.types.attrs;
    ${attr} = { api-secret = "Your API secret value"; };
  };
}`;
  assert.equal(secretFindings({ 'a.nix': unit('example') }).length, 0);
  assert.ok(secretFindings({ 'a.nix': unit('default') }).length > 0);
});

test('a binding named for a service is not a credential when its value is a set', () => {
  const unit = (value) => `{ config, lib, pkgs, ... }: {
  config.systemd.user.services.pass-secret-service = ${value};
}`;
  const set = `let b = "\${pkgs.hello}/bin/hello"; in { Service.ExecStart = b; }`;
  assert.equal(secretFindings({ 'a.nix': unit(set) }).length, 0);
  const scalar = `"hunter2-hunter2-value"`;
  assert.ok(secretFindings({ 'a.nix': unit(scalar) }).length > 0);
});

test('an option whose name ends in script or command refers to code, not to a secret value', () => {
  const unit = (name) => `{ config, lib, pkgs, ... }:
let cfg = config.services.demo; in {
  options.services.demo.${name} = lib.mkOption { type = lib.types.lines; };
  config.systemd.services.demo.environment.LOADER_TOKEN = cfg.${name};
}`;
  assert.equal(secretFindings({ 'a.nix': unit('secretScript') }).length, 0);
  assert.equal(secretFindings({ 'a.nix': unit('tokenCommand') }).length, 0);
  assert.ok(secretFindings({ 'a.nix': unit('secretValue') }).length > 0);
});
