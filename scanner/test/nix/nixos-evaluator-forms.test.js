// NIX-002: the widened bounded option evaluator. Every form is pinned in BOTH directions: a fully known
// expression yields a value, and the same shape with ONE unknown part yields `unknown`, never a guess.
// All fixtures are written for this file; no corpus case is read.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveNixosConfig } from '../../src/language/nixos-module-resolver.js';
import { deepEq, isPlain, Closure } from '../../src/language/nixos-eval-forms.js';

const lines = (...l) => l.join('\n');
const run = (src, extra = {}) => resolveNixosConfig({ entry: 'configuration.nix', files: { 'configuration.nix': src }, ...extra });
const PORTS = 'networking.firewall.allowedTCPPorts';
const HOST = 'networking.hostName';
const SSH = 'services.openssh.enable';

/** The effective value of `opt` when the module sets it to `expr` (module body may carry a prelude). */
function valueOf(expr, { prelude = '', opt = PORTS, extra = {}, formals = '{ lib, config, pkgs, ... }' } = {}) {
  const src = `${formals}: ${prelude}{ ${opt} = ${expr}; }`;
  const r = run(src, extra);
  const o = r.lookup(opt);
  return { known: o.valueKnown && o.status === 'set', value: o.value, status: o.status, report: r, option: o };
}
const known = (expr, want, o) => { const v = valueOf(expr, o); assert.equal(v.known, true, `expected known: ${expr} (status ${v.status})`); assert.deepEqual(v.value, want, expr); };
const unknown = (expr, o) => { const v = valueOf(expr, o); assert.equal(v.known, false, `expected unknown: ${expr} -> ${JSON.stringify(v.value)}`); };

// ── let / in and shadowing ──

test('let/in: a bound list is known, an unbound or unknown binding makes the value unknown', () => {
  known('let a = [ 22 ]; in a', [22]);
  known('let a = 22; b = 80; in [ a b ]', [22, 80]);
  known('let a = [ 22 ]; in let b = a ++ [ 80 ]; in b', [22, 80]);
  unknown('let a = [ 22 ]; in b');
  unknown('let a = config.not.a.real.option; in [ a ]');
  // an unused unknown binding is not demanded, so it cannot poison the result (let is lazy)
  known('let junk = config.not.a.real.option; a = [ 22 ]; in a', [22]);
});

test('let/in: an inner binding shadows an outer one, and a lambda parameter shadows a let name', () => {
  known('let a = [ 1 ]; in let a = [ 2 ]; in a', [2]);
  known('let a = [ 1 ]; in (a: a) [ 2 ]', [2]);
  known('let a = [ 1 ]; in [ ((a: a) 2) (builtins.head2 or 3) ]'.replace('(builtins.head2 or 3)', '3'), [2, 3]);
  // the outer binding is untouched after the inner scope ends
  known('let a = [ 1 ]; b = (let a = [ 9 ]; in a); in a ++ b', [1, 9]);
  // a let-bound name that shadows a TARGET ARGUMENT wins over the argument
  known('let flag = [ 7 ]; in flag', [7], { extra: { target: { args: { flag: [1] } } } });
  known('flag', [1], { extra: { target: { args: { flag: [1] } } } });
});

test('let/in: a duplicate or dotted binding, or an unsupported inherit form, is unknown rather than guessed', () => {
  unknown('let a = [ 1 ]; a = [ 2 ]; in a');
  unknown('let a.b = [ 1 ]; in a.b');
  unknown('let a = [ 1 ]; inherit a; in a');
  unknown('let inherit (config.x) y; in y');
});

test('let/in: inherit reads the enclosing scope, and inherit (lib) binds a modelled function', () => {
  known('let a = [ 5 ]; in let inherit a; in a', [5]);
  known('let inherit (lib) optionals; in optionals true [ 22 ]', [22]);
  known('let inherit (builtins) map; in map (x: x + 1) [ 1 2 ]', [2, 3]);
  // a function lib does not model stays unknown
  unknown('let inherit (lib) fileContents; in [ (fileContents ./x) ]');
  // an inherit whose source is shadowed by this let's own binding is ambiguous
  unknown('let lib = { optionals = c: l: l; }; inherit (lib) optionals; in optionals true [ 1 ]');
});

test('let/in: config and lib read through a let alias are still resolved as options / the real lib', () => {
  const r = run(lines('{ config, lib, ... }:', 'let cfg = config.networking.firewall; in {', `  ${PORTS} = [ 22 ];`, `  ${SSH} = lib.mkIf (builtins.elem 22 cfg.allowedTCPPorts) true;`, '}'));
  assert.equal(r.lookup(SSH).value, true);
});

test('a local binding named config is NOT an option read; a local lambda over config is not either', () => {
  known('let config = { a = [ 4 ]; }; in config.a', [4]);
  known('(config: config.a) { a = [ 6 ]; }', [6]);
  // the real config is still readable where it is not shadowed
  const r = run(lines('{ config, lib, ... }: {', `  ${HOST} = "h1";`, `  ${SSH} = lib.mkIf (config.${HOST} == "h1") true;`, '}'));
  assert.equal(r.lookup(SSH).value, true);
  // ... and a shadowing one hides it: this reads the local attribute set, not the host name
  const r2 = run(lines('{ config, lib, ... }: {', `  ${HOST} = "h1";`, `  ${SSH} = let config = { ${HOST} = "other"; }; in lib.mkIf (config.${HOST} == "h1") true;`, '}'));
  assert.notEqual(r2.lookup(SSH).value, true, 'the local config must not be confused with the module config');
});

// ── with ──

test('with: a known attribute set supplies names; an unknown one makes every free name unknown', () => {
  known('with { a = [ 1 ]; }; a', [1]);
  known('with { a = [ 1 ]; b = [ 2 ]; }; a ++ b', [1, 2]);
  unknown('with config.x; a');
  unknown('with pkgs; [ vim ]');
  // an unknown with blocks a name that an OUTER with (or lib) would otherwise supply: it may shadow it
  const blocked = run(lines('{ lib, config, ... }:', 'with lib; {', `  ${PORTS} = with config.not.a.real.option; optionals true [ 22 ];`, '}'));
  assert.equal(blocked.lookup(PORTS).valueKnown, false);
  // a name the known set lacks is unknown (it could come from anywhere else), not empty
  unknown('with { a = [ 1 ]; }; b');
});

test('with: a lexical binding beats every with, and the innermost with beats an outer with', () => {
  known('let a = [ 1 ]; in with { a = [ 2 ]; }; a', [1]);
  known('with { a = [ 1 ]; }; let a = [ 2 ]; in a', [2]);
  known('with { a = [ 1 ]; }; with { a = [ 2 ]; }; a', [2]);
  known('with { a = [ 1 ]; b = [ 3 ]; }; with { a = [ 2 ]; }; a ++ b', [2, 3]);
  // a lambda parameter beats a with that is outside AND inside it
  known('with { a = [ 1 ]; }; (a: a) [ 2 ]', [2]);
  known('(a: with { a = [ 1 ]; }; a) [ 2 ]', [2]);
});

test('with lib: modelled names resolve, and a name the file binds itself is not taken from lib', () => {
  known('with lib; optionals true [ 22 ]', [22]);
  known('with builtins; map (x: x * 2) [ 1 2 ]', [2, 4]);
  unknown('with lib; someFunctionLibMayHave true');
  // a module-level `with lib;` is honoured for the definitions beneath it
  const r = run(lines('{ lib, ... }:', 'with lib; {', `  ${PORTS} = optionals true [ 22 ];`, '}'));
  assert.deepEqual(r.lookup(PORTS).value, [22]);
  // ... but a module-level let that rebinds the name wins over the with
  const r2 = run(lines('{ lib, ... }:', 'let optionals = c: l: [ 99 ]; in with lib; {', `  ${PORTS} = optionals true [ 22 ];`, '}'));
  assert.deepEqual(r2.lookup(PORTS).value, [99]);
  // an unrelated module-level with leaves bare names unknown
  const r3 = run(lines('{ lib, pkgs, ... }:', 'with pkgs; {', `  ${PORTS} = optionals true [ 22 ];`, '}'));
  assert.equal(r3.lookup(PORTS).valueKnown, false);
});

// ── if / then / else, assert ──

test('if/then/else: a known condition selects one branch lazily; an unknown one is unknown', () => {
  known('if true then [ 1 ] else [ 2 ]', [1]);
  known('if false then [ 1 ] else [ 2 ]', [2]);
  known('if 1 < 2 then [ 1 ] else [ 2 ]', [1]);
  // the branch NOT taken is never evaluated, so an unknown there is irrelevant
  known('if false then config.not.a.real.option else [ 2 ]', [2]);
  unknown('if true then config.not.a.real.option else [ 2 ]');
  unknown('if config.not.a.real.option then [ 1 ] else [ 1 ]');
  unknown('if "yes" then [ 1 ] else [ 2 ]');
  known('assert true; [ 3 ]', [3]);
  unknown('assert false; [ 3 ]');
  unknown('assert config.not.a.real.option; [ 3 ]');
  // the same inside an expression (not split by the collector)
  known('[ 0 ] ++ (if 1 < 2 then [ 1 ] else [ 2 ])', [0, 1]);
  known('[ 0 ] ++ (if false then config.not.a.real.option else [ 2 ])', [0, 2]);
  unknown('[ 0 ] ++ (if config.not.a.real.option then [ 1 ] else [ 2 ])');
  unknown('[ 0 ] ++ (if "yes" then [ 1 ] else [ 2 ])');
  unknown('[ 0 ] ++ (if config.not.a.real.option then [ 1 ] else [ 1 ])');
});

test('if/then/else on a config read uses the effective option value', () => {
  const src = lines('{ config, lib, ... }: {', '  services.openssh.enable = true;', `  ${PORTS} = if config.services.openssh.enable then [ 22 ] else [ ];`, '}');
  assert.deepEqual(run(src).lookup(PORTS).value, [22]);
  const src2 = src.replace('enable = true', 'enable = false');
  assert.deepEqual(run(src2).lookup(PORTS).value, []);
});

// ── list concatenation, attribute update, arithmetic ──

test('++ and //: known operands combine, one unknown operand makes the result unknown', () => {
  known('[ 1 ] ++ [ 2 ] ++ [ 3 ]', [1, 2, 3]);
  unknown('[ 1 ] ++ config.not.a.real.option');
  unknown('[ 1 ] ++ "x"');
  unknown('[ 1 ] ++ { }');
  const V = { opt: 'services.nginx.virtualHosts' };
  assert.deepEqual(valueOf('let r = { a = 1; } // { b = 2; a = 3; }; in r', V).value, { a: 3, b: 2 });
  assert.equal(valueOf('let r = { a = 1; } // config.not.a.real.option; in r', V).known, false);
  assert.equal(valueOf('let r = { a = 1; } // [ 1 ]; in r', V).known, false);
});

test('arithmetic and comparison are integer-only and refuse results JavaScript cannot represent exactly', () => {
  known('[ (1 + 2) (5 - 7) (3 * 4) ]', [3, -2, 12]);
  known('[ (-3) ]', [-3]);
  known('if 2 >= 2 && 2 <= 2 && 3 > 2 then [ 1 ] else [ 0 ]', [1]);
  unknown('[ (1 + "a") ]');
  unknown('[ (9007199254740991 + 1) ]');
  unknown('[ 99999999999999999999 ]');
  unknown('[ ("a" < "b") ]');
  unknown('[ (1 / 2) ]');
  known('[ ("a" + "b") ]', ['ab']);
});

// ── equality ──

test('== compares structurally and ignores attribute order; functions are never compared', () => {
  assert.equal(deepEq({ a: 1, b: [2] }, { b: [2], a: 1 }), true);
  assert.equal(deepEq({ a: 1 }, { a: 1, b: 2 }), false);
  assert.equal(deepEq([1, 2], [1, 2, 3]), false);
  assert.equal(deepEq(1, '1'), false);
  assert.equal(deepEq(null, false), false);
  assert.equal(deepEq(new Closure(null, null, null), new Closure(null, null, null)), null);
  known('if { a = 1; b = 2; } == { b = 2; a = 1; } then [ 1 ] else [ 0 ]', [1]);
  known('if { a = 1; } != { a = 2; } then [ 1 ] else [ 0 ]', [1]);
  unknown('if (x: x) == (x: x) then [ 1 ] else [ 0 ]');
  unknown('if config.not.a.real.option == 1 then [ 1 ] else [ 0 ]');
});

// ── library functions ──

test('lib.optionals / lib.optional / builtins.elem: known inputs evaluate, unknown condition or list does not', () => {
  known('lib.optionals true [ 22 80 ]', [22, 80]);
  known('lib.optionals false [ 22 80 ]', []);
  known('lib.optional true 22', [22]);
  known('lib.optional false 22', []);
  known('[ 1 ] ++ lib.optionals (1 == 1) [ 2 ] ++ lib.optional (1 == 2) 3', [1, 2]);
  unknown('lib.optionals config.not.a.real.option [ 22 ]');
  unknown('lib.optionals true config.not.a.real.option');
  unknown('lib.optionals "yes" [ 22 ]');
  unknown('lib.optional 1 22');
  known('lib.optionals (builtins.elem 2 [ 1 2 3 ]) [ 22 ]', [22]);
  known('lib.optionals (lib.elem 9 [ 1 2 3 ]) [ 22 ]', []);
  unknown('lib.optionals (builtins.elem 2 config.not.a.real.option) [ 22 ]');
  unknown('lib.optionals (builtins.elem 2 "not a list") [ 22 ]');
  // elem over a list containing a function cannot be decided
  unknown('lib.optionals (builtins.elem 2 [ (x: x) 3 ]) [ 22 ]');
});

test('lib.optionalAttrs / optionalString / boolToString / hasPrefix / hasSuffix', () => {
  const V = { opt: 'services.nginx.virtualHosts' };
  assert.deepEqual(valueOf('let r = lib.optionalAttrs true { a = 1; } // lib.optionalAttrs false { b = 2; }; in r', V).value, { a: 1 });
  assert.equal(valueOf('let r = lib.optionalAttrs config.not.a.real.option { a = 1; }; in r', V).known, false);
  known('[ (lib.optionalString true "x") (lib.optionalString false "y") (lib.boolToString true) ]', ['x', '', 'true']);
  known('[ (lib.hasPrefix "ab" "abc") (lib.hasSuffix "bc" "abc") (lib.hasPrefix "x" "abc") ]', [true, true, false]);
  unknown('[ (lib.hasPrefix 1 "abc") ]');
  unknown('[ (lib.optionalString "no" "x") ]');
});

test('map / filter / concatMap / concatLists / length over known lists with simple lambdas', () => {
  known('map (x: x + 1) [ 1 2 3 ]', [2, 3, 4]);
  known('builtins.map (x: x * 2) [ 1 2 ]', [2, 4]);
  known('lib.map (x: x + 1) [ 1 ]', [2]);
  known('builtins.filter (x: x > 1) [ 1 2 3 ]', [2, 3]);
  known('lib.filter (x: x != 2) [ 1 2 3 ]', [1, 3]);
  known('builtins.concatMap (x: [ x x ]) [ 1 2 ]', [1, 1, 2, 2]);
  known('lib.concatLists [ [ 1 ] [ 2 3 ] ]', [1, 2, 3]);
  known('[ (builtins.length [ 1 2 3 ]) ]', [3]);
  // a pattern lambda over attribute-set elements
  known('map ({ port, ... }: port) [ { port = 22; } { port = 80; extra = true; } ]', [22, 80]);
  unknown('map (x: x + 1) config.not.a.real.option');
  unknown('map (x: config.not.a.real.option) [ 1 ]');
  unknown('map (x: x + 1) [ 1 "a" ]');
  unknown('builtins.filter (x: x) [ 1 ]');
  unknown('builtins.filter (x: x > 1) [ 1 config.not.a.real.option ]');
  unknown('lib.concatLists [ [ 1 ] 2 ]');
  unknown('builtins.concatMap (x: x) [ 1 ]');
  unknown('map (x: x)');
});

test('concatStringsSep / concatMapStringsSep / toString build strings only from known strings', () => {
  const o = { opt: HOST };
  known('lib.concatStringsSep "-" [ "a" "b" "c" ]', 'a-b-c', o);
  known('lib.strings.concatStringsSep "," [ "x" ]', 'x', o);
  known('lib.concatMapStringsSep "." (n: toString n) [ 1 2 3 ]', '1.2.3', o);
  known('lib.concatMapStringsSep "," (s: s + "!") [ "a" "b" ]', 'a!,b!', o);
  known('builtins.toString 7', '7', o);
  unknown('lib.concatStringsSep "-" [ "a" 1 ]', o);
  unknown('lib.concatStringsSep "-" [ "a" config.not.a.real.option ]', o);
  unknown('lib.concatStringsSep config.not.a.real.option [ "a" ]', o);
  unknown('lib.concatMapStringsSep "," (n: n) [ 1 2 ]', o);
  unknown('builtins.toString [ 1 2 ]', o);
  unknown('builtins.toString config.not.a.real.option', o);
});

test('lib.mkMerge: a merge of plain lists is a list; anything else cannot be merged without the option type', () => {
  known('lib.mkMerge [ [ 1 ] [ 2 ] ]', [1, 2], { prelude: 'let x = 1; in ' });
  known('let m = lib.mkMerge [ [ 22 ] (lib.optionals true [ 80 ]) ]; in m', [22, 80]);
  unknown('let m = lib.mkMerge [ [ 22 ] (lib.mkIf true [ 80 ]) ]; in m');
  unknown('let m = lib.mkMerge [ { a = 1; } { b = 2; } ]; in m');
  unknown('let m = lib.mkMerge [ [ 22 ] config.not.a.real.option ]; in m');
});

// ── string interpolation ──

test('string interpolation is known only when every interpolated part is a known string', () => {
  const o = { opt: HOST };
  known('let n = "web"; in "${n}-01"', 'web-01', o);
  known('let n = "web"; i = toString 2; in "${n}-${i}"', 'web-2', o);
  known('"${"a"}${"b"}"', 'ab', o);
  known('"x-${lib.concatStringsSep "+" [ "a" "b" ]}"', 'x-a+b', o);
  unknown('let n = "web"; in "${n}-${config.not.a.real.option}"', o);
  unknown('"${pkgs.hello}"', o);
  unknown('"${1}"', o);
  unknown('"${toString 1}${undefinedName}"', o);
  // an escaped interpolation is literal text
  known("''a''${b}''", 'a${b}', o);
});

// ── local functions ──

test('local function application: closures, currying, patterns, defaults and arity errors', () => {
  known('let f = x: x ++ [ 1 ]; in f [ 0 ]', [0, 1]);
  known('let add = a: b: a ++ b; in add [ 1 ] [ 2 ]', [1, 2]);
  known('let f = { a, b ? [ 9 ] }: a ++ b; in f { a = [ 1 ]; }', [1, 9]);
  known('let f = { a, b ? a }: a ++ b; in f { a = [ 1 ]; }', [1, 1]);
  known('let f = { a, ... }: a; in f { a = [ 1 ]; z = 2; }', [1]);
  known('let f = args@{ a, ... }: args.a; in f { a = [ 4 ]; }', [4]);
  known('let f = x: y: x; g = f [ 1 ]; in g [ 2 ]', [1]);
  // a closure's definition scope is used, not the call site's
  known('let a = [ 1 ]; f = x: a; in let a = [ 2 ]; in f 0', [1]);
  known('(x: x) [ 3 ]', [3]);
  // a missing required argument, an extra argument without an ellipsis, a non-set argument, an unknown argument
  unknown('let f = { a }: a; in f { }');
  unknown('let f = { a }: a; in f { a = [ 1 ]; b = 2; }');
  unknown('let f = { a }: a; in f [ 1 ]');
  unknown('let f = x: x; in f config.not.a.real.option');
  unknown('let f = x: x; in f');
  unknown('let f = x: x; in f [ 1 ] [ 2 ]');
  unknown('undefinedFunction [ 1 ]');
});

test('a function, a partial application or a namespace is never a final option value', () => {
  unknown('x: x');
  unknown('let f = x: y: x; in f [ 1 ]');
  unknown('lib.optionals true');
  unknown('lib');
  unknown('builtins');
  unknown('[ (x: x) ]');
  unknown('let r = { f = x: x; }; in r', { opt: 'services.nginx.virtualHosts' });
  assert.equal(isPlain([1, { a: 'x', b: null }]), true);
  assert.equal(isPlain([1, new Closure(null, null, null)]), false);
});

// ── priority wrappers ──

test('mkDefault / mkForce / mkOverride around evaluated forms keep their priority and value', () => {
  const src = lines('{ lib, ... }:', 'let base = [ 22 ]; in {', `  ${PORTS} = lib.mkDefault (base ++ lib.optionals true [ 80 ]);`, '}');
  const r = run(src);
  const o = r.lookup(PORTS);
  assert.deepEqual(o.value, [22, 80]);
  assert.equal(o.sources[0].priorityLabel, 'mkDefault');
  assert.equal(o.sources[0].priority, 1000);

  const forced = run(lines('{ lib, ... }:', 'let p = "no"; in {', `  services.openssh.settings.PermitRootLogin = lib.mkDefault "yes";`, `  imports = [ ];`, '}'));
  assert.equal(forced.lookup('services.openssh.settings.PermitRootLogin').value, 'yes');

  // mkForce built from a computed value outranks a plain definition; the computed value is what wins
  const two = run(lines('{ lib, ... }:', 'let v = if 1 < 2 then "no" else "yes"; in {', '  services.openssh.settings.PermitRootLogin = lib.mkForce v;', '  services.openssh.settings.PermitRootLogin2 = "x";', '}'));
  assert.equal(two.lookup('services.openssh.settings.PermitRootLogin').value, 'no');
  assert.equal(two.lookup('services.openssh.settings.PermitRootLogin').sources[0].priorityLabel, 'mkForce');

  const ov = run(lines('{ lib, ... }: {', `  ${PORTS} = lib.mkOverride 40 (map (x: x + 1) [ 21 ]);`, '}'));
  assert.deepEqual(ov.lookup(PORTS).value, [22]);
  assert.equal(ov.lookup(PORTS).sources[0].priority, 40);
});

test('a priority wrapper INSIDE an evaluated value is unknown: the priority cannot be recovered from a value', () => {
  unknown('let p = lib.mkDefault [ 22 ]; in p');
  unknown('map (x: x) [ (lib.mkForce 22) ]');
  unknown('[ 1 ] ++ lib.mkForce [ 22 ]');
  unknown('[ 1 ] ++ lib.mkIf true [ 22 ]');
  unknown('[ 1 ] ++ lib.mkBefore [ 22 ]');
  unknown('[ 1 ] ++ lib.mkOverride 10 [ 22 ]');
});

// ── conditions ──

test('mkIf / if conditions use the widened evaluator and keep their definitions certain or inactive', () => {
  const mk = (cond) => run(lines('{ lib, config, ... }:', 'let roles = [ "web" "db" ]; in {', `  ${SSH} = lib.mkIf (${cond}) true;`, '}')).lookup(SSH);
  assert.equal(mk('builtins.elem "web" roles').value, true);
  assert.equal(mk('builtins.elem "web" roles').status, 'set');
  assert.equal(mk('builtins.elem "cache" roles').status, 'default');
  assert.equal(mk('builtins.length roles > 1').status, 'set');
  assert.equal(mk('builtins.length roles > 5').status, 'default');
  // an unknown condition keeps the definition conditional, never assumed either way
  const unk = mk('builtins.elem "web" config.not.a.real.option');
  assert.notEqual(unk.status, 'set');
  assert.equal(unk.sources[0].conditions[0].outcome, 'unknown');
});

test('a module-level let / with that wraps the body is seen through by the collector', () => {
  const r = run(lines('{ lib, config, ... }:', 'let', '  web = [ 80 443 ];', '  ssh = [ 22 ];', 'in with lib; {', `  ${PORTS} = ssh ++ web;`, `  ${HOST} = "h-${'${toString (length web)}'}";`, '}'));
  assert.deepEqual(r.lookup(PORTS).value, [22, 80, 443]);
  assert.equal(r.lookup(HOST).value, 'h-2', 'bare `length` resolves through the module-level `with lib;`');
  const r3 = run(lines('{ lib, pkgs, ... }:', 'let web = [ 80 ]; in with pkgs; {', `  ${HOST} = "h-${'${toString (length web)}'}";`, '}'));
  assert.equal(r3.lookup(HOST).valueKnown, false, 'a with over an unrelated set leaves bare names unknown');
  const r2 = run(lines('{ lib, ... }:', 'let n = 2; in {', `  ${HOST} = "h-${'${toString n}'}";`, '}'));
  assert.equal(r2.lookup(HOST).value, 'h-2');
});

test('a module-level let name defined twice, or also a function parameter, is not resolved', () => {
  const dup = run(lines('{ lib, ... }: {', `  ${PORTS} = if true then (let a = [ 1 ]; in a) else (let a = [ 2 ]; in a);`, '}'));
  assert.deepEqual(dup.lookup(PORTS).value, [1]);
  const dup2 = run(lines('{ lib, ... }:', 'let', '  a = [ 1 ];', 'in {', `  ${PORTS} = if true then a else (let a = [ 2 ]; in a);`, `  ${SSH} = false;`, '}'));
  // `a` is bound twice in the file (module-level and inner), so the bare reference is ambiguous
  assert.equal(dup2.lookup(PORTS).valueKnown, false);
  const param = run(lines('{ lib, a, ... }:', 'let b = [ 1 ]; in {', `  ${PORTS} = a ++ b;`, '}'));
  assert.equal(param.lookup(PORTS).valueKnown, false, 'a module parameter without a supplied value is unknown');
  const supplied = run(lines('{ lib, a, ... }:', 'let b = [ 1 ]; in {', `  ${PORTS} = a ++ b;`, '}'), { target: { args: { a: [7] } } });
  assert.deepEqual(supplied.lookup(PORTS).value, [7, 1]);
});

test('a file-level let is used only where it lexically encloses the reference and nothing else can bind the name', () => {
  // `n` below is bound by the rec set, not by the module-level let: the let must NOT supply it
  const rec = run(lines('{ lib, ... }:', 'let n = [ 80 ]; in {', `  networking = rec { n = [ 22 ]; firewall.allowedTCPPorts = n; };`, '}'));
  assert.equal(rec.lookup(PORTS).valueKnown, false, 'inside a rec set a bare name may be a sibling attribute');
  // a let that exists elsewhere in the file but does not enclose this definition does not bind the name
  const away = run(lines('{ lib, ... }: {', '  services.nginx.virtualHosts.a.root = let n = "/srv"; in n;', `  ${PORTS} = n;`, '}'));
  assert.equal(away.lookup(PORTS).valueKnown, false, 'a let in another definition is not in scope here');
  assert.equal(away.lookup('services.nginx.virtualHosts.a.root').value, '/srv');
  // the same holds for a let-alias of a config path used in a condition
  const cfgAway = run(lines('{ config, lib, ... }: {', '  networking.firewall.enable = true;', '  foo.bar = let cfg = config.networking.firewall; in cfg.enable;', `  ${SSH} = lib.mkIf cfg.enable true;`, '}'));
  assert.notEqual(cfgAway.lookup(SSH).status, 'set', 'cfg is not in scope at the mkIf, so the condition is undecidable');
  const cfgIn = run(lines('{ config, lib, ... }:', 'let cfg = config.networking.firewall; in {', '  networking.firewall.enable = true;', `  ${SSH} = lib.mkIf cfg.enable true;`, '}'));
  assert.equal(cfgIn.lookup(SSH).value, true);
  // the enclosing case still works
  const inside = run(lines('{ lib, ... }:', 'let n = [ 80 ]; in {', `  ${PORTS} = n;`, '}'));
  assert.deepEqual(inside.lookup(PORTS).value, [80]);
  // an assert in a wrapper is honoured (the definition is evaluated through its wrapper)
  const asrt = run(lines('{ lib, ... }: {', `  ${PORTS} = assert false; [ 22 ];`, '}'));
  assert.equal(asrt.lookup(PORTS).valueKnown, false);
});

test('a conditional definition is split by the collector: each branch keeps its own priority and condition', () => {
  const r = run(lines('{ lib, config, ... }: {', '  services.openssh.enable = true;', `  ${PORTS} = if config.services.openssh.enable then lib.mkForce [ 22 ] else [ 80 ];`, '}'));
  const o = r.lookup(PORTS);
  assert.deepEqual(o.value, [22]);
  assert.equal(o.sources.find((x) => x.role === 'winner').priorityLabel, 'mkForce');
});

// ── not modelled: stays unknown ──

test('effectful, environment-dependent, path and recursive forms are never evaluated', () => {
  unknown('[ (builtins.readFile ./ports) ]');
  unknown('import ./ports.nix');
  unknown('builtins.fromJSON (builtins.readFile ./p.json)');
  unknown('[ (builtins.fetchurl "https://example.invalid/x") ]');
  unknown('[ builtins.currentSystem ]');
  unknown('[ (builtins.getEnv "HOME") ]');
  unknown('[ ./relative/path ]');
  unknown('[ (lib.fileContents ./x) ]');
  unknown('[ (builtins.toFile "x" "y") ]');
  unknown('[ (builtins.trace "x" 1) ]');
  unknown('[ (throw "no") ]');
  unknown('[ (builtins.head [ ]) ]');
  const V = { opt: 'services.nginx.virtualHosts' };
  unknown('let r = rec { a = 1; b = a; }; in r', V);
  unknown('let r = { ${"dyn"} = 1; }; in r', V);
  unknown('let r = { a = 1; a = 2; }; in r', V);
  unknown('let r = { inherit (config.x) y; }; in r', V);
  unknown('[ (lib.pkgs.x) ]');
  // a name that looks like lib but is the file's own shadowing binding is that binding, not the library
  const shadow = run(lines('{ pkgs, ... }:', 'let lib = { optionals = c: l: [ 99 ]; }; in {', `  ${PORTS} = lib.optionals true [ 22 ];`, '}'));
  assert.deepEqual(shadow.lookup(PORTS).value, [99]);
  const shadowUnk = run(lines('{ pkgs, ... }:', 'let lib = pkgs.lib; in {', `  ${PORTS} = lib.optionals true [ 22 ];`, '}'));
  assert.equal(shadowUnk.lookup(PORTS).valueKnown, false);
  // lib without a module parameter named lib is not the nixpkgs lib
  const nolib = run(lines('{ pkgs, ... }: {', `  ${PORTS} = lib.optionals true [ 22 ];`, '}'));
  assert.equal(nolib.lookup(PORTS).valueKnown, false);
});

test('attribute names are handled safely, including __proto__', () => {
  const v = valueOf('let r = { __proto__ = 1; a = 2; }; in r', { opt: 'services.nginx.virtualHosts' });
  assert.equal(v.known, true);
  assert.equal(Object.getPrototypeOf(v.value), Object.prototype);
  assert.equal(Object.prototype.hasOwnProperty.call(v.value, '__proto__'), true);
  const merged = valueOf('let r = { a.b = 1; a.c = 2; }; in r', { opt: 'services.nginx.virtualHosts' });
  assert.deepEqual(merged.value, { a: { b: 1, c: 2 } });
  assert.equal(valueOf('let r = { a = { b = 1; }; a.c = 2; }; in r', { opt: 'services.nginx.virtualHosts' }).known, false);
  const sel = valueOf('({ a = { b = [ 5 ]; }; }).a.b');
  assert.deepEqual(sel.value, [5]);
  known('({ a = 1; }).b or [ 8 ]', [8]);
  known('({ a = [ 1 ]; }).a or [ 8 ]', [1]);
  unknown('({ a = 1; }).b');
  unknown('({ a = 1; }).a.b');
});

// ── bounds ──

test('bounded evaluation: runaway recursion and oversize results are reported as truncation, never guessed', () => {
  const rec = run(lines('{ lib, ... }:', 'let f = x: f x; in {', `  ${PORTS} = f [ 1 ];`, '}'));
  const o = rec.lookup(PORTS);
  assert.equal(o.valueKnown, false);
  assert.ok(rec.truncated.some((t) => t.budget === 'maxExprDepth'), JSON.stringify(rec.truncated));

  const big = run(lines('{ lib, ... }: {', `  ${PORTS} = builtins.concatLists [ [ 1 2 ] [ 3 4 ] ];`, '}'), { budgets: { maxValueSize: 3 } });
  assert.equal(big.lookup(PORTS).valueKnown, false);
  assert.ok(big.truncated.some((t) => t.budget === 'maxValueSize'));
  // within the cap the same expression is known
  const ok = run(lines('{ lib, ... }: {', `  ${PORTS} = builtins.concatLists [ [ 1 2 ] [ 3 4 ] ];`, '}'), { budgets: { maxValueSize: 4 } });
  assert.deepEqual(ok.lookup(PORTS).value, [1, 2, 3, 4]);

  const steps = run(lines('{ lib, ... }: {', `  ${PORTS} = map (x: x + 1) [ 1 2 3 4 5 6 7 8 ];`, '}'), { budgets: { maxEvaluations: 20 } });
  assert.equal(steps.lookup(PORTS).valueKnown, false);
  assert.ok(steps.truncated.some((t) => t.budget === 'maxEvaluations'));

  // a self-referential let binding is unknown (a Nix infinite recursion), not a hang
  unknown('let a = a; in [ a ]');
  unknown('let a = b; b = a; in a');
});

test('known results of the earlier evaluator are unchanged', () => {
  known('[ { from = 1; to = 65535; } ]', [{ from: 1, to: 65535 }], { opt: 'networking.firewall.allowedTCPPortRanges' });
  known('[ 22 80 ]', [22, 80]);
  const r = run(lines('{ config, lib, pkgs, ... }: {', '  services.openssh.enable = true;', `  ${SSH}2 = true;`, `  networking.firewall.enable = !config.services.openssh.enable;`, '}'), { target: { system: 'x86_64-linux' } });
  assert.equal(r.lookup('networking.firewall.enable').value, false);
  const plat = run(lines('{ config, lib, pkgs, ... }: {', `  networking.firewall.enable = pkgs.stdenv.isLinux;`, '}'), { target: { system: 'x86_64-linux' } });
  assert.equal(plat.lookup('networking.firewall.enable').value, true);
  // pkgs shadowed locally is not the platform pkgs
  const shadow = run(lines('{ config, lib, pkgs, ... }: {', `  networking.firewall.enable = let pkgs = { stdenv.isLinux = false; }; in pkgs.stdenv.isLinux;`, '}'), { target: { system: 'x86_64-linux' } });
  assert.equal(shadow.lookup('networking.firewall.enable').value, false);
});
