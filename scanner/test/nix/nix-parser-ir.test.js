// NIX-001: Nix parser, expression/config IR and locations.
// Suite "nix-parser-ir" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseNix, spanText, DEFAULT_PARSE_BUDGETS } from '../../src/language/nix-parser.js';
import { analyzeNix, lookupAttr, buildNixImportGraph } from '../../src/language/nix-ir.js';
import { loadNixGrammar, GRAMMAR_DATA, NIX_GRAMMAR_SHA256, nixGrammarChecksum } from '../../src/language/nix-grammar.js';
import { createNixAdapter } from '../../src/language/nix-adapter.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const langDir = path.join(here, '../../src/language');

const lines = (...l) => l.join('\n');
const kinds = (ir) => ir.unresolved.map((u) => u.kind);
const pathTexts = (ir) => ir.bindings.map((b) => b.pathText);

// ── AC01 ───────────────────────────────────────────────────────────────────

test('[NIX-001.AC01] spans index the original file in lines, columns, UTF-8 bytes and offsets', () => {
  const src = lines('{', '  greeting = "héllo → wörld";', '  next = 1;', '}');
  const { ir } = analyzeNix(src, { file: 'a.nix' });
  assert.equal(ir.status, 'ok');
  const g = ir.bindings.find((b) => b.pathText === 'greeting');
  const n = ir.bindings.find((b) => b.pathText === 'next');
  assert.equal(g.value.literal, 'héllo → wörld');
  assert.equal(spanText(src, g.span), 'greeting = "héllo → wörld";');
  assert.equal(spanText(src, g.valueSpan), '"héllo → wörld"');
  assert.equal(spanText(src, n.span), 'next = 1;');
  assert.equal(spanText(src, n.valueSpan), '1');
  assert.equal(n.span.startLine, 3);
  assert.equal(n.span.endLine, 3);
  assert.equal(n.span.startColumn, 2);
  assert.equal(n.span.endColumn, 2 + 'next = 1;'.length);
  // é is 2 bytes, → is 3, ö is 2: four extra bytes precede `next` on earlier lines
  assert.equal(n.span.startByte - n.span.startOffset, 4);
  assert.equal(src.slice(n.span.startOffset, n.span.endOffset), 'next = 1;');
});

test('[NIX-001.AC01] module bindings, imports, literal text and interpolation are distinguished', () => {
  const src = lines(
    '{ config, lib, pkgs, ... }:',
    '{',
    '  imports = [ ./hardware.nix ./extra/default.nix ];',
    '  services.nginx.enable = true;',
    '  services.nginx = { virtualHosts."example.org".root = "/srv"; };',
    '  networking.hostName = "box-${config.name}";',
    '  networking.domain = "plain.example";',
    "  environment.etc.\"motd\".text = ''",
    "    hello ''${notinterp} ${pkgs.hello}",
    "  '';",
    '}',
  );
  const { ir } = analyzeNix(src, { file: 'hosts/a/configuration.nix' });
  assert.equal(ir.status, 'ok');
  assert.equal(ir.fileKind, 'module');
  assert.deepEqual(ir.rootFunction.params, ['config', 'lib', 'pkgs']);
  assert.equal(ir.rootFunction.ellipsis, true);

  // import graph edges with resolved paths and original spans
  assert.deepEqual(ir.imports.map((i) => [i.kind, i.target.literal, i.resolved, i.literal]), [
    ['module-import', './hardware.nix', 'hosts/a/hardware.nix', true],
    ['module-import', './extra/default.nix', 'hosts/a/extra/default.nix', true],
  ]);
  assert.equal(spanText(src, ir.imports[0].span), './hardware.nix');
  assert.equal(spanText(src, ir.imports[1].span), './extra/default.nix');

  // attributes merge across `a.b.c = ..` and `a.b = { c = ..; }` spellings
  const enable = lookupAttr(ir, 'services.nginx.enable');
  assert.equal(enable.length, 1);
  assert.deepEqual(enable[0].value, { type: 'bool', value: true });
  assert.equal(spanText(src, enable[0].span), 'services.nginx.enable = true;');
  const root = lookupAttr(ir, ['services', 'nginx', 'virtualHosts', 'example.org', 'root']);
  assert.equal(root.length, 1);
  assert.equal(root[0].value.literal, '/srv');
  assert.equal(root[0].origin, 'attr');
  assert.deepEqual(ir.conflicts, []);

  // literal vs interpolated
  const host = lookupAttr(ir, 'networking.hostName')[0];
  assert.equal(host.value.literal, null);
  assert.equal(host.value.interpolated, true);
  const plain = lookupAttr(ir, 'networking.domain')[0];
  assert.equal(plain.value.literal, 'plain.example');
  assert.equal(plain.value.interpolated, false);

  const motd = lookupAttr(ir, ['environment', 'etc', 'motd', 'text'])[0];
  assert.equal(motd.value.indented, true);
  assert.equal(motd.value.interpolated, true);
  assert.equal(motd.value.interpolations.length, 1);
  assert.equal(motd.value.interpolations[0].text, 'pkgs.hello');
  assert.equal(spanText(src, motd.value.interpolations[0].span), '${pkgs.hello}');
  const motdInterps = ir.interpolations.filter((i) => i.context === 'indented-string');
  assert.equal(motdInterps.length, 1);
  assert.equal(motdInterps[0].exprKind, 'select');
  const hostInterp = ir.interpolations.find((i) => i.context === 'string');
  assert.equal(spanText(src, hostInterp.span), '${config.name}');
});

test('[NIX-001.AC01] text parts keep original spans and resolve nested and indented escapes', () => {
  const src = lines(
    '{',
    '  s = "q\\"uote\\n\\${notinterp}\\\\";',
    "  u = ''",
    "    one '''two''' ''\\t tab",
    "      deeper ''${lit}",
    "  '';",
    "  m = ''  inline ${x} end'';",
    '}',
  );
  const parse = parseNix(src, { file: 'e.nix' });
  assert.equal(parse.status, 'ok');
  const { ir } = analyzeNix(src, { file: 'e.nix' });
  const s = lookupAttr(ir, 's')[0];
  assert.equal(s.value.literal, 'q"uote\n${notinterp}\\');
  assert.equal(s.value.interpolated, false);
  const u = lookupAttr(ir, 'u')[0];
  assert.equal(u.value.literal, "one ''two'' \t tab\n  deeper ${lit}\n");
  assert.equal(u.value.interpolated, false);
  // `u` text parts index the original (un-dedented, un-unescaped) text
  const attrset = parse.ast.type === 'attrset' ? parse.ast : null;
  const uBinding = attrset.bindings.find((b) => b.kind === 'attr' && b.path[0].name === 'u');
  const part = uBinding.value.parts[0];
  assert.equal(part.kind, 'text');
  assert.equal(spanText(src, part.span), "one '''two''' ''\\t tab\n      deeper ''${lit}\n");
  // an interpolation inside an indented string leaves text parts around it
  const mBinding = attrset.bindings.find((b) => b.kind === 'attr' && b.path[0].name === 'm');
  assert.deepEqual(mBinding.value.parts.map((p) => p.kind), ['text', 'interp', 'text']);
  assert.equal(mBinding.value.parts[0].value, 'inline ');
  assert.equal(mBinding.value.parts[2].value, ' end');
  assert.equal(mBinding.value.literal, null);
});

test('[NIX-001.AC01] // updates, mkMerge, mkIf, if/else, priority and duplicates resolve as merges', () => {
  const src = lines(
    '{',
    '  a = { x = 1; y = 2; } // { y = 3; };',
    '  b.c = 1;',
    '  b = { d = 2; };',
    '  e = lib.mkIf cond { f = 1; };',
    '  g = lib.mkMerge [ { h = 1; } { i = 2; } ];',
    '  j = if cond then { k = 1; } else { k = 2; };',
    '  l = lib.mkForce 5;',
    '  dup = 1;',
    '  dup = 2;',
    '}',
  );
  const { ir } = analyzeNix(src, { file: 'm.nix' });
  assert.equal(lookupAttr(ir, 'a.x')[0].value.value, 1);
  const y = lookupAttr(ir, 'a.y');
  assert.equal(y.length, 1, 'the overridden left-hand y is dropped from the tree');
  assert.equal(y[0].value.value, 3);
  assert.equal(y[0].update, true);
  assert.ok(ir.bindings.some((b) => b.pathText === 'a.y' && b.overridden === true));
  assert.equal(lookupAttr(ir, 'b.c')[0].value.value, 1);
  assert.equal(lookupAttr(ir, 'b.d')[0].value.value, 2);
  const f = lookupAttr(ir, 'e.f')[0];
  assert.equal(f.conditions.length, 1);
  assert.equal(f.conditions[0].kind, 'mkIf');
  assert.equal(f.conditions[0].text, 'cond');
  assert.equal(lookupAttr(ir, 'g.h')[0].merge, 'mkMerge');
  assert.equal(lookupAttr(ir, 'g.i')[0].merge, 'mkMerge');
  const k = lookupAttr(ir, 'j.k');
  assert.deepEqual(k.map((b) => b.conditions[0].branch), ['then', 'else']);
  assert.deepEqual(k.map((b) => b.value.value), [1, 2]);
  assert.equal(lookupAttr(ir, 'l')[0].priority, 'mkForce');
  assert.equal(ir.conflicts.length, 1);
  assert.equal(ir.conflicts[0].kind, 'duplicate-definition');
  assert.deepEqual(ir.conflicts[0].path, ['dup']);
  assert.equal(ir.conflicts[0].spans.length, 2);
});

test('[NIX-001.AC01] flake files expose inputs, follows and outputs; overlays and packages are classified', () => {
  const flake = lines(
    '{',
    '  description = "demo";',
    '  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";',
    '  inputs.utils = { url = "github:numtide/flake-utils"; inputs.nixpkgs.follows = "nixpkgs"; };',
    '  outputs = { self, nixpkgs, utils }: {',
    '    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;',
    '  };',
    '}',
  );
  const { ir } = analyzeNix(flake, { file: 'flake.nix' });
  assert.equal(ir.status, 'ok');
  assert.equal(ir.fileKind, 'flake');
  assert.equal(ir.flake.description, 'demo');
  assert.deepEqual(ir.flake.inputs.map((i) => [i.name, i.url]), [
    ['nixpkgs', 'github:NixOS/nixpkgs/nixos-24.05'],
    ['utils', 'github:numtide/flake-utils'],
  ]);
  assert.deepEqual(ir.flake.inputs[1].nestedFollows, [{ path: ['nixpkgs'], follows: 'nixpkgs' }]);
  assert.deepEqual(ir.flake.outputs.params, ['self', 'nixpkgs', 'utils']);
  assert.equal(spanText(flake, ir.flake.outputs.span), '{ self, nixpkgs, utils }: {\n    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;\n  }');
  const out = ir.bindings.find((b) => b.scope === 'outputs');
  assert.deepEqual(out.path, ['packages', 'x86_64-linux', 'default']);

  const overlay = analyzeNix('final: prev: { hello2 = prev.hello; }', { file: 'overlay.nix' }).ir;
  assert.equal(overlay.fileKind, 'overlay');
  assert.equal(overlay.overlays.length, 1);
  assert.deepEqual(overlay.overlays[0].params, ['final', 'prev']);
  assert.equal(overlay.overlays[0].bindings, 1);

  const inModule = analyzeNix('{ nixpkgs.overlays = [ (final: prev: { x = 1; }) ]; }', { file: 'm.nix' }).ir;
  assert.equal(inModule.overlays.length, 1);
  assert.deepEqual(inModule.overlays[0].params, ['final', 'prev']);

  const pkg = analyzeNix('{ stdenv }: stdenv.mkDerivation { name = "app"; src = ./.; }', { file: 'default.nix' }).ir;
  assert.equal(pkg.fileKind, 'package');
  assert.equal(lookupAttr(pkg, 'name')[0].value.literal, 'app');
  assert.equal(lookupAttr(pkg, 'name')[0].callee, 'mkDerivation');
});

test('[NIX-001.AC01] a bounded import graph links import, callPackage and module imports', () => {
  const files = {
    'default.nix': lines(
      '{ pkgs ? import <nixpkgs> {} }:',
      'let',
      '  lib = import ./lib.nix;',
      'in',
      '{',
      '  imports = [ ./mod.nix ];',
      '  app = pkgs.callPackage ./app.nix { };',
      '}',
    ),
    'lib.nix': '{ inc = n: n + 1; }',
    'mod.nix': '{ services.foo.enable = true; }',
    'app.nix': '{ stdenv }: stdenv.mkDerivation { name = "app"; }',
  };
  const graph = buildNixImportGraph('default.nix', { readFile: (p) => (p in files ? files[p] : null) });
  assert.equal(graph.usedNixBinary, false);
  assert.equal(graph.truncated, false);
  assert.deepEqual(graph.edges.map((e) => `${e.from}->${e.to}:${e.kind}`).sort(), [
    'default.nix->app.nix:call-package',
    'default.nix->lib.nix:import',
    'default.nix->mod.nix:module-import',
  ]);
  assert.deepEqual(graph.files.map((f) => f.file).sort(), ['app.nix', 'default.nix', 'lib.nix', 'mod.nix']);
  assert.deepEqual(graph.unresolved, []);
  const { ir } = analyzeNix(files['default.nix'], { file: 'default.nix' });
  const ext = ir.imports.find((i) => i.external);
  assert.equal(ext.target.literal, 'nixpkgs');
  assert.equal(ext.resolved, null);
});

// ── AC02 ───────────────────────────────────────────────────────────────────

test('[NIX-001.AC02] comments and strings that name options never create assignments', () => {
  const src = lines(
    '{ config, ... }:',
    '{',
    '  # services.openssh.enable = true;',
    '  /* users.users.root.password = "x"; */',
    '  description = "services.openssh.enable = true; networking.firewall.enable = false;";',
    "  note = ''",
    '    users.users.root.initialPassword = "hunter2";',
    "    ${config.secretOption} = 1;",
    "  '';",
    '}',
  );
  const { ir } = analyzeNix(src, { file: 'c.nix' });
  assert.deepEqual(pathTexts(ir), ['description', 'note']);
  for (const p of ['services.openssh.enable', 'users.users.root.password', 'users.users.root.initialPassword', 'networking.firewall.enable']) {
    assert.deepEqual(lookupAttr(ir, p), [], p);
  }
  assert.ok(!kinds(ir).includes('dynamic-attribute'), 'text inside a string is not a dynamic attribute');
});

test('[NIX-001.AC02] a syntax error in one binding is visible partial coverage and spares its siblings', () => {
  const src = lines('{', '  good.a = 1;', '  bad = ;', '  also.good = 2;', '}');
  const { parse, ir } = analyzeNix(src, { file: 'p.nix' });
  assert.equal(parse.status, 'partial');
  assert.equal(parse.errors.length, 1);
  assert.equal(parse.errors[0].kind, 'syntax-error');
  assert.equal(parse.errors[0].span.startLine, 3);
  assert.equal(parse.errors[0].span.startColumn, 8);
  assert.equal(spanText(src, parse.errors[0].span), ';');
  assert.equal(ir.status, 'partial');
  assert.ok(kinds(ir).includes('syntax-error'));
  assert.deepEqual(pathTexts(ir), ['good.a', 'also.good']);
  assert.deepEqual(lookupAttr(ir, 'bad'), []);

  const adapter = createNixAdapter();
  const out = adapter.analyze('p.nix', src);
  assert.ok(out.unresolved.some((u) => u.line === 3 && u.reason.startsWith('syntax-error')));
});

test('[NIX-001.AC02] an unrecoverable syntax error fails closed and is never reported as clean', () => {
  for (const bad of ['{ a = 1; ', '(1','let x = 1; x', 'if true then 1', '"unterminated', "''unterminated", '/* open']) {
    const { parse, ir } = analyzeNix(bad, { file: 'bad.nix' });
    assert.equal(parse.status, 'failed', bad);
    assert.equal(parse.ast, null, bad);
    assert.ok(parse.errors.length >= 1, bad);
    assert.equal(parse.errors[0].kind, 'syntax-error', bad);
    assert.ok(parse.errors[0].span.startLine >= 1, bad);
    assert.equal(ir.status, 'failed', bad);
    assert.ok(kinds(ir).includes('syntax-error'), bad);
    assert.deepEqual(ir.bindings, [], bad);
  }
});

test('[NIX-001.AC02] cyclic, missing and dynamic imports become visible partial coverage', () => {
  const cyc = { 'a.nix': '{ imports = [ ./b.nix ]; }', 'b.nix': '{ imports = [ ./a.nix ]; }' };
  const graph = buildNixImportGraph('a.nix', { readFile: (p) => (p in cyc ? cyc[p] : null) });
  const cycle = graph.unresolved.filter((u) => u.kind === 'import-cycle');
  assert.equal(cycle.length, 1);
  assert.deepEqual(cycle[0].cycle, ['a.nix', 'b.nix', 'a.nix']);
  assert.equal(graph.edges.length, 2);

  const self = buildNixImportGraph('s.nix', { readFile: (p) => (p === 's.nix' ? '{ imports = [ ./s.nix ]; }' : null) });
  assert.equal(self.unresolved.filter((u) => u.kind === 'import-cycle').length, 1);

  const missing = buildNixImportGraph('m.nix', { readFile: (p) => (p === 'm.nix' ? '{ imports = [ ./nope.nix ]; }' : null) });
  assert.ok(missing.unresolved.some((u) => u.kind === 'missing-import'));
  assert.equal(missing.edges.length, 0);

  const src = lines(
    '{ name, ... }:',
    '{',
    '  imports = [ (./mods + "/${name}.nix") ];',
    '  x = import (if name == "a" then ./a.nix else ./b.nix);',
    '  ${name} = 1;',
    '  static = 2;',
    '}',
  );
  const { ir } = analyzeNix(src, { file: 'd.nix' });
  assert.equal(ir.status, 'partial');
  assert.equal(kinds(ir).filter((k) => k === 'dynamic-import').length, 2);
  assert.ok(ir.unresolved.every((u) => u.kind !== 'dynamic-import' || u.span));
  assert.equal(ir.imports.filter((i) => !i.literal).length, 2);
  assert.ok(ir.imports.every((i) => i.resolved === null));
  const dyn = ir.unresolved.find((u) => u.kind === 'dynamic-attribute');
  assert.ok(dyn, 'dynamic attribute names are exposed, not guessed');
  assert.equal(spanText(src, dyn.span), '${name}');
  assert.ok(ir.bindings.some((b) => b.dynamic === true));
  assert.equal(lookupAttr(ir, 'static').length, 1);
});

test('[NIX-001.AC02] lazy recursion is exposed as unresolved instead of evaluated', () => {
  const src = '{ a = rec { x = y; y = x; z = 1; }; b = lib.fix (self: { c = self.d; d = 1; }); }';
  const { ir } = analyzeNix(src, { file: 'r.nix' });
  assert.equal(ir.status, 'partial');
  const lazy = ir.unresolved.filter((u) => u.kind === 'lazy-recursion');
  assert.ok(lazy.some((u) => u.name === 'x'));
  assert.ok(lazy.some((u) => u.name === 'y'));
  assert.ok(lazy.some((u) => u.name === 'fix'));
  assert.ok(!lazy.some((u) => u.name === 'z'), 'a non-cyclic sibling is not reported');
  const letCycle = analyzeNix('let p = q; q = p; in { v = 1; }', { file: 'l.nix' }).ir;
  assert.ok(letCycle.unresolved.some((u) => u.kind === 'lazy-recursion' && u.name === 'p'));
  assert.ok(letCycle.bindings.filter((b) => b.scope === 'let').length === 2);
  assert.deepEqual(lookupAttr(letCycle, 'p'), [], 'let bindings are not option assignments');
});

// ── AC03 ───────────────────────────────────────────────────────────────────

test('[NIX-001.AC03] the grammar loads from the installed package, pinned by checksum, with no nix binary', () => {
  const loaded = loadNixGrammar();
  assert.equal(loaded.available, true);
  assert.equal(loaded.checksum, NIX_GRAMMAR_SHA256);
  assert.equal(nixGrammarChecksum(GRAMMAR_DATA), NIX_GRAMMAR_SHA256);
  const { parse, ir } = analyzeNix('{ a = 1; }', { file: 'x.nix' });
  assert.equal(parse.usedNixBinary, false);
  assert.equal(ir.usedNixBinary, false);
  assert.equal(parse.grammar.sha256, NIX_GRAMMAR_SHA256);
  assert.equal(parse.grammar.name, GRAMMAR_DATA.name);

  // source-level proof: none of the Nix modules can start a process
  for (const f of ['nix-grammar.js', 'nix-parser.js', 'nix-ir.js', 'nix-adapter.js']) {
    const text = fs.readFileSync(path.join(langDir, f), 'utf8');
    assert.ok(!/child_process|\bspawn(Sync)?\s*\(|\bexec(Sync|FileSync)\s*\(|\bexecFile\s*\(|from\s+['"]node:(net|http|https|dns|worker_threads)['"]/.test(text), `${f} must not start processes or touch the network`);
  }

  // behavioural proof: parsing works with no PATH at all
  const saved = process.env.PATH;
  process.env.PATH = '';
  try {
    assert.equal(parseNix('{ a = 1; }').status, 'ok');
  } finally {
    process.env.PATH = saved;
  }
});

test('[NIX-001.AC03] an absent or tampered grammar is a visible gap, never a throw or a clean parse', () => {
  const absent = parseNix('{ a = 1; }', { grammarSource: () => null });
  assert.equal(absent.status, 'missing_grammar');
  assert.equal(absent.ast, null);
  assert.equal(absent.gap.kind, 'missing-grammar');
  const throwing = parseNix('{ a = 1; }', { grammarSource: () => { throw new Error('disk gone'); } });
  assert.equal(throwing.status, 'missing_grammar');
  const tampered = parseNix('{ a = 1; }', { grammarSource: () => ({ ...GRAMMAR_DATA, keywords: [...GRAMMAR_DATA.keywords, 'evil'] }) });
  assert.equal(tampered.status, 'missing_grammar');
  assert.equal(tampered.gap.kind, 'corrupt-grammar');
  const { ir } = analyzeNix('{ a = 1; }', { grammarSource: () => null });
  assert.equal(ir.status, 'missing_grammar');
  assert.ok(kinds(ir).includes('missing-grammar'));
  assert.equal(createNixAdapter({ grammarSource: () => null }).hasGrammar(), false);
  assert.equal(createNixAdapter().hasGrammar(), true);
});

test('[NIX-001.AC03] recursion, token, node, string, size and time budgets stop the parser without throwing', () => {
  const budget = (r) => r.budget && r.budget.name;

  const deepList = parseNix('['.repeat(20_000) + ']'.repeat(20_000));
  assert.equal(deepList.status, 'budget_exceeded');
  assert.equal(budget(deepList), 'maxDepth');
  assert.equal(deepList.ast, null);

  const deepParen = parseNix(`${'('.repeat(20_000)}1${')'.repeat(20_000)}`);
  assert.equal(deepParen.status, 'budget_exceeded');
  assert.equal(budget(deepParen), 'maxDepth');

  const deepSet = parseNix(`${'{ a = '.repeat(5_000)}1;${' }'.repeat(5_000)}`);
  assert.equal(deepSet.status, 'budget_exceeded');

  const deepNeg = parseNix(`${'-'.repeat(20_000)}1`);
  assert.equal(deepNeg.status, 'budget_exceeded');

  const longChain = parseNix(`f ${'a '.repeat(5_000)}`);
  assert.equal(longChain.status, 'budget_exceeded');
  assert.equal(budget(longChain), 'maxAstDepth');

  const huge = parseNix(`{ x = "${'a'.repeat(2_000_000)}"; }`);
  assert.equal(huge.status, 'budget_exceeded');
  assert.equal(budget(huge), 'maxStringBytes');
  const hugeIndented = parseNix(`{ x = ''${'a'.repeat(2_000_000)}''; }`);
  assert.equal(hugeIndented.status, 'budget_exceeded');
  assert.equal(budget(hugeIndented), 'maxStringBytes');

  const big = parseNix('x'.repeat(5 * 1024 * 1024));
  assert.equal(big.status, 'budget_exceeded');
  assert.equal(budget(big), 'maxBytes');
  assert.equal(big.stats.bytes, 5 * 1024 * 1024);

  const nums = `[ ${'1 '.repeat(2_000)}]`;
  assert.equal(budget(parseNix(nums, { budgets: { maxTokens: 50 } })), 'maxTokens');
  assert.equal(budget(parseNix(nums, { budgets: { maxNodes: 10 } })), 'maxNodes');
  assert.equal(budget(parseNix(nums, { budgets: { deadlineMs: -1 } })), 'deadlineMs');
  assert.equal(budget(parseNix('{ a = 1; }'.repeat(1), { budgets: { maxBytes: 4 } })), 'maxBytes');
  assert.equal(parseNix(nums).status, 'ok', 'the same input parses under the default budgets');

  const manyErrors = parseNix(`{ ${'b = ; '.repeat(200)} }`);
  assert.equal(manyErrors.status, 'budget_exceeded');
  assert.equal(budget(manyErrors), 'maxErrors');

  assert.ok(DEFAULT_PARSE_BUDGETS.maxDepth > 0 && Object.isFrozen(DEFAULT_PARSE_BUDGETS));
  // a budget hit is reported upstream, not swallowed
  const ir = analyzeNix(nums, { budgets: { maxTokens: 50 } }).ir;
  assert.equal(ir.status, 'budget_exceeded');
  assert.ok(kinds(ir).includes('budget-exceeded'));
  assert.deepEqual(ir.bindings, []);
});

test('[NIX-001.AC03] a parser deadline surfaces as a timeout through the language adapter', () => {
  const adapter = createNixAdapter({ budgets: { deadlineMs: -1 } });
  assert.throws(() => adapter.analyze('t.nix', `[ ${'1 '.repeat(2_000)}]`), (e) => e.code === 'LANG_TIMEOUT');
});

test('[NIX-001.AC03] IR budgets truncate with a visible gap instead of silently dropping bindings', () => {
  const src = `{ ${Array.from({ length: 10 }, (_, i) => `a${i} = ${i};`).join(' ')} }`;
  const cut = analyzeNix(src, { irBudgets: { maxBindings: 3 } }).ir;
  assert.equal(cut.bindings.length, 3);
  assert.deepEqual(cut.truncated, ['maxBindings']);
  assert.equal(cut.status, 'partial');
  assert.ok(cut.unresolved.some((u) => u.kind === 'ir-budget' && u.detail.includes('maxBindings')));

  const imports = `{ imports = [ ${Array.from({ length: 10 }, (_, i) => `./m${i}.nix`).join(' ')} ]; }`;
  const cutImports = analyzeNix(imports, { file: 'i.nix', irBudgets: { maxImports: 4 } }).ir;
  assert.equal(cutImports.imports.length, 4);
  assert.ok(cutImports.truncated.includes('maxImports'));

  const interps = `{ a = "\${x}\${y}\${z}"; }`;
  const cutInterps = analyzeNix(interps, { irBudgets: { maxInterpolations: 1 } }).ir;
  assert.equal(cutInterps.interpolations.length, 1);
  assert.ok(cutInterps.truncated.includes('maxInterpolations'));

  const wide = analyzeNix('{ a = 1; }', { irBudgets: { maxBindings: 100 } }).ir;
  assert.deepEqual(wide.truncated, []);
  assert.equal(wide.status, 'ok');

  const chain = (n) => ({ readFile: (p) => { const m = /^f(\d+)\.nix$/.exec(p); return m && Number(m[1]) < n ? `{ imports = [ ./f${Number(m[1]) + 1}.nix ]; }` : (m ? '{}' : null); } });
  const g = buildNixImportGraph('f0.nix', { ...chain(1000), budgets: { maxImportDepth: 5 } });
  assert.equal(g.truncated, true);
  assert.ok(g.unresolved.some((u) => u.kind === 'import-depth'));
  const g2 = buildNixImportGraph('f0.nix', { ...chain(1000), budgets: { maxFiles: 3 } });
  assert.equal(g2.truncated, true);
  assert.ok(g2.unresolved.some((u) => u.kind === 'import-budget'));
  assert.ok(g2.files.length <= 3);
});

test('[NIX-001.AC03] malformed and fuzzed input never throws and always yields a bounded, honest result', () => {
  for (const bad of [null, undefined, 42, {}, [], '\u0000{ a = 1; }', '\u0001\u0002\u0003', '￿', '{ a = "\ud800"; }', '${', '}', "''", '"\\']) {
    const { parse, ir } = analyzeNix(bad, { file: 'z.nix' });
    assert.ok(['failed', 'partial', 'ok'].includes(parse.status), String(bad));
    assert.ok(Array.isArray(ir.unresolved), String(bad));
    if (parse.status === 'failed') {
      assert.ok(parse.errors.length >= 1, String(bad));
      assert.notEqual(ir.status, 'ok', String(bad));
    }
  }
  assert.equal(analyzeNix(null).parse.errors[0].kind, 'malformed-input');

  // deterministic token-soup fuzz
  let seed = 0x9e3779b9;
  const rnd = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 4294967296; };
  const toks = ['{', '}', '[', ']', '(', ')', ';', '=', '.', ',', ':', '@', '?', '//', '++', '"', "''", '${', '$', 'let', 'in', 'if', 'then', 'else', 'with', 'rec', 'inherit', 'assert',
    'a', 'b.c', 'x1', '1', '2.5', './p', '<n>', '# c\n', '/* c */', ' ', '\n', '\\', 'import', 'or', '...', '-', '!', '+', '/', '~/h'];
  for (let n = 0; n < 400; n++) {
    let s = '';
    const len = 1 + Math.floor(rnd() * 40);
    for (let k = 0; k < len; k++) s += toks[Math.floor(rnd() * toks.length)] + (rnd() < 0.5 ? ' ' : '');
    const { parse, ir } = analyzeNix(s, { file: 'fuzz.nix' });
    assert.ok(['ok', 'partial', 'failed', 'budget_exceeded'].includes(parse.status), s);
    assert.ok(!parse.errors.some((e) => e.kind === 'internal-error'), `internal error for ${JSON.stringify(s)}`);
    for (const e of parse.errors) {
      if (e.span) assert.ok(e.span.startOffset >= 0 && e.span.endOffset <= s.length && e.span.startOffset <= e.span.endOffset, s);
    }
    if (parse.status === 'ok') assert.deepEqual(parse.errors, [], s);
    assert.ok(ir.bindings.length <= 20_000, s);
  }
});
