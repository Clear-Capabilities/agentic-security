// X-001: Secrets parity and leaked-secret response for Haskell and Nix.
// Suite "language-secrets" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Provider-shaped canaries are assembled at runtime so this file never contains a literal token (push
// protection) and so any appearance of a canary in an output is detectable.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, readdirSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { blankHaskell, blankNix, scanLanguageSecretConcat, scanDependencyUrlCredentials, providerInfo, redactSecret } from '../../src/language/secrets.js';
import { sweepGitHistory, splitDiffByFile } from '../../src/posture/secret-history.js';
import { scanCredentials } from '../../src/secrets/index.js';
import { mkTestTmp } from '../helpers/tmp.js';

const SCANNER = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = join(SCANNER, 'bin', 'agentic-security.js');
const AWS = ['AKIA', 'QWERTYUIOPASDFGH'].join('');                         // 20 chars
const GH = ['ghp_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
const GH2 = ['ghp_', 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2'].join('');
const PW = ['xK9mQ2vL8nR4', 'tY7wZ3pA6sD1fG5hJ0bC'].join('');
const URLPW = ['Tr0ub4dor', 'And3Canary99xyz'].join('');
const nix = (s) => s.replace(/@\{/g, '${');
const detect = (fp, text) => scanLanguageSecretConcat(fp, text);
const lines = (fs) => fs.map((f) => f.line).sort((a, b) => a - b);

const HS = [
  'module S where',                                               // 1
  '{- outer {- nested -} still a comment: k = "AKIA" ++ "' + AWS.slice(4) + '" -}', // 2  (nested comment hides a split secret)
  'live :: String',                                               // 3
  `live = "${GH}"`,                                               // 4  known token
  `split = "AKIA" ++ "${AWS.slice(4)}"`,                          // 5  split with ++
  `split2 = "ghp_" <> "${GH.slice(4)}"`,                          // 6  split with <>
  `-- commented = "AKIA" ++ "${AWS.slice(4)}"`,                   // 7  line comment
  `{- {- x -} also = "AKIA" ++ "${AWS.slice(4)}" -}`,             // 8  inside a nested comment
  `afterNested = "AKIA" ++ "${AWS.slice(4)}"`,                    // 9  after the nested comment closed: live code
  'arrow a b = a --> b',                                          // 10 `-->` is an operator, not a comment
  `viaArrow = "AKIA" ++ "${AWS.slice(4)}" --> 1`,                 // 11 the secret precedes an operator run `-->`
  'safe1 = "your_api_key_here" ++ "_placeholder"',                // 12
  'safe2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEPUBLICKEYXXXXXXXXXXXXXXXXXXXXX"', // 13 public key
  'safe3 = "123e4567-e89b-12d3-a456-426614174000"',               // 14 uuid
  "foo' = 1; bar' = 2",                                           // 15 primes are not string openers
  `afterPrime = "AKIA" ++ "${AWS.slice(4)}"`,                     // 16
].join('\n') + '\n';

const NIX = nix([
  '{ lib, ... }:',                                                // 1
  '{',                                                            // 2
  "  doc = ''",                                                   // 3
  '    # not a comment: inside an indented string',                // 4
  `    split inside = "AKIA" + "${AWS.slice(4)}";`,               // 5  inside the string body: text, not code
  "  '';",                                                        // 6
  `  split = "AKIA" + "${AWS.slice(4)}";`,                        // 7
  `  # hidden = "AKIA" + "${AWS.slice(4)}";`,                     // 8  comment
  `  /* hidden2 = "AKIA" + "${AWS.slice(4)}"; */`,                // 9  block comment
  `  after = "ghp_" + "${GH.slice(4)}";`,                         // 10
  `  indented = ''AKIA'' + ''${AWS.slice(4)}'';`,                 // 11 indented-string concat
  '  safe = "ENC[AES256_GCM,data:Zm9vYmFy,iv:abc,tag:def,type:str]";', // 12 sops ciphertext
  '  pub = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";', // 13 age recipient
  '  tpl = "@{lib.optionalString true "AKIA"}";',                 // 14 interpolation: not a plain literal concat
  '}',
].join('\n') + '\n');

test('[X-001.AC01] Haskell and Nix lexers blank comments but keep strings, offsets and lines exactly', () => {
  const hs = 'a = "x -- y"  -- tail\n{- one {- two -} three -}\nb = c --> d\n{-# LANGUAGE CPP #-}\nq = [expr| -- kept |]\nf\' = \'x\' -- c\n';
  const b = blankHaskell(hs);
  assert.equal(b.length, hs.length); assert.equal(b.split('\n').length, hs.split('\n').length);
  assert.ok(b.includes('"x -- y"'), 'a dash run inside a string is not a comment');
  assert.ok(!b.includes('tail') && !b.includes('two') && !b.includes('three') && !b.includes('LANGUAGE'));
  assert.ok(b.includes('c --> d'), '--> is an operator');
  assert.ok(b.includes('[expr| -- kept |]'), 'quasi-quotes are opaque');
  assert.ok(b.includes("f' = 'x'"));
  const nx = nix("{ a = \"# not\"; # c1\n b = ''\n # in string @{x /* nope */}\n''; /* c2 */ c = ''a''${y}b''; d = ''p'''q''; } # tail\n");
  const n = blankNix(nx);
  assert.equal(n.length, nx.length); assert.equal(n.split('\n').length, nx.split('\n').length);
  assert.ok(n.includes('"# not"') && n.includes('# in string') && !n.includes('c1') && !n.includes('c2') && !n.includes('tail'));
  assert.ok(n.includes("''a''${y}b''") && n.includes("''p'''q''"), "''$ and ''' are escapes inside an indented string, so the string continues");
  assert.equal(blankHaskell(''), ''); assert.equal(blankNix('/* unterminated').trim(), '');
});

test('[X-001.AC01] split secrets are found in Haskell and Nix; comments, nested comments and public values are not', () => {
  const hs = detect('src/S.hs', HS);
  assert.deepEqual(lines(hs), [5, 6, 9, 11, 16], 'only live code: ++ and <>, after a nested comment, before an operator run, after primes');
  for (const f of hs) { assert.equal(f.parser, 'SECRET-CONCAT'); assert.equal(f.cwe, 'CWE-798'); assert.equal(f.language, 'haskell'); assert.ok(f.masked.includes('…')); }
  const nx = detect('modules/c.nix', NIX);
  assert.deepEqual(lines(nx), [7, 10, 11], 'a split in a string body, a comment, a block comment, ciphertext, a public key and an interpolation are not code');
  for (const f of nx) assert.equal(f.language, 'nix');
  assert.equal(detect('a.js', 'x = "AKIA" + "' + AWS.slice(4) + '"').length, 0, 'other languages stay with the generic detector');
});

test('[X-001.AC01] a real scan finds known, entropy and split secrets and keeps the public values out', () => {
  const dir = mkTestTmp('x001-scan-');
  mkdirSync(join(dir, 'src')); mkdirSync(join(dir, 'modules'));
  writeFileSync(join(dir, 'src', 'S.hs'), HS);
  writeFileSync(join(dir, 'modules', 'c.nix'), NIX);
  writeFileSync(join(dir, 'src', 'E.hs'), `module E where\n\nadminPassword :: String\nadminPassword = "${PW}"\n\nbuildHash :: String\nbuildHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n`);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
  const out = JSON.parse(p.stdout);
  const secrets = out.findings.filter((f) => /SECRET/i.test(f.parser) || /secret|credential|token|key|password/i.test(f.vuln || ''));
  const at = (file, line) => secrets.filter((f) => f.file.endsWith(file) && f.line === line);
  assert.ok(at('S.hs', 4).some((f) => f.parser === 'SECRETS'), 'known token');
  assert.ok(at('S.hs', 5).some((f) => f.parser === 'SECRET-CONCAT'), 'split ++');
  assert.ok(at('S.hs', 9).some((f) => f.parser === 'SECRET-CONCAT'), 'live code after a nested comment');
  assert.ok(at('c.nix', 7).some((f) => f.parser === 'SECRET-CONCAT'), 'Nix split');
  assert.ok(at('E.hs', 4).length >= 1, 'entropy / credential-named literal');
  for (const l of [7, 8, 12, 13, 14]) assert.equal(secrets.filter((f) => f.file.endsWith('S.hs') && f.line === l && f.parser === 'SECRET-CONCAT').length, 0, `S.hs:${l}`);
  assert.equal(secrets.filter((f) => f.file.endsWith('E.hs') && f.line === 7).length, 0, 'an integrity hash is not a secret');
  assert.equal(secrets.filter((f) => f.file.endsWith('c.nix') && [12, 13].includes(f.line) && f.parser !== 'NIX-SECRET').length, 0, 'ciphertext and a public key are not secrets');
  const all = JSON.stringify(out);
  assert.ok(!all.includes(AWS) && !all.includes(GH) && !all.includes(PW), 'no finding carries a value');
});

test('[X-001.AC02] git history findings name the committed file, line, commit and provider, and never the value', () => {
  const repo = mkTestTmp('x001-hist-');
  const git = (...a) => execFileSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } });
  git('init', '-q');
  mkdirSync(join(repo, 'src'));
  writeFileSync(join(repo, 'src', 'Main.hs'), `module Main where\n\nmain :: IO ()\nmain = pure ()\n\ntoken :: String\ntoken = "${GH}"\n\nsplit :: String\nsplit = "AKIA" ++ "${AWS.slice(4)}"\n`);
  writeFileSync(join(repo, 'cabal.project'), `packages: .\nsource-repository-package\n  type: git\n  location: https://deploy:${URLPW}@github.com/example/private-lib.git\n  tag: main\n`);
  git('add', '-A'); git('commit', '-q', '-m', 'add');
  writeFileSync(join(repo, 'src', 'Main.hs'), 'module Main where\n\nmain :: IO ()\nmain = pure ()\n');
  git('add', '-A'); git('commit', '-q', '-m', 'remove the literals');
  let calls = 0; const realFetch = globalThis.fetch; globalThis.fetch = () => { calls++; throw new Error('no network'); };
  let hist;
  try { hist = sweepGitHistory(repo, scanCredentials, { maxCommits: 10 }); } finally { globalThis.fetch = realFetch; }
  assert.equal(calls, 0, 'no provider is contacted');
  const gh = hist.find((f) => f.sourceFile === 'src/Main.hs' && f.provider === 'GitHub');
  assert.ok(gh, JSON.stringify(hist.map((f) => [f.sourceFile, f.provider, f.vuln])));
  assert.equal(gh.sourceLine, 7); assert.match(gh.commit, /^[0-9a-f]{12}$/); assert.equal(gh._historical, true);
  assert.equal(gh.file, `git-history@${gh.commit}`);
  assert.equal(gh.rotation.provider, 'GitHub'); assert.equal(gh.rotation.automatic, false); assert.equal(gh.rotation.liveCheck, 'not performed');
  assert.ok(gh.rotation.steps.length >= 2 && /github\.com\/settings\/tokens/.test(gh.rotation.revokeUrl));
  assert.match(gh.description, /src\/Main\.hs:7/);
  const concat = hist.find((f) => f.sourceFile === 'src/Main.hs' && f.parser === 'SECRET-CONCAT');
  assert.ok(concat, 'the Haskell split secret is found in history with its real path'); assert.equal(concat.sourceLine, 10); assert.equal(concat.provider, 'AWS');
  const url = hist.find((f) => f.sourceFile === 'cabal.project');
  assert.ok(url, 'the dependency-URL credential is found in history'); assert.equal(url.sourceLine, 4); assert.equal(url.provider, 'GitHub');
  const dump = JSON.stringify(hist);
  for (const v of [GH, AWS, URLPW, GH.slice(4), AWS.slice(4)]) assert.ok(!dump.includes(v), 'no history finding contains a secret value');
  assert.ok(splitDiffByFile('diff --git a/x.hs b/x.hs\n@@ -0,0 +3,2 @@\n+a\n+b\n').every((s) => s.path === 'x.hs' && s.added[0].line === 3 && s.added[1].line === 4));
  // a provider is derived from the SHAPE only: nothing is checked against the provider
  assert.equal(providerInfo(GH).provider, 'GitHub'); assert.equal(providerInfo(AWS).provider, 'AWS'); assert.equal(providerInfo('plain').provider, undefined);
  assert.equal(providerInfo('x', 'gitlab.com').provider, 'GitLab');
  const src = readFileSync(join(SCANNER, 'src', 'language', 'secrets.js'), 'utf8');
  assert.ok(!/\bfetch\(|from 'node:(?:http|https|net|child_process)'/.test(src), 'the module cannot reach a provider');
});

test('[X-001.AC02] the --secret-history entry point and the response guidance work on a Haskell/Nix repository', () => {
  const repo = mkTestTmp('x001-cli-');
  const git = (...a) => execFileSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' });
  git('init', '-q');
  writeFileSync(join(repo, 'flake.nix'), nix(`{\n  inputs.priv.url = "git+https://ci:${URLPW}@git.example-corp.invalid/priv.git";\n  outputs = { self, priv }: { };\n}\n`));
  writeFileSync(join(repo, 'Keys.hs'), `module Keys where\nk = "${GH2}"\n`);
  git('add', '-A'); git('commit', '-q', '-m', 'init');
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', repo, '--format', 'json', '--secret-history'], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
  assert.match(p.stderr, /\[secret-history\] \d+ secret\(s\) found/);
  assert.ok(!(p.stdout + p.stderr).includes(GH2) && !(p.stdout + p.stderr).includes(URLPW), 'neither stream carries a value');
  const out = JSON.parse(p.stdout);
  const urlF = out.findings.filter((f) => f.parser === 'SECRET-DEPURL' && f.file.endsWith('flake.nix'));
  assert.equal(urlF.length, 1); assert.equal(urlF[0].line, 2);
  const hist = out.findings.filter((f) => f.parser === 'SECRET-DEPURL' && /^git-history@/.test(f.file));
  assert.ok(hist.length >= 1, 'the same credential is also reported from history');
});

test('[X-001.AC03] planted credentials never appear in any output format, in persisted state, or in test logs', () => {
  const dir = mkTestTmp('x001-redact-');
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', 'App.hs'), `module App where\nimport System.Process (callCommand)\ntoken :: String\ntoken = "${GH}"\nsplit = "AKIA" ++ "${AWS.slice(4)}"\npw :: String\npw = "${PW}"\n`);
  writeFileSync(join(dir, 'app.cabal'), `name: app\nversion: 0.1\nlibrary\n  build-depends: base\n`);
  writeFileSync(join(dir, 'cabal.project'), `packages: .\nsource-repository-package\n  type: git\n  location: https://deploy:${URLPW}@github.com/example/private-lib.git\n  tag: main\n`);
  writeFileSync(join(dir, 'configuration.nix'), nix(`{ config, pkgs, ... }:\n{\n  systemd.services.ci.script = ''\n    curl -H "Authorization: Bearer ${GH2}" https://api.example.invalid/x\n  '';\n  users.users.u.password = "${PW}";\n  nix.settings.substituters = [ "https://cache:${URLPW}@cache.example-corp.invalid" ];\n  tool = pkgs.fetchurl { url = "https://u:${URLPW}@h.example-corp.invalid/x.tgz"; };\n}\n`));
  writeFileSync(join(dir, 'flake.nix'), nix(`{\n  inputs.priv.url = "git+https://ci:${URLPW}@git.example-corp.invalid/priv.git";\n  outputs = { self, priv }: { };\n}\n`));
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const streams = {};
  for (const fmt of ['json', 'sarif', 'md', 'html', 'csv', 'junit', 'stix', 'cli', 'cyclonedx', 'spdx', 'oscal']) {
    const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', fmt], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
    streams[fmt] = `${p.stdout}\n${p.stderr}`;
    assert.ok(streams[fmt].length > 20, fmt);
  }
  const walk = (p, acc = []) => { for (const e of readdirSync(p, { withFileTypes: true })) { const q = join(p, e.name); if (e.isDirectory()) walk(q, acc); else acc.push(q); } return acc; };
  const state = walk(join(dir, '.agentic-security')).map((f) => { try { return readFileSync(f, 'utf8'); } catch { return ''; } }).join('\n');
  const everything = `${Object.values(streams).join('\n')}\n${state}`;
  for (const [name, v] of [['github token', GH], ['aws key', AWS], ['password', PW], ['url password', URLPW], ['generated-script token', GH2], ['aws tail', AWS.slice(4)], ['github tail', GH.slice(4)]]) {
    assert.ok(!everything.includes(v), `${name} appears unredacted in an output or persisted state`);
  }
  const json = JSON.parse(streams.json.slice(0, streams.json.lastIndexOf('}') + 1).slice(streams.json.indexOf('{')));
  assert.ok(json.findings.some((f) => f.parser === 'SECRET-DEPURL' && f.file.endsWith('cabal.project')), 'the dependency URL credential is reported (masked)');
  assert.ok(json.findings.some((f) => f.parser === 'SECRET-DEPURL' && f.file.endsWith('configuration.nix')));
  assert.equal(redactSecret(GH).includes('…'), true);
  const nixFinding = json.findings.find((f) => /NIX-SECRET/.test(f.parser) && f.file.endsWith('configuration.nix'));
  assert.ok(nixFinding, 'the generated-script and password findings exist, redacted');
});

test('[X-001.AC03] dependency-URL credentials: placeholders, hosts for documentation and a bare user are not credentials', () => {
  const f = (fp, text) => scanDependencyUrlCredentials(fp, text);
  assert.equal(f('cabal.project', `location: https://u:${URLPW}@github.com/a/b.git\n`).length, 1);
  assert.equal(f('stack.yaml', `- git: https://${GH}@github.com/a/b.git\n`).length, 1, 'a token used as the user part');
  assert.equal(f('cabal.project', 'location: https://git@github.com/a/b.git\n').length, 0, 'a bare ssh-style user');
  assert.equal(f('cabal.project', 'location: https://user:${TOKEN}@github.com/a/b.git\n').length, 0, 'a variable reference');
  assert.equal(f('cabal.project', 'location: https://user:changeme@github.com/a/b.git\n').length, 0, 'a placeholder');
  assert.equal(f('cabal.project', `location: https://u:${URLPW}@localhost:8080/a\n`).length, 0, 'localhost');
  assert.equal(f('cabal.project', `-- location: https://u:${URLPW}@github.com/a/b.git\n`).length, 1, 'a commented line is still a leak in a manifest (it is in the repository)');
  assert.equal(f('src/App.hs', `x = "https://u:${URLPW}@github.com/a"`).length, 0, 'only manifests, locks and Nix are URL-credential scanned here');
  assert.equal(f('flake.nix', nix(`# note\n{ inputs.a.url = "git+https://u:${URLPW}@h.example-corp.invalid/r"; }`)).length, 1);
  assert.equal(f('flake.nix', nix(`/* inputs.a.url = "git+https://u:${URLPW}@h.example-corp.invalid/r"; */ {}`)).length, 1, 'a Nix comment is still repository content: the same policy as every other language');
});

test('[X-001.AC03] the bodyguard recognises Haskell and Nix credential assignments before they are written', () => {
  const hook = join(SCANNER, '..', 'hooks', 'pre-edit-bodyguard.js');
  const dir = mkTestTmp('x001-bg-');
  mkdirSync(join(dir, '.agentic-security'));
  writeFileSync(join(dir, 'package.json'), '{"name":"x"}');
  writeFileSync(join(dir, '.agentic-security', 'bodyguard.json'), JSON.stringify({ mode: 'block' }));
  const run = (file, content) => spawnSync(process.execPath, [hook], { input: JSON.stringify({ tool_name: 'Write', tool_input: { file_path: join(dir, file), content } }), encoding: 'utf8', env: { ...process.env, CLAUDE_PROJECT_DIR: dir } });
  assert.equal(run('App.hs', `apiKey = "${GH}"\n`).status, 2, 'Haskell record/binding');
  assert.equal(run('App.hs', `config = Config { token = T.pack "${GH}" }\n`).status, 2, 'Haskell record field applied through T.pack');
  assert.equal(run('c.nix', `{ services.x.token = "${GH}"; }\n`).status, 2, 'Nix attribute');
  assert.equal(run('c.nix', '{ services.x.tokenFile = "/run/secrets/x"; }\n').status, 0, 'a runtime file reference is fine');
  assert.equal(run('App.hs', 'apiKey = "your_api_key_here"\n').status, 0);
  assert.ok(!run('App.hs', `apiKey = "${GH}"\n`).stderr.includes(GH), 'the hook does not echo the value');
});
