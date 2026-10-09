// NIX-006: Nix secret placement and configuration lineage.
// Suite "nix-secrets-store" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Real .nix fixtures under test/fixtures/nix-secrets/. The planted credentials all contain the marker
// "CANARY" so any appearance in an output is detectable; the labels live here, never in the fixtures.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, cpSync, existsSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeNixSecrets, plausibleSecret, SECRET_RULES } from '../../src/language/nix-secrets.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, '..', '..');
const FIX = join(HERE, '..', 'fixtures', 'nix-secrets');
const BIN = join(SCANNER, 'bin', 'agentic-security.js');
const load = (d) => Object.fromEntries(readdirSync(join(FIX, d)).filter((f) => !f.startsWith('.') && statSync(join(FIX, d, f)).isFile()).map((f) => [f, readFileSync(join(FIX, d, f), 'utf8')]));
const run = (d) => analyzeNixSecrets({ files: load(d) });
const lineOf = (files, f) => files[f.file].split('\n')[f.line - 1];
const rulesAt = (r, files, re) => r.findings.filter((f) => re.test(lineOf(files, f))).map((f) => f.rule).sort();

test('[NIX-006.AC01] plaintext credentials in Nix source are found, and placeholders, paths and references are not', () => {
  const files = load('plaintext');
  const r = run('plaintext');
  const at = (re) => rulesAt(r, files, re);
  assert.deepEqual(at(/users\.users|password = "CANARY-alice/), ['nix-secret-plaintext']);
  assert.deepEqual(at(/apiToken =/), ['nix-secret-plaintext']);
  assert.deepEqual(at(/psk =/), ['nix-secret-plaintext']);
  assert.deepEqual(at(/ghp_/), ['nix-secret-plaintext']);
  assert.deepEqual(at(/PRIVATE KEY/), ['nix-secret-plaintext']);
  assert.deepEqual(at(/passwordFile|credentialsFile/), [], 'a runtime file reference is safe');
  assert.deepEqual(at(/changeme|secret = ""|stateDir|port/), [], 'placeholders, empty values and non-secrets are not credentials');
  assert.equal(r.findings.length, 5);
  const known = r.findings.filter((f) => f.evidence.format);
  assert.deepEqual(known.map((f) => f.severity).sort(), ['critical', 'critical']);
  assert.ok(r.safe.some((s) => /passwordFile/.test(s.attr)), 'the safe reference is recorded as safe, with its reason');
});

test('[NIX-006.AC01] secret-to-store, build and log exposures are distinct and evidenced', () => {
  const files = load('store');
  const r = run('store');
  const by = (rule) => r.findings.filter((f) => f.rule === rule);
  const dests = (rule) => by(rule).map((f) => f.destination.label);
  assert.deepEqual(dests('nix-secret-store').sort(), [
    '/etc file built from the store', 'Home Manager file', 'generated script systemd.services.myapp.script (a store file)',
    'store file written by writeText', 'systemd unit file', 'systemd unit file',
  ].sort());
  assert.equal(by('nix-secret-build').length, 1);
  assert.match(by('nix-secret-build')[0].destination.label, /derivation mkDerivation attribute API_KEY/);
  assert.deepEqual(by('nix-secret-log').map((f) => f.destination.kind), ['log', 'log']);
  assert.ok(by('nix-secret-log').some((f) => /echo/.test(f.description)), 'a script that echoes the secret');
  assert.ok(by('nix-secret-log').some((f) => /trace/.test(f.destination.label)), 'an evaluation trace');
  for (const f of r.findings) {
    assert.ok(f.source && f.destination && f.exposure, 'source, destination and exposure on every finding');
    assert.ok(f.chain.length >= 1);
    assert.equal(f.secretValue, 'redacted');
    assert.ok(['store', 'build', 'log'].includes(f.exposure));
    assert.equal(f.cwe, SECRET_RULES[f.rule].cwe);
  }
  // one exposure per value location (build wins over the generic store view), never the same site twice
  const sites = r.findings.filter((f) => f.rule !== 'nix-secret-log').map((f) => `${f.file}:${f.line}:${f.column}`);
  assert.equal(new Set(sites).size, sites.length);
  assert.ok(!r.findings.some((f) => /LOG_LEVEL|VERSION/.test(lineOf(files, f))), 'non-secret environment values are not reported');
});

test('[NIX-006.AC01] runtime references and encrypted files are safe for the boundary they model', () => {
  const r = run('safe-refs');
  assert.deepEqual(r.findings, []);
  const reasons = new Set(r.safe.map((s) => s.reason));
  assert.deepEqual([...reasons], ['runtime secret reference']);
  assert.ok(r.safe.length >= 5);
});

test('[NIX-006.AC02] reading a runtime secret during evaluation is a decrypt-and-copy and still fires', () => {
  const files = load('decrypt-copy');
  const r = run('decrypt-copy');
  assert.equal(r.findings.length, 4);
  assert.ok(r.findings.every((f) => f.rule === 'nix-secret-decrypt-copy' && f.severity === 'high'));
  const at = (re) => r.findings.filter((f) => re.test(lineOf(files, f))).length;
  assert.equal(at(/etc."token"/), 1, 'sops path read into /etc text');
  assert.equal(at(/writeText/), 1, '/run/secrets path read into writeText');
  assert.equal(at(/age\.secrets/), 1, 'agenix path read into a unit environment');
  assert.equal(at(/fileContents/), 1, 'lib.fileContents of a sops path into an option');
  assert.equal(at(/public-notes/), 0, 'reading an ordinary repository file is not a secret copy');
  assert.ok(r.findings.every((f) => f.origins.some((o) => /decrypted secret copied/.test(o.detail))));
});

test('[NIX-006.AC02] naming a manager does not sanitise: plaintext files and manager-looking values are judged by content', () => {
  const files = load('bad-sops');
  const r = run('bad-sops');
  assert.deepEqual(r.findings.map((f) => f.rule), ['nix-secret-plaintext-file']);
  assert.match(r.findings[0].description, /no sops\/age encryption markers/);
  assert.ok(!/CANARY/.test(JSON.stringify(r)), 'the plaintext file content is never copied into the finding');
  // the same option pointing at an encrypted file is clean
  const enc = analyzeNixSecrets({ files: { 'configuration.nix': files['configuration.nix'], 'plain.yaml': readFileSync(join(FIX, 'safe-refs', 'secrets.yaml'), 'utf8') } });
  assert.deepEqual(enc.findings, []);
  // a runtime-looking option used as a LITERAL credential is still a credential
  const lit = analyzeNixSecrets({ files: { 'a.nix': '{ config, ... }: { sops.secrets.x.owner = "bob"; services.a.password = "CANARY-real-literal-12ab"; }\n' } });
  assert.deepEqual(lit.findings.map((f) => f.rule), ['nix-secret-plaintext']);
  assert.ok(plausibleSecret('hunter2-xyz') && !plausibleSecret('changeme') && !plausibleSecret('/run/secrets/x') && !plausibleSecret('${cfg.pw}'));
});

test('[NIX-006.AC03] secret values never appear in findings, and source/destination/policy evidence survives', () => {
  for (const d of ['plaintext', 'store', 'decrypt-copy', 'bad-sops']) {
    const r = run(d);
    const text = JSON.stringify(r);
    assert.ok(!/CANARY-[a-z0-9-]+/.test(text), `${d}: a planted value leaked into the analysis result`);
    assert.ok(!/ghp_CANARY|BEGIN OPENSSH/.test(text), `${d}: a token or key body leaked`);
    for (const f of r.findings) {
      assert.ok(f.file && f.line && f.destination && f.source, 'location, source and destination preserved');
      assert.equal(f.evidence.redacted, true);
      if (f.rule === 'nix-secret-plaintext') assert.ok(Number.isInteger(f.evidence.length), 'only the length of a literal is kept');
    }
  }
});

test('[NIX-006.AC03] CLI outputs and persisted state redact the planted credentials', () => {
  const dir = mkTestTmp('nix-secret-cli-');
  for (const d of ['plaintext', 'store']) { mkdirSync(join(dir, d)); cpSync(join(FIX, d, 'configuration.nix'), join(dir, d, 'configuration.nix')); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const out = {};
  for (const fmt of ['json', 'sarif']) {
    const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', fmt], { encoding: 'utf8', env, timeout: 180000, maxBuffer: 64 << 20 });
    out[fmt] = p.stdout + p.stderr;
    if (fmt === 'json') out.parsed = JSON.parse(p.stdout);
  }
  const json = out.parsed;
  const nixSecret = json.findings.filter((f) => f.parser === 'NIX-SECRET');
  assert.ok(nixSecret.length >= 10, `NIX-SECRET findings reached the scan output: ${nixSecret.length}`);
  assert.ok(nixSecret.every((f) => f.exposure && f.destination), 'the normalized output keeps exposure and destination');
  const walk = (p, acc = []) => { for (const e of readdirSync(p, { withFileTypes: true })) { const q = join(p, e.name); if (e.isDirectory()) walk(q, acc); else acc.push(q); } return acc; };
  const state = (existsSync(join(dir, '.agentic-security')) ? walk(join(dir, '.agentic-security')) : []).map((f) => { try { return readFileSync(f, 'utf8'); } catch { return ''; } }).join('\n');
  const everything = `${out.json}\n${out.sarif}\n${state}`;
  for (const canary of ['CANARY-alice-pw-7f3a91', 'CANARY-api-token-b21c44', 'CANARY-wifi-psk-55aa10', 'ghp_CANARYabcdefghijklmnopqrstuvwxyz0123456789']) {
    assert.ok(!everything.includes(canary), `${canary} appears unredacted in an output or in persisted state`);
  }
});

test('[NIX-006.AC04] the analysis decrypts nothing, reads no host file and spawns nothing', () => {
  // Static: the modules that do the analysis import neither a process spawner nor a filesystem reader.
  for (const f of ['nix-secrets.js', 'nix-script-taint.js']) {
    const src = readFileSync(join(SCANNER, 'src', 'language', f), 'utf8');
    assert.ok(!/from 'node:(?:fs|child_process|net|http|https|dgram|worker_threads|os)'|require\(/.test(src), `${f} must not import fs/child_process/network`);
  }
  // Dynamic: run it under Node's permission model with read access to the sources ONLY and no child processes.
  const script = [
    "import { analyzeNixSecrets } from './src/language/nix-secrets.js';",
    "const files = { 'a.nix': '{ config, pkgs, ... }: {\\n  environment.etc.\"x\".text = builtins.readFile /run/secrets/token;\\n  a = builtins.readFile /etc/shadow;\\n  b = builtins.readFile /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-secret/key;\\n  c = builtins.readFile config.sops.secrets.t.path;\\n  d = builtins.fetchurl \"https://example.invalid/s\";\\n}\\n' };",
    'const r = analyzeNixSecrets({ files });',
    'console.log(JSON.stringify({ n: r.findings.length, rules: [...new Set(r.findings.map((f) => f.rule))] }));',
  ].join('\n');
  const wrapper = script.replace(/'\.\/src\/language\/nix-secrets\.js'/, JSON.stringify(`file://${join(SCANNER, 'src', 'language', 'nix-secrets.js')}`));
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, ['--permission', `--allow-fs-read=${SCANNER}`, '--input-type=module', '-e', wrapper], { encoding: 'utf8', env, timeout: 60000, cwd: SCANNER });
  assert.equal(p.status, 0, `${p.stdout}\n${p.stderr}`);
  const res = JSON.parse(p.stdout.trim());
  assert.ok(res.n >= 1 && res.rules.includes('nix-secret-decrypt-copy'));
  // and the permission model really would have stopped a read or a spawn
  const deny = spawnSync(process.execPath, ['--permission', `--allow-fs-read=${SCANNER}`, '-e', "try { require('fs').readFileSync('/etc/hosts'); console.log('READ') } catch (e) { console.log(e.code) }; try { require('child_process').spawnSync('true'); console.log('SPAWN') } catch (e) { console.log(e.code) }"], { encoding: 'utf8', env });
  assert.deepEqual(deny.stdout.trim().split('\n'), ['ERR_ACCESS_DENIED', 'ERR_ACCESS_DENIED']);
  assert.ok(!existsSync('/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-secret'));
});
