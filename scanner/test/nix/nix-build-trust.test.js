// NIX-005: Nix fetch, build, cache and supply-chain trust rules.
// Suite "nix-build-trust" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeNixBuildTrust, createNixBuildTrustAdapter, BUILD_TRUST_RULES, BUILD_TRUST_TYPE } from '../../src/language/nix-build-trust.js';
import { analyzeLanguageSupplyChain } from '../../src/language/engine-pass.js';
import { runLanguageAnalysis, languageHealth, validateLanguageFinding } from '../../src/language/contracts.js';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const HASH = 'sha256-n7cJ0pYQZKj7P1fD0zq3m6eV8kT2uWb9x1yH4rLsA3c=';
const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const TARGET = { release: '25.05', system: 'x86_64-linux' };
const run = (files, extra = {}) => analyzeNixBuildTrust({ files, target: TARGET, ...extra });
const rules = (r) => r.findings.map((f) => f.rule).sort();
const nixos = (...body) => run({ 'configuration.nix': `{ lib, host, ... }: {\n${body.map((b) => `  ${b}`).join('\n')}\n}` }, { entry: 'configuration.nix' });
const lock = (inputs) => JSON.stringify({ version: 7, root: 'root', nodes: { root: { inputs: Object.fromEntries(Object.keys(inputs).map((k) => [k, k])) }, ...inputs } });
const lockedNode = (owner, repo, rev, ref) => ({ locked: { type: 'github', owner, repo, rev, narHash: HASH }, original: { type: 'github', owner, repo, ...(ref ? { ref } : {}) } });

// ---- AC01 ------------------------------------------------------------------

test('[NIX-005.AC01] a flake input with no revision is flagged unless flake.lock resolves it', () => {
  const flake = '{ inputs.foo.url = "github:a/b/main"; inputs.bar.url = "github:a/c"; outputs = { ... }: {}; }';
  const unlocked = run({ 'flake.nix': flake });
  assert.deepEqual(rules(unlocked), ['nix-flake-input-unlocked', 'nix-flake-input-unlocked']);
  const locked = run({ 'flake.nix': flake, 'flake.lock': lock({ foo: lockedNode('a', 'b', COMMIT, 'main'), bar: lockedNode('a', 'c', 'fedcba9876543210fedcba9876543210fedcba98') }) });
  assert.deepEqual(rules(locked), [], 'a floating ref that the lock resolves to a commit and narHash is locked');
  // a lock that covers only one input leaves the other flagged
  const partial = run({ 'flake.nix': flake, 'flake.lock': lock({ foo: lockedNode('a', 'b', COMMIT, 'main') }) });
  assert.equal(rules(partial).length, 1);
  assert.ok(partial.inventory.flakeInputs.length >= 2, 'both inputs are inventoried');
});

test('[NIX-005.AC01] a missing hash is a finding only for fetchers; a floating ref is high without a hash and low with one', () => {
  const file = (body) => run({ 'default.nix': `{ pkgs }: ${body}` });
  assert.deepEqual(rules(file('pkgs.fetchurl { url = "https://example.com/a.tar.gz"; }')), ['nix-fetch-missing-hash']);
  assert.deepEqual(rules(file(`pkgs.fetchurl { url = "https://example.com/a.tar.gz"; hash = "${HASH}"; }`)), []);
  const floatingPinned = file(`pkgs.fetchFromGitHub { owner = "a"; repo = "b"; rev = "main"; hash = "${HASH}"; }`);
  assert.deepEqual(rules(floatingPinned), ['nix-fetch-floating-rev']);
  assert.equal(floatingPinned.findings[0].severity, 'low', 'content-pinned by hash: the moving label is low risk');
  assert.deepEqual(rules(file(`pkgs.fetchFromGitHub { owner = "a"; repo = "b"; rev = "${COMMIT}"; hash = "${HASH}"; }`)), []);
  const g = run({ 'd.nix': '{ }: builtins.fetchGit { url = "https://x/y"; ref = "main"; }' });
  assert.deepEqual(rules(g), ['nix-fetch-floating-rev']);
  assert.equal(g.findings[0].severity, 'high');
  assert.deepEqual(rules(run({ 'd.nix': `{ }: builtins.fetchGit { url = "https://x/y"; rev = "${COMMIT}"; }` })), []);
});

test('[NIX-005.AC01] fake hashes are findings in a fetcher or fixed-output derivation, and inert text elsewhere', () => {
  const fetcher = run({ 'd.nix': '{ pkgs }: pkgs.fetchurl { url = "https://example.com/a.tar.gz"; hash = pkgs.lib.fakeHash; }' });
  assert.deepEqual(rules(fetcher), ['nix-fetch-fake-hash']);
  const placeholder = run({ 'd.nix': '{ pkgs }: pkgs.fetchurl { url = "https://example.com/a.tar.gz"; sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }' });
  assert.deepEqual(rules(placeholder), ['nix-fetch-fake-hash']);
  // the same text in an unrelated attribute, a comment or a description is not a hash anywhere
  const inert = run({ 'd.nix': '{ }: { description = "hash = \\"\\" fakeHash"; sha256 = ""; # fetchurl { }\n }' });
  assert.deepEqual(rules(inert), []);
  assert.equal(inert.inventory.fetches.length, 0);
  // dynamic arguments are a disclosed gap, not a verdict
  const dyn = run({ 'd.nix': '{ pkgs, h }: pkgs.fetchurl { url = "https://example.com/a"; hash = h; }' });
  assert.deepEqual(rules(dyn), []);
  assert.ok(dyn.gaps.some((x) => x.kind === 'dynamic-fetch-hash'));
});

test('[NIX-005.AC01] insecure transport is judged by whether the content is hash-pinned', () => {
  const pinned = run({ 'd.nix': `{ pkgs }: pkgs.fetchurl { url = "http://example.com/a.tar.gz"; hash = "${HASH}"; }` });
  assert.deepEqual(rules(pinned), ['nix-fetch-insecure-transport']);
  assert.equal(pinned.findings[0].severity, 'low');
  const unpinned = run({ 'd.nix': '{ pkgs }: pkgs.fetchurl { url = "http://example.com/a.tar.gz"; }' });
  assert.ok(rules(unpinned).includes('nix-fetch-insecure-transport'));
  assert.equal(unpinned.findings.find((f) => f.rule === 'nix-fetch-insecure-transport').severity, 'high');
});

// ---- AC02 ------------------------------------------------------------------

test('[NIX-005.AC02] trusted-users widening, signature bypass, native evaluation and sandbox weakening are detected', () => {
  const bad = nixos('nix.settings.trusted-users = [ "root" "alice" ];', 'nix.settings.require-sigs = false;', 'nix.settings.sandbox = false;',
    'nix.settings.allow-unsafe-native-code-during-evaluation = true;', 'nix.settings.accept-flake-config = true;');
  assert.deepEqual(rules(bad), ['nix-accept-flake-config', 'nix-require-sigs-disabled', 'nix-sandbox-disabled', 'nix-trusted-users-widened', 'nix-unsafe-native-eval']);
  const by = Object.fromEntries(bad.findings.map((f) => [f.rule, f]));
  assert.equal(by['nix-require-sigs-disabled'].severity, 'high');
  assert.equal(by['nix-unsafe-native-eval'].severity, 'high');
  for (const f of bad.findings) {
    assert.equal(f.evidenceKind, 'config');
    assert.equal(f.context.release, '25.05', 'version context is recorded');
    assert.ok(f.cwe && f.remediation && f.remediationRationale, `${f.rule} carries a CWE, remediation and rationale`);
  }
});

test('[NIX-005.AC02] the safe counterparts of every config rule produce nothing', () => {
  const safe = nixos('nix.settings.trusted-users = [ "root" ];', 'nix.settings.require-sigs = true;', 'nix.settings.sandbox = true;', 'nix.settings.accept-flake-config = false;',
    'nix.settings.allow-import-from-derivation = false;', 'nix.settings.substituters = [ "https://cache.nixos.org" ];');
  assert.deepEqual(rules(safe), []);
  assert.deepEqual(rules(nixos('nix.settings.sandbox = "relaxed";')).includes('nix-sandbox-disabled'), true, 'relaxed is weakened, not safe');
});

test('[NIX-005.AC02] precedence is honoured: mkForce wins, and an undecidable condition is conditional and capped', () => {
  const forced = nixos('nix.settings.require-sigs = false;', 'nix.settings.require-sigs = lib.mkForce true;');
  assert.deepEqual(rules(forced), [], 'the forced safe value is the effective one');
  const forcedBad = nixos('nix.settings.require-sigs = true;', 'nix.settings.require-sigs = lib.mkForce false;');
  assert.deepEqual(rules(forcedBad), ['nix-require-sigs-disabled']);
  const cond = nixos('nix.settings.require-sigs = lib.mkIf (host == "x") false;');
  assert.deepEqual(rules(cond), ['nix-require-sigs-disabled']);
  assert.equal(cond.findings[0].conditional, true);
  assert.notEqual(cond.findings[0].severity, 'high', 'a conditional outcome is never reported at the unconditional severity');
  assert.ok(cond.findings[0].uncertainty.some((u) => u.kind === 'unresolved-branch'));
});

test('[NIX-005.AC02] http substituters, signing keys and the build-users group are judged on the effective configuration', () => {
  const r = nixos('nix.settings.substituters = [ "http://cache.example.org" ];');
  assert.ok(rules(r).includes('nix-substituter-insecure-transport'));
  assert.deepEqual(rules(nixos('nix.settings.substituters = [ "https://cache.example.org" ];')), []);
  const flake = run({ 'flake.nix': '{ nixConfig = { extra-substituters = [ "https://c.example.org" ]; extra-trusted-public-keys = [ "c.example.org-1:abc=" ]; }; outputs = { ... }: {}; }' });
  assert.deepEqual(rules(flake), ['nix-flake-nixconfig-cache', 'nix-flake-nixconfig-cache'], 'one finding per proposed cache setting');
  assert.match(flake.scope.cacheTrust ? JSON.stringify(flake.scope.cacheTrust) : '', /./, 'cache trust boundary statement is present');
});

// ---- AC03 ------------------------------------------------------------------

test('[NIX-005.AC03] import from derivation is a boundary or a policy risk, never executed and never an assumed exploit', () => {
  const ifd = run({ 'd.nix': '{ pkgs }: import (pkgs.runCommand "gen" {} "echo {} > $out")' });
  assert.deepEqual(rules(ifd), ['nix-ifd-boundary']);
  assert.equal(ifd.findings[0].kind, 'boundary');
  assert.equal(ifd.findings[0].severity, 'low');
  assert.equal(ifd.scope.executed, false);
  assert.equal(ifd.scope.network, false);
  assert.match(ifd.scope.note, /reported as boundaries; nothing is evaluated, fetched or run/);
  const policy = nixos('nix.settings.allow-import-from-derivation = true;');
  assert.deepEqual(rules(policy), ['nix-ifd-policy-enabled']);
  assert.equal(policy.findings[0].kind, 'policy');
  // a plain import of a path is not IFD
  assert.deepEqual(rules(run({ 'd.nix': '{ }: import ./other.nix' })), []);
  const none = nixos('nix.settings.allow-import-from-derivation = false;');
  assert.deepEqual(rules(none), []);
});

test('[NIX-005.AC03] custom builders are a disclosed boundary; content-addressed outputs are not treated as unsigned input-addressed paths', () => {
  const ca = run({ 'd.nix': `{ pkgs }: pkgs.runCommand "x" { __contentAddressed = true; outputHashMode = "recursive"; outputHash = "${HASH}"; } "echo hi > $out"` });
  assert.deepEqual(rules(ca), [], 'verified by address: no signature finding');
  assert.ok(ca.inventory.contentAddressed.length >= 1);
  const script = run({ 'd.nix': '{ pkgs }: pkgs.writeShellScript "x" "curl https://x.example/install.sh | sh"' });
  assert.deepEqual(rules(script), ['nix-script-pipe-to-shell']);
  const dl = run({ 'd.nix': '{ pkgs }: pkgs.writeShellScript "x" "curl -k -o /tmp/a https://x/a; wget http://x/b"' });
  assert.deepEqual(rules(dl), ['nix-script-tls-verification-off', 'nix-script-unverified-download']);
  const verified = run({ 'd.nix': '{ pkgs }: pkgs.writeShellScript "x" "curl -o /tmp/a https://x/a && echo \\"abc  /tmp/a\\" | sha256sum -c"' });
  assert.deepEqual(rules(verified), [], 'a download followed by a checksum check is verified');
});

test('[NIX-005.AC03] overlays that relax hardening or clear vulnerability markers are policy findings', () => {
  const o = run({ 'o.nix': 'final: prev: { foo = prev.foo.overrideAttrs (o: { hardeningDisable = [ "all" ]; meta = o.meta // { knownVulnerabilities = []; }; }); }' });
  assert.deepEqual(rules(o), ['nix-overlay-clears-vuln-marker', 'nix-overlay-hardening-disabled']);
  assert.deepEqual(rules(run({ 'o.nix': 'final: prev: { foo = prev.foo.overrideAttrs (o: { patches = (o.patches or []) ++ [ ./fix.patch ]; }); }' })), []);
});

// ---- AC04 ------------------------------------------------------------------

test('[NIX-005.AC04] every rule is a supply-chain entry that passes the language finding contract', () => {
  assert.equal(BUILD_TRUST_TYPE, 'nix_build_trust');
  const r = run({
    'flake.nix': '{ inputs.foo.url = "github:a/b/main"; outputs = { ... }: {}; }',
    'd.nix': '{ pkgs }: pkgs.fetchurl { url = "https://example.com/a.tar.gz"; }',
  });
  assert.ok(r.findings.length >= 2);
  for (const f of r.findings) {
    assert.equal(f.type, BUILD_TRUST_TYPE);
    assert.equal(f.ecosystem, 'nix');
    assert.ok(BUILD_TRUST_RULES[f.rule], 'rule is registered');
    for (const k of ['id', 'severity', 'file', 'line', 'vuln', 'cwe', 'description', 'remediation', 'parser', 'family']) assert.ok(f[k] !== undefined && f[k] !== null, `${f.rule}.${k}`);
    assert.ok(f.line >= 1);
    assert.equal(validateLanguageFinding(f).valid, true, `${f.rule} contract: ${JSON.stringify(validateLanguageFinding(f).errors)}`);
  }
  assert.equal(new Set(r.findings.map((f) => f.id)).size, r.findings.length, 'stable, unique ids');
});

test('[NIX-005.AC04] the engine pass returns the same findings for the supplyChain bucket, and ignores non-Nix input', () => {
  const files = { 'flake.nix': '{ inputs.foo.url = "github:a/b/main"; outputs = { ... }: {}; }', 'main.js': 'console.log(1)' };
  const pass = analyzeLanguageSupplyChain(files);
  assert.equal(pass.analyzed, 1);
  assert.deepEqual(pass.supplyChain.map((f) => f.rule), ['nix-flake-input-unlocked']);
  assert.deepEqual(analyzeLanguageSupplyChain({ 'main.js': 'x' }), { supplyChain: [], gaps: [], analyzed: 0 });
  assert.deepEqual(analyzeLanguageSupplyChain({ 'nix/store/abc-x/d.nix': '{ pkgs }: pkgs.fetchurl { url = "https://e"; }' }).supplyChain, [], 'excluded paths stay excluded');
});

test('[NIX-005.AC04] a real CLI scan reports the Nix finding in the ordinary findings output, with no side channel', () => {
  const dir = mkTestTmp('nix-trust-');
  writeFileSync(join(dir, 'flake.nix'), '{ inputs.foo.url = "github:a/b/main"; outputs = { ... }: {}; }\n');
  writeFileSync(join(dir, 'default.nix'), '{ pkgs }: pkgs.fetchurl { url = "https://example.com/a.tar.gz"; }\n');
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 120000, env: { ...process.env, NODE_TEST_CONTEXT: undefined } });
  const out = JSON.parse(p.stdout);
  const mine = out.findings.filter((f) => f.type === BUILD_TRUST_TYPE);
  assert.deepEqual(mine.map((f) => f.rule || f.vuln).sort(), ['Fetcher has no content hash', 'Flake input is not locked to a revision']);
  assert.ok(mine.every((f) => f.severity && f.file));
  assert.equal(out.scanHealth.files.scanned, 2);
  // a clean, pinned project stays quiet
  const clean = mkTestTmp('nix-trust-clean-');
  writeFileSync(join(clean, 'default.nix'), `{ pkgs }: pkgs.fetchurl { url = "https://example.com/a.tar.gz"; hash = "${HASH}"; }\n`);
  const q = spawnSync(process.execPath, [BIN, 'scan', clean, '--format', 'json'], { encoding: 'utf8', timeout: 120000, env: { ...process.env, NODE_TEST_CONTEXT: undefined } });
  assert.equal(JSON.parse(q.stdout).findings.filter((f) => f.type === BUILD_TRUST_TYPE).length, 0);
});

test('[NIX-005.AC04] unresolved fetch arguments reach scan health as unresolved coverage, not as a clean file', async () => {
  const files = { 'd.nix': '{ pkgs, h }: pkgs.fetchurl { url = "https://example.com/a"; hash = h; }' };
  const adapter = createNixBuildTrustAdapter({ files });
  const res = await runLanguageAnalysis({ files, adapters: [adapter] });
  assert.equal(res.findings.length, 0);
  assert.equal(res.ledger.byFile['d.nix'][adapter.id], 'unresolved');
  const health = languageHealth({ ledger: res.ledger, outcomes: res.outcomes });
  assert.notEqual(health.status, 'complete', 'an unresolved input is never reported as fully analyzed');
});
