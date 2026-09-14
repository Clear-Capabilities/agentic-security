// Rust SAST rules: TLS verification, weak crypto, weak RNG for security
// tokens, and unsafe raw-memory operations. Smoke against vulnerable/clean
// fixture pairs, per test/fixtures/<rule>/{vulnerable,clean}.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRust } from '../src/sast/rust.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function scanFixture(rule, variant) {
  const fp = path.join(__dirname, 'fixtures', rule, variant, 'main.rs');
  const raw = fs.readFileSync(fp, 'utf8');
  return scanRust('main.rs', raw);
}

test('rust-tls-verify-disabled: fires on danger_accept_invalid_certs(true), not on a plain builder', () => {
  const vuln = scanFixture('rust-tls-verify-disabled', 'vulnerable');
  assert.ok(vuln.some(f => f.id.startsWith('rust-tls-verify-disabled')), vuln.map(f => f.id).join(','));
  assert.equal(vuln.find(f => f.id.startsWith('rust-tls-verify-disabled')).cwe, 'CWE-295');
  const clean = scanFixture('rust-tls-verify-disabled', 'clean');
  assert.equal(clean.filter(f => f.id.startsWith('rust-tls-verify-disabled')).length, 0);
});

test('rust-weak-hash: fires on md5::compute and Sha1::new, not on Sha256', () => {
  const vuln = scanFixture('rust-weak-crypto', 'vulnerable');
  assert.ok(vuln.some(f => f.id.startsWith('rust-weak-hash-md5')), vuln.map(f => f.id).join(','));
  assert.ok(vuln.some(f => f.id.startsWith('rust-weak-hash-sha1')), vuln.map(f => f.id).join(','));
  const clean = scanFixture('rust-weak-crypto', 'clean');
  assert.equal(clean.filter(f => f.id.startsWith('rust-weak-hash')).length, 0);
});

test('rust-weak-rng-token: fires on rand::random() bound to a token identifier, not on OsRng', () => {
  const vuln = scanFixture('rust-weak-rng-token', 'vulnerable');
  assert.ok(vuln.some(f => f.id.startsWith('rust-weak-rng-token')), vuln.map(f => f.id).join(','));
  assert.equal(vuln.find(f => f.id.startsWith('rust-weak-rng-token')).cwe, 'CWE-338');
  const clean = scanFixture('rust-weak-rng-token', 'clean');
  assert.equal(clean.filter(f => f.id.startsWith('rust-weak-rng-token')).length, 0);
});

test('rust-unsafe-raw-memory: fires on transmute and get_unchecked, not on from_le_bytes/get', () => {
  const vuln = scanFixture('rust-unsafe-raw-memory', 'vulnerable');
  const ids = vuln.filter(f => f.id.startsWith('rust-unsafe-raw-memory'));
  assert.ok(ids.length >= 2, `expected transmute + get_unchecked, got: ${ids.map(f => f.line)}`);
  const clean = scanFixture('rust-unsafe-raw-memory', 'clean');
  assert.equal(clean.filter(f => f.id.startsWith('rust-unsafe-raw-memory')).length, 0);
});

test('rust-actix-extract-string / rust-rng-zero-seed / rust-sqlx-format still work (pre-existing rules, not touched)', () => {
  const findings = scanRust('main.rs', `
use std::process::Command;
fn f(user: &str, pool: &sqlx::PgPool) {
    Command::new("sh").arg("-c").arg(user).output().unwrap();
}
`);
  assert.ok(findings.some(f => f.id.startsWith('rust-cmd-shell')));
  assert.equal(findings.find(f => f.id.startsWith('rust-cmd-shell')).family, 'command-injection');
});
