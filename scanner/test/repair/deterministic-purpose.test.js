// FR-01 / GAP-01 (T-01, T-02): the weak-hash transformation is chosen by the purpose of the operation, never by the CWE alone.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { planDeterministicFix, synthesizeDeterministicPatch, classifyHashPurpose } from '../../src/posture/deterministic-fix.js';

const PY_PW = 'import hashlib\n\n\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n\n\ndef login(user, password):\n    return hash_password(password) == user["pw"]\n\n\ndef register(store, name, password):\n    store[name] = {"pw": hash_password(password)}\n';
const JS_PW = "const crypto = require('crypto');\nfunction hashPassword(password) { return crypto.createHash('md5').update(password).digest('hex'); }\nfunction login(user, password) { return hashPassword(password) === user.pw; }\nfunction register(store, name, password) { store[name] = { pw: hashPassword(password) }; }\nmodule.exports = { hashPassword, login, register };\n";

test('AC-01.1 / T-01: a CWE-916 MD5 password hash never becomes plain SHA-256', () => {
  for (const [file, src, line] of [['auth.py', PY_PW, 5], ['auth.js', JS_PW, 2]]) {
    const plan = planDeterministicFix({ file, line, cwe: 'CWE-916', family: 'weak-password-hash' }, src);
    assert.equal(plan.purpose, 'password-storage');
    assert.equal(plan.disposition, 'proposed');
    assert.equal(plan.ruleId, 'weak-hash-password-kdf');
    const out = plan.patch[file];
    assert.doesNotMatch(out, /sha256/i, `${file}: no fast-hash substitution`);
    assert.match(out, /scrypt/);
    assert.ok(plan.requiredObligations.includes('password-legacy-login-preserved'));
  }
});

test('AC-01.1: a CWE-916 finding whose code shows no password is needs-review, not a sha256 swap', () => {
  const src = "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\n";
  const plan = planDeterministicFix({ file: 'a.js', line: 2, cwe: 'CWE-916' }, src);
  assert.equal(plan.disposition, 'needs-review');
  assert.equal(synthesizeDeterministicPatch({ file: 'a.js', line: 2, cwe: 'CWE-916' }, src), null);
});

test('AC-01.2 / T-02: password hashing and a compatibility digest in one file: only the justified operation changes', () => {
  const src = PY_PW + '\n\ndef s3_content_md5(body):\n    # Content-MD5 header the storage API recomputes\n    return hashlib.md5(body).hexdigest()\n';
  const pw = planDeterministicFix({ file: 'm.py', line: 5, cwe: 'CWE-916' }, src);
  assert.equal(pw.disposition, 'proposed');
  assert.match(pw.patch['m.py'], /def s3_content_md5\(body\):\n    # Content-MD5 header the storage API recomputes\n    return hashlib\.md5\(body\)\.hexdigest\(\)/, 'the compatibility digest is untouched');
  const compat = planDeterministicFix({ file: 'm.py', line: src.split('\n').findIndex((l) => l.includes('hashlib.md5(body)')) + 1, cwe: 'CWE-328' }, src);
  assert.equal(compat.purpose, 'protocol-compatibility');
  assert.equal(compat.disposition, 'needs-review');
});

test('a non-password integrity digest is swapped at that one call site only', () => {
  const src = "const crypto = require('crypto');\nfunction checksum(data) { return crypto.createHash('md5').update(data).digest('hex'); }\nfunction legacyId(x) { return crypto.createHash('md5').update(x).digest('hex'); }\n";
  const plan = planDeterministicFix({ file: 'c.js', line: 2, cwe: 'CWE-328' }, src);
  assert.equal(plan.purpose, 'non-password-integrity');
  assert.equal(plan.disposition, 'proposed');
  assert.match(plan.patch['c.js'].split('\n')[1], /sha256/);
  assert.match(plan.patch['c.js'].split('\n')[2], /'md5'/, 'the other call is left alone');
  assert.equal(plan.scope.otherOccurrencesLeftAlone, 1);
});

test('AC-01.3: an unknown purpose is needs-review with the missing facts named', () => {
  const src = "const crypto = require('crypto');\nfunction f(x) { const d = crypto.createHash('sha1').update(x).digest('hex'); db.save(d); }\n";
  const plan = planDeterministicFix({ file: 'u.js', line: 2, cwe: 'CWE-328' }, src);
  assert.equal(plan.disposition, 'needs-review');
  assert.ok(plan.missingFacts.length >= 1 && plan.missingFacts.every((m) => typeof m === 'string' && m.length > 10));
  const bare = planDeterministicFix({ file: 'b.js', line: 2, cwe: 'CWE-328' }, "const crypto = require('crypto');\nconst h = crypto.createHash('md5');\n");
  assert.equal(bare.purpose, 'unknown');
  assert.equal(bare.disposition, 'needs-review');
});

test('signatures and an unrecognised password shape are refused, never guessed', () => {
  const sig = planDeterministicFix({ file: 's.py', line: 3, cwe: 'CWE-327' }, 'import hashlib\ndef sign(msg, key):\n    return hashlib.md5(key + msg).hexdigest()\n');
  assert.equal(sig.purpose, 'signature'); assert.equal(sig.disposition, 'needs-review');
  const salted = planDeterministicFix({ file: 'p.py', line: 3, cwe: 'CWE-916' }, 'import hashlib\ndef hash_password(password):\n    return hashlib.md5((SALT + password).encode()).hexdigest()\n');
  assert.equal(salted.purpose, 'password-storage'); assert.equal(salted.disposition, 'needs-review');
  assert.match(salted.missingFacts[0], /recomputed exactly/);
  const oddUse = planDeterministicFix({ file: 'q.py', line: 3, cwe: 'CWE-916' }, 'import hashlib\ndef hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()\n\nprint(hash_password(x)[:4])\n');
  assert.equal(oddUse.disposition, 'needs-review');
});

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pwmig-'));
const md5 = (s) => createHash('md5').update(s).digest('hex');
const hasPython = spawnSync('python3', ['-c', 'import hashlib; hashlib.scrypt(b"x", salt=b"s", n=16, r=1, p=1)']).status === 0;

test('AC-01.4: the Python migration keeps legacy login, writes the new format, rejects wrong passwords (executed)', { skip: hasPython ? false : 'python3 with hashlib.scrypt is not available on this host' }, () => {
  const plan = planDeterministicFix({ file: 'auth.py', line: 5, cwe: 'CWE-916' }, PY_PW);
  const dir = tmp();
  try {
    fs.writeFileSync(path.join(dir, 'auth.py'), plan.patch['auth.py']);
    const check = `import sys; sys.path.insert(0, ${JSON.stringify(dir)})\nimport auth\nlegacy = {"pw": ${JSON.stringify(md5('hunter2'))}}\nassert auth.login(legacy, "hunter2") is True, "legacy login"\nassert auth.login(legacy, "wrong") is False, "legacy wrong"\nassert auth.password_needs_rehash(legacy["pw"]) is True\nstore = {}\nauth.register(store, "ann", "s3cret")\nassert store["ann"]["pw"].startswith("scrypt$"), store\nassert auth.login(store["ann"], "s3cret") is True, "new login"\nassert auth.login(store["ann"], "s3cret!") is False, "new wrong"\nassert auth.password_needs_rehash(store["ann"]["pw"]) is False\nassert auth.hash_password("a") != auth.hash_password("a"), "salted"\nassert auth.login({"pw": "scrypt$bad"}, "x") is False\nprint("ok")\n`;
    const r = spawnSync('python3', ['-I', '-c', check], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ok/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('AC-01.4: the JavaScript migration keeps legacy login, writes the new format, rejects wrong passwords (executed)', () => {
  const plan = planDeterministicFix({ file: 'auth.js', line: 2, cwe: 'CWE-916' }, JS_PW);
  const dir = tmp();
  try {
    fs.writeFileSync(path.join(dir, 'auth.cjs'), plan.patch['auth.js']);
    const check = `const a = require(${JSON.stringify(path.join(dir, 'auth.cjs'))}); const assert = require('assert');\nconst legacy = { pw: ${JSON.stringify(md5('hunter2'))} };\nassert.equal(a.login(legacy, 'hunter2'), true); assert.equal(a.login(legacy, 'nope'), false); assert.equal(a.passwordNeedsRehash(legacy.pw), true);\nconst s = {}; a.register(s, 'ann', 's3cret'); assert.ok(s.ann.pw.startsWith('scrypt$'));\nassert.equal(a.login(s.ann, 's3cret'), true); assert.equal(a.login(s.ann, 's3cret!'), false); assert.equal(a.passwordNeedsRehash(s.ann.pw), false);\nassert.notEqual(a.hashPassword('a'), a.hashPassword('a')); assert.equal(a.verifyPassword('x', 'scrypt$1$2'), false);\nconsole.log('ok');\n`;
    const r = spawnSync(process.execPath, ['-e', check], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ok/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('purpose comes from the code, not the file name', () => {
  const src = "const crypto = require('crypto');\nfunction checksum(data) { return crypto.createHash('md5').update(data).digest('hex'); }\n";
  assert.equal(classifyHashPurpose(src, 'password-utils.js', 2).purpose, 'non-password-integrity');
});

test('AC-01.6: house-style examples are labelled candidates and never offer a fast hash for a password', async () => {
  const { findStyleExamples } = await import('../../src/posture/fix-style-mirror.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'style-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.js'), "const h = crypto.createHash('sha256').update(x).digest('hex');\n");
    fs.writeFileSync(path.join(dir, 'b.js'), "db.query('SELECT 1 WHERE a = ?', [a]);\n");
    fs.writeFileSync(path.join(dir, 't.js'), 'x\n');
    const sql = findStyleExamples(dir, { family: 'sqli', file: 't.js' });
    assert.ok(sql.length >= 1);
    for (const e of sql) { assert.equal(e.establishesSafety, false); assert.equal(e.status, 'candidate-pattern'); }
    assert.deepEqual(findStyleExamples(dir, { family: 'crypto-weak-hash', cwe: 'CWE-916', file: 't.js' }), []);
    assert.ok(findStyleExamples(dir, { family: 'crypto-weak-hash', cwe: 'CWE-328', file: 't.js' }).every((e) => e.establishesSafety === false));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
