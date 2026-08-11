// Phase-1 (Sentinel-parity) new detector regression tests.
//
// Each new SAST module ships with a fixture pair (vulnerable/ + clean/-ish
// alternative) under scanner/test/fixtures/<name>/. This file scans each
// fixture directory and asserts the detector fires on the vuln files and
// not on the safe files.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { scanPrototypePollution } from '../src/sast/prototype-pollution.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

async function findingsFor(dir) {
  const { scan } = await runScan(dir);
  return scan.findings || [];
}

function endsWith(f, suffix) {
  return (f.file || '').endsWith(suffix);
}

test('mass-assignment: vuln fires, allow-list clean', async () => {
  const fs = await findingsFor(FIX('mass-assignment'));
  const vuln1 = fs.some(f => endsWith(f, 'vuln-express-objassign.js') && /Mass Assignment/.test(f.vuln));
  const vuln2 = fs.some(f => endsWith(f, 'vuln-mongoose-create.js') && /Mass Assignment/.test(f.vuln));
  const safeFalsePos = fs.some(f => endsWith(f, 'safe-allowlist.js') && /Mass Assignment/.test(f.vuln) && f.severity !== 'low');
  assert.ok(vuln1, 'Object.assign(user, req.body) should fire');
  assert.ok(vuln2, 'Mongoose User.create(req.body) should fire');
  assert.ok(!safeFalsePos, 'allow-listed write should not fire above low severity');
});

test('prototype-pollution: lodash.merge + hand-rolled fire, fresh target clean', async () => {
  const fs = await findingsFor(FIX('prototype-pollution'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-lodash-merge.js') && /Prototype Pollution/.test(f.vuln)),
    'lodash.merge(cfg, req.body) should fire');
  assert.ok(fs.some(f => endsWith(f, 'vuln-handrolled-merge.js') && /Prototype Pollution/.test(f.vuln)),
    'hand-rolled deep merge should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-fresh-target.js') && /Prototype Pollution/.test(f.vuln)),
    'Object.assign with fresh target should not fire');
});

// Stage 1 correctness audit: the direct-write detector's write-context guard
// (`/=\s*[^=]/.test(post)`, "only flag write context") doesn't anchor to the
// FIRST `=` — it matches anywhere in the 60-char window, including the
// trailing `=` of a `===`/`==` chain followed by a space and operand. A
// read-only strict-equality comparison (a common defensive/type-check idiom)
// was flagged as "Direct write to __proto__" despite never writing anything.
test('prototype-pollution direct-write does not fire on a read-only === comparison', () => {
  const src = 'function isPlainObject(obj) {\n  return obj.__proto__ === Object.prototype;\n}\n';
  const findings = scanPrototypePollution('app.js', src);
  assert.equal(findings.filter(f => /Direct write to __proto__/.test(f.vuln)).length, 0,
    `expected no finding for a read-only comparison, got: ${JSON.stringify(findings)}`);
});

test('prototype-pollution direct-write still fires on a genuine assignment', () => {
  const src = 'function pollute(obj) {\n  obj.__proto__ = { polluted: true };\n}\n';
  const findings = scanPrototypePollution('app.js', src);
  assert.equal(findings.filter(f => /Direct write to __proto__/.test(f.vuln)).length, 1);
});

test('csrf: POST without protection fires; csurf and bearer auth are clean', async () => {
  const fs = await findingsFor(FIX('csrf-routes'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-express-post.js') && /CSRF/.test(f.vuln)),
    'unprotected POST should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-csurf.js') && /CSRF/.test(f.vuln)),
    'csurf-protected route should not fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-bearer-auth.js') && /CSRF/.test(f.vuln)),
    'Bearer-token-authed route should not fire');
});

test('toctou: fs.access → fs.readFile fires; direct read clean', async () => {
  const fs = await findingsFor(FIX('toctou'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-access-then-open.js') && /TOCTOU/.test(f.vuln)),
    'access-then-read should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-direct-open.js') && /TOCTOU/.test(f.vuln)),
    'direct read should not fire');
});

test('nosql-injection: Mongo find(req.body) + $where concat fire, coerced clean', async () => {
  const fs = await findingsFor(FIX('nosql-injection'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-mongo-find-body.js') && /NoSQL Injection/.test(f.vuln)),
    'findOne(req.body) should fire');
  assert.ok(fs.some(f => endsWith(f, 'vuln-mongo-where-concat.js') && /NoSQL Injection/.test(f.vuln)),
    '$where concatenation should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-mongo-coerce.js') && /NoSQL Injection/.test(f.vuln)),
    'String()-coerced query should not fire');
});

test('ldap-injection: concat fires, EqualityFilter clean', async () => {
  const fs = await findingsFor(FIX('ldap-injection'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-ldapjs-concat.js') && /LDAP Injection/.test(f.vuln)),
    'LDAP filter concat should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-structured-filter.js') && /LDAP Injection/.test(f.vuln)),
    'EqualityFilter form should not fire');
});

test('xpath-injection: concat fires, variable-resolver clean', async () => {
  const fs = await findingsFor(FIX('xpath-injection'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-java-concat.java') && /XPath Injection/.test(f.vuln)),
    'XPath compile() with concat should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-java-variable.java') && /XPath Injection/.test(f.vuln)),
    'XPath variable form should not fire');
});

test('ssrf-cloud-metadata: user-controlled URL without guard fires; with guard clean', async () => {
  const fs = await findingsFor(FIX('ssrf-cloud-metadata'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-user-url-no-guard.js') && /SSRF/.test(f.vuln)),
    'axios.get(req.query.url) without guard should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-with-metadata-guard.js')
                          && /SSRF \(metadata-aware\)/.test(f.vuln || '')),
    'guarded fetch should not fire the metadata-aware SSRF');
});

test('mutation-xss: DOMParser round-trip fires; textContent clean', async () => {
  const fs = await findingsFor(FIX('mutation-xss'));
  assert.ok(fs.some(f => endsWith(f, 'vuln-parser-roundtrip.js') && /Mutation XSS/.test(f.vuln)),
    'DOMParser → body.innerHTML round-trip should fire');
  assert.ok(!fs.some(f => endsWith(f, 'safe-textcontent.js') && /Mutation XSS/.test(f.vuln)),
    'textContent assignment should not fire');
});

test('deserialization-gadgets: unsafe sink + commons-collections in classpath fires', async () => {
  const fsVuln = await findingsFor(FIX('deserialization-gadgets/vuln'));
  const fsSafe = await findingsFor(FIX('deserialization-gadgets/safe'));
  assert.ok(fsVuln.some(f => /Gadget-Chain/.test(f.vuln || '')),
    'unsafe sink + commons-collections should fire gadget-chain finding');
  assert.ok(!fsSafe.some(f => /Gadget-Chain/.test(f.vuln || '')),
    'no unsafe sink should not fire');
});

test('precision pipeline: every finding has stableId, confidence, exploitability', async () => {
  const fs = await findingsFor(FIX('mass-assignment'));
  assert.ok(fs.length > 0, 'sanity: fixture should produce findings');
  for (const f of fs) {
    assert.ok(typeof f.stableId === 'string' && f.stableId.length === 16,
      `stableId missing or wrong shape on: ${f.vuln}`);
    assert.ok(typeof f.confidence === 'number' && f.confidence >= 0 && f.confidence <= 1,
      `confidence missing or out of range on: ${f.vuln}`);
    assert.ok(['high', 'medium', 'low', 'very-low'].includes(f.confidenceTier),
      `confidenceTier invalid on: ${f.vuln}`);
    assert.ok(typeof f.exploitability === 'number' && f.exploitability >= 0 && f.exploitability <= 1,
      `exploitability missing or out of range on: ${f.vuln}`);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(f.exploitabilityTier),
      `exploitabilityTier invalid on: ${f.vuln}`);
  }
});
